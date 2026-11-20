"""`exposure` check (per site): hygiene risks, separate from active compromise. Database dumps, archives,
backups and logs in the web root; phpinfo pages; directory listings; XML-RPC; code the web server can write;
PHP and Ubuntu past end of support.

Files are found on the host (find/grep through the policy); whether they are actually reachable is confirmed
with a few plain GET requests from the worker (`CheckContext.services.http`), never from the host.
"""

from __future__ import annotations

import fnmatch
import json
import posixpath
import re
from datetime import date
from functools import cache
from typing import Any

from pydantic import BaseModel

from handscheck.agents._framework.check import (
    Check,
    CheckContext,
    DiffView,
    Facts,
    Output,
    Raw,
    output_warning,
    split_fields,
)
from handscheck.agents._framework.findings import FindingItem
from handscheck.agents._framework.rules import EolRule, load_rules, shared_rules_dir
from handscheck.agents._framework.services import HttpResponse
from handscheck.ssh.probe import parse_os_release

LISTING = re.compile(r"<title>\s*Index of\b", re.IGNORECASE)
PHPINFO = re.compile(r"phpinfo\(\)|<h1 class=\"p\">PHP Version", re.IGNORECASE)
XMLRPC = "XML-RPC server accepts POST requests only"
MAX_FILES = 200
DUMP_RULE = "exposure.downloadable-dump"
LISTING_RULE = "exposure.directory-listing"
PHPINFO_RULE = "exposure.public-phpinfo"
_DUMP_OR_SECRET = ("*.sql", "*.sql.*", "*.dump", ".env", "wp-config.php.*", "*.wp-config.php")


def _is_dump_or_secret(path: str) -> bool:
    name = posixpath.basename(path).lower()
    return any(fnmatch.fnmatchcase(name, pat) for pat in _DUMP_OR_SECRET)


@cache
def eol_rules() -> tuple[EolRule, ...]:
    return load_rules(shared_rules_dir() / "eol.yaml", EolRule)


class SensitiveFile(BaseModel):
    path: str
    size: int | None = None
    http_status: int | None = None
    """Status of a GET for it from the worker (200 = anyone can download it). None = not probed."""


class PhpInfoFile(BaseModel):
    path: str
    served: bool | None = None


class Ownership(BaseModel):
    path: str
    owner: str
    group: str
    mode: str
    web_writable: bool


class Eol(BaseModel):
    product: str
    version: str
    eol: date
    past: bool


class ExposureFacts(Facts):
    root: str | None = None
    sensitive_files: list[SensitiveFile] = []
    phpinfo_files: list[PhpInfoFile] = []
    directory_listings: list[str] = []
    """Paths (relative to the site) that return an "Index of" listing."""
    listing_probes: int = 0
    xmlrpc_enabled: bool | None = None
    code_ownership: list[Ownership] = []
    code_writable_by_web_user: bool | None = None
    php_version: str | None = None
    php_eol: Eol | None = None
    os_version: str | None = None
    os_eol: Eol | None = None
    probe_errors: list[str] = []

    def diff_view(self) -> DiffView:
        return {
            # The size class makes a dump that gains data (schema only → customer rows) a change, while a
            # nightly backup of about the same size is not.
            "sensitive_files": {f.path: [f.http_status, size_class(f.size)] for f in self.sensitive_files},
            "phpinfo_files": {f.path: f.served for f in self.phpinfo_files},
            "directory_listings": dict.fromkeys(self.directory_listings, True),
            "attributes": {
                "xmlrpc_enabled": self.xmlrpc_enabled,
                "code_writable_by_web_user": self.code_writable_by_web_user,
                "php_version": self.php_version,
                "php_eol_past": self.php_eol.past if self.php_eol else None,
                "os_version": self.os_version,
                "os_eol_past": self.os_eol.past if self.os_eol else None,
            },
        }

    def metrics(self) -> dict[str, float]:
        m: dict[str, float] = {
            "sensitive_files": len(self.sensitive_files),
            "downloadable_sensitive_files": sum(1 for f in self.sensitive_files if f.http_status == 200),
            "phpinfo_files": len(self.phpinfo_files),
            "directory_listings": len(self.directory_listings),
        }
        for name, value in (
            ("xmlrpc_enabled", self.xmlrpc_enabled),
            ("code_writable_by_web_user", self.code_writable_by_web_user),
            ("php_eol_past", self.php_eol.past if self.php_eol else None),
            ("os_eol_past", self.os_eol.past if self.os_eol else None),
        ):
            if value is not None:
                m[name] = int(value)
        return m


class ExposureCheck(Check[ExposureFacts]):
    name = "exposure"
    facts_model = ExposureFacts

    async def collect(self, ctx: CheckContext, settings: dict[str, Any]) -> dict[str, Output]:
        raw: dict[str, Output] = {}
        site = ctx.site
        raw["php"] = await ctx.run(["php", "-v"])
        raw["os"] = await ctx.run(["cat", "/etc/os-release"])
        raw["today"] = await ctx.run(["date", "-u", "+%Y-%m-%d"])
        if site is None or not site.docroot:
            return raw
        root = site.docroot
        raw["site"] = Output(stdout=root + "\n")  # not a command: what was checked

        names: list[str] = ["("]
        for i, glob in enumerate(settings["sensitive_names"]):
            names += (["-o"] if i else []) + ["-iname", glob]
        names.append(")")
        raw["sensitive"] = await ctx.run_privileged(
            ["find", root, "-maxdepth", str(settings["sensitive_depth"]), "-type", "f", *names]
            + ["-printf", r"%p\t%s\n"]
        )
        raw["php_top"] = await ctx.run_privileged(
            ["find", root, "-maxdepth", "2", "-type", "f", "-name", "*.php", "-printf", r"%p\n"]
        )
        raw["phpinfo"] = await ctx.run_batched(
            ["grep", "-l", "-E", r"phpinfo\s*\("], sorted(raw["php_top"].lines())[:MAX_FILES], privileged=True
        )
        raw["dirs"] = await ctx.run_privileged(
            ["find", root, "-mindepth", "1", "-maxdepth", "3", "(", "-name", ".git", "-o", "-name"]
            + ["node_modules", ")", "-prune", "-o", "-type", "d", "-printf", r"%p\n"]
        )
        raw["index_dirs"] = await ctx.run_privileged(
            ["find", root, "-mindepth", "1", "-maxdepth", "4", "-type", "f", "("]
            + ["-name", "index.php", "-o", "-name", "index.html", "-o", "-name", "index.htm", ")"]
            + ["-printf", r"%h\n"]
        )
        code = [root]
        if site.wordpress:
            wp = site.wordpress.path
            code = [posixpath.join(wp, d) for d in ("wp-admin", "wp-includes")]
            code += [posixpath.join(wp, "wp-content", d) for d in ("plugins", "themes")]
        raw["ownership"] = await ctx.run(["find", *code, "-maxdepth", "0", "-printf", r"%p\t%u\t%g\t%m\n"])

        http = ctx.services.http
        if http is not None and settings["http_probes"]:
            probes: list[dict[str, Any]] = []
            site_name = site.name

            async def probe(kind: str, path: str) -> None:
                try:
                    response: HttpResponse = await http.get(ctx.address, site_name, path)
                except ValueError as exc:  # a path we won't put in a URL (spaces, odd characters)
                    response = HttpResponse(url=path, error=str(exc))
                probes.append({"kind": kind, "path": path, **response.model_dump()})

            for row in sorted(_rows(raw["sensitive"], 2))[:20]:
                await probe("sensitive", _url_path(root, row[0]))
            for file in sorted(raw["phpinfo"].lines())[:10]:
                await probe("phpinfo", _url_path(root, file))
            for d in listing_candidates(
                raw["dirs"].lines(), raw["index_dirs"].lines(), root, settings["listing_probe_limit"]
            ):
                await probe("listing", _url_path(root, d) + "/")
            if site.wordpress:
                await probe("xmlrpc", _url_path(root, posixpath.join(site.wordpress.path, "xmlrpc.php")))
            raw["http"] = Output(stdout=json.dumps(probes))  # not a command: the worker's HTTP probes
        return raw

    def guaranteed_findings(self, facts: dict[str, Any]) -> list[FindingItem]:
        """Exposures the worker confirmed over HTTP: a database dump or secrets file anyone can download
        (the incident's customer dump), a listable folder, and a public phpinfo page."""
        out = []
        for f in facts.get("sensitive_files") or []:
            path = str(f.get("path", ""))
            if f.get("http_status") != 200 or not _is_dump_or_secret(path):
                continue
            out.append(
                FindingItem(
                    kind="downloadable_dump",
                    subject=path,
                    severity="high",
                    confidence="high",
                    title=f"Anyone can download {posixpath.basename(path)} from the site",
                    summary=(
                        f"{path} ({f.get('size')} bytes) is in the web root and the site serves it "
                        "(HTTP 200). Database dumps and config backups hold customer data and passwords; the "
                        "October 2026 attackers left one like this."
                    ),
                    evidence=[f"sensitive_files: {path} size {f.get('size')} http_status 200"],
                    rule_ids=[DUMP_RULE],
                    recommended_action=(
                        f"Move {path} out of the web root now; if it holds passwords or keys, change them."
                    ),
                )
            )
        for url in facts.get("directory_listings") or []:
            uploads = "/wp-content/uploads/" in url
            out.append(
                FindingItem(
                    kind="directory_listing",
                    subject=url,
                    severity="high" if uploads else "medium",
                    confidence="high",
                    title=f"Folder {url} shows a list of its files to anyone",
                    summary=(
                        f'Requesting {url} returns an "Index of" page, so anyone can list and download every '
                        "file in it"
                        + (" (uploaded files, which often include customer documents)." if uploads else ".")
                    ),
                    evidence=[f"directory_listings: {url}"],
                    rule_ids=[LISTING_RULE],
                    recommended_action=f"Turn off listings for {url} (Options -Indexes) or add an index.",
                )
            )
        for p in facts.get("phpinfo_files") or []:
            if p.get("served") is not True:
                continue
            path = str(p.get("path", ""))
            out.append(
                FindingItem(
                    kind="public_phpinfo",
                    subject=path,
                    severity="medium",
                    confidence="high",
                    title=f"Public phpinfo page: {posixpath.basename(path)}",
                    summary=(
                        f"{path} calls phpinfo() and the site serves it, showing PHP's configuration, paths "
                        "and environment to anyone (useful to an attacker)."
                    ),
                    evidence=[f"phpinfo_files: {path} served"],
                    rule_ids=[PHPINFO_RULE],
                    recommended_action=f"Delete or move {path} out of the web root.",
                )
            )
        return out

    def parse(self, raw: Raw, settings: dict[str, Any]) -> ExposureFacts:
        warnings = [w for key, out in raw.items() if (w := output_warning(key, out))]
        facts = ExposureFacts(warnings=warnings)
        today = _date(raw.get("today", Output.missing()).stdout) or date.today()
        facts.php_version = parse_php_version(raw.get("php", Output.missing()).stdout)
        if facts.php_version:
            facts.php_eol = eol_status("php", ".".join(facts.php_version.split(".")[:2]), today)
        os_info = parse_os_release(raw.get("os", Output.missing()).stdout)
        if os_info.id == "ubuntu" and os_info.version_id:
            facts.os_version = f"ubuntu {os_info.version_id}"
            facts.os_eol = eol_status("ubuntu", os_info.version_id, today)
        if "site" not in raw:
            return facts
        root = facts.root = raw["site"].stdout.strip()

        probes = json.loads(raw["http"].stdout) if "http" in raw else []
        status = {(p["kind"], p["path"]): p for p in probes}
        facts.probe_errors = sorted({f"{p['path']}: {p['error']}" for p in probes if p.get("error")})[:20]

        for path, size in sorted(_rows(raw.get("sensitive", Output.missing()), 2)):
            p = status.get(("sensitive", _url_path(root, path)))
            facts.sensitive_files.append(
                SensitiveFile(path=path, size=_int(size), http_status=p.get("status") if p else None)
            )
        for path in sorted(raw.get("phpinfo", Output.missing()).lines()):
            p = status.get(("phpinfo", _url_path(root, path)))
            served = (
                None
                if not p or p.get("status") is None
                else p["status"] == 200 and bool(PHPINFO.search(p["body"]))
            )
            facts.phpinfo_files.append(PhpInfoFile(path=path, served=served))
        listings = [p for p in probes if p["kind"] == "listing"]
        facts.listing_probes = len(listings)
        facts.directory_listings = sorted(
            p["path"] for p in listings if p.get("status") == 200 and LISTING.search(p.get("body") or "")
        )
        xml = next((p for p in probes if p["kind"] == "xmlrpc"), None)
        if xml and xml.get("status") is not None:
            facts.xmlrpc_enabled = xml["status"] == 405 and XMLRPC in (xml.get("body") or "")

        web_users = set(settings["web_users"])
        for path, owner, group, mode in _rows(raw.get("ownership", Output.missing()), 4):
            perms = int(mode, 8) if re.fullmatch(r"[0-7]{3,4}", mode) else 0
            writable = (owner in web_users and perms & 0o200 != 0) or (
                group in web_users and perms & 0o020 != 0
            )
            writable = writable or perms & 0o002 != 0
            facts.code_ownership.append(
                Ownership(path=path, owner=owner, group=group, mode=mode.zfill(4), web_writable=writable)
            )
        if facts.code_ownership:
            facts.code_writable_by_web_user = any(o.web_writable for o in facts.code_ownership)
        return facts


CHECK = ExposureCheck


# ── pure helpers ─────────────────────────────────────────────────────────────


def parse_php_version(stdout: str) -> str | None:
    m = re.match(r"^PHP (\d+\.\d+\.\d+)", stdout.strip())
    return m.group(1) if m else None


def eol_status(product: str, version: str, today: date) -> Eol | None:
    for rule in eol_rules():
        if rule.product == product and rule.version == version:
            return Eol(product=product, version=version, eol=rule.eol, past=today > rule.eol)
    return None


def listing_candidates(dirs: list[str], index_dirs: list[str], root: str, limit: int) -> list[str]:
    """Folders without an index file, most interesting first (uploads, then shallow ones), at most `limit`."""
    has_index = set(index_dirs)
    candidates = [d for d in dirs if d not in has_index and not posixpath.basename(d).startswith(".")]

    def rank(d: str) -> tuple[int, int, str]:
        rel = d[len(root) :]
        return (0 if "/wp-content/uploads" in rel else 1, rel.count("/"), rel)

    return sorted(candidates, key=rank)[:limit]


def _url_path(root: str, path: str) -> str:
    rel = (
        path[len(root.rstrip("/")) :]
        if path.startswith(root.rstrip("/") + "/")
        else "/" + posixpath.basename(path)
    )
    return rel or "/"


def _rows(out: Output, n: int) -> list[tuple[str, ...]]:
    return [tuple(f) for line in out.lines() if (f := split_fields(line, n))]


def _date(text: str) -> date | None:
    try:
        return date.fromisoformat(text.strip())
    except ValueError:
        return None


def _int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def size_class(size: int | None) -> str:
    """A coarse size for the diff: unknown, empty, <1KB, <1MB, <100MB or larger."""
    if size is None:
        return "unknown"
    for limit, label in ((0, "empty"), (1023, "<1KB"), (1024**2 - 1, "<1MB"), (100 * 1024**2 - 1, "<100MB")):
        if size <= limit:
            return label
    return ">=100MB"
