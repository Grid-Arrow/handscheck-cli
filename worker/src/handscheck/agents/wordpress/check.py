"""`wordpress` check (per WordPress site): core version, plugins, themes, mu-plugins, administrators
(rogue-admin signals), known-vulnerable plugin versions, and core/plugin file checksums against wordpress.org.

WordPress itself is **never loaded**: loading it (any wp-cli command such as `wp user list`) makes WordPress
spawn wp-cron with a loopback HTTP request that runs scheduled events with every plugin. Versions come from
file headers; administrators come from `wp db query` with fixed SELECT templates (wp-cli reads wp-config.php
for the database credentials, so handscheck needs none, and doesn't load WordPress). Checksums are fetched
by the worker; the host only runs md5sum.
"""

from __future__ import annotations

import json
import posixpath
import re
from functools import cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from handscheck.agents._framework.check import (
    Check,
    CheckContext,
    DiffView,
    Facts,
    Output,
    Raw,
    grep_h_lines,
    output_warning,
    split_fields,
)
from handscheck.agents._framework.findings import SEVERITY_ORDER, FindingItem
from handscheck.agents._framework.rules import AccountRule, VulnerablePluginRule, load_rules, shared_rules_dir
from handscheck.agents._framework.services import ChecksumUnavailable
from handscheck.ssh.policy import WP_DB_QUERIES

RULES = Path(__file__).parent / "rules"
HEADER = re.compile(r"^[ \t/*#@]*(Plugin Name|Theme Name|Version)\s*:\s*(.*?)\s*(\*/)?$", re.IGNORECASE)
PREFIX = re.compile(r"""^\s*\$table_prefix\s*=\s*['"]([A-Za-z0-9_]{1,32})['"]\s*;""")
MAX_PLUGINS = 300


@cache
def account_rules() -> tuple[AccountRule, ...]:
    return load_rules(RULES / "accounts.yaml", AccountRule)


@cache
def vulnerable_plugin_rules() -> tuple[VulnerablePluginRule, ...]:
    return load_rules(shared_rules_dir() / "vulnerable-plugins.yaml", VulnerablePluginRule)


class Plugin(BaseModel):
    slug: str
    name: str | None = None
    version: str | None = None
    file: str


class Theme(BaseModel):
    slug: str
    name: str | None = None
    version: str | None = None


class FileInfo(BaseModel):
    path: str
    size: int | None = None
    mtime: int | None = None
    ctime: int | None = None
    owner: str | None = None


class Account(BaseModel):
    id: int
    login: str
    email: str = ""
    registered: str = ""
    flags: list[str] = []
    """Matched account rules, and `registered_copied` (first user's registration time, higher ID)."""


class VulnerablePlugin(BaseModel):
    slug: str
    version: str | None
    rule: str
    severity: str
    description: str
    fixed_in: str | None = None
    ajax_nopriv: list[str] = []
    """AJAX actions the plugin offers to visitors who aren't logged in (`wp_ajax_nopriv_<action>` in its
    code): what a virtual patch refuses."""
    rest_namespaces: list[str] = []
    """REST API namespaces it registers (`register_rest_route('<namespace>', …)`)."""


class ChecksumReport(BaseModel):
    available: bool
    """False when wordpress.org has no checksums (premium/custom plugin, unknown version)."""
    verified: int = 0
    mismatched: list[str] = []
    extra: list[str] = []
    """PHP files that aren't part of the release (and aren't older than it)."""
    stale: list[str] = []
    """PHP files not in the release but older than all of its files: leftovers of a previous version."""
    missing: list[str] = []
    error: str | None = None


class WordPressFacts(Facts):
    installed: bool = False
    path: str | None = None
    version: str | None = None
    locale: str | None = None
    table_prefix: str | None = None
    plugins: list[Plugin] = []
    themes: list[Theme] = []
    mu_plugins: list[FileInfo] = []
    admins: list[Account] | None = None
    """None when the database couldn't be read (no wp-cli, no sudo for the site user)."""
    first_user: Account | None = None
    vulnerable_plugins: list[VulnerablePlugin] = []
    core_checksums: ChecksumReport | None = None
    plugin_checksums: dict[str, ChecksumReport] = {}

    def diff_view(self) -> DiffView:
        view: DiffView = {
            "core": {"version": self.version},
            "plugins": {p.slug: p.version for p in self.plugins},
            "themes": {t.slug: t.version for t in self.themes},
            "mu_plugins": {m.path: m.size for m in self.mu_plugins},
            "vulnerable_plugins": {f"{v.slug} {v.rule}": v.version for v in self.vulnerable_plugins},
        }
        if self.admins is not None:
            view["admins"] = {
                a.login: {"id": a.id, "email": a.email, "registered": a.registered, "flags": a.flags}
                for a in self.admins
            }
        failures: dict[str, Any] = {}
        reports = {
            "core": self.core_checksums,
            **{f"plugin:{k}": v for k, v in self.plugin_checksums.items()},
        }
        for name, report in reports.items():
            if report is None or not report.available:
                continue
            failures.update({f"{name}:{p}": "mismatch" for p in report.mismatched})
            failures.update({f"{name}:{p}": "extra" for p in report.extra})
        if self.core_checksums is not None:
            view["checksum_failures"] = failures
        return view

    def metrics(self) -> dict[str, float]:
        m: dict[str, float] = {
            "plugins": len(self.plugins),
            "mu_plugins": len(self.mu_plugins),
            "vulnerable_plugins": len(self.vulnerable_plugins),
        }
        if self.admins is not None:
            m["admins"] = len(self.admins)
            m["flagged_admins"] = sum(1 for a in self.admins if a.flags)
        reports = [self.core_checksums, *self.plugin_checksums.values()]
        m["checksum_failures"] = sum(len(r.mismatched) + len(r.extra) for r in reports if r)
        return m


class WordPressCheck(Check[WordPressFacts]):
    name = "wordpress"
    facts_model = WordPressFacts

    async def collect(self, ctx: CheckContext, settings: dict[str, Any]) -> dict[str, Output]:
        raw: dict[str, Output] = {}
        site = ctx.site
        if site is None or site.wordpress is None:
            return raw
        wp = site.wordpress.path
        content = posixpath.join(wp, "wp-content")
        raw["path"] = Output(stdout=wp + "\n")  # not a command: which install this is
        raw["version"] = await ctx.run_privileged(
            ["grep", "-s", "-H", "-E", r"^[$](wp_version|wp_local_package)\s*=", "--"]
            + [posixpath.join(wp, "wp-includes", "version.php")]
        )
        raw["prefix"] = await ctx.run_privileged(
            ["grep", "-s", "-h", "-E", r"^\s*\$table_prefix\s*=", "--"]
            + [posixpath.join(wp, "wp-config.php"), posixpath.join(posixpath.dirname(wp), "wp-config.php")]
        )
        raw["plugin_files"] = await ctx.run_privileged(
            ["find", posixpath.join(content, "plugins"), "-mindepth", "1", "-maxdepth", "2"]
            + ["-type", "f", "-name", "*.php", "-printf", r"%p\n"]
        )
        header = ["grep", "-H", "-m", "6", "-i", "-E", r"^[ \t/*#@]*(Plugin Name|Theme Name|Version)\s*:"]
        raw["plugin_headers"] = await ctx.run_batched(
            header, sorted(raw["plugin_files"].lines())[: MAX_PLUGINS * 5], privileged=True
        )
        raw["theme_files"] = await ctx.run_privileged(
            ["find", posixpath.join(content, "themes"), "-mindepth", "2", "-maxdepth", "2"]
            + ["-type", "f", "-name", "style.css", "-printf", r"%p\n"]
        )
        raw["theme_headers"] = await ctx.run_batched(
            header, sorted(raw["theme_files"].lines())[:MAX_PLUGINS], privileged=True
        )
        raw["mu_plugins"] = await ctx.run_privileged(
            ["find", posixpath.join(content, "mu-plugins"), "-maxdepth", "2", "-type", "f"]
            + ["-printf", r"%p\t%s\t%T@\t%C@\t%u\n"]
        )

        prefix = parse_prefix(raw["prefix"].stdout)
        if prefix and settings["read_admins"]:
            for key in ("admins", "first_user"):  # `sessions` belongs to the activity agent (watch pass)
                template = WP_DB_QUERIES[key]
                raw[f"db_{key}"] = await ctx.run(
                    ["wp", "db", "query", template.format(p=prefix), f"--path={wp}"],
                    sudo=True,
                    sudo_user=settings["wp_cli_user"],
                )

        version, locale = parse_version(raw["version"].stdout)
        source = ctx.services.checksums
        if source is not None and version and settings["verify_core_checksums"]:
            try:
                expected = await source.core(version, locale or "en_US")
            except ChecksumUnavailable as exc:
                raw["core_checksums"] = Output(stdout="", exit_status=1, stderr=str(exc))
            else:
                raw["core_checksums"] = Output(stdout=json.dumps(expected))
                if expected:
                    files = sorted(f for f in expected if _check_file(f, settings))
                    raw["core_md5"] = await ctx.run_batched(
                        ["md5sum"], [posixpath.join(wp, f) for f in files], privileged=True
                    )
                    raw["core_php_files"] = await ctx.run_privileged(
                        ["find", posixpath.join(wp, "wp-admin"), posixpath.join(wp, "wp-includes")]
                        + ["-type", "f", "-name", "*.php", "-printf", r"%p\n"]
                    )

        plugins = parse_plugins(raw["plugin_headers"].stdout, content)
        in_folder = {p.slug for p in plugins if "/" in p.file.removeprefix(content + "/plugins/")}
        vulnerable_dirs = sorted(
            {
                posixpath.join(content, "plugins", v.slug)
                for v in match_vulnerable(plugins)
                if v.slug in in_folder
            }
        )
        if vulnerable_dirs:
            # Entry points a virtual patch can close for anonymous visitors (read-only grep of the code).
            raw["vulnerable_entry_points"] = await ctx.run_privileged(
                ["grep", "-r", "-o", "-H", "-I", "-E", "--include=*.php"]
                + ["-e", ENTRY_AJAX.pattern, "-e", ENTRY_REST.pattern, "--", *vulnerable_dirs],
                max_output=1_000_000,
                timeout=120,
            )
        if source is not None and settings["verify_plugin_checksums"]:
            sums: dict[str, Any] = {}
            to_hash: list[str] = []
            for plugin in plugins:
                if not plugin.version or "/" not in plugin.file.removeprefix(content + "/plugins/"):
                    continue
                try:
                    expected_files = await source.plugin(plugin.slug, plugin.version)
                except ChecksumUnavailable as exc:
                    sums[plugin.slug] = {"error": str(exc)}
                    continue
                sums[plugin.slug] = expected_files
            raw["plugin_checksums"] = Output(stdout=json.dumps(sums))
            with_sums = [slug for slug, v in sums.items() if v and "error" not in v]
            if with_sums:
                dirs = [posixpath.join(content, "plugins", slug) for slug in with_sums]
                raw["plugin_all_files"] = await ctx.run_privileged(
                    ["find", *dirs, "-type", "f", "-printf", r"%p\t%C@\n"], max_output=8_000_000
                )
                files = sorted(line.split("\t", 1)[0] for line in raw["plugin_all_files"].lines())
                to_hash = [p for p in files if _check_file(p, settings)]
                raw["plugin_md5"] = await ctx.run_batched(["md5sum"], to_hash, privileged=True)
        return raw

    def guaranteed_findings(self, facts: dict[str, Any]) -> list[FindingItem]:
        """Rule matches the facts prove on their own: administrators flagged by an account rule (rogue and
        bulk-created admins of the Oct 2026 incident) and plugin versions with a known exploit."""
        return admin_findings(facts) + vulnerable_plugin_findings(facts)

    def parse(self, raw: Raw, settings: dict[str, Any]) -> WordPressFacts:
        warnings = [
            w for key, out in raw.items() if not key.startswith("db_") and (w := output_warning(key, out))
        ]
        facts = WordPressFacts(warnings=warnings)
        if "path" not in raw:
            return facts
        facts.installed = True
        facts.path = raw["path"].stdout.strip()
        content = posixpath.join(facts.path, "wp-content")
        facts.version, facts.locale = parse_version(raw.get("version", Output.missing()).stdout)
        facts.table_prefix = parse_prefix(raw.get("prefix", Output.missing()).stdout)
        facts.plugins = parse_plugins(raw.get("plugin_headers", Output.missing()).stdout, content)
        facts.themes = parse_themes(raw.get("theme_headers", Output.missing()).stdout, content)
        facts.mu_plugins = [
            FileInfo(path=f[0], size=_int(f[1]), mtime=_int(f[2]), ctime=_int(f[3]), owner=f[4])
            for line in raw.get("mu_plugins", Output.missing()).lines()
            if (f := split_fields(line, 5))
        ]
        facts.vulnerable_plugins = match_vulnerable(facts.plugins)
        entry = raw.get("vulnerable_entry_points")
        if entry is not None:
            points = parse_entry_points(entry.stdout, content)
            for v in facts.vulnerable_plugins:
                v.ajax_nopriv, v.rest_namespaces = points.get(v.slug, ([], []))

        admins_out = raw.get("db_admins")
        first_out = raw.get("db_first_user")
        if admins_out is not None and first_out is not None and admins_out.ok and first_out.ok:
            first = parse_accounts(first_out.stdout)
            facts.first_user = first[0] if first else None
            facts.admins = flag_accounts(parse_accounts(admins_out.stdout), facts.first_user)
        elif settings["read_admins"]:
            why = (
                "no table prefix in wp-config.php"
                if not facts.table_prefix
                else _why(admins_out or first_out)
            )
            facts.warnings.append(f"administrators not read: {why}")

        core = raw.get("core_checksums")
        if core is not None:
            facts.core_checksums = core_report(
                core,
                raw.get("core_md5", Output.missing()),
                raw.get("core_php_files", Output.missing()),
                facts.path,
                settings,
            )
        sums_out = raw.get("plugin_checksums")
        if sums_out is not None:
            facts.plugin_checksums = plugin_reports(
                json.loads(sums_out.stdout or "{}"),
                raw.get("plugin_md5", Output.missing()),
                content,
                settings,
                ctimes=parse_ctimes(raw.get("plugin_all_files", Output.missing()).stdout),
            )
        return facts


CHECK = WordPressCheck


def _check_file(path: str, settings: dict[str, Any]) -> bool:
    return not settings["checksum_php_only"] or path.endswith(".php")


def _why(out: Output | None) -> str:
    if out is None:
        return "not attempted"
    if out.sudo_failure:
        return f"sudo as the site user refused ({out.sudo_failure})"
    return (out.stderr.strip().splitlines() or [f"exit status {out.exit_status}"])[-1][:200]


# ── pure parsers ─────────────────────────────────────────────────────────────


def parse_version(stdout: str) -> tuple[str | None, str | None]:
    version = locale = None
    for line in stdout.splitlines():
        text = line.split(":", 1)[-1]
        if m := re.match(r"""^\$wp_version\s*=\s*['"]([^'"]+)['"]""", text):
            version = m.group(1)
        elif m := re.match(r"""^\$wp_local_package\s*=\s*['"]([^'"]+)['"]""", text):
            locale = m.group(1)
    return version, locale


def parse_prefix(stdout: str) -> str | None:
    for line in stdout.splitlines():
        if m := PREFIX.match(line):
            return m.group(1)
    return None


def _headers(stdout: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for path, lines in grep_h_lines(stdout).items():
        for line in lines:
            if m := HEADER.match(line):
                out.setdefault(path, {}).setdefault(m.group(1).lower(), m.group(2).strip())
    return out


def parse_plugins(stdout: str, content: str) -> list[Plugin]:
    """Plugins = PHP files directly in plugins/ or one folder down that carry a `Plugin Name:` header."""
    plugins: dict[str, Plugin] = {}
    base = content.rstrip("/") + "/plugins/"
    for path, header in sorted(_headers(stdout).items()):
        if "plugin name" not in header or not path.startswith(base):
            continue
        rel = path[len(base) :]
        slug = rel.split("/", 1)[0] if "/" in rel else rel.removesuffix(".php")
        plugins.setdefault(
            slug, Plugin(slug=slug, name=header["plugin name"], version=header.get("version"), file=path)
        )
    return list(plugins.values())


def parse_themes(stdout: str, content: str) -> list[Theme]:
    themes = []
    base = content.rstrip("/") + "/themes/"
    for path, header in sorted(_headers(stdout).items()):
        if "theme name" in header and path.startswith(base):
            slug = path[len(base) :].split("/", 1)[0]
            themes.append(Theme(slug=slug, name=header["theme name"], version=header.get("version")))
    return themes


def parse_accounts(stdout: str) -> list[Account]:
    """mysql batch output (tab-separated, header row): ID, user_login, [user_email,] user_registered."""
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        return []
    header = lines[0].split("\t")
    accounts = []
    for line in lines[1:]:
        row = dict(zip(header, line.split("\t"), strict=False))
        try:
            accounts.append(
                Account(
                    id=int(row.get("ID", "")),
                    login=row.get("user_login", ""),
                    email=row.get("user_email", ""),
                    registered=row.get("user_registered", ""),
                )
            )
        except ValueError:
            continue
    return accounts


def flag_accounts(admins: list[Account], first: Account | None) -> list[Account]:
    for admin in admins:
        flags = [r.id for r in account_rules() if r.matches(f"{admin.login} {admin.email}")]
        if (
            first is not None
            and admin.id != first.id
            and admin.registered
            and admin.registered == first.registered
        ):
            flags.append("registered_copied")
        admin.flags = flags
    return admins


def admin_findings(facts: dict[str, Any]) -> list[FindingItem]:
    """An administrator matching an account rule. A copied registration date on top of a rule match is a
    deliberate cover-up (the incident's `root` admin), so that is critical."""
    severities = {r.id: r.severity.value for r in account_rules()}
    out = []
    for a in facts.get("admins") or []:
        flags = list(a.get("flags") or [])
        rated = [severities[f] for f in flags if f in severities]
        if not rated:
            continue
        severity = max(rated, key=lambda s: SEVERITY_ORDER.get(s, 0))
        if "registered_copied" in flags:
            severity = "critical"
        if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER["medium"]:
            continue
        login, email = str(a.get("login", "")), str(a.get("email", ""))
        copied = (
            " Its registration date is copied from the first user's, to look old."
            if "registered_copied" in flags
            else ""
        )
        out.append(
            FindingItem(
                kind="suspicious_admin",
                subject=login,
                severity=severity,
                confidence="high" if severity == "critical" else "medium",
                title=f"Suspicious administrator {login} <{email}>",
                summary=(
                    f"The administrator {login} ({email}) matches patterns of the rogue admins the October "
                    f"2026 attackers created ({', '.join(flags)}).{copied} An unknown admin can do anything "
                    "on the "
                    "site, including installing a backdoor plugin."
                ),
                evidence=[
                    f"admin #{a.get('id')}: {login} {email} registered {a.get('registered')} flags {flags}"
                ],
                rule_ids=[f for f in flags if f in severities],
                recommended_action=(
                    f"If nobody on your team created {login}, remove its administrator role and sessions, "
                    "then look for what it changed (plugins, themes, other users)."
                ),
            )
        )
    return out


def vulnerable_plugin_findings(facts: dict[str, Any]) -> list[FindingItem]:
    names = {str(p.get("slug")): p.get("name") for p in facts.get("plugins") or []}
    out = []
    for v in facts.get("vulnerable_plugins") or []:
        slug, version = str(v.get("slug", "")), v.get("version") or "unknown version"
        severity = str(v.get("severity", "high"))
        if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER["medium"]:
            continue
        name = names.get(slug) or slug
        fixed = f"Update to {v.get('fixed_in')} or later" if v.get("fixed_in") else "Remove or replace it"
        out.append(
            FindingItem(
                kind="vulnerable_plugin",
                subject=slug,
                severity=severity,
                confidence="high",
                title=f"{name} ({slug}) {version} has a known exploit",
                summary=f"{name} {version} is installed. {v.get('description')}",
                evidence=[f"plugin {slug} {version} matches {v.get('rule')}"],
                rule_ids=[str(v.get("rule"))],
                recommended_action=f"{fixed}, then check the site for signs it was already exploited.",
            )
        )
    return out


ENTRY_AJAX = re.compile(r"wp_ajax_nopriv_[A-Za-z0-9_-]+")
ENTRY_REST = re.compile(r"register_rest_route[ \t]*\([ \t]*['\"][A-Za-z0-9_./-]+['\"]")
MAX_ENTRY_POINTS = 50


def parse_entry_points(stdout: str, content: str) -> dict[str, tuple[list[str], list[str]]]:
    """`grep -o -H` output → per plugin slug: anonymous AJAX actions and REST namespaces, sorted."""
    base = content.rstrip("/") + "/plugins/"
    found: dict[str, tuple[set[str], set[str]]] = {}
    for line in stdout.splitlines():
        path, sep, match = line.partition(":")
        if not sep or not path.startswith(base):
            continue
        slug = path[len(base) :].split("/", 1)[0]
        ajax, rest = found.setdefault(slug, (set(), set()))
        if match.startswith("wp_ajax_nopriv_"):
            ajax.add(match.removeprefix("wp_ajax_nopriv_"))
        elif m := re.search(r"['\"]([A-Za-z0-9_./-]+)['\"]", match):
            namespace = m.group(1).strip("/")
            if namespace:
                rest.add(namespace)
    return {
        slug: (sorted(a)[:MAX_ENTRY_POINTS], sorted(r)[:MAX_ENTRY_POINTS]) for slug, (a, r) in found.items()
    }


def match_vulnerable(plugins: list[Plugin]) -> list[VulnerablePlugin]:
    hits = []
    for plugin in plugins:
        for rule in vulnerable_plugin_rules():
            if rule.matches(f"{plugin.slug} {plugin.version or ''}"):
                hits.append(
                    VulnerablePlugin(
                        slug=plugin.slug,
                        version=plugin.version,
                        rule=rule.id,
                        severity=rule.severity.value,
                        description=rule.description,
                        fixed_in=rule.fixed_in,
                    )
                )
    return hits


def parse_md5sum(stdout: str) -> dict[str, str]:
    sums = {}
    for line in stdout.splitlines():
        m = re.match(r"^\\?([0-9a-f]{32}) [ *](.+)$", line)
        if m:
            sums[m.group(2)] = m.group(1)
    return sums


def core_report(
    checksums: Output, md5: Output, php_files: Output, wp: str, settings: dict[str, Any]
) -> ChecksumReport:
    if not checksums.ok:
        return ChecksumReport(available=False, error=checksums.stderr.strip()[:200] or "unavailable")
    expected: dict[str, str] | None = json.loads(checksums.stdout or "null")
    if not expected:
        return ChecksumReport(available=False)
    actual = parse_md5sum(md5.stdout)
    report = ChecksumReport(available=True)
    for rel, want in sorted(expected.items()):
        # Bundled themes and plugins (wp-content/) are updated or deleted on their own schedule.
        if not _check_file(rel, settings) or rel.startswith("wp-content/"):
            continue
        got = actual.get(posixpath.join(wp, rel))
        if got is None:
            report.missing.append(rel)
        elif got != want:
            report.mismatched.append(rel)
        else:
            report.verified += 1
    prefix = wp.rstrip("/") + "/"
    report.extra = sorted(
        p[len(prefix) :]
        for p in php_files.lines()
        if p.startswith(prefix) and p[len(prefix) :] not in expected
    )
    return report


def parse_ctimes(stdout: str) -> dict[str, float]:
    """`find -printf '%p\\t%C@\\n'` → {path: ctime}."""
    out: dict[str, float] = {}
    for line in stdout.splitlines():
        path, sep, ctime = line.rpartition("\t")
        if sep:
            try:
                out[path] = float(ctime)
            except ValueError:
                continue
    return out


def plugin_reports(
    sums: dict[str, Any],
    md5: Output,
    content: str,
    settings: dict[str, Any],
    ctimes: dict[str, float] | None = None,
) -> dict[str, ChecksumReport]:
    """Per plugin: verified, mismatched, extra (PHP not in the release) and missing files.

    Extra files whose ctime is older than every verified file of the release are `stale`: leftovers of an
    older version (updates that copy over a plugin don't delete removed files). ctime can't be faked with
    touch, so a planted file is never older than the release it hides in."""
    ctimes = ctimes or {}
    actual = parse_md5sum(md5.stdout)
    reports: dict[str, ChecksumReport] = {}
    for slug, expected in sorted(sums.items()):
        if expected is None:
            reports[slug] = ChecksumReport(available=False)
            continue
        if "error" in expected and isinstance(expected["error"], str):
            reports[slug] = ChecksumReport(available=False, error=expected["error"][:200])
            continue
        base = posixpath.join(content, "plugins", slug) + "/"
        report = ChecksumReport(available=True)
        mine = {p[len(base) :]: h for p, h in actual.items() if p.startswith(base)}
        verified_ctimes = []
        for rel, got in sorted(mine.items()):
            want = expected.get(rel)
            if want is None:
                if rel.endswith(".php"):
                    report.extra.append(rel)
            elif got in want:
                report.verified += 1
                if base + rel in ctimes:
                    verified_ctimes.append(ctimes[base + rel])
            else:
                report.mismatched.append(rel)
        if verified_ctimes:
            oldest = min(verified_ctimes)
            stale = [rel for rel in report.extra if ctimes.get(base + rel, oldest) < oldest]
            report.stale = stale
            report.extra = [rel for rel in report.extra if rel not in stale]
        report.missing = sorted(rel for rel in expected if _check_file(rel, settings) and rel not in mine)
        reports[slug] = report
    return reports


def _int(value: str) -> int | None:
    try:
        return int(float(value))
    except ValueError:
        return None
