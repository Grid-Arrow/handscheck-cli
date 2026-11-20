"""Site discovery: Apache and Nginx virtual hosts, plus WordPress installs (in vhost document roots and under
/var/www). Runs on every full scan; new and removed sites become change events.

A site is identified by its primary name (ServerName / first server_name). WordPress installs that no vhost
serves are still listed, named by their path, because their code can be attacked through another site.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from typing import Any, Literal

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
)

DISCOVERY_VERSION = 1
CONFIG_DIRS = (
    "/etc/apache2/sites-enabled",
    "/etc/httpd/conf.d",
    "/etc/nginx/sites-enabled",
    "/etc/nginx/conf.d",
)
WEB_ROOTS = ("/var/www",)
WP_SEARCH_DEPTH = 4
"""find -maxdepth from each root to wp-includes/version.php (site/wp-includes/version.php is 3)."""
MAX_WP_INSTALLS = 500

ServerKind = Literal["apache", "nginx", "none"]


class WordPressInstall(BaseModel):
    path: str
    version: str | None = None


class Site(BaseModel):
    name: str
    aliases: list[str] = []
    docroot: str | None = None
    server: ServerKind
    config: str | None = None
    listen: list[str] = []
    type: Literal["wordpress", "unknown"] = "unknown"
    wordpress: WordPressInstall | None = None


class SiteInventory(Facts):
    sites: list[Site] = []

    def diff_view(self) -> DiffView:
        return {
            "sites": {
                s.name: {
                    "docroot": s.docroot,
                    "type": s.type,
                    "aliases": s.aliases,
                    "server": s.server,
                    "wordpress_version": s.wordpress.version if s.wordpress else None,
                }
                for s in self.sites
            }
        }

    def metrics(self) -> dict[str, float]:
        return {"count": len(self.sites), "wordpress": sum(1 for s in self.sites if s.type == "wordpress")}


class SiteDiscovery(Check[SiteInventory]):
    name = "sites"
    facts_model = SiteInventory

    async def collect(self, ctx: CheckContext, settings: dict[str, Any]) -> dict[str, Output]:
        raw: dict[str, Output] = {}
        raw["configs"] = await ctx.run_privileged(
            ["grep", "-s", "-H", "-R", "", "--", *CONFIG_DIRS], max_output=4_000_000
        )
        vhosts = parse_configs(raw["configs"].stdout)
        roots = search_roots([v.docroot for v in vhosts if v.docroot])
        raw["wp_versions_files"] = await ctx.run_privileged(
            [
                "find",
                *roots,
                "-maxdepth",
                str(WP_SEARCH_DEPTH),
                "-path",
                "*/wp-includes/version.php",
                "-type",
                "f",
                "-printf",
                r"%p\n",
            ]
        )
        files = sorted(raw["wp_versions_files"].lines())[:MAX_WP_INSTALLS]
        if files:
            raw["wp_versions"] = await ctx.run_privileged(
                ["grep", "-s", "-H", "-E", r"^\$wp_version\s*=", "--", *files]
            )
        return raw

    def parse(self, raw: Raw, settings: dict[str, Any]) -> SiteInventory:
        warnings = [w for key, out in raw.items() if (w := output_warning(key, out))]
        vhosts = parse_configs(raw.get("configs", Output.missing()).stdout)
        installs = parse_wp_versions(
            raw.get("wp_versions_files", Output.missing()).lines(),
            raw.get("wp_versions", Output.missing()).stdout,
        )
        return SiteInventory(warnings=warnings, sites=merge_sites(vhosts, installs))


# ── pure parsers ─────────────────────────────────────────────────────────────


def parse_configs(stdout: str) -> list[Site]:
    sites: list[Site] = []
    for path, lines in grep_h_lines(stdout).items():
        if path.startswith("/etc/nginx/"):
            sites.extend(parse_nginx(path, lines))
        else:
            sites.extend(parse_apache(path, lines))
    return sites


_VHOST_OPEN = re.compile(r"^<VirtualHost\s+([^>]*)>", re.IGNORECASE)
_VHOST_CLOSE = re.compile(r"^</VirtualHost\s*>", re.IGNORECASE)


def parse_apache(path: str, lines: list[str]) -> list[Site]:
    sites: list[Site] = []
    current: dict[str, Any] | None = None
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if m := _VHOST_OPEN.match(line):
            current = {"listen": m.group(1).split(), "names": [], "docroot": None}
            continue
        if _VHOST_CLOSE.match(line):
            if current is not None:
                site = _site(current["names"], current["docroot"], "apache", path, current["listen"])
                if site:
                    sites.append(site)
            current = None
            continue
        if current is None:
            continue
        words = _words(line)
        if not words:
            continue
        directive = words[0].lower()
        if directive in ("servername", "serveralias"):
            current["names"].extend(words[1:])
        elif directive == "documentroot" and len(words) > 1:
            current["docroot"] = words[1].rstrip("/") or "/"
    return sites


def parse_nginx(path: str, lines: list[str]) -> list[Site]:
    text = "\n".join(line.split("#", 1)[0] for line in lines)
    tokens = re.findall(r""""[^"]*"|'[^']*'|[{};]|[^\s{};]+""", text)
    sites: list[Site] = []
    stack: list[str] = []
    statement: list[str] = []
    server: dict[str, Any] | None = None
    server_depth = -1
    for tok in tokens:
        if tok == "{":
            name = statement[0] if statement else ""
            stack.append(name)
            if name == "server" and server is None:
                server = {"listen": [], "names": [], "docroot": None}
                server_depth = len(stack)
            statement = []
        elif tok == "}":
            if server is not None and len(stack) == server_depth:
                names = [n for n in server["names"] if n not in ("_", '""', "")]
                site = _site(names, server["docroot"], "nginx", path, server["listen"])
                if site:
                    sites.append(site)
                server, server_depth = None, -1
            if stack:
                stack.pop()
            statement = []
        elif tok == ";":
            if server is not None and len(stack) == server_depth and statement:
                directive, args = statement[0], [a.strip("\"'") for a in statement[1:]]
                if directive == "server_name":
                    server["names"].extend(args)
                elif directive == "root" and args:
                    server["docroot"] = args[0].rstrip("/") or "/"
                elif directive == "listen" and args:
                    server["listen"].append(" ".join(args))
            statement = []
        else:
            statement.append(tok)
    return sites


def _site(
    names: list[str], docroot: str | None, server: ServerKind, config: str, listen: list[str]
) -> Site | None:
    names = list(dict.fromkeys(n.lower() for n in names if n))
    if not names and not docroot:
        return None
    name = names[0] if names else docroot or config
    return Site(name=name, aliases=names[1:], docroot=docroot, server=server, config=config, listen=listen)


def _words(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=False)
    except ValueError:
        return line.split()


def search_roots(docroots: list[str]) -> list[str]:
    roots: list[str] = []
    for root in sorted({*WEB_ROOTS, *(posixpath.normpath(d) for d in docroots)}):
        if root in ("/", "") or not root.startswith("/"):
            continue
        if not any(root == r or root.startswith(r + "/") for r in roots):
            roots.append(root)
    return roots


_WP_VERSION = re.compile(r"""^\$wp_version\s*=\s*['"]([^'"]+)['"]""")


def parse_wp_versions(version_files: list[str], grep_out: str) -> list[WordPressInstall]:
    versions: dict[str, str] = {}
    for path, lines in grep_h_lines(grep_out).items():
        for line in lines:
            if m := _WP_VERSION.match(line.strip()):
                versions[path] = m.group(1)
    installs = []
    for file in sorted(set(version_files)):
        install = posixpath.dirname(posixpath.dirname(file))
        installs.append(WordPressInstall(path=install, version=versions.get(file)))
    return installs


def merge_sites(vhosts: list[Site], installs: list[WordPressInstall]) -> list[Site]:
    """One entry per site name (http + https vhosts merge), WordPress attached by document root."""
    merged: dict[str, Site] = {}
    for v in vhosts:
        site = merged.get(v.name)
        if site is None:
            merged[v.name] = v.model_copy(deep=True)
            continue
        site.aliases = sorted(set(site.aliases) | set(v.aliases))
        site.listen = list(dict.fromkeys([*site.listen, *v.listen]))
        site.docroot = site.docroot or v.docroot
    for site in merged.values():
        site.aliases = sorted(set(site.aliases) - {site.name})

    claimed: set[str] = set()
    for site in merged.values():
        if not site.docroot:
            continue
        # The install at the document root, else the shallowest one below it (WordPress in a subfolder).
        below = [i for i in installs if i.path == site.docroot or i.path.startswith(site.docroot + "/")]
        if below:
            best = min(below, key=lambda i: (i.path.count("/"), i.path))
            site.type, site.wordpress = "wordpress", best
            claimed.add(best.path)
    for install in installs:
        if install.path not in claimed and install.path not in merged:
            merged[install.path] = Site(
                name=install.path, docroot=install.path, server="none", type="wordpress", wordpress=install
            )
    return sorted(merged.values(), key=lambda s: s.name)


DISCOVERY = SiteDiscovery()
