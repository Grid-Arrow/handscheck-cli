"""Recon's deterministic inventory (M7c): what kind of server this is, read-only, before any Claude call.

It answers the questions that decide per-host agent settings: which accounts own the WordPress sites
(wp-cli reads as www-data, so another owner is worth a note), which accounts the web server and PHP pools run
as, where SSH logins are logged, where each site's access log is and how big it is, whether wp-cli is
installed, and how much of auth.log is sudo noise from our own commands (the cause of the ga-aws-24
truncation). `code_changes`
turns the clear-cut answers into setting changes, so recon is useful without Claude.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field

from handscheck.agents._framework.check import (
    LOG_TAIL_BYTES,
    Check,
    CheckContext,
    Facts,
    Output,
    Raw,
    output_warning,
)
from handscheck.agents._framework.definition import AgentDefinition
from handscheck.agents.activity.check import access_log_path
from handscheck.agents.health.check import Service, parse_services
from handscheck.contracts import HostAgentState, SettingChange
from handscheck.sites.discovery import Site

AUTH_LOGS = ("/var/log/auth.log", "/var/log/secure")
POOL_PATH = re.compile(r"^/etc/php(?:/(\d+(?:\.\d+)?)|(5))/fpm/[^:]*:\s*user\s*=\s*(\S+)")
APACHE_USER = re.compile(r"^\s*export\s+APACHE_RUN_USER=['\"]?([A-Za-z0-9_.-]+)", re.M)
NGINX_USER = re.compile(r"^\s*user\s+([A-Za-z0-9_.-]+)", re.M)
SYSTEM_OWNERS = frozenset({"root", "nobody", "UNKNOWN"})


class SiteInfo(BaseModel):
    name: str
    type: str
    server: str
    docroot: str | None = None
    owner: str | None = None
    access_log: str | None = None
    access_log_bytes: int | None = None


class ReconInventory(Facts):
    os: str | None = None
    services: list[Service] = Field(default_factory=list)
    pool_users: dict[str, list[str]] = Field(default_factory=dict)
    apache_user: str | None = None
    nginx_user: str | None = None
    sites: list[SiteInfo] = Field(default_factory=list)
    logs: dict[str, int] = Field(default_factory=dict)
    """Auth log path → size in bytes (only the ones that exist)."""
    wp_cli: str | None = None
    sudo_lines: int | None = None
    """sudo COMMAND lines in the auth log (ours and everyone's)."""

    def web_accounts(self) -> list[str]:
        found = {u for users in self.pool_users.values() for u in users}
        found |= {u for u in (self.apache_user, self.nginx_user) if u}
        return sorted(found - SYSTEM_OWNERS)


class ReconCheck(Check[ReconInventory]):
    name = "recon"
    facts_model = ReconInventory

    async def collect(self, ctx: CheckContext, settings: dict[str, Any]) -> dict[str, Output]:
        raw: dict[str, Output] = {
            "os": await ctx.run(["cat", "/etc/os-release"]),
            "units": await ctx.run(
                ["systemctl", "list-units", "--all", "--no-legend", "--plain"]
                + ["php*-fpm.service", "apache2.service", "nginx.service"]
            ),
            "pools": await ctx.run_privileged(
                ["grep", "-s", "-H", "-R", "-E", r"^\s*user\s*=", "--", "/etc/php", "/etc/php5"]
            ),
            "apache_user": await ctx.run(
                ["grep", "-s", "-h", "-E", r"^\s*export\s+APACHE_RUN_USER=", "--", "/etc/apache2/envvars"]
            ),
            "nginx_user": await ctx.run_privileged(
                ["grep", "-s", "-h", "-E", r"^\s*user\s", "--", "/etc/nginx/nginx.conf"]
            ),
            "wp_cli": await ctx.run(["which", "wp"]),
        }
        if not raw["units"].ok or not raw["units"].stdout.strip():
            raw["ps"] = await ctx.run(["ps", "-eo", "args"])  # no systemd (containers)
        docroots = sorted({s.docroot for s in ctx.sites if s.docroot})
        raw["owners"] = await ctx.run_batched(["stat", "-c", "%U %n"], docroots, privileged=True)
        logs: list[str] = list(AUTH_LOGS)
        for site in ctx.sites:
            if site.config:
                conf = await ctx.run_privileged(
                    ["grep", "-s", "-h", "-i", "-E", r"^\s*(CustomLog|access_log)\s", "--", site.config]
                )
                raw[f"logconf@{site.name}"] = conf
                if (log := access_log_path(conf.stdout, site.name)) is not None:
                    logs.append(log)
        raw["sizes"] = await ctx.run_batched(["stat", "-c", "%s %n"], sorted(set(logs)), privileged=True)
        auth = next(
            (p for p in AUTH_LOGS if any(line.endswith(f" {p}") for line in raw["sizes"].lines())), None
        )
        if auth is not None:
            raw["sudo_lines"] = await ctx.run_privileged(["grep", "-c", "-F", "COMMAND=", "--", auth])
        return raw

    def parse(self, raw: Raw, settings: dict[str, Any]) -> ReconInventory:
        return build_inventory(raw, [])


CHECK = ReconCheck()


def build_inventory(raw: Raw, sites: list[Site]) -> ReconInventory:
    """The inventory from the collected output and the sites discovery found."""
    warnings = [w for key in ("os", "owners", "sizes") if key in raw and (w := output_warning(key, raw[key]))]
    inv = ReconInventory(
        warnings=warnings,
        os=parse_os_release(raw.get("os", Output.missing()).stdout),
        services=parse_services(raw.get("units", Output.missing()), raw.get("ps")),
        pool_users=parse_pool_users(raw.get("pools", Output.missing()).stdout),
        apache_user=_first(APACHE_USER, raw.get("apache_user", Output.missing()).stdout),
        nginx_user=_first(NGINX_USER, raw.get("nginx_user", Output.missing()).stdout),
        wp_cli=next(iter(raw.get("wp_cli", Output.missing()).lines()), None),
    )
    owners = parse_owners(raw.get("owners", Output.missing()).stdout)
    sizes = {path: int(v) for v, path in _pairs(raw.get("sizes", Output.missing()).stdout) if v.isdigit()}
    inv.logs = {p: sizes[p] for p in AUTH_LOGS if p in sizes}
    for site in sites:
        conf = raw.get(f"logconf@{site.name}")
        log = access_log_path(conf.stdout, site.name) if conf is not None else None
        inv.sites.append(
            SiteInfo(
                name=site.name,
                type=site.type,
                server=site.server,
                docroot=site.docroot,
                owner=owners.get(site.docroot or ""),
                access_log=log,
                access_log_bytes=sizes.get(log or ""),
            )
        )
    count = raw.get("sudo_lines", Output.missing()).stdout.strip()
    inv.sudo_lines = int(count) if count.isdigit() else None
    return inv


# ── pure parsers ─────────────────────────────────────────────────────────────


def parse_os_release(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip("\"'") or None
    return None


def parse_pool_users(stdout: str) -> dict[str, list[str]]:
    """`grep -H -R user= /etc/php` → {"php8.3-fpm": ["www-data", "deploy"]}."""
    pools: dict[str, set[str]] = defaultdict(set)
    for line in stdout.splitlines():
        if m := POOL_PATH.match(line):
            version = m.group(1) or m.group(2)
            pools[f"php{version}-fpm"].add(m.group(3).strip(";\"'"))
    return {k: sorted(v) for k, v in sorted(pools.items())}


def _pairs(stdout: str) -> list[tuple[str, str]]:
    """`stat -c '%X %n'` lines → (value, path); a path may contain spaces."""
    return [(v, path) for line in stdout.splitlines() if " " in line for v, path in [line.split(" ", 1)]]


def parse_owners(stdout: str) -> dict[str, str]:
    """`stat -c '%U %n'` → {path: owner}."""
    return {path: value for value, path in _pairs(stdout)}


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    return m.group(1).rstrip(";") if m else None


# ── changes code can make on its own ─────────────────────────────────────────


LOG_LINES_STEP = 5000
LOG_LINES_MARGIN = 1.25
"""Room for busier hours than the one the health agent last measured."""
ACCESS_LINE_BYTES = 250
"""A typical combined-format access log line, to tell whether the lines fit in the last LOG_TAIL_BYTES."""


def busy_log_lines(
    definitions: dict[str, AgentDefinition],
    stored: dict[str, dict[str, Any]],
    facts: dict[str, dict[str, Any]],
) -> tuple[dict[str, tuple[int, str]], list[str]]:
    """`access_log_lines` for agents whose lookback window holds more requests than the lines they read, from
    the health agent's last count of requests per site. Only raises it, in steps of 5000, up to the schema's
    maximum. Returns {agent: (lines, reason)} and notes."""
    shares = (facts.get("health") or {}).get("site_share") or []
    busiest = max(shares, key=lambda s: s.get("requests", 0), default=None)
    health = definitions.get("health")
    if busiest is None or health is None or not busiest.get("requests"):
        return {}, []
    measured = int(stored.get("health", {}).get("lookback_minutes") or health.defaults()["lookback_minutes"])
    site, requests = str(busiest["name"]), int(busiest["requests"])
    out: dict[str, tuple[int, str]] = {}
    notes: list[str] = []
    for name, d in sorted(definitions.items()):
        if "access_log_lines" not in d.settings or "lookback_minutes" not in d.settings:
            continue
        settings = {**d.defaults(), **stored.get(name, {})}
        lookback, lines = int(settings["lookback_minutes"]), int(settings["access_log_lines"])
        if lines <= 0:
            continue  # access logs turned off on purpose
        needed = (
            math.ceil(requests * lookback / measured * LOG_LINES_MARGIN / LOG_LINES_STEP) * LOG_LINES_STEP
        )
        ceiling = d.settings["access_log_lines"].max
        needed = min(needed, int(ceiling)) if ceiling is not None else needed
        if needed <= lines:
            continue
        out[name] = (
            needed,
            f"{site} had {requests} requests in {measured} minutes; {name} looks back {lookback} minutes, "
            f"so it needs about {needed} lines of that access log, not {lines}.",
        )
        if (
            requests * lookback / measured * ACCESS_LINE_BYTES > LOG_TAIL_BYTES
        ):  # the window itself, unrounded
            notes.append(
                f"{site}'s access log is busy enough that the last {LOG_TAIL_BYTES // 1_000_000} MB read may "
                f"not reach back {lookback} minutes for {name}."
            )
    return out, notes


def code_changes(
    inv: ReconInventory,
    definitions: dict[str, AgentDefinition],
    current: list[HostAgentState],
    facts: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[SettingChange], list[str]]:
    """Setting changes the inventory (and the latest facts) justify, and notes about what they couldn't
    settle. Only adds accounts and paths that exist on the host, and only raises log line counts; never turns
    a check off."""
    stored = {s.agent: s.settings for s in current}
    wanted: dict[str, tuple[Any, str]] = {}
    notes: list[str] = []

    # wp-cli runs as www-data only (command policy and sudoers), so an owner is a note, not a setting.
    wp_owners = sorted({s.owner for s in inv.sites if s.type == "wordpress" and s.owner})
    others = [o for o in wp_owners if o != "www-data"]
    if others:
        notes.append(
            f"WordPress files belong to {', '.join(others)}, not www-data. wp-cli reads the databases as "
            "www-data; if it can't read a site's wp-config.php, its sessions and admins go unchecked."
        )

    if "/var/log/auth.log" not in inv.logs and "/var/log/secure" in inv.logs:
        wanted["auth_log_path"] = ("/var/log/secure", "SSH logins are logged in /var/log/secure here.")

    accounts = inv.web_accounts()
    log_lines, log_notes = busy_log_lines(definitions, stored, facts or {})
    notes.extend(log_notes)
    changes: dict[str, SettingChange] = {}
    for name, d in sorted(definitions.items()):
        settings: dict[str, Any] = {}
        reasons: list[str] = []
        defaults = d.defaults()
        for key, (value, reason) in wanted.items():
            if key in d.settings and value != defaults.get(key) and stored.get(name, {}).get(key) != value:
                settings[key] = value
                reasons.append(reason)
        if "web_users" in d.settings and accounts:
            base = list(stored.get(name, {}).get("web_users") or defaults["web_users"])
            extra = [a for a in accounts if a not in base]
            if extra:
                settings["web_users"] = [*base, *extra]
                reasons.append(f"The web server or PHP runs as {', '.join(extra)} too.")
        if name in log_lines:
            settings["access_log_lines"], why = log_lines[name]
            reasons.append(why)
        if settings:
            changes[name] = SettingChange(agent=name, settings=settings, reason=" ".join(reasons)[:500])
    if inv.sudo_lines and inv.sudo_lines > 20_000:
        notes.append(
            f"{inv.sudo_lines} sudo command lines in the auth log: login checks read only its last 4 MB."
        )
    return list(changes.values()), notes
