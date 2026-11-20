"""`health` check (host, watch pass): each site's homepage probed from the worker, plus what explains a slow
or failing site from inside: load, memory, swap, which php-fpm / web server units run, php-fpm
`pm.max_children` warnings, which pool serves each site, and the traffic share per site and user agent. Rules
only: a finding needs user-visible impact on two passes in a row (2026 PHP-FPM incident); pressure alone is
evidence, never a finding."""

from __future__ import annotations

import json
import re
import statistics
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel

from handscheck.agents._framework.check import (
    LOG_TAIL_BYTES,
    Check,
    CheckContext,
    DiffView,
    Facts,
    Output,
    Raw,
    last_lines,
    output_warning,
    tail_command,
)
from handscheck.agents._framework.findings import FindingItem
from handscheck.agents.activity.check import access_log_path
from handscheck.agents.users.check import parse_now

HISTORY = 12
UNIT = re.compile(r"^(php\d+(?:\.\d+)?-fpm|apache2|nginx)\.service$")
FPM_VERSION = re.compile(r"php(\d+(?:\.\d+)?)[-/]fpm")
MAX_CHILDREN = re.compile(r"^\[([^\]]+)\] WARNING: \[pool ([^\]]+)\] server reached pm\.max_children")
COMBINED = re.compile(
    r'^(?:[^\s:]+:\d+\s+)?\S+ \S+ \S+ \[(?P<time>[^\]]+)\] "[^"]*" \d{3} \S+ "[^"]*" "(?P<ua>[^"]*)"'
)
RULE = "health.{}"


class Probe(BaseModel):
    time: int
    status: int | None = None
    elapsed_s: float | None = None
    error: str | None = None

    @property
    def bad(self) -> bool:
        return self.status is None or self.status >= 500


class Service(BaseModel):
    name: str
    active: bool


class Share(BaseModel):
    name: str
    requests: int
    share: float


class HealthFacts(Facts):
    now: int = 0
    cores: int | None = None
    load: list[float] = []
    """1, 5 and 15 minute load averages."""
    mem_total_kb: int | None = None
    mem_available_kb: int | None = None
    swap_used_kb: int | None = None
    services: list[Service] = []
    max_children: dict[str, int] = {}
    """php-fpm unit (php8.3-fpm) → `server reached pm.max_children` warnings within the lookback."""
    site_pools: dict[str, str] = {}
    """site → the php-fpm unit that serves it."""
    probes: dict[str, list[Probe]] = {}
    """site → the latest probes of its homepage, oldest first (this pass last; carried between passes)."""
    site_share: list[Share] = []
    agent_share: list[Share] = []
    rule_settings: dict[str, Any] = {}

    def diff_view(self) -> DiffView:
        return {
            "services": {s.name: s.active for s in self.services},
            "site_pools": dict(self.site_pools),
        }

    def metrics(self) -> dict[str, float]:
        out: dict[str, float] = {"max_children_warnings": float(sum(self.max_children.values()))}
        if self.load:
            out["load1"] = self.load[0]
        if self.mem_available_kb is not None:
            out["mem_available_mb"] = self.mem_available_kb / 1024
        for site, series in self.probes.items():
            if series and series[-1].elapsed_s is not None:
                out[f"probe_s.{site}"] = series[-1].elapsed_s
        return out


class HealthCheck(Check[HealthFacts]):
    name = "health"
    facts_model = HealthFacts

    async def collect(self, ctx: CheckContext, settings: dict[str, Any]) -> dict[str, Output]:
        raw: dict[str, Output] = {
            "now": await ctx.run(["date", "+%s %z"]),
            "nproc": await ctx.run(["nproc"]),
            "loadavg": await ctx.run(["cat", "/proc/loadavg"]),
            "meminfo": await ctx.run(["cat", "/proc/meminfo"]),
            "units": await ctx.run(
                ["systemctl", "list-units", "--all", "--no-legend", "--plain"]
                + ["php*-fpm.service", "apache2.service", "nginx.service"]
            ),
        }
        if not raw["units"].ok or not raw["units"].stdout.strip():
            raw["ps"] = await ctx.run(["ps", "-eo", "args"])  # no systemd (containers)
        services = parse_services(raw["units"], raw.get("ps"))
        for svc in services:
            if m := FPM_VERSION.search(svc.name):
                raw[f"fpmlog@{svc.name}"] = await ctx.run_privileged(
                    tail_command(f"/var/log/php{m.group(1)}-fpm.log", 1_000_000), max_output=1_100_000
                )
        http = ctx.services.http
        for site in ctx.sites:
            if site.config:
                raw[f"pool@{site.name}"] = await ctx.run_privileged(
                    ["grep", "-s", "-h", "-o", "-E", r"php[0-9.]+[-/]fpm", "--", site.config]
                )
                if settings["access_log_lines"] > 0:
                    conf = await ctx.run_privileged(
                        ["grep", "-s", "-h", "-i", "-E", r"^\s*(CustomLog|access_log)\s", "--", site.config]
                    )
                    log = access_log_path(conf.stdout, site.name)
                    if log is not None:
                        raw[f"access@{site.name}"] = await ctx.run_privileged(
                            tail_command(log), max_output=LOG_TAIL_BYTES + 65_536
                        )
            if http is not None:
                response = await http.get(ctx.address, site.name, "/")
                probe = {
                    "status": response.status,
                    "elapsed_s": response.elapsed_s,
                    "error": response.error,
                }
                raw[f"probe@{site.name}"] = Output(stdout=json.dumps(probe))  # not a command: a worker probe
        return raw

    def parse(self, raw: Raw, settings: dict[str, Any]) -> HealthFacts:
        warnings = [
            w
            for key, out in raw.items()
            if not key.startswith(("probe@", "access@", "fpmlog@", "pool@")) and key not in ("units", "ps")
            if (w := output_warning(key, out))
        ]
        now, _tz = parse_now(raw.get("now", Output.missing()).stdout)
        since = now - timedelta(minutes=settings["lookback_minutes"])
        facts = HealthFacts(
            warnings=warnings,
            now=int(now.timestamp()),
            rule_settings={"slow_s": settings["slow_s"], "slow_factor": settings["slow_factor"]},
        )
        nproc = raw.get("nproc", Output.missing()).stdout.strip()
        facts.cores = int(nproc) if nproc.isdigit() else None
        facts.load = parse_loadavg(raw.get("loadavg", Output.missing()).stdout)
        facts.mem_total_kb, facts.mem_available_kb, facts.swap_used_kb = parse_meminfo(
            raw.get("meminfo", Output.missing()).stdout
        )
        facts.services = parse_services(raw.get("units", Output.missing()), raw.get("ps"))
        fpm_units = [s.name for s in facts.services if FPM_VERSION.search(s.name)]
        sites: Counter[str] = Counter()
        agents: Counter[str] = Counter()
        for key, out in sorted(raw.items()):
            kind, _, name = key.partition("@")
            if kind == "fpmlog":
                facts.max_children[name] = count_max_children(out.stdout, since)
            elif kind == "pool":
                facts.site_pools[name] = pool_for(out.stdout, fpm_units) or ""
            elif kind == "access":
                for ua in count_requests(last_lines(out.stdout, settings["access_log_lines"]), since):
                    sites[name] += 1
                    agents[ua] += 1
            elif kind == "probe":
                data = json.loads(out.stdout or "{}")
                facts.probes[name] = [Probe(time=facts.now, **data)]
        facts.site_pools = {k: v for k, v in facts.site_pools.items() if v}
        for site in facts.probes:  # a site without a vhost pool line, on a server with one php-fpm
            if site not in facts.site_pools and len(fpm_units) == 1:
                facts.site_pools[site] = fpm_units[0]
        facts.site_share = _shares(sites)
        facts.agent_share = _shares(agents)[:8]
        return facts

    def carry(self, previous: dict[str, Any], facts: HealthFacts) -> HealthFacts:
        """Each site's earlier probes (the last HISTORY), so the rules can see two passes in a row and its
        usual response time."""
        before = previous.get("probes") or {}
        for site, current in facts.probes.items():
            earlier = [Probe.model_validate(p) for p in before.get(site) or []]
            facts.probes[site] = [*earlier, *current][-HISTORY:]
        return facts

    def guaranteed_findings(self, facts: dict[str, Any]) -> list[FindingItem]:
        f = HealthFacts.model_validate(facts)
        out = []
        for site, series in sorted(f.probes.items()):
            item = site_down(f, site, series) or site_slow(f, site, series)
            if item is not None:
                out.append(item)
        return out


CHECK = HealthCheck


# ── pure parsers ─────────────────────────────────────────────────────────────


def parse_services(units: Output, ps: Output | None) -> list[Service]:
    """`systemctl list-units --plain --no-legend` lines, or (no systemd) `ps -eo args` process names."""
    out: dict[str, bool] = {}
    for line in units.lines() if units.ok else []:
        fields = line.split()
        if len(fields) >= 4 and (m := UNIT.match(fields[0])):
            out[m.group(1)] = fields[2] == "active"
    if not out and ps is not None:
        for line in ps.lines():
            if m := re.search(r"php-fpm: master process \(/etc/php/(\d+(?:\.\d+)?)/fpm/", line):
                out[f"php{m.group(1)}-fpm"] = True
            elif re.match(r"^/usr/sbin/(apache2|nginx)\b", line):
                out[line.split()[0].rsplit("/", 1)[-1]] = True
    return [Service(name=n, active=a) for n, a in sorted(out.items())]


def parse_loadavg(text: str) -> list[float]:
    try:
        return [float(x) for x in text.split()[:3]]
    except ValueError:
        return []


def parse_meminfo(text: str) -> tuple[int | None, int | None, int | None]:
    values = {}
    for line in text.splitlines():
        name, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            values[name.strip()] = int(parts[0])
    swap = None
    if "SwapTotal" in values and "SwapFree" in values:
        swap = values["SwapTotal"] - values["SwapFree"]
    return values.get("MemTotal"), values.get("MemAvailable"), swap


def count_max_children(log: str, since: datetime) -> int:
    """`server reached pm.max_children` warnings at or after `since` (php-fpm log times are local; lines
    without a parsable time are counted, a recent read is short)."""
    count = 0
    for line in log.splitlines():
        m = MAX_CHILDREN.match(line)
        if m is None:
            continue
        when = None
        for fmt in ("%d-%b-%Y %H:%M:%S", "%d-%b-%Y %H:%M:%S.%f"):
            try:
                when = datetime.strptime(m.group(1), fmt).replace(tzinfo=since.tzinfo)
                break
            except ValueError:
                continue
        if when is None or when >= since:
            count += 1
    return count


def pool_for(conf_match: str, fpm_units: list[str]) -> str | None:
    """The php-fpm unit a vhost hands PHP to (`proxy:unix:/run/php/php8.3-fpm.sock`)."""
    for line in conf_match.splitlines():
        if m := FPM_VERSION.search(line):
            unit = f"php{m.group(1)}-fpm"
            if unit in fpm_units or not fpm_units:
                return unit
    return None


def count_requests(log: str, since: datetime) -> list[str]:
    """User agents of the requests at or after `since` (one per request)."""
    out = []
    for line in log.splitlines():
        m = COMBINED.match(line)
        if m is None:
            continue
        try:
            when = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        if when >= since and not m.group("ua").startswith("handscheck/"):  # our own probes aren't traffic
            out.append(_agent(m.group("ua")))
    return out


def _agent(ua: str) -> str:
    """A user agent's family: a named crawler (Bytespider, Googlebot) or the browser string's first token."""
    if m := re.search(r"([A-Za-z][A-Za-z0-9_-]*(?:bot|spider|crawler|Spider|Bot))", ua):
        return m.group(1)
    return (ua.split(" ", 1)[0] or "-")[:60]


def _shares(counts: Counter[str]) -> list[Share]:
    total = sum(counts.values())
    return (
        [Share(name=n, requests=c, share=round(c / total, 3)) for n, c in counts.most_common()]
        if total
        else []
    )


# ── rules ────────────────────────────────────────────────────────────────────


def _stamp(t: int) -> str:
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d %H:%M UTC")


def _describe(p: Probe) -> str:
    if p.status is None:
        return f"{_stamp(p.time)}: no answer ({(p.error or 'error')[:80]})"
    return f"{_stamp(p.time)}: HTTP {p.status} in {p.elapsed_s if p.elapsed_s is not None else '?'} s"


def _episode_start(series: list[Probe], bad: Any) -> int:
    start = series[-1].time
    for p in reversed(series):
        if not bad(p):
            break
        start = p.time
    return start


def _context(f: HealthFacts, site: str) -> list[str]:
    """What explains it: the site's pool and its max_children warnings, load, memory, services, traffic."""
    lines = []
    pool = f.site_pools.get(site)
    if pool:
        lines.append(
            f"php-fpm pool {pool}: pm.max_children reached {f.max_children.get(pool, 0)} time(s) recently"
        )
    if f.load:
        per_core = f" ({f.load[0] / f.cores:.1f} per core)" if f.cores else ""
        lines.append(f"load {', '.join(f'{x:.2f}' for x in f.load)} on {f.cores or '?'} cores{per_core}")
    if f.mem_available_kb is not None and f.mem_total_kb:
        lines.append(
            f"memory available {f.mem_available_kb // 1024} MB of {f.mem_total_kb // 1024} MB, swap used "
            f"{(f.swap_used_kb or 0) // 1024} MB"
        )
    stopped = [s.name for s in f.services if not s.active]
    if stopped:
        lines.append(f"not running: {', '.join(stopped)}")
    if f.site_share:
        lines.append("traffic by site: " + ", ".join(f"{s.name} {s.share:.0%}" for s in f.site_share[:5]))
    if f.agent_share:
        lines.append(
            "traffic by user agent: " + ", ".join(f"{s.name} {s.share:.0%}" for s in f.agent_share[:5])
        )
    return lines


def _cause(f: HealthFacts, site: str) -> str:
    pool = f.site_pools.get(site)
    stopped = {s.name for s in f.services if not s.active}
    if pool and pool in stopped:
        return f"{pool}, which runs the site's PHP, isn't running."
    if stopped & {"apache2", "nginx"}:
        return f"The web server ({', '.join(sorted(stopped & {'apache2', 'nginx'}))}) isn't running."
    if pool and f.max_children.get(pool):
        crawler = next((s for s in f.agent_share if re.search(r"bot|spider|crawler", s.name, re.I)), None)
        extra = f"; {crawler.name} sends {crawler.share:.0%} of the requests" if crawler else ""
        return (
            f"Its PHP pool ({pool}) ran out of workers (pm.max_children reached {f.max_children[pool]} "
            "time(s)"
            f"{extra}). A restart frees the workers, but if it keeps happening the pool needs more "
            "capacity or "
            "the traffic needs limiting."
        )
    return (
        "Nothing on the server explains it yet (PHP pool and services look fine): check the database, "
        "external services and recent changes."
    )


def site_down(f: HealthFacts, site: str, series: list[Probe]) -> FindingItem | None:
    if len(series) < 3 or not (series[-1].bad and series[-2].bad):
        return None
    if not any(not p.bad for p in series[:-2]):
        return None  # never answered normally: not something that just broke
    start = _episode_start(series, lambda p: p.bad)
    return FindingItem(
        kind="site_down",
        subject=f"{site}@{_stamp(start)}",
        severity="high",
        confidence="high",
        title=f"{site} is down: errors or no answer two checks in a row",
        summary=(
            f"{site}'s homepage has answered with a server error or not at all since {_stamp(start)}, "
            "on the last "
            f"two checks from outside, after answering normally before. Visitors can't use the site. "
            + _cause(f, site)
        ),
        evidence=[f"probe {_describe(p)}" for p in series[-4:]] + _context(f, site),
        rule_ids=[RULE.format("site-down")],
        recommended_action=(
            "Find what is failing (the web server and PHP error logs, the database); if the cause below is a "
            "stopped service or a full PHP pool, the offered restart brings the site back for now."
        ),
    )


def site_slow(f: HealthFacts, site: str, series: list[Probe]) -> FindingItem | None:
    s = f.rule_settings
    slow_s, factor = float(s.get("slow_s", 5.0)), float(s.get("slow_factor", 3.0))
    if len(series) < 3:
        return None
    usual_times = [p.elapsed_s for p in series[:-2] if not p.bad and p.elapsed_s is not None]
    if not usual_times:
        return None
    usual = statistics.median(usual_times)

    def slow(p: Probe) -> bool:
        return not p.bad and p.elapsed_s is not None and p.elapsed_s > slow_s and p.elapsed_s > factor * usual

    if not (slow(series[-1]) and slow(series[-2])):
        return None
    start = _episode_start(series, slow)
    return FindingItem(
        kind="site_slow",
        subject=f"{site}@{_stamp(start)}",
        severity="medium",
        confidence="high",
        title=f"{site} is slow: {series[-1].elapsed_s} s for the homepage (usually {usual:.1f} s)",
        summary=(
            f"{site}'s homepage took {series[-2].elapsed_s} s and {series[-1].elapsed_s} s on the last "
            "two checks "
            f"from outside, against {usual:.1f} s usually. Visitors wait or give up. " + _cause(f, site)
        ),
        evidence=[f"probe {_describe(p)}" for p in series[-4:]] + _context(f, site),
        rule_ids=[RULE.format("site-slow")],
        recommended_action=(
            "Look at what changed and at the traffic below; if the PHP pool keeps running out of workers, "
            "add capacity or limit the crawler rather than restarting again."
        ),
    )
