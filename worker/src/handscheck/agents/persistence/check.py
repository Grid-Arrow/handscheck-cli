"""`persistence` check (host level): every crontab (especially web users'), cron script directories, systemd
timers, and notable files in /tmp, /var/tmp and /dev/shm (hidden, owned by a web user, or executable).

Site-level persistence is collected by the site agents: `.user.ini`/`.htaccess` prepends in `malware`,
mu-plugins in `wordpress`.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from typing import Any

from pydantic import BaseModel

from handscheck.agents._framework.check import (
    Check,
    CheckContext,
    DiffView,
    Facts,
    Output,
    Raw,
    canonical_path,
    grep_h_lines,
    output_warning,
    parse_dpkg_search,
    path_aliases,
    split_fields,
)
from handscheck.agents._framework.findings import FindingItem
from handscheck.agents.system.check import UNIT_PATTERN, collect_units

USER_CRONTABS = "/var/spool/cron/crontabs"
SYSTEM_CRONTABS = ("/etc/crontab", "/etc/cron.d")
CRON_SCRIPT_DIRS = ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly")
MAX_TEMP_ENTRIES = 2000


class CronEntry(BaseModel):
    file: str
    user: str
    schedule: str
    command: str


class CronScript(BaseModel):
    path: str
    owner: str
    mode: str
    package: str | None = None


class TimerUnit(BaseModel):
    path: str
    packaged: bool


class TempEntry(BaseModel):
    path: str
    type: str
    """f file, d directory, l link, s socket, p fifo."""
    owner: str
    mode: str
    size: int
    mtime: int | None = None
    reasons: list[str]
    """hidden | web_user | executable"""


class PersistenceFacts(Facts):
    cron_entries: list[CronEntry] = []
    cron_env: list[str] = []
    """Variable assignments in crontabs (e.g. PATH=, MAILTO=), as file: line."""
    web_user_crontabs: list[str] = []
    """Web users (www-data, …) with a personal crontab."""
    cron_scripts: list[CronScript] = []
    timers: list[TimerUnit] = []
    temp_entries: list[TempEntry] = []
    """Notable entries only; see `temp_counts` for everything."""
    temp_counts: dict[str, int] = {}

    def diff_view(self) -> DiffView:
        return {
            "cron_entries": {f"{e.file}: {e.user} {e.schedule} {e.command}": True for e in self.cron_entries},
            "cron_env": dict.fromkeys(self.cron_env, True),
            "cron_scripts": {s.path: s.package for s in self.cron_scripts},
            "timers": {t.path: t.packaged for t in self.timers},
            "temp_entries": {
                e.path: {"type": e.type, "owner": e.owner, "mode": e.mode, "reasons": e.reasons}
                for e in self.temp_entries
            },
        }

    def metrics(self) -> dict[str, float]:
        return {
            "cron_entries": len(self.cron_entries),
            "web_user_crontabs": len(self.web_user_crontabs),
            "unpackaged_cron_scripts": sum(1 for s in self.cron_scripts if s.package is None),
            "unpackaged_timers": sum(1 for t in self.timers if not t.packaged),
            "notable_temp_entries": len(self.temp_entries),
        }


WEB_CRON_RULE = "persistence.web-user-cron-temp"
HIDDEN_TEMP_RULE = "persistence.hidden-temp-entry"
_RUNS_FROM_TEMP = re.compile(r"(^|[\s;|&(=\"'])(/dev/shm|/tmp|/var/tmp)/")
_FETCHES_CODE = re.compile(
    r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|dash|php|python3?|perl)\b|\bbase64\s+(-d|--decode)\b"
)


def web_cron_signal(command: str) -> str | None:
    """Why a web user's cron command looks like attacker persistence, or None (wp-cron and the like)."""
    if _RUNS_FROM_TEMP.search(command):
        return "runs a program from a temp directory"
    if _FETCHES_CODE.search(command):
        return "downloads or decodes code and runs it"
    return None


def hidden_temp_findings(facts: dict[str, Any]) -> list[FindingItem]:
    """A hidden file or folder in a temp directory that a web user owns or that holds a program: attackers'
    working directories (/dev/shm/.x in the Oct 2026 incident). One finding per top hidden entry."""
    roots = sorted(facts.get("temp_counts") or {}, key=len, reverse=True)
    groups: dict[str, list[dict[str, Any]]] = {}
    for e in facts.get("temp_entries") or []:
        reasons = set(e.get("reasons") or [])
        if "hidden" not in reasons or not reasons & {"web_user", "executable"}:
            continue
        path = str(e.get("path", ""))
        root = next((r.rstrip("/") for r in roots if path.startswith(r.rstrip("/") + "/")), None)
        if root is None:
            continue
        parts = path[len(root) + 1 :].split("/")
        hidden = next(i for i, p in enumerate(parts) if p.startswith("."))
        groups.setdefault(root + "/" + "/".join(parts[: hidden + 1]), []).append(e)
    out = []
    for top, entries in sorted(groups.items()):
        owners = sorted({str(e.get("owner")) for e in entries})
        out.append(
            FindingItem(
                kind="hidden_temp_entry",
                subject=top,
                severity="high",
                confidence="medium",
                title=f"Hidden {top} in a temp directory (owner {', '.join(owners)})",
                summary=(
                    f"{top} is hidden (its name starts with a dot) in a world-writable temp directory and is "
                    "owned by a web server user or holds a program. Attackers keep their tools and lists "
                    "there; the October 2026 attackers used /dev/shm/.x."
                ),
                evidence=[
                    f"temp_entries: {e.get('path')} {e.get('type')} {e.get('owner')} {e.get('mode')} "
                    f"({', '.join(e.get('reasons') or [])})"
                    for e in entries[:10]
                ],
                rule_ids=[HIDDEN_TEMP_RULE],
                recommended_action=(
                    f"Look at what is in {top} and which process or cron job uses it; if nobody on your team "
                    "made it, copy it aside for analysis and look for the web shell that created it."
                ),
            )
        )
    return out


class PersistenceCheck(Check[PersistenceFacts]):
    name = "persistence"
    facts_model = PersistenceFacts

    async def collect(self, ctx: CheckContext, settings: dict[str, Any]) -> dict[str, Output]:
        raw: dict[str, Output] = {}
        raw["crontab_files"] = await ctx.run_privileged(
            [
                "find",
                USER_CRONTABS,
                *SYSTEM_CRONTABS,
                "-maxdepth",
                "1",
                "-type",
                "f",
                "-printf",
                r"%p\t%u\t%m\n",
            ]
        )
        files = sorted(f[0] for f in _rows(raw["crontab_files"], 3))
        if files:
            raw["crontabs"] = await ctx.run_privileged(["grep", "-s", "-H", "", "--", *files])
        raw["cron_scripts"] = await ctx.run(
            ["find", *CRON_SCRIPT_DIRS, "-maxdepth", "1", "-type", "f", "-printf", r"%p\t%u\t%m\n"]
        )
        scripts = sorted(f[0] for f in _rows(raw["cron_scripts"], 3))
        if scripts:
            raw["cron_scripts_owned"] = await ctx.run(
                ["dpkg-query", "-S", *[a for s in scripts for a in path_aliases(s)]]
            )
        raw["units"] = await collect_units(ctx)
        raw["units_owned"] = await ctx.run(["dpkg-query", "-S", UNIT_PATTERN])
        raw["temp"] = await ctx.run_privileged(
            [
                "find",
                *settings["temp_dirs"],
                "-xdev",
                "-mindepth",
                "1",
                "-maxdepth",
                str(settings["temp_depth"]),
                "-printf",
                r"%p\t%y\t%u\t%m\t%s\t%T@\n",
            ]
        )
        return raw

    def guaranteed_findings(self, facts: dict[str, Any]) -> list[FindingItem]:
        """A web user's cron job that runs from a temp directory or fetches code: the re-planting cron of the
        Oct 2026 incident. Reported every time (legitimate web-user crons such as wp-cron don't match)."""
        web_users = set(facts.get("web_user_crontabs") or [])
        out = []
        for e in facts.get("cron_entries") or []:
            user, file, command = str(e.get("user", "")), str(e.get("file", "")), str(e.get("command", ""))
            signal = web_cron_signal(command)
            if user not in web_users or signal is None:
                continue
            out.append(
                FindingItem(
                    kind="web_user_cron",
                    subject=file,
                    severity="critical",
                    confidence="high",
                    title=f"{user}'s crontab {signal}: {command[:120]}",
                    summary=(
                        f"The web server user {user} has a cron job ({e.get('schedule')}) that {signal}. "
                        "A web shell plants jobs like this so the attacker gets back in after a cleanup."
                    ),
                    evidence=[f"{file}: {e.get('schedule')} {command}"[:1000]],
                    rule_ids=[WEB_CRON_RULE],
                    recommended_action=(
                        f"If nobody added it, save a copy of {file} and the program it runs, remove the job "
                        "(crontab -r -u " + user + "), and look for the web shell that created it."
                    ),
                )
            )
        out.extend(hidden_temp_findings(facts))
        return out

    def parse(self, raw: Raw, settings: dict[str, Any]) -> PersistenceFacts:
        warnings = [w for key, out in raw.items() if (w := output_warning(key, out))]
        facts = PersistenceFacts(warnings=warnings)
        if not raw.get("crontab_files", Output.missing()).ran:
            facts.warnings.append("crontabs not readable (needs read-only sudo)")
        facts.cron_entries, facts.cron_env = parse_crontabs(raw.get("crontabs", Output.missing()).stdout)
        web_users = settings["web_users"]
        facts.web_user_crontabs = sorted(
            {
                posixpath.basename(f[0])
                for f in _rows(raw.get("crontab_files", Output.missing()), 3)
                if f[0].startswith(USER_CRONTABS + "/") and posixpath.basename(f[0]) in web_users
            }
        )

        owned_scripts = parse_dpkg_search(raw.get("cron_scripts_owned", Output.missing()).stdout)
        facts.cron_scripts = [
            CronScript(path=p, owner=u, mode=m.zfill(4), package=_first(owned_scripts.get(canonical_path(p))))
            for p, u, m in sorted(_rows(raw.get("cron_scripts", Output.missing()), 3))
        ]

        owned_units = parse_dpkg_search(raw.get("units_owned", Output.missing()).stdout)
        timers: dict[str, TimerUnit] = {}
        for fields in _rows(raw.get("units", Output.missing()), 5):
            path, kind = canonical_path(fields[0]), fields[1]
            if kind == "f" and path.endswith(".timer"):
                timers.setdefault(path, TimerUnit(path=path, packaged=path in owned_units))
        facts.timers = sorted(timers.values(), key=lambda t: t.path)

        facts.temp_entries, facts.temp_counts = parse_temp_entries(
            raw.get("temp", Output.missing()).stdout,
            roots=settings["temp_dirs"],
            web_users=web_users,
            ignore_names=settings["ignore_temp_names"],
        )
        return facts


CHECK = PersistenceCheck


# ── pure parsers ─────────────────────────────────────────────────────────────


def parse_crontabs(stdout: str) -> tuple[list[CronEntry], list[str]]:
    """User crontabs (`/var/spool/cron/crontabs/<user>`: 5 time fields + command) and system crontabs
    (`/etc/crontab`, `/etc/cron.d/*`: 5 time fields + user + command). `@reboot`-style specials too."""
    entries: list[CronEntry] = []
    env: list[str] = []
    for path, lines in grep_h_lines(stdout).items():
        system = not path.startswith(USER_CRONTABS + "/")
        owner = posixpath.basename(path)
        for line in lines:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            first = text.split(None, 1)[0]
            if "=" in first and not first.startswith("@") and not first[0].isdigit() and first[0] != "*":
                env.append(f"{path}: {text}")
                continue
            entry = _cron_entry(path, text, system=system, owner=owner)
            if entry:
                entries.append(entry)
    return entries, env


def _cron_entry(path: str, text: str, *, system: bool, owner: str) -> CronEntry | None:
    n_time = 1 if text.startswith("@") else 5
    parts = text.split(None, n_time + (1 if system else 0))
    if len(parts) < n_time + (2 if system else 1):
        return None
    schedule = " ".join(parts[:n_time])
    if system:
        return CronEntry(file=path, user=parts[n_time], schedule=schedule, command=parts[n_time + 1])
    return CronEntry(file=path, user=owner, schedule=schedule, command=parts[n_time])


def parse_temp_entries(
    stdout: str, *, roots: list[str], web_users: list[str], ignore_names: list[str]
) -> tuple[list[TempEntry], dict[str, int]]:
    notable: list[TempEntry] = []
    counts: dict[str, int] = dict.fromkeys(roots, 0)
    for line in stdout.splitlines():
        fields = split_fields(line, 6)
        if not fields:
            continue
        path, kind, owner, mode, size, mtime = fields
        root = next((r for r in roots if path.startswith(r.rstrip("/") + "/")), None)
        if root is None:
            continue
        counts[root] += 1
        parts = path[len(root.rstrip("/")) + 1 :].split("/")
        if any(fnmatch.fnmatchcase(p, pat) for p in parts for pat in ignore_names):
            continue
        reasons = []
        if any(p.startswith(".") for p in parts):
            reasons.append("hidden")
        if owner in web_users:
            reasons.append("web_user")
        try:
            perms = int(mode, 8)
        except ValueError:
            perms = 0
        if kind == "f" and perms & 0o111:
            reasons.append("executable")
        if reasons and len(notable) < MAX_TEMP_ENTRIES:
            notable.append(
                TempEntry(
                    path=path,
                    type=kind,
                    owner=owner,
                    mode=mode.zfill(4),
                    size=int(size) if size.isdigit() else 0,
                    mtime=int(float(mtime)) if _is_number(mtime) else None,
                    reasons=reasons,
                )
            )
    return sorted(notable, key=lambda e: e.path), counts


def _rows(out: Output, n: int) -> list[tuple[str, ...]]:
    return [tuple(f) for line in out.lines() if (f := split_fields(line, n))]


def _first(values: list[str] | None) -> str | None:
    return values[0] if values else None


def _is_number(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True
