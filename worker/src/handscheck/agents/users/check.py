"""`users` check: accounts, privileged groups, sudoers rules, every authorized_keys file, and an auth.log
summary (logins, su/sudo by web users, failed su, root-TTY sudo).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import posixpath
import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, ClassVar

from pydantic import BaseModel

from handscheck.agents._framework.check import (
    LOG_TAIL_BYTES,
    Check,
    CheckContext,
    DiffView,
    Facts,
    Output,
    Raw,
    grep_h_lines,
    last_lines,
    output_warning,
    split_fields,
    tail_command,
)

SUDOERS = ("/etc/sudoers", "/etc/sudoers.d")
_SKIP_HOME_PREFIXES = (
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/nonexistent",
    "/boot",
)
MAX_KEY_FILES = 200
NON_LOGIN_SHELLS = ("nologin", "false", "sync", "halt", "shutdown")


class Account(BaseModel):
    name: str
    uid: int
    gid: int
    home: str
    shell: str

    @property
    def login_shell(self) -> bool:
        base = posixpath.basename(self.shell)
        return bool(base) and base not in NON_LOGIN_SHELLS


class SudoersRule(BaseModel):
    file: str
    line: str


class AuthorizedKey(BaseModel):
    path: str
    owner: str | None = None
    mode: str | None = None
    type: str
    fingerprint: str
    """SHA256:… as printed by ssh-keygen -l."""
    comment: str = ""
    options: str = ""


class SshLogin(BaseModel):
    user: str
    source: str
    method: str
    count: int
    last: str | None = None


class AuthEvent(BaseModel):
    kind: str
    """su_by_web_user, failed_su, sudo_by_web_user, sudo_not_in_sudoers, sudo_auth_failure, root_tty_sudo"""
    time: str | None = None
    user: str | None = None
    line: str


class AuthSummary(BaseModel):
    path: str
    window_hours: int
    lines_read: int
    lines_in_window: int
    first_time: str | None = None
    last_time: str | None = None
    ssh_logins: list[SshLogin] = []
    failed_logins: int = 0
    sudo_commands: dict[str, int] = {}
    events: list[AuthEvent] = []


class UsersFacts(Facts):
    accounts: list[Account] = []
    privileged_groups: dict[str, list[str]] = {}
    sudoers_rules: list[SudoersRule] = []
    authorized_keys: list[AuthorizedKey] = []
    auth: AuthSummary | None = None

    append_only: ClassVar[frozenset[str]] = frozenset({"auth_events", "ssh_login_sources"})
    """Collections where a key disappearing (a log line aging out of the window) is not a change."""

    def diff_view(self) -> DiffView:
        view: DiffView = {
            "accounts": {
                a.name: {"uid": a.uid, "gid": a.gid, "home": a.home, "shell": a.shell} for a in self.accounts
            },
            "privileged_groups": {
                f"{group}:{member}": True
                for group, members in self.privileged_groups.items()
                for member in members
            },
            "sudoers_rules": {f"{r.file}: {r.line}": True for r in self.sudoers_rules},
            "authorized_keys": {
                f"{k.path} {k.fingerprint}": {"comment": k.comment, "options": k.options}
                for k in self.authorized_keys
            },
        }
        if self.auth is not None:
            view["auth_events"] = {_event_key(e): e.line for e in self.auth.events}
            view["ssh_login_sources"] = {f"{s.user}@{s.source}": s.method for s in self.auth.ssh_logins}
        return view

    def metrics(self) -> dict[str, float]:
        m: dict[str, float] = {
            "accounts": len(self.accounts),
            "login_accounts": sum(1 for a in self.accounts if a.login_shell),
            "authorized_keys": len(self.authorized_keys),
            "sudoers_rules": len(self.sudoers_rules),
        }
        if self.auth is not None:
            m["failed_logins"] = self.auth.failed_logins
            m["auth_events"] = len(self.auth.events)
            m["ssh_logins"] = sum(s.count for s in self.auth.ssh_logins)
        return m


class UsersCheck(Check[UsersFacts]):
    name = "users"
    facts_model = UsersFacts

    async def collect(self, ctx: CheckContext, settings: dict[str, Any]) -> dict[str, Output]:
        raw: dict[str, Output] = {}
        raw["passwd"] = await ctx.run(["cat", "/etc/passwd"])
        raw["group"] = await ctx.run(["cat", "/etc/group"])
        raw["now"] = await ctx.run(["date", "+%s %z"])
        raw["scan_user"] = await ctx.run(["id", "-un"])
        raw["sudoers_files"] = await ctx.run_privileged(
            ["find", *SUDOERS, "-maxdepth", "1", "-type", "f", "-printf", r"%p\n"]
        )
        sudoers = sorted(raw["sudoers_files"].lines())
        if sudoers:
            raw["sudoers"] = await ctx.run_privileged(["grep", "-s", "-H", "", "--", *sudoers])

        homes = search_roots(parse_passwd(raw["passwd"].stdout))
        raw["key_files"] = await ctx.run_privileged(
            [
                "find",
                *homes,
                "-maxdepth",
                "3",
                "-path",
                "*/.ssh/authorized_keys*",
                "-type",
                "f",
                "-printf",
                r"%p\t%u\t%m\n",
            ]
        )
        key_files = sorted(f[0] for f in _rows(raw["key_files"], 3))[:MAX_KEY_FILES]
        if key_files:
            raw["keys"] = await ctx.run_privileged(["grep", "-s", "-H", "", "--", *key_files])

        if settings["auth_log_lines"] > 0:
            raw["auth_log"] = await ctx.run_privileged(
                tail_command(settings["auth_log_path"]), max_output=LOG_TAIL_BYTES + 65_536
            )
        return raw

    def parse(self, raw: Raw, settings: dict[str, Any]) -> UsersFacts:
        warnings = [w for key, out in raw.items() if (w := output_warning(key, out))]
        facts = UsersFacts(warnings=warnings)
        facts.accounts = parse_passwd(raw.get("passwd", Output.missing()).stdout)
        facts.privileged_groups = parse_groups(
            raw.get("group", Output.missing()).stdout, facts.accounts, settings["privileged_groups"]
        )
        facts.sudoers_rules = parse_sudoers(raw.get("sudoers", Output.missing()).stdout)
        if not raw.get("sudoers", Output.missing()).ran:
            facts.warnings.append("sudoers not readable")

        file_info = {f[0]: (f[1], f[2]) for f in _rows(raw.get("key_files", Output.missing()), 3)}
        facts.authorized_keys = parse_authorized_keys(raw.get("keys", Output.missing()).stdout, file_info)

        log = raw.get("auth_log")
        if log is not None:
            if log.exit_status == 0:
                now, tz = parse_now(raw.get("now", Output.missing()).stdout)
                facts.auth = summarize_auth_log(
                    last_lines(log.stdout, settings["auth_log_lines"]),
                    path=settings["auth_log_path"],
                    now=now,
                    tz=tz,
                    window_hours=settings["auth_log_hours"],
                    web_users=settings["web_users"],
                    # Our own read-only sudo calls show up in auth.log too.
                    ignore_sudo_users=[
                        *settings["ignore_sudo_users"],
                        *raw.get("scan_user", Output.missing()).lines()[:1],
                    ],
                )
            else:
                facts.warnings.append(
                    f"{settings['auth_log_path']} not readable (no syslog, or no permission)"
                )
        return facts


CHECK = UsersCheck


# ── pure parsers ─────────────────────────────────────────────────────────────


def parse_passwd(text: str) -> list[Account]:
    accounts = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 7 or not parts[0]:
            continue
        try:
            accounts.append(
                Account(name=parts[0], uid=int(parts[2]), gid=int(parts[3]), home=parts[5], shell=parts[6])
            )
        except ValueError:
            continue
    return accounts


def parse_groups(text: str, accounts: list[Account], groups: list[str]) -> dict[str, list[str]]:
    """Members of each privileged group: listed members plus accounts whose primary gid is the group."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 4 or parts[0] not in groups:
            continue
        try:
            gid = int(parts[2])
        except ValueError:
            continue
        members = {m.strip() for m in parts[3].split(",") if m.strip()}
        members |= {a.name for a in accounts if a.gid == gid and parts[0] != "root"}
        out[parts[0]] = sorted(members)
    return dict(sorted(out.items()))


def search_roots(accounts: list[Account]) -> list[str]:
    """Where to look for authorized_keys: /root, /home and every real home directory (no nesting)."""
    homes = {"/root", "/home"}
    for a in accounts:
        home = posixpath.normpath(a.home) if a.home else ""
        if home in ("", "/", ".") or home.startswith(_SKIP_HOME_PREFIXES):
            continue
        homes.add(home)
    roots: list[str] = []
    for home in sorted(homes):
        if not any(home == r or home.startswith(r.rstrip("/") + "/") for r in roots):
            roots.append(home)
    return roots


def parse_sudoers(stdout: str) -> list[SudoersRule]:
    rules: list[SudoersRule] = []
    joined: dict[str, list[str]] = {}
    for path, lines in grep_h_lines(stdout).items():
        buf = ""
        for line in lines:
            text = line.strip()
            if text.endswith("\\"):
                buf += text[:-1] + " "
                continue
            text = (buf + text).strip()
            buf = ""
            if not text or (text.startswith("#") and not text.startswith(("#include", "#includedir"))):
                continue
            joined.setdefault(path, []).append(" ".join(text.split()))
    for path, lines in joined.items():
        rules.extend(SudoersRule(file=path, line=line) for line in lines)
    return rules


_KEY = re.compile(r"(?:^|\s)((?:ssh|ecdsa|sk)-[A-Za-z0-9@._-]+)\s+([A-Za-z0-9+/]+={0,3})(?:\s+(.*))?$")


def parse_authorized_keys(stdout: str, file_info: dict[str, tuple[str, str]]) -> list[AuthorizedKey]:
    keys = []
    for path, lines in grep_h_lines(stdout).items():
        owner, mode = file_info.get(path, (None, None))
        for line in lines:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            m = _KEY.search(text)
            if not m:
                continue
            try:
                blob = base64.b64decode(m.group(2), validate=True)
            except (binascii.Error, ValueError):
                continue
            digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
            keys.append(
                AuthorizedKey(
                    path=path,
                    owner=owner,
                    mode=mode,
                    type=m.group(1),
                    fingerprint=f"SHA256:{digest}",
                    comment=(m.group(3) or "").strip(),
                    options=text[: m.start(1)].strip(),
                )
            )
    return keys


def parse_now(stdout: str) -> tuple[datetime, timezone]:
    """`date '+%s %z'` → (now, the host's UTC offset). Falls back to the local clock and UTC."""
    parts = stdout.split()
    tz = UTC
    if len(parts) >= 2 and re.fullmatch(r"[+-]\d{4}", parts[1]):
        sign = 1 if parts[1][0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(parts[1][1:3]), minutes=int(parts[1][3:5])))
    try:
        return datetime.fromtimestamp(int(parts[0]), tz), tz
    except (ValueError, IndexError):
        return datetime.now(tz), tz


_ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?([+-]\d{2}:\d{2}|Z)?\s+(\S+)\s+(.*)$")
_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(.*)$")
_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}

_ACCEPTED = re.compile(r"^sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port")
_FAILED = re.compile(r"^sshd\[\d+\]: (?:Failed \S+ for|Invalid user)")
_SUDO_CMD = re.compile(r"^sudo(?:\[\d+\])?:\s+(\S+) : (.*)$")
_SU_OPENED = re.compile(
    r"^su(?:\[\d+\])?: .*session opened for user (\S+?)(?:\(uid=\d+\))? by (\S*?)\(uid=(\d+)\)"
)
_FAILED_SU = re.compile(r"^su(?:\[\d+\])?: FAILED SU \(to (\S+)\) (\S+)")
_PAM_FAIL = re.compile(
    r"^(su|sudo)(?:\[\d+\])?: pam_unix\((?:su|su-l|sudo):auth\): authentication failure;(.*)$"
)


def _parse_time(line: str, now: datetime, tz: timezone) -> tuple[datetime | None, str]:
    """(timestamp, message after the hostname). Handles RFC 3339 (24.04 rsyslog) and classic syslog."""
    if m := _ISO_TS.match(line):
        stamp, offset, _, rest = m.groups()
        try:
            when = datetime.fromisoformat(stamp + (offset.replace("Z", "+00:00") if offset else ""))
        except ValueError:
            return None, rest
        return (when if when.tzinfo else when.replace(tzinfo=tz)), rest
    if m := _SYSLOG_TS.match(line):
        mon, day, hh, mm, ss, _, rest = m.groups()
        month = _MONTHS.get(mon)
        if month is None:
            return None, rest
        try:
            when = datetime(now.year, month, int(day), int(hh), int(mm), int(ss), tzinfo=tz)
        except ValueError:
            return None, rest
        if when > now + timedelta(days=1):  # December lines read in January
            when = when.replace(year=now.year - 1)
        return when, rest
    return None, line


def summarize_auth_log(
    text: str,
    *,
    path: str,
    now: datetime,
    tz: timezone,
    window_hours: int,
    web_users: list[str],
    ignore_sudo_users: list[str],
) -> AuthSummary:
    since = now - timedelta(hours=window_hours)
    lines = text.splitlines()
    summary = AuthSummary(path=path, window_hours=window_hours, lines_read=len(lines), lines_in_window=0)
    logins: dict[tuple[str, str, str], SshLogin] = {}
    for line in lines:
        when, msg = _parse_time(line, now, tz)
        if when is None or when < since:
            continue
        summary.lines_in_window += 1
        stamp = when.isoformat()
        summary.first_time = summary.first_time or stamp
        summary.last_time = stamp

        clipped = line.strip()[:500]

        def event(kind: str, user: str | None, stamp: str = stamp, clipped: str = clipped) -> None:
            summary.events.append(AuthEvent(kind=kind, time=stamp, user=user, line=clipped))

        if m := _ACCEPTED.match(msg):
            method, user, source = m.groups()
            key = (user, source, method)
            entry = logins.get(key)
            if entry is None:
                entry = logins[key] = SshLogin(user=user, source=source, method=method, count=0)
            entry.count += 1
            entry.last = stamp
        elif _FAILED.match(msg):
            summary.failed_logins += 1
        elif m := _SUDO_CMD.match(msg):
            user, rest = m.groups()
            if "user NOT in sudoers" in rest:
                event("sudo_not_in_sudoers", user)
            elif "incorrect password attempt" in rest:
                event("sudo_auth_failure", user)
            elif "COMMAND=" in rest:
                if user in web_users:
                    event("sudo_by_web_user", user)
                elif user == "root" and ("TTY=pts" in rest or "TTY=tty" in rest):
                    event("root_tty_sudo", user)
                if user not in ignore_sudo_users:
                    summary.sudo_commands[user] = summary.sudo_commands.get(user, 0) + 1
        elif m := _SU_OPENED.match(msg):
            _target, by, uid = m.groups()
            if by in web_users or uid == "33":
                event("su_by_web_user", by or f"uid={uid}")
        elif m := _FAILED_SU.match(msg):
            _target, by = m.groups()
            event("su_by_web_user" if by in web_users else "failed_su", by)
        elif m := _PAM_FAIL.match(msg):
            program, details = m.groups()
            fields = dict(re.findall(r"(\w+)=(\S*)", details))
            ruser = fields.get("ruser") or fields.get("logname") or ""
            if ruser in web_users or fields.get("uid") == "33":
                event(f"{program}_by_web_user", ruser or "uid=33")
            elif program == "sudo":
                event("sudo_auth_failure", ruser or None)
            # failed su by a real user is already a FAILED SU line
    summary.ssh_logins = sorted(logins.values(), key=lambda s: (s.user, s.source, s.method))
    summary.sudo_commands = dict(sorted(summary.sudo_commands.items()))
    return summary


def _event_key(event: AuthEvent) -> str:
    return hashlib.sha256(f"{event.time}|{event.line}".encode()).hexdigest()[:16]


def _rows(out: Output, n: int) -> list[list[str]]:
    return [f for line in out.lines() if (f := split_fields(line, n))]
