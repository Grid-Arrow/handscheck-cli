"""`activity` check (host, watch pass): WordPress login sessions on every site, the recent access log of
each site, and SSH logins from auth.log, turned into deterministic login rules (forged sessions, synchronized
logins, login → upload, new IPs). No Claude: `guaranteed_findings` is the whole review.

Sessions come from each site's `session_tokens` usermeta through the fixed `sessions` query (`ssh/policy.py`),
read with wp-cli as the site owner, so handscheck needs no database credentials. The value is a PHP-serialized
array; `php_sessions` reads only the fields we need and refuses anything else (objects, references)."""

from __future__ import annotations

import ipaddress
import posixpath
import re
from collections import defaultdict
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
from handscheck.agents.users.check import _ACCEPTED, _parse_time, parse_now
from handscheck.ssh.policy import WP_DB_QUERIES

PREFIX = re.compile(r"""^\s*\$table_prefix\s*=\s*['"]([A-Za-z0-9_]{1,32})['"]\s*;""", re.M)
LOG_DIRECTIVE = re.compile(r"^\s*(?:CustomLog|access_log)\s+(\S+)", re.I | re.M)
COMBINED = re.compile(
    r"^(?:(?P<vhost>[^\s:]+):\d+\s+)?(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]{3,10}) (?P<path>\S+)[^"]*" (?P<status>\d{3})'
)
INTEREST = re.compile(
    r"^/(?:[^?]*/)?(?:wp-login\.php|wp-admin/(?:plugin-install\.php|update\.php|theme-editor\.php|"
    r"plugin-editor\.php|plugins\.php))(?:\?|$)"
)
UPLOAD = re.compile(
    r"wp-admin/(?:update\.php\?(?:[^ ]*&)?action=upload-(?:plugin|theme)"
    r"|plugin-install\.php\?(?:[^ ]*&)?tab=upload|theme-editor\.php|plugin-editor\.php)"
)
DEFAULT_LOGS = ("/var/log/apache2/other_vhosts_access.log", "/var/log/apache2/access.log")
MAX_SESSIONS = 2000
MAX_REQUESTS = 2000
MAX_KNOWN_PER_ACCOUNT = 50
RULE = "activity.{}"


class Session(BaseModel):
    site: str
    user_id: int
    login: str
    email: str = ""
    admin: bool = False
    ip: str
    time: int
    """Unix time the session was created (its `login` field)."""
    ua: str = ""


class Request(BaseModel):
    site: str | None
    ip: str
    time: int
    method: str
    path: str
    status: int


class SshLogin(BaseModel):
    user: str
    ip: str
    time: int
    method: str


class ActivityFacts(Facts):
    now: int = 0
    """The host's clock when the pass ran (unix time)."""
    lookback_minutes: int = 90
    known_ip_days: int = 90
    sessions: list[Session] = []
    """Sessions created within the lookback window."""
    requests: list[Request] = []
    """Logins, uploads and editor use within the lookback window."""
    ssh_logins: list[SshLogin] = []
    known_ips: dict[str, dict[str, int]] = {}
    """account → {ip: last seen (unix time)}. Accounts are `wp:<login>` and `ssh:<user>`."""
    new_ips: dict[str, list[str]] = {}
    """IPs an account used this pass that weren't known before (empty on the first pass)."""
    has_baseline: bool = False
    """True once a previous pass's known IPs were carried in: the new-IP rules need them."""
    rule_settings: dict[str, Any] = {}
    """The rule thresholds of this pass (settings), so the rules are a pure function of the facts."""

    append_only = frozenset({"sessions", "requests", "ssh_logins"})

    def diff_view(self) -> DiffView:
        return {
            "sessions": {f"{s.site} {s.login} {s.ip} {s.time}": s.admin for s in self.sessions},
            "requests": {f"{r.ip} {r.time} {r.method} {r.path}": r.status for r in self.requests},
            "ssh_logins": {f"{s.user} {s.ip} {s.time}": s.method for s in self.ssh_logins},
            "new_ips": {k: ", ".join(v) for k, v in self.new_ips.items()},
        }

    def metrics(self) -> dict[str, float]:
        return {
            "sessions_recent": len(self.sessions),
            "requests_of_interest": len(self.requests),
            "ssh_logins": len(self.ssh_logins),
            "new_ips": sum(len(v) for v in self.new_ips.values()),
        }


class ActivityCheck(Check[ActivityFacts]):
    name = "activity"
    facts_model = ActivityFacts

    async def collect(self, ctx: CheckContext, settings: dict[str, Any]) -> dict[str, Output]:
        raw: dict[str, Output] = {"now": await ctx.run(["date", "+%s %z"])}
        shared_log_read = False
        for site in ctx.sites:
            if site.wordpress is not None:
                wp = site.wordpress.path
                config = await ctx.run_privileged(
                    ["grep", "-s", "-h", "-E", r"^\s*\$table_prefix\s*=", "--"]
                    + [
                        posixpath.join(wp, "wp-config.php"),
                        posixpath.join(posixpath.dirname(wp), "wp-config.php"),
                    ]
                )
                m = PREFIX.search(config.stdout)
                if m:
                    raw[f"sessions@{site.name}"] = await ctx.run(
                        ["wp", "db", "query", WP_DB_QUERIES["sessions"].format(p=m.group(1)), f"--path={wp}"],
                        sudo=True,
                        sudo_user=settings["wp_cli_user"],
                        max_output=4_000_000,
                    )
            if settings["access_log_lines"] <= 0:
                continue
            log = None
            if site.config:
                conf = await ctx.run_privileged(
                    ["grep", "-s", "-h", "-i", "-E", r"^\s*(CustomLog|access_log)\s", "--", site.config]
                )
                log = access_log_path(conf.stdout, site.name)
            if log is not None:
                raw[f"access@{site.name}"] = await ctx.run_privileged(
                    tail_command(log), max_output=LOG_TAIL_BYTES + 65_536
                )
            elif not shared_log_read:
                shared_log_read = True
                for path in DEFAULT_LOGS:
                    out = await ctx.run_privileged(tail_command(path), max_output=LOG_TAIL_BYTES + 65_536)
                    if out.ok:
                        raw["access@*"] = out
                        break
        if settings["auth_log_lines"] > 0:
            raw["auth_log"] = await ctx.run_privileged(
                tail_command(settings["auth_log_path"]), max_output=LOG_TAIL_BYTES + 65_536
            )
        return raw

    def parse(self, raw: Raw, settings: dict[str, Any]) -> ActivityFacts:
        warnings = [
            w
            for key, out in raw.items()
            if key != "access@*" and not key.startswith("access@") and (w := output_warning(key, out))
        ]
        now, tz = parse_now(raw.get("now", Output.missing()).stdout)
        since = int((now - timedelta(minutes=settings["lookback_minutes"])).timestamp())
        facts = ActivityFacts(
            warnings=warnings,
            now=int(now.timestamp()),
            lookback_minutes=settings["lookback_minutes"],
            known_ip_days=settings["known_ip_days"],
            rule_settings={k: settings[k] for k in RULE_SETTINGS},
        )
        known: dict[str, dict[str, int]] = defaultdict(dict)

        for key, out in sorted(raw.items()):
            if key.startswith("sessions@") and out.ok:
                site = key.split("@", 1)[1]
                for s in parse_sessions(out.stdout, site):
                    account = account_of(s)
                    known[account][s.ip] = max(known[account].get(s.ip, 0), s.time)
                    if s.time >= since:
                        facts.sessions.append(s)
            elif key.startswith("access@"):
                site_name = key.split("@", 1)[1]
                facts.requests.extend(
                    parse_access_log(
                        last_lines(out.stdout, settings["access_log_lines"]),
                        None if site_name == "*" else site_name,
                        since,
                    )
                )
        auth = raw.get("auth_log")
        if auth is not None and auth.ran:
            for line in last_lines(auth.stdout, settings["auth_log_lines"]).splitlines():
                when, msg = _parse_time(line, now, tz)
                if when is None or (m := _ACCEPTED.match(msg)) is None:
                    continue
                method, user, ip = m.groups()
                t = int(when.timestamp())
                known[f"ssh:{user}"][ip] = max(known[f"ssh:{user}"].get(ip, 0), t)
                if t >= since:
                    facts.ssh_logins.append(SshLogin(user=user, ip=ip, time=t, method=method))
        facts.sessions = sorted(facts.sessions, key=lambda s: (s.time, s.site, s.login))[-MAX_SESSIONS:]
        facts.requests = sorted(facts.requests, key=lambda r: (r.time, r.ip))[-MAX_REQUESTS:]
        facts.known_ips = {a: dict(sorted(ips.items())) for a, ips in sorted(known.items())}
        return facts

    def carry(self, previous: dict[str, Any], facts: ActivityFacts) -> ActivityFacts:
        """Known IPs survive between passes (for `known_ip_days`); IPs not known before are this pass's new
        ones."""
        before: dict[str, dict[str, int]] = previous.get("known_ips") or {}
        cutoff = facts.now - facts.known_ip_days * 86400
        merged: dict[str, dict[str, int]] = {}
        new: dict[str, list[str]] = {}
        for account in sorted(set(before) | set(facts.known_ips)):
            old = {ip: int(t) for ip, t in (before.get(account) or {}).items()}
            now_ips = facts.known_ips.get(account, {})
            fresh = sorted(ip for ip in now_ips if ip not in old)
            if fresh:
                new[account] = fresh
            ips = {**old, **{ip: max(t, old.get(ip, 0)) for ip, t in now_ips.items()}}
            kept = sorted(((t, ip) for ip, t in ips.items() if t >= cutoff), reverse=True)[
                :MAX_KNOWN_PER_ACCOUNT
            ]
            if kept:
                merged[account] = {ip: t for t, ip in sorted(kept, key=lambda x: x[1])}
        facts.known_ips = merged
        facts.new_ips = new
        facts.has_baseline = True
        return facts

    def guaranteed_findings(self, facts: dict[str, Any]) -> list[FindingItem]:
        f = ActivityFacts.model_validate(facts)
        return forged_sessions(f) + synchronized_logins(f) + login_then_upload(f) + new_ip_logins(f)


CHECK = ActivityCheck

RULE_SETTINGS = (
    "forged_min_users",
    "forged_window_s",
    "sync_window_s",
    "sync_min_accounts",
    "upload_window_s",
    "trusted_ips",
)


# ── pure parsers ─────────────────────────────────────────────────────────────


def access_log_path(conf: str, site: str) -> str | None:
    """The first CustomLog/access_log path in a vhost's config (Apache's ${APACHE_LOG_DIR} expanded)."""
    for m in LOG_DIRECTIVE.finditer(conf):
        path = m.group(1).strip("\"'").rstrip(";")
        path = path.replace("${APACHE_LOG_DIR}", "/var/log/apache2")
        if path.startswith("/") and "$" not in path and path not in ("/dev/null",):
            return posixpath.normpath(path)
    return None


def account_of(s: Session) -> str:
    """A WordPress account across the server's sites: by login (the same person often has a different email
    on each site, and the Oct 2026 logins reused the same logins)."""
    return f"wp:{s.login.lower()}"


_MYSQL_ESCAPES = {"\\\\": "\\", "\\t": "\t", "\\n": "\n", "\\0": "\0"}


def _mysql_unescape(value: str) -> str:
    return re.sub(r"\\[\\tn0]", lambda m: _MYSQL_ESCAPES[m.group(0)], value)


def parse_sessions(stdout: str, site: str) -> list[Session]:
    """`wp db query` (tab-separated, header row first) → one Session per session token."""
    out = []
    for line in stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 5 or not fields[0].isdigit():
            continue  # header or odd row
        uid, login, email, admin, meta = fields
        for token in php_sessions(_mysql_unescape(meta)):
            out.append(
                Session(
                    site=site,
                    user_id=int(uid),
                    login=login[:60],
                    email=email[:100],
                    admin=admin.strip() == "1",
                    ip=token["ip"],
                    time=token["login"],
                    ua=token.get("ua", "")[:200],
                )
            )
    return out


class _Unserialize:
    """Just enough of PHP's unserialize for session_tokens: arrays, strings, ints, bools, floats, null.
    Refuses objects, references and anything malformed (returns nothing)."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def value(self, depth: int = 0) -> Any:
        if depth > 4:
            raise ValueError("too deep")
        kind = self.data[self.pos : self.pos + 2]
        if kind == b"N;":
            self.pos += 2
            return None
        if kind in (b"i:", b"b:", b"d:"):
            end = self.data.index(b";", self.pos)
            raw = self.data[self.pos + 2 : end].decode()
            self.pos = end + 1
            return int(raw) if kind == b"i:" else (raw == "1" if kind == b"b:" else float(raw))
        if kind == b"s:":
            colon = self.data.index(b":", self.pos + 2)
            length = int(self.data[self.pos + 2 : colon])
            if length < 0 or length > 10_000 or self.data[colon + 1 : colon + 2] != b'"':
                raise ValueError("bad string")
            start = colon + 2
            text = self.data[start : start + length]
            if self.data[start + length : start + length + 2] != b'";':
                raise ValueError("bad string end")
            self.pos = start + length + 2
            return text.decode("utf-8", "replace")
        if kind == b"a:":
            colon = self.data.index(b":", self.pos + 2)
            count = int(self.data[self.pos + 2 : colon])
            if count < 0 or count > 500 or self.data[colon + 1 : colon + 2] != b"{":
                raise ValueError("bad array")
            self.pos = colon + 2
            items: dict[Any, Any] = {}
            for _ in range(count):
                key = self.value(depth + 1)
                if not isinstance(key, (str, int)):
                    raise ValueError("bad key")
                items[key] = self.value(depth + 1)
            if self.data[self.pos : self.pos + 1] != b"}":
                raise ValueError("bad array end")
            self.pos += 1
            return items
        raise ValueError(f"unsupported type {kind!r}")


def php_sessions(meta: str) -> list[dict[str, Any]]:
    """session_tokens value → [{ip, login, ua}] (sessions without an IP and login time are skipped)."""
    try:
        reader = _Unserialize(meta.strip().encode())
        value = reader.value()
        if reader.pos != len(reader.data) or not isinstance(value, dict):
            return []
    except (ValueError, IndexError, UnicodeDecodeError):
        return []
    out = []
    for token in value.values():
        if not isinstance(token, dict):
            continue
        ip, login = token.get("ip"), token.get("login")
        if isinstance(ip, str) and _is_ip(ip) and isinstance(login, int):
            out.append({"ip": ip, "login": login, "ua": str(token.get("ua") or "")})
    return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_access_log(stdout: str, site: str | None, since: int) -> list[Request]:
    """Combined-format lines (optionally `vhost:port ` first) → logins, uploads, editor use since `since`."""
    out = []
    for line in stdout.splitlines():
        m = COMBINED.match(line)
        if m is None or not INTEREST.match(m.group("path")):
            continue
        try:
            when = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        t = int(when.timestamp())
        if t < since or not _is_ip(m.group("ip")):
            continue
        out.append(
            Request(
                site=site if site is not None else m.group("vhost"),
                ip=m.group("ip"),
                time=t,
                method=m.group("method"),
                path=m.group("path")[:300],
                status=int(m.group("status")),
            )
        )
    return out


# ── rules ────────────────────────────────────────────────────────────────────


def _minute(t: int) -> str:
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%dT%H:%MZ")


def _stamp(t: int) -> str:
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _trusted(ip: str, trusted: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in trusted:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def _clusters(items: list[Any], window: int) -> list[list[Any]]:
    """Groups of time-sorted items where each one is within `window` seconds of the group's first."""
    groups: list[list[Any]] = []
    for item in sorted(items, key=lambda x: x.time):
        if groups and item.time - groups[-1][0].time <= window:
            groups[-1].append(item)
        else:
            groups.append([item])
    return groups


def forged_sessions(f: ActivityFacts) -> list[FindingItem]:
    s = f.rule_settings
    out = []
    by_site: dict[str, list[Session]] = defaultdict(list)
    for session in f.sessions:
        by_site[session.site].append(session)
    for site, sessions in sorted(by_site.items()):
        for group in _clusters(sessions, s["forged_window_s"]):
            users = sorted({x.login for x in group})
            if len(users) < s["forged_min_users"]:
                continue
            first = group[0]
            out.append(
                FindingItem(
                    kind="forged_sessions",
                    subject=f"{site}@{_minute(first.time)}",
                    severity="critical",
                    confidence="high",
                    title=f"{len(users)} users of {site} 'logged in' within {s['forged_window_s']} s",
                    summary=(
                        f"{len(users)} different users of {site} have login sessions created within "
                        f"{s['forged_window_s']} seconds of each other, starting {_stamp(first.time)}. "
                        "People don't "
                        "log in like that: in the October 2026 incident the attacker forged a session "
                        "for every "
                        "user of a site in the same second, which gives them everyone's access."
                    ),
                    evidence=[
                        f"session {x.login} on {x.site} from {x.ip} at {_stamp(x.time)} ({x.ua[:80]})"
                        for x in group[:20]
                    ],
                    rule_ids=[RULE.format("forged-sessions")],
                    recommended_action=(
                        f"Destroy every session on {site} (rotate the AUTH/LOGGED_IN keys and salts in "
                        "wp-config.php), reset admin passwords, and look for how the attacker got "
                        "database or "
                        "code access (web shells, a vulnerable plugin)."
                    ),
                )
            )
    return out


def synchronized_logins(f: ActivityFacts) -> list[FindingItem]:
    s = f.rule_settings
    if not f.has_baseline:
        return []  # "new IP" needs a previous pass
    new = {(a, ip) for a, ips in f.new_ips.items() for ip in ips}
    fresh = [x for x in f.sessions if (account_of(x), x.ip) in new and not _trusted(x.ip, s["trusted_ips"])]
    out: list[FindingItem] = []
    by_account: dict[str, list[Session]] = defaultdict(list)
    for x in fresh:
        by_account[account_of(x)].append(x)
    for account, sessions in sorted(by_account.items()):
        for group in _clusters(sessions, s["sync_window_s"]):
            sites = sorted({x.site for x in group})
            if len(sites) < 2:
                continue
            out.append(_sync_item(account.removeprefix("wp:"), group, sites, s["sync_window_s"]))
    by_ip: dict[str, list[Session]] = defaultdict(list)
    for x in fresh:
        by_ip[x.ip].append(x)
    for ip, sessions in sorted(by_ip.items()):
        for group in _clusters(sessions, s["sync_window_s"]):
            accounts = sorted({account_of(x) for x in group})
            sites = sorted({x.site for x in group})
            if len(accounts) >= s["sync_min_accounts"] and len(sites) >= 2:
                out.append(_sync_item(ip, group, sites, s["sync_window_s"]))
    return out


def _sync_item(subject: str, group: list[Session], sites: list[str], window: int) -> FindingItem:
    first = group[0]
    ips = sorted({x.ip for x in group})
    accounts = sorted({x.login for x in group})
    return FindingItem(
        kind="synchronized_logins",
        subject=f"{subject}@{_minute(first.time)}",
        severity="high",
        confidence="high",
        title=f"Logins on {len(sites)} sites within {window} s from a new IP ({', '.join(ips[:3])})",
        summary=(
            f"{', '.join(accounts[:5])} logged in on {', '.join(sites[:5])} within {window} seconds of "
            "each other "
            f"at {_stamp(first.time)}, from {', '.join(ips[:3])}, which these accounts hadn't used "
            "before. On "
            "Oct 21 2026 the attackers logged in to three sites at once, each time from a new "
            "residential IP, "
            "using stolen passwords."
        ),
        evidence=[
            f"session {x.login} on {x.site} from {x.ip} at {_stamp(x.time)} ({x.ua[:80]})" for x in group[:20]
        ],
        rule_ids=[RULE.format("synchronized-logins")],
        recommended_action=(
            "Check with the account owners whether this was them. If not: reset their passwords, destroy "
            "their "
            "sessions on every site, enable 2FA, and check what they did after logging in (new admins, "
            "plugin "
            "uploads, edited files)."
        ),
    )


def login_then_upload(f: ActivityFacts) -> list[FindingItem]:
    s = f.rule_settings
    if not f.has_baseline:
        return []  # without known IPs every admin's own upload would look the same
    known = {
        ip
        for ips in f.known_ips.values()
        for ip in ips
        if ip not in {i for v in f.new_ips.values() for i in v}
    }
    out = []
    by_ip: dict[str, list[Request]] = defaultdict(list)
    for r in f.requests:
        by_ip[r.ip].append(r)
    for ip, requests in sorted(by_ip.items()):
        if ip in known or _trusted(ip, s["trusted_ips"]):
            continue
        requests.sort(key=lambda r: r.time)
        for login in (
            r for r in requests if r.method == "POST" and "wp-login.php" in r.path and r.status == 302
        ):
            uploads = [
                r
                for r in requests
                if 0 <= r.time - login.time <= s["upload_window_s"]
                and UPLOAD.search(r.path)
                and r.status < 400
            ]
            if not uploads:
                continue
            where = login.site or uploads[0].site or "a site"
            out.append(
                FindingItem(
                    kind="login_then_upload",
                    subject=f"{ip}@{_minute(login.time)}",
                    severity="high",
                    confidence="medium",
                    title=f"Login from unknown IP {ip} on {where}, then a plugin upload or file edit",
                    summary=(
                        f"{ip}, an IP no account here has used before, logged in on {where} at "
                        f"{_stamp(login.time)} and within {s['upload_window_s'] // 60} minutes opened "
                        f"{uploads[0].path.split('?')[0].rsplit('/', 1)[-1]}. In the October 2026 incident "
                        "attackers uploaded a malicious plugin right after logging in with a stolen password."
                    ),
                    evidence=[
                        f"{r.method} {r.path} {r.status} from {r.ip} at {_stamp(r.time)} ({r.site or '-'})"
                        for r in [login, *uploads][:20]
                    ],
                    rule_ids=[RULE.format("login-then-upload")],
                    recommended_action=(
                        "Find out who logged in (the site's users and their sessions), check recently "
                        "added or "
                        "changed plugins and theme files, and if nobody on your team did this, treat the "
                        "site as "
                        "compromised."
                    ),
                )
            )
            break  # one finding per IP per pass
    return out


def new_ip_logins(f: ActivityFacts) -> list[FindingItem]:
    s = f.rule_settings
    if not f.has_baseline:
        return []
    out = []
    seen: set[tuple[str, str]] = set()
    for x in f.sessions:
        account = account_of(x)
        if not x.admin or x.ip not in f.new_ips.get(account, []) or _trusted(x.ip, s["trusted_ips"]):
            continue
        if (account, x.ip) in seen:
            continue
        seen.add((account, x.ip))
        out.append(
            FindingItem(
                kind="new_ip_admin_login",
                subject=f"{account.removeprefix('wp:')}@{x.ip}",
                severity="medium",
                confidence="medium",
                title=f"Administrator {x.login} logged in on {x.site} from a new IP ({x.ip})",
                summary=(
                    f"The administrator {x.login} has a session on {x.site} created at {_stamp(x.time)} "
                    f"from {x.ip}, "
                    "an IP this account hasn't used on this server before. It may be them on a new "
                    "network, or "
                    "someone with their password."
                ),
                evidence=[f"session {x.login} on {x.site} from {x.ip} at {_stamp(x.time)} ({x.ua[:80]})"],
                rule_ids=[RULE.format("new-ip-admin")],
                recommended_action=(
                    f"Ask {x.login} whether this login was theirs; if not, reset the password and destroy "
                    "their sessions."
                ),
            )
        )
    for login in f.ssh_logins:
        account = f"ssh:{login.user}"
        if (
            login.ip not in f.new_ips.get(account, [])
            or _trusted(login.ip, s["trusted_ips"])
            or (account, login.ip) in seen
        ):
            continue
        seen.add((account, login.ip))
        out.append(
            FindingItem(
                kind="new_ip_ssh_login",
                subject=f"{login.user}@{login.ip}",
                severity="medium",
                confidence="medium",
                title=f"SSH login as {login.user} from a new IP ({login.ip})",
                summary=(
                    f"{login.user} logged in over SSH ({login.method}) at {_stamp(login.time)} from "
                    f"{login.ip}, an IP not seen for "
                    "this user on this server before."
                ),
                evidence=[
                    f"Accepted {login.method} for {login.user} from {login.ip} at {_stamp(login.time)}"
                ],
                rule_ids=[RULE.format("new-ip-ssh")],
                recommended_action=(
                    f"Confirm the login was expected; if not, check {login.user}'s authorized_keys and "
                    "recent commands, and rotate its credentials."
                ),
            )
        )
    return out
