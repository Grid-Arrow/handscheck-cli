"""`activity` (watch pass): the session reader, log parsing, carried IPs, and each login rule."""

from __future__ import annotations

import hashlib
from typing import Any

from handscheck.agents._framework.check import Output
from handscheck.agents.activity.check import (
    CHECK,
    ActivityFacts,
    access_log_path,
    parse_access_log,
    parse_sessions,
    php_sessions,
)

NOW = 1_795_000_000  # the host's clock in these tests
SETTINGS: dict[str, Any] = {
    "wp_cli_user": "www-data",
    "lookback_minutes": 90,
    "access_log_lines": 5000,
    "auth_log_path": "/var/log/auth.log",
    "auth_log_lines": 5000,
    "forged_min_users": 5,
    "forged_window_s": 2,
    "sync_window_s": 120,
    "sync_min_accounts": 3,
    "upload_window_s": 900,
    "known_ip_days": 90,
    "trusted_ips": ["203.0.113.0/24"],
}


def token(ip: str, login: int, ua: str = "Mozilla/5.0") -> str:
    h = hashlib.sha256(f"{ip} {login} {ua}".encode()).hexdigest()  # a real token is a sha256 too
    inner = (
        f's:10:"expiration";i:{login + 86400};s:2:"ip";s:{len(ip)}:"{ip}";'
        f's:2:"ua";s:{len(ua)}:"{ua}";s:5:"login";i:{login};'
    )
    return f's:64:"{h}";a:4:{{{inner}}}'


def tokens(*items: str) -> str:
    return f"a:{len(items)}:{{{''.join(items)}}}"


def row(uid: int, login: str, meta: str, admin: bool = True, email: str = "") -> str:
    return f"{uid}\t{login}\t{email or login + '@example.test'}\t{1 if admin else 0}\t{meta}"


def sessions_out(*rows: str) -> Output:
    return Output(stdout="ID\tuser_login\tuser_email\tIF(...)\tmeta_value\n" + "\n".join(rows) + "\n")


def facts_from(raw: dict[str, Output], previous: ActivityFacts | None = None) -> ActivityFacts:
    raw = {"now": Output(stdout=f"{NOW} +0000\n"), **raw}
    facts = CHECK().parse(raw, SETTINGS)
    if previous is not None:
        facts = CHECK().carry(previous.model_dump(mode="json"), facts)
    return facts


def kinds(facts: ActivityFacts) -> list[tuple[str, str, str]]:
    return [
        (f.kind, f.subject, f.severity) for f in CHECK().guaranteed_findings(facts.model_dump(mode="json"))
    ]


# ── parsers ──────────────────────────────────────────────────────────────────


def test_php_sessions_reads_tokens_and_refuses_anything_else() -> None:
    meta = tokens(token("198.51.100.7", NOW - 60), token("2001:db8::1", NOW - 30, ua="curl/8"))
    assert php_sessions(meta) == [
        {"ip": "198.51.100.7", "login": NOW - 60, "ua": "Mozilla/5.0"},
        {"ip": "2001:db8::1", "login": NOW - 30, "ua": "curl/8"},
    ]
    for bad in (
        'O:8:"stdClass":0:{}',  # an object
        tokens(token("198.51.100.7", NOW)) + "trailing",
        'a:1:{s:64:"' + "a" * 64 + '";a:1:{s:2:"ip";s:99:"1.2.3.4";}}',  # wrong string length
        tokens(token("not-an-ip", NOW)),  # no usable session
        "a:9999999:{}",
        "",
    ):
        assert php_sessions(bad) == [], bad


def test_sessions_rows_unescape_mysql_batch_output() -> None:
    ua = "Mozilla\\tTab"  # mysql -B writes a tab inside a value as \\t
    meta = tokens(token("198.51.100.7", NOW, ua="Mozilla\tTab")).replace("\t", "\\t")
    [s] = parse_sessions(row(3, "editor", meta, admin=False), "alpha.lab.test")
    assert (s.login, s.admin, s.ip, s.ua) == ("editor", False, "198.51.100.7", "Mozilla\tTab")
    assert ua  # (documenting the escape)


def test_access_log_lines_of_interest_only() -> None:
    def line(ip: str, t: str, req: str, status: int, vhost: str = "") -> str:
        prefix = f"{vhost}:443 " if vhost else ""
        return f'{prefix}{ip} - - [{t} +0000] "{req} HTTP/1.1" {status} 512 "-" "Mozilla/5.0"'

    t = "18/Nov/2026:20:26:40"
    log = "\n".join(
        [
            line("198.51.100.7", t, "POST /wp-login.php", 302),
            line(
                "198.51.100.7",
                t,
                "GET /wp-admin/update.php?action=upload-plugin",
                200,
                vhost="gamma.lab.test",
            ),
            line("198.51.100.7", t, "GET /blog/hello-world/", 200),
            line("198.51.100.7", "01/Jan/2020:00:00:00", "POST /wp-login.php", 302),  # too old
            "garbage",
        ]
    )
    requests = parse_access_log(log, None, since=NOW - 3600 * 24 * 365)
    assert [(r.site, r.path, r.status) for r in requests] == [
        (None, "/wp-login.php", 302),
        ("gamma.lab.test", "/wp-admin/update.php?action=upload-plugin", 200),
    ]


def test_access_log_path_from_the_vhost() -> None:
    conf = "    CustomLog ${APACHE_LOG_DIR}/gamma.lab.test-access.log combined\n"
    assert access_log_path(conf, "gamma.lab.test") == "/var/log/apache2/gamma.lab.test-access.log"
    assert access_log_path("  access_log /var/log/nginx/x.log main;\n", "x") == "/var/log/nginx/x.log"
    assert access_log_path("CustomLog /dev/null combined\n", "x") is None
    assert access_log_path("CustomLog ${OTHER}/x.log combined\n", "x") is None


# ── carry and the rules ──────────────────────────────────────────────────────


def baseline() -> ActivityFacts:
    """The previous pass: alice and bob have logged in from their usual IPs on both sites."""
    old = NOW - 3 * 3600
    return facts_from(
        {
            "sessions@alpha.lab.test": sessions_out(
                row(1, "alice", tokens(token("192.0.2.10", old))),
                row(2, "bob", tokens(token("192.0.2.20", old))),
            ),
            "sessions@beta.lab.test": sessions_out(row(1, "alice", tokens(token("192.0.2.10", old)))),
        }
    )


def test_first_pass_only_learns() -> None:
    first = baseline()
    assert not first.has_baseline and first.new_ips == {}
    assert first.known_ips["wp:alice"] == {"192.0.2.10": NOW - 3 * 3600}
    assert kinds(first) == []


def test_synchronized_logins_from_a_new_ip_across_sites() -> None:
    burst = NOW - 600
    facts = facts_from(
        {
            "sessions@alpha.lab.test": sessions_out(row(1, "alice", tokens(token("198.51.100.7", burst)))),
            "sessions@beta.lab.test": sessions_out(
                row(1, "alice", tokens(token("198.51.100.7", burst + 40)))
            ),
        },
        previous=baseline(),
    )
    assert facts.has_baseline and facts.new_ips == {"wp:alice": ["198.51.100.7"]}
    found = kinds(facts)
    assert ("synchronized_logins", f"alice@{_minute(burst)}", "high") in found
    assert ("new_ip_admin_login", "alice@198.51.100.7", "medium") in found
    # The IP is remembered: the next pass reports nothing new.
    again = facts_from(
        {"sessions@alpha.lab.test": sessions_out(row(1, "alice", tokens(token("198.51.100.7", burst))))},
        previous=facts,
    )
    assert again.new_ips == {} and kinds(again) == []


def test_logins_on_two_sites_from_a_known_ip_or_too_far_apart_are_fine() -> None:
    usual = facts_from(
        {
            "sessions@alpha.lab.test": sessions_out(row(1, "alice", tokens(token("192.0.2.10", NOW - 600)))),
            "sessions@beta.lab.test": sessions_out(row(1, "alice", tokens(token("192.0.2.10", NOW - 590)))),
        },
        previous=baseline(),
    )
    assert kinds(usual) == []
    apart = facts_from(
        {
            "sessions@alpha.lab.test": sessions_out(
                row(1, "alice", tokens(token("198.51.100.7", NOW - 3000)))
            ),
            "sessions@beta.lab.test": sessions_out(row(1, "alice", tokens(token("198.51.100.7", NOW - 600)))),
        },
        previous=baseline(),
    )
    assert [k for k, *_ in kinds(apart)] == ["new_ip_admin_login"]  # new IP, but not synchronized
    trusted = facts_from(
        {
            "sessions@alpha.lab.test": sessions_out(row(1, "alice", tokens(token("203.0.113.5", NOW - 600)))),
            "sessions@beta.lab.test": sessions_out(row(1, "alice", tokens(token("203.0.113.5", NOW - 590)))),
        },
        previous=baseline(),
    )
    assert kinds(trusted) == []


def test_forged_sessions_on_one_site_even_on_the_first_pass() -> None:
    t = NOW - 300
    users = [row(i, f"user{i}", tokens(token("198.51.100.9", t + (i % 2))), admin=False) for i in range(1, 7)]
    facts = facts_from({"sessions@delta.lab.test": sessions_out(*users)})
    assert kinds(facts) == [("forged_sessions", f"delta.lab.test@{_minute(t)}", "critical")]
    # Four users in two seconds, or six spread over minutes, are not forged.
    few = facts_from({"sessions@delta.lab.test": sessions_out(*users[:4])})
    spread = [row(i, f"user{i}", tokens(token("198.51.100.9", t + 30 * i)), admin=False) for i in range(1, 7)]
    assert kinds(few) == [] and kinds(facts_from({"sessions@delta.lab.test": sessions_out(*spread)})) == []


def test_login_then_upload_from_an_unknown_ip() -> None:
    def log(ip: str) -> Output:
        lines = [
            f'{ip} - - [18/Nov/2026:20:16:40 +0000] "POST /wp-login.php HTTP/1.1" 302 0 "-" "Mozilla/5.0"',
            f'{ip} - - [18/Nov/2026:20:20:00 +0000] "POST /wp-admin/update.php?action=upload-plugin '
            'HTTP/1.1" 200 900 "-" "Mozilla/5.0"',
        ]
        return Output(stdout="\n".join(lines) + "\n")

    found = facts_from({"access@gamma.lab.test": log("198.51.100.7")}, previous=baseline())
    assert [k for k, *_ in kinds(found)] == ["login_then_upload"]
    known = facts_from({"access@gamma.lab.test": log("192.0.2.10")}, previous=baseline())  # alice's usual IP
    assert kinds(known) == []
    first_pass = facts_from({"access@gamma.lab.test": log("198.51.100.7")})
    assert kinds(first_pass) == []  # no baseline yet: every admin's upload would look like this


def test_new_ip_ssh_login() -> None:
    def auth(ip: str) -> Output:
        return Output(
            stdout="2026-11-18T20:20:00+00:00 web1 sshd[901]: Accepted publickey for deploy from "
            f"{ip} port 52144 ssh2: ED25519 SHA256:x\n"
        )

    first = facts_from({"auth_log": auth("192.0.2.30")})
    assert first.known_ips["ssh:deploy"] and kinds(first) == []
    later = facts_from({"auth_log": auth("198.51.100.44")}, previous=first)
    assert kinds(later) == [("new_ip_ssh_login", "deploy@198.51.100.44", "medium")]


def test_known_ips_expire_and_are_capped() -> None:
    previous = baseline().model_dump(mode="json")
    previous["known_ips"]["wp:alice"]["192.0.2.99"] = NOW - 200 * 86400  # long ago
    facts = CHECK().carry(previous, facts_from({}))
    assert "192.0.2.99" not in facts.known_ips["wp:alice"]
    assert "192.0.2.10" in facts.known_ips["wp:alice"]  # kept from before, though not seen now


def _minute(t: int) -> str:
    from handscheck.agents.activity.check import _minute as minute

    return minute(t)
