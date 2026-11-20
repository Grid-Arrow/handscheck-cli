from datetime import UTC, datetime, timedelta, timezone

import asyncssh

from handscheck.agents.users.check import (
    UsersFacts,
    parse_authorized_keys,
    parse_groups,
    parse_now,
    parse_passwd,
    parse_sudoers,
    search_roots,
    summarize_auth_log,
)
from tests.agents.conftest import collect_facts

ACCOUNT_LINES = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000::/home/ubuntu:/bin/bash
deploy:x:1001:27::/srv/deploy:/bin/sh
"""


def test_accounts_groups_and_key_search_roots() -> None:
    accounts = parse_passwd(ACCOUNT_LINES + "broken\n")
    assert [a.name for a in accounts if a.login_shell] == ["root", "ubuntu", "deploy"]
    groups = parse_groups("sudo:x:27:ubuntu\nadm:x:4:syslog\nroot:x:0:\n", accounts, ["sudo", "root"])
    assert groups == {"root": [], "sudo": ["deploy", "ubuntu"]}
    assert search_roots(accounts) == ["/home", "/root", "/srv/deploy", "/var/www"]


def test_sudoers_rules() -> None:
    text = (
        "/etc/sudoers:# comment\n"
        "/etc/sudoers:Defaults\tenv_reset\n"
        "/etc/sudoers:root    ALL=(ALL:ALL) ALL\n"
        "/etc/sudoers:#includedir /etc/sudoers.d\n"
        "/etc/sudoers:\n"
        "/etc/sudoers.d/hc:Cmnd_Alias R = /bin/cat, \\\n"
        "/etc/sudoers.d/hc:   /bin/ls\n"
        "/etc/sudoers.d/hc:www-data ALL=(ALL) NOPASSWD: ALL\n"
    )
    assert [(r.file, r.line) for r in parse_sudoers(text)] == [
        ("/etc/sudoers", "Defaults env_reset"),
        ("/etc/sudoers", "root ALL=(ALL:ALL) ALL"),
        ("/etc/sudoers", "#includedir /etc/sudoers.d"),
        ("/etc/sudoers.d/hc", "Cmnd_Alias R = /bin/cat, /bin/ls"),
        ("/etc/sudoers.d/hc", "www-data ALL=(ALL) NOPASSWD: ALL"),
    ]


def test_authorized_keys_fingerprints_match_ssh_keygen() -> None:
    key = asyncssh.generate_private_key("ssh-ed25519", comment="ops@example.test")
    line = key.export_public_key("openssh").decode().strip()
    text = (
        f"/home/ubuntu/.ssh/authorized_keys:{line}\n"
        f'/home/ubuntu/.ssh/authorized_keys:from="192.0.2.1",no-pty {line.rsplit(" ", 1)[0]} deploy key\n'
        "/home/ubuntu/.ssh/authorized_keys:# a comment\n"
        "/home/ubuntu/.ssh/authorized_keys:garbage\n"
    )
    keys = parse_authorized_keys(text, {"/home/ubuntu/.ssh/authorized_keys": ("ubuntu", "600")})
    assert len(keys) == 2
    assert {k.fingerprint for k in keys} == {key.get_fingerprint("sha256")}
    assert keys[0].comment == "ops@example.test" and keys[0].options == "" and keys[0].owner == "ubuntu"
    assert keys[1].options == 'from="192.0.2.1",no-pty' and keys[1].comment == "deploy key"


NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
AUTH_LOG = """\
Oct 20 01:00:00 aws24 sshd[1]: Accepted publickey for ubuntu from 198.51.100.1 port 1 ssh2: ED25519 SHA256:x
Oct 26 02:54:01 aws24 sshd[2]: Accepted publickey for ubuntu from 198.51.100.1 port 2 ssh2: ED25519 SHA256:x
Oct 26 02:55:01 aws24 sshd[3]: Accepted password for jpeterson from 203.0.113.9 port 3 ssh2
Oct 26 02:56:01 aws24 sshd[4]: Failed password for invalid user admin from 203.0.113.10 port 4 ssh2
Oct 26 02:56:02 aws24 sshd[5]: Invalid user test from 203.0.113.10 port 5
Oct 26 03:00:00 aws24 su[10]: FAILED SU (to ubuntu) www-data on none
Oct 26 03:00:01 aws24 su[11]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty= ruser=www-data rhost=  user=root
Oct 26 03:00:02 aws24 su[12]: FAILED SU (to root) bob on pts/1
Oct 26 03:01:00 aws24 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/ls
Oct 26 03:01:01 aws24 sudo: handscheck : PWD=/home/handscheck ; USER=root ; COMMAND=/usr/bin/find /
Oct 26 03:02:00 aws24 sudo:     root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/chmod 000 /usr/bin/sudo
Oct 26 03:03:00 aws24 sudo: www-data : user NOT in sudoers ; TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/bin/sh
2026-10-26T03:04:00.123456+00:00 aws24 su[13]: pam_unix(su:session): session opened for user root(uid=0) by www-data(uid=33)
2026-10-26T03:05:00.000000+00:00 aws24 sudo: pam_unix(sudo:auth): authentication failure; logname=ubuntu uid=1000 euid=0 tty=/dev/pts/0 ruser=ubuntu rhost=  user=ubuntu
not a log line
"""  # noqa: E501


def test_auth_log_summary() -> None:
    summary = summarize_auth_log(
        AUTH_LOG,
        path="/var/log/auth.log",
        now=NOW,
        tz=UTC,
        window_hours=48,
        web_users=["www-data"],
        ignore_sudo_users=["handscheck"],
    )
    assert summary.lines_read == 15 and summary.lines_in_window == 13  # Oct 20 is outside; one unparsable
    assert [(s.user, s.source, s.method, s.count) for s in summary.ssh_logins] == [
        ("jpeterson", "203.0.113.9", "password", 1),
        ("ubuntu", "198.51.100.1", "publickey", 1),
    ]
    assert summary.failed_logins == 2
    assert summary.sudo_commands == {"root": 1, "ubuntu": 1}
    kinds = [(e.kind, e.user) for e in summary.events]
    assert kinds == [
        ("su_by_web_user", "www-data"),
        ("su_by_web_user", "www-data"),
        ("failed_su", "bob"),
        ("root_tty_sudo", "root"),
        ("sudo_not_in_sudoers", "www-data"),
        ("su_by_web_user", "www-data"),
        ("sudo_auth_failure", "ubuntu"),
    ]


def test_auth_events_are_append_only_in_the_diff() -> None:
    assert "auth_events" in UsersFacts.append_only


def test_year_rollover_and_now() -> None:
    now, tz = parse_now("1767225600 -0500\n")  # 2026-01-01 00:00 UTC
    assert tz == timezone(-timedelta(hours=5))
    summary = summarize_auth_log(
        "Dec 31 18:30:00 h su[1]: FAILED SU (to root) www-data on none\n",
        path="x",
        now=now,
        tz=tz,
        window_hours=24,
        web_users=["www-data"],
        ignore_sudo_users=[],
    )
    assert summary.events and summary.events[0].time == "2025-12-31T18:30:00-05:00"
    fallback_now, fallback_tz = parse_now("garbage")
    assert fallback_tz == UTC and fallback_now.tzinfo is UTC


async def test_lab_hosts() -> None:
    clean = await collect_facts("lab-wp1", "users")
    assert isinstance(clean, UsersFacts)
    assert [k.path for k in clean.authorized_keys] == ["/home/handscheck/.ssh/authorized_keys"]
    assert any("handscheck" in r.line and "NOPASSWD" in r.line for r in clean.sudoers_rules)
    assert clean.auth is None and any("auth.log" in w for w in clean.warnings)  # no syslog in containers

    compromised = await collect_facts("lab-wp2", "users")
    assert isinstance(compromised, UsersFacts)
    uid0 = [a.name for a in compromised.accounts if a.uid == 0]
    assert uid0 == ["root", "sysbackup"]

    locked = await collect_facts("lab-locked", "users", sudo_ok=False)
    assert isinstance(locked, UsersFacts)
    assert locked.sudoers_rules == [] and any("without sudo" in w for w in locked.warnings)


def test_a_long_auth_log_read_by_size_is_still_summarized() -> None:
    """ga-aws-24 (2026-11-19): sudo logs every command in full, so 20,000 lines passed the output cap and the
    log came back truncated and unread. It is now read by size (`tail -c`), so the newest lines are there; the
    first line of the read may be cut and is dropped."""
    from handscheck.agents._framework.check import LOG_TAIL_BYTES, Output
    from handscheck.agents._framework.registry import all_agents
    from handscheck.agents.users.check import CHECK

    settings = all_agents()["users"].definition.effective_settings()
    noise = "2026-11-19T10:00:00+00:00 web1 sudo: handscheck : COMMAND=/usr/bin/grep " + "x" * 3000 + "\n"
    login = "2026-11-19T11:00:00+00:00 web1 sshd[901]: Accepted publickey for deploy from 192.0.2.30 "
    login += "port 5 ssh2\n"
    text = "partial line" + noise * (LOG_TAIL_BYTES // len(noise)) + login
    raw = {
        "now": Output(stdout="1795132800 +0000\n"),  # 2026-11-19T12:00Z
        "auth_log": Output(stdout=text[-LOG_TAIL_BYTES:]),
    }
    facts = CHECK().parse(raw, settings)
    assert not any("auth.log" in w for w in facts.warnings)
    assert facts.auth is not None and [(s.user, s.source) for s in facts.auth.ssh_logins] == [
        ("deploy", "192.0.2.30")
    ]
