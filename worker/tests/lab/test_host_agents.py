"""M2 against the Docker lab: every planted fixture is detected, the clean host gives no false positives.

    docker compose up -d lab-db lab-wp1 lab-wp2 lab-locked
    docker compose run --rm worker pytest -m lab

- lab-wp1 (Ubuntu 24.04, usr-merged): clean. Nothing may be reported, including packaged units that dpkg only
  knows under the other /lib ↔ /usr/lib name.
- lab-wp2 (Ubuntu 16.04): lab/fixtures/host-compromise (uid-0 user, fake systemd unit + set-uid binary,
  www-data crontab, hidden /dev/shm directory).
- lab-locked (Ubuntu 24.04): lab/fixtures/sudo-lockout (`chmod 000 /usr/bin/sudo`).
"""

import json
from typing import Any

import pytest
from typer.testing import CliRunner

from handscheck.cli import app
from tests.lab.test_lab_hosts import _lab_key

pytestmark = pytest.mark.lab
cli = CliRunner()
HOSTS = ("lab-wp1", "lab-wp2", "lab-locked")


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Two consecutive `hc check` runs of every lab host, plus `hc diff` and `hc sites`."""
    mp = pytest.MonkeyPatch()
    mp.setenv("HANDSCHECK_STATE_DIR", str(tmp_path_factory.mktemp("state")))
    key = _lab_key()
    try:
        for host in HOSTS:
            added = cli.invoke(app, ["host", "add", host, "--address", host, "--key", str(key), "--json"])
            assert added.exit_code == 0, added.output
        first = cli.invoke(app, ["check", "--all", "--no-agents", "--json"])
        assert first.exit_code == 0, first.output
        second = cli.invoke(app, ["check", "--all", "--no-agents", "--json"])
        assert second.exit_code == 0, second.output
        diffs = {h: json.loads(cli.invoke(app, ["diff", "--host", h, "--json"]).output) for h in HOSTS}
        sites = {h: json.loads(cli.invoke(app, ["sites", "--host", h, "--json"]).output) for h in HOSTS}
    finally:
        mp.undo()
    return {
        "first": {o["run"]["host"]: o["run"] for o in json.loads(first.output)},
        "second": {o["run"]["host"]: o["run"] for o in json.loads(second.output)},
        "diffs": diffs,
        "sites": sites,
    }


def facts(run: dict[str, Any], agent: str) -> dict[str, Any]:
    result = next(r for r in [run["sites"], *run["agents"]] if r["agent"] == agent)
    assert result["status"] != "failed", result
    return result["facts"]


def test_compromised_host_fixtures_are_detected(runs: dict[str, Any]) -> None:
    run = runs["first"]["lab-wp2"]
    assert run["sudo_ok"]
    system = facts(run, "system")
    assert system["uid0_accounts"] == ["root", "sysbackup"]
    [unit] = system["unpackaged_units"]
    assert unit["path"] == "/etc/systemd/system/dbus-socket-helper.service"
    assert "ExecStart=/usr/sbin/authd" in unit["lines"]
    assert unit["enabled_by"] == ["/etc/systemd/system/multi-user.target.wants/dbus-socket-helper.service"]
    assert [f["path"] for f in system["unpackaged_setid_files"]] == ["/usr/sbin/authd"]

    persistence = facts(run, "persistence")
    assert persistence["web_user_crontabs"] == ["www-data"]
    assert [e["command"] for e in persistence["cron_entries"] if e["user"] == "www-data"] == [
        "/dev/shm/.x/checker >/dev/null 2>&1"
    ]
    temp = {e["path"]: e["reasons"] for e in persistence["temp_entries"]}
    assert temp == {"/dev/shm/.x": ["hidden", "web_user"], "/dev/shm/.x/checker": ["hidden", "web_user"]}

    users = facts(run, "users")
    assert {a["name"] for a in users["accounts"] if a["uid"] == 0} == {"root", "sysbackup"}


def test_sudo_lockout_is_detected(runs: dict[str, Any]) -> None:
    run = runs["first"]["lab-locked"]
    system = facts(run, "system")
    assert system["sudo_binary"] == {
        "path": "/usr/bin/sudo",
        "mode": "0000",
        "owner": "root",
        "group": "root",
    }
    assert system["sudo_binary_ok"] is False
    assert not run["sudo_ok"] and run["status"] == "partial"
    assert any("read-only sudo is not working" in e for e in run["errors"])
    assert any("without sudo" in w for w in facts(run, "users")["warnings"])


def test_clean_host_has_no_false_positives(runs: dict[str, Any]) -> None:
    run = runs["first"]["lab-wp1"]
    assert run["sudo_ok"]
    system = facts(run, "system")
    assert system["uid0_accounts"] == ["root"]
    assert system["unpackaged_units"] == []
    # The /lib ↔ /usr/lib quirk is present on this host and handled.
    assert system["units_matched_via_usr_merge"] > 0 and system["packaged_units"] > 100
    assert system["unpackaged_setid_files"] == [] and system["setid_files"] > 0
    assert system["tampered_files"] == [] and system["verified_packages"]
    assert system["sudo_binary_ok"] is True and system["ld_so_preload"] == []
    assert system["modprobe_files"] == [] or all(f["package"] for f in system["modprobe_files"])

    persistence = facts(run, "persistence")
    assert persistence["web_user_crontabs"] == [] and persistence["temp_entries"] == []
    assert all(e["user"] == "root" for e in persistence["cron_entries"])
    assert all(s["package"] for s in persistence["cron_scripts"])
    assert persistence["timers"] and all(t["packaged"] for t in persistence["timers"])

    users = facts(run, "users")
    assert [a["name"] for a in users["accounts"] if a["uid"] == 0] == ["root"]
    # The scan user and the fix user (M6, remediate key only); nobody else has SSH keys.
    assert {k["path"] for k in users["authorized_keys"]} == {
        "/home/handscheck/.ssh/authorized_keys",
        "/home/handscheck-fix/.ssh/authorized_keys",
    }


def test_sites_are_discovered(runs: dict[str, Any]) -> None:
    expected = {
        "lab-wp1": ("6.7.2", ["alpha.lab.test", "beta.lab.test"]),
        "lab-wp2": ("6.5.5", ["delta.lab.test", "gamma.lab.test"]),
    }
    for host, (version, names) in expected.items():
        sites = runs["sites"][host]["sites"]
        assert [s["name"] for s in sites] == names
        assert all(s["type"] == "wordpress" and s["wordpress"]["version"] == version for s in sites)
        assert [s["name"] for s in facts(runs["first"][host], "sites")["sites"]] == names
    assert runs["sites"]["lab-locked"]["sites"] == []


def test_second_run_is_quiet_and_diffable(runs: dict[str, Any]) -> None:
    for host in HOSTS:
        first, second = runs["first"][host], runs["second"][host]
        results = [second["sites"], *second["agents"]]
        assert all(r["baseline"] for r in [first["sites"], *first["agents"]])
        assert not any(r["baseline"] for r in results), host
        assert [c for r in results for c in r["changes"]] == [], host
        assert second["change_events"] == []
        diff = runs["diffs"][host]
        assert diff["changes"] == [] and diff["baseline"] == []
        metrics = {m["name"] for m in second["metrics"]}
        assert {"run.duration_s", "run.commands", "system.packages_installed", "sites.count"} <= metrics
