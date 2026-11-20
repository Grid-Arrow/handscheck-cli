from typing import Any

import pytest

from handscheck.agents._framework.registry import all_agents
from handscheck.pipeline.run import PreviousSnapshot, run_host, snapshot_key
from handscheck.ssh.runner import SSHError
from tests.agents.conftest import replay_run
from tests.agents.replay import ReplayRunner, replay_services

SITES = {
    "lab-wp1": ["alpha.lab.test", "beta.lab.test"],
    "lab-wp2": ["delta.lab.test", "gamma.lab.test"],
    "lab-locked": [],
}


def _previous(run: Any) -> dict[str, PreviousSnapshot]:
    return {
        snapshot_key(s.agent, s.site): PreviousSnapshot(version=s.agent_version, facts=s.facts)
        for s in run.snapshots()
    }


@pytest.mark.parametrize("host", ["lab-wp1", "lab-wp2", "lab-locked"])
async def test_every_command_passes_the_policy_and_runs_are_stable(host: str) -> None:
    first = await replay_run(host)  # ReplayRunner enforces the policy on every command
    host_agents = ["sites", "activity", "health", "persistence", "system", "users"]
    sites = SITES[host]
    expected = sorted(
        [*host_agents, *(f"{a}@{s}" for a in ("exposure", "malware", "wordpress") for s in sites)]
    )
    assert sorted(r.key for r in first.results()) == expected
    assert all(r.baseline and r.status != "failed" for r in first.results())
    assert first.claude is False and first.commands > 20
    second = await replay_run(host, previous=_previous(first))
    assert not any(r.baseline for r in second.results())
    assert second.changes == [] and second.change_events == []  # same host state, no spurious diff


async def test_metrics_and_snapshots() -> None:
    run = await replay_run("lab-wp2")
    names = {m.name: m.value for m in run.metrics}
    assert names["system.uid0_accounts"] == 2 and names["system.unpackaged_units"] == 1
    assert names["persistence.web_user_crontabs"] == 1 and names["sites.count"] == 2
    assert names["run.sudo_ok"] == 1 and "users.accounts" in names and "system.duration_s" in names
    assert {s.agent for s in run.snapshots()} == {
        "sites",
        "activity",
        "health",
        "system",
        "users",
        "persistence",
        "exposure",
        "malware",
        "wordpress",
    }
    assert {s.site for s in run.snapshots() if s.agent == "malware"} == {"gamma.lab.test", "delta.lab.test"}
    assert run.status == "partial"  # users: no auth.log in the lab containers


async def test_sudo_lockout_is_reported() -> None:
    run = await replay_run("lab-locked")
    assert not run.sudo_ok and run.status == "partial"
    assert any("read-only sudo is not working" in e for e in run.errors)


async def test_diff_against_a_cleaner_previous_snapshot() -> None:
    """lab-wp2's fixtures appear as diff entries when the previous snapshot didn't have them."""
    current = await replay_run("lab-wp2")
    previous = _previous(current)
    system = previous["system"].facts
    system["uid0_accounts"] = ["root"]
    system["unpackaged_units"] = []
    system["unpackaged_setid_files"] = []
    system["packages"] = {k: v for k, v in system["packages"].items() if k != "sudo"}
    persistence = previous["persistence"].facts
    persistence["cron_entries"] = [e for e in persistence["cron_entries"] if e["user"] != "www-data"]
    persistence["temp_entries"] = []
    previous["sites"].facts["sites"] = previous["sites"].facts["sites"][:1]
    gamma = previous["wordpress@gamma.lab.test"].facts
    gamma["admins"] = [a for a in gamma["admins"] if a["id"] == 1]
    gamma["plugins"] = [p for p in gamma["plugins"] if p["slug"] != "revslider"]
    malware = previous["malware@gamma.lab.test"].facts
    malware["php_in_uploads"] = []
    malware["fingerprint_hits"] = []

    run = await replay_run("lab-wp2", previous=previous)
    found = {(c.agent, c.collection, c.op, c.key) for c in run.changes}
    assert ("system", "uid0_accounts", "added", "sysbackup") in found
    assert ("system", "unpackaged_units", "added", "/etc/systemd/system/dbus-socket-helper.service") in found
    assert ("system", "unpackaged_setid_files", "added", "/usr/sbin/authd") in found
    assert ("persistence", "temp_entries", "added", "/dev/shm/.x/checker") in found
    assert any(
        c.agent == "persistence" and c.key.startswith("/var/spool/cron/crontabs/www-data")
        for c in run.changes
    )
    assert ("wordpress", "admins", "added", "root") in found
    assert (
        "malware",
        "php_in_uploads",
        "added",
        "/var/www/gamma.lab.test/wp-content/uploads/2026/10/cache.php",
    ) in found
    events = sorted((e.kind, e.agent, e.site or "") for e in run.change_events)
    assert events == [
        ("package", "system", ""),
        ("package", "wordpress", "gamma.lab.test"),
        ("site", "sites", "gamma.lab.test"),
    ]


async def test_version_change_starts_a_new_baseline() -> None:
    first = await replay_run("lab-wp1")
    previous = _previous(first)
    previous["system"] = PreviousSnapshot(version=99, facts=previous["system"].facts)
    previous["users"] = PreviousSnapshot(version=1, facts={"unknown_field": 1})
    run = await replay_run("lab-wp1", previous=previous)
    by_agent = {r.agent: r for r in run.results()}
    assert by_agent["system"].baseline and "new baseline" in by_agent["system"].warnings[-1]
    assert by_agent["users"].baseline
    assert not by_agent["persistence"].baseline


async def test_policy_violation_fails_only_that_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    check = all_agents()["persistence"].check
    assert check is not None

    async def bad_collect(ctx: Any, settings: Any) -> Any:
        await ctx.run(["rm", "-rf", "/tmp/x"])

    monkeypatch.setattr(check, "collect", bad_collect)
    runner = ReplayRunner.load("lab-wp1")
    run = await run_host(runner, "lab-wp1", list(all_agents().values()), services=replay_services("lab-wp1"))
    by_agent = {r.agent: r for r in run.results()}
    assert by_agent["persistence"].status == "failed" and "policy" in (by_agent["persistence"].error or "")
    assert by_agent["system"].status == "ok"
    assert not any(c.startswith("rm") for c in runner.commands_run)


async def test_unreachable_host_raises() -> None:
    class Down:
        async def run(self, *args: Any, **kwargs: Any) -> Any:
            raise SSHError("lab-x: cannot connect")

    with pytest.raises(SSHError):
        await run_host(Down(), "lab-x", list(all_agents().values()))
