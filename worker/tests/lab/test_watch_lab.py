"""M7 watch pass against the Docker lab: a replay of the Oct 21 2026 pattern on lab-wp2 is caught by the
next watch pass, and the clean lab-wp1 (an ordinary admin login, site-lookalikes) reports nothing.

The burst is planted with current timestamps through the fix user (a test-only `PlanPolicy`, as the M6 lab
tests use), and removed again afterwards:
- `labadmin` logs in on gamma and delta 40 s apart from 198.51.100.7, an IP it never used (synchronized);
- gamma's four users all "log in" in the same second (forged sessions; the threshold is 4 here, gamma has four
  users);
- gamma's access log gets a successful wp-login.php POST from that IP, then a plugin upload (login → upload).

Run: docker compose up -d lab-db lab-wp1 lab-wp2 && docker compose run --rm worker pytest -m lab
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from handscheck.agents._framework.registry import all_agents
from handscheck.pipeline.run import PreviousSnapshot, run_host, snapshot_key
from handscheck.remediation.policy import PlanPolicy, normalize
from handscheck.ssh.runner import SSHRunner, SSHTarget

from .test_lab_hosts import _lab_key

pytestmark = pytest.mark.lab

IP = "198.51.100.7"
GAMMA, DELTA = "/var/www/gamma.lab.test", "/var/www/delta.lab.test"
GAMMA_LOG = "/var/log/apache2/gamma.lab.test-access.log"


def _wp(path: str, *args: str) -> tuple[str, ...]:
    return ("wp", f"--path={path}", "--skip-plugins", "--skip-themes", "user", "meta", *args)


def _session(t: int, ua: str = "Mozilla/5.0 (replay)") -> str:
    token = hashlib.sha256(f"replay {t} {ua}".encode()).hexdigest()
    return json.dumps({token: {"expiration": t + 172800, "ip": IP, "ua": ua, "login": t}})


async def _as_fix_user(key: Path, host: str, commands: list[tuple[tuple[str, ...], str, str | None]]) -> None:
    """Run exact (argv, sudo user, stdin) commands as the lab's fix user: the test's own planting."""
    allowed = frozenset(normalize(argv, user) for argv, user, _ in commands)
    target = SSHTarget(name=host, address=host, user="handscheck-fix", key_path=key)
    async with SSHRunner(target, policy=PlanPolicy(allowed=allowed)) as ssh:
        for argv, user, stdin in commands:
            res = await ssh.run(
                list(argv), sudo=True, sudo_user=None if user == "root" else user, stdin=stdin
            )
            assert res.ok, (argv, res.stderr)


async def _watch(key: Path, host: str, previous: dict[str, PreviousSnapshot] | None) -> Any:
    agents = [a for a in all_agents().values() if a.definition.cadence.watch]
    target = SSHTarget(name=host, address=host, user="handscheck", key_path=key)
    async with SSHRunner(target) as ssh:
        return await run_host(
            ssh, host, agents, previous=previous, overrides={"activity": {"forged_min_users": 4}}
        )


def _previous(run: Any) -> dict[str, PreviousSnapshot]:
    return {
        snapshot_key(s.agent, s.site): PreviousSnapshot(version=s.agent_version, facts=s.facts)
        for s in run.snapshots()
    }


def _activity(run: Any) -> set[str]:
    return {rf.finding.dedupe_key.split(":")[1] for rf in run.findings if rf.finding.agent == "activity"}


async def test_the_oct21_replay_is_caught_by_the_next_watch_pass() -> None:
    key = _lab_key()
    baseline = await _watch(key, "lab-wp2", None)  # the first pass only learns
    assert "activity" in {r.agent for r in baseline.results()} and _activity(baseline) == set()

    t = int(time.time()) - 120
    stamp = datetime.fromtimestamp(t, UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")
    later = datetime.fromtimestamp(t + 90, UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")
    log = (
        f'{IP} - - [{stamp}] "POST /wp-login.php HTTP/1.1" 302 0 "-" "Mozilla/5.0 (replay)"\n'
        f'{IP} - - [{later}] "POST /wp-admin/update.php?action=upload-plugin HTTP/1.1" 200 812 "-" '
        '"Mozilla/5.0"\n'
    )
    plant = [
        (_wp(GAMMA, "update", str(uid), "session_tokens", _session(t), "--format=json"), "www-data", None)
        for uid in (1, 2, 3, 4)
    ]
    plant.append(
        (_wp(DELTA, "update", "1", "session_tokens", _session(t + 40), "--format=json"), "www-data", None)
    )
    plant.append((("tee", "-a", GAMMA_LOG), "root", log))
    cleanup = [(_wp(GAMMA, "delete", str(uid), "session_tokens"), "www-data", None) for uid in (1, 2, 3, 4)]
    cleanup.append((_wp(DELTA, "delete", "1", "session_tokens"), "www-data", None))

    await _as_fix_user(key, "lab-wp2", plant)
    try:
        caught = await _watch(key, "lab-wp2", _previous(baseline))
    finally:
        await _as_fix_user(key, "lab-wp2", cleanup)
    found = _activity(caught)
    assert {"synchronized_logins", "forged_sessions", "login_then_upload"} <= found, found
    by_kind = {
        rf.finding.dedupe_key.split(":")[1]: rf for rf in caught.findings if rf.finding.agent == "activity"
    }
    assert by_kind["forged_sessions"].finding.severity.value == "critical"
    assert by_kind["synchronized_logins"].finding.severity.value == "high"
    assert any(IP in e for e in by_kind["synchronized_logins"].finding.evidence)
    assert all(rf.verification.status == "pending" for rf in by_kind.values())  # off to the verifier
    assert caught.claude is False


async def test_ordinary_logins_on_the_clean_host_report_nothing() -> None:
    key = _lab_key()
    first = await _watch(key, "lab-wp1", None)
    second = await _watch(key, "lab-wp1", _previous(first))
    assert _activity(first) == set() and _activity(second) == set()
    activity = next(r for r in second.results() if r.agent == "activity")
    assert activity.facts is not None and "wp:labadmin" in activity.facts["known_ips"]
