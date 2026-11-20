"""M7b against the Docker lab: the 2026 PHP-FPM incident in miniature on lab-wp2.

A `lab-hang.php` that sleeps is planted in delta's web root through the fix user (test-only `PlanPolicy`),
and six slow requests to it fill Ubuntu's default php-fpm pool (`pm.max_children = 5`). The sites on that
pool stop answering; two watch passes of the health agent report it with the max_children warnings, a
`restart_service` fix is proposed from those facts, and applying it (as the fix user, `service php7.0-fpm
restart` in the container) frees the workers: the homepage answers again and verify passes. The file is
moved aside afterwards.

Run: docker compose up -d lab-db lab-wp2 && docker compose run --rm worker pytest -m lab
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from handscheck.agents._framework.registry import all_agents
from handscheck.agents._framework.services import HttpxProber, Services
from handscheck.contracts import Approval, Job, JobKind, RemediateInput
from handscheck.contracts.models import HostTarget
from handscheck.pipeline.run import PreviousSnapshot, run_host, snapshot_key
from handscheck.remediation.actions.restart_service import RestartService
from handscheck.remediation.handler import run_remediate
from handscheck.remediation.policy import PlanPolicy, normalize
from handscheck.remediation.propose import propose_fix
from handscheck.ssh.runner import SSHRunner, SSHTarget

from .test_lab_hosts import _lab_key

pytestmark = pytest.mark.lab

HOST = "lab-wp2"
HANG = "/var/www/delta.lab.test/lab-hang.php"


async def _as_fix_user(key: Path, argv: tuple[str, ...], stdin: str | None = None) -> None:
    target = SSHTarget(name=HOST, address=HOST, user="handscheck-fix", key_path=key)
    async with SSHRunner(target, policy=PlanPolicy(allowed=frozenset({normalize(argv, "root")}))) as ssh:
        res = await ssh.run(list(argv), sudo=True, stdin=stdin)
    assert res.ok, res.stderr


async def _pass(key: Path, previous: dict[str, PreviousSnapshot] | None) -> Any:
    target = SSHTarget(name=HOST, address=HOST, user="handscheck", key_path=key)
    http = HttpxProber(timeout=6.0)
    try:
        async with SSHRunner(target) as ssh:
            return await run_host(
                ssh, HOST, [all_agents()["health"]], previous=previous, services=Services(http=http)
            )
    finally:
        await http.close()


def _previous(run: Any) -> dict[str, PreviousSnapshot]:
    return {
        snapshot_key(s.agent, s.site): PreviousSnapshot(version=s.agent_version, facts=s.facts)
        for s in run.snapshots()
    }


async def _hang(client: httpx.AsyncClient) -> None:
    with contextlib.suppress(httpx.HTTPError):
        await client.get(
            f"http://{HOST}/lab-hang.php", params={"s": "120"}, headers={"Host": "delta.lab.test"}
        )


async def test_a_saturated_php_pool_is_reported_and_a_restart_brings_the_site_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = _lab_key()
    monkeypatch.setattr(RestartService, "VERIFY_SECONDS", 90.0)
    healthy = await _pass(key, None)
    health = next(r for r in healthy.results() if r.agent == "health")
    assert health.facts is not None and health.facts["site_pools"].get("gamma.lab.test") == "php7.0-fpm"

    await _as_fix_user(
        key, ("tee", HANG), stdin="<?php sleep(min(120, (int) ($_GET['s'] ?? 0))); echo 'ok';\n"
    )
    client = httpx.AsyncClient(timeout=150)
    hangs = [asyncio.create_task(_hang(client)) for _ in range(6)]
    try:
        await asyncio.sleep(3)  # the pool fills
        first = await _pass(key, _previous(healthy))
        second = await _pass(key, _previous(first))
        findings = {
            rf.finding.dedupe_key.split(":")[1]: rf for rf in second.findings if rf.finding.agent == "health"
        }
        assert {"site_down", "site_slow"} & set(findings), [rf.finding.dedupe_key for rf in second.findings]
        item = next(iter(findings.values()))
        assert any("pm.max_children reached" in e and "0 time" not in e for e in item.finding.evidence)

        facts = next(r for r in second.results() if r.agent == "health").facts
        fix = propose_fix(item.finding, facts)
        assert fix is not None and fix.action == "restart_service" and fix.params["service"] == "php7.0-fpm"

        prober = HttpxProber(timeout=6.0)
        try:
            result = await run_remediate(
                Job(
                    job_id="lab-restart",
                    task_id="1",
                    kind=JobKind.remediate,
                    host=HostTarget(
                        host_id="2",
                        name=HOST,
                        address=HOST,
                        user="handscheck-fix",
                        private_key=SecretStr(key.read_text()),
                    ),
                    remediate=RemediateInput(
                        proposal_id="lab-restart",
                        mode="apply",
                        fix=fix,
                        approval=Approval(user="lab@handscheck.test", approved_at=datetime.now(UTC)),
                        sites=[fix.params["site"]],
                    ),
                    deadline=datetime.now(UTC) + timedelta(hours=1),
                ),
                http=prober,
                timeout=120,
            )
        finally:
            await prober.close()
        out = result.remediation
        assert out is not None and out.status == "succeeded", out.message if out else result.errors
        assert any("service php7.0-fpm restart" in s.command for s in out.steps)
    finally:
        for task in hangs:
            task.cancel()
        await client.aclose()
        await _as_fix_user(key, ("mv", "-f", HANG, "/tmp/lab-hang.php"))  # aside, not deleted

    # The look-alike: the warnings are still in the php-fpm log, but visitors are fine again: no finding.
    after = await _pass(key, _previous(second))
    again = await _pass(key, _previous(after))
    facts = next(r for r in again.results() if r.agent == "health").facts
    assert facts["max_children"].get("php7.0-fpm", 0) > 0
    assert all(series[-1]["status"] == 200 for series in facts["probes"].values())
    assert not [rf for rf in again.findings if rf.finding.agent == "health"]
