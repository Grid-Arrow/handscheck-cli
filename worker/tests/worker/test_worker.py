"""`hc worker` offline: jobs run through the pipeline on replayed lab output, results match the contract, and
the loop talks to a fake control plane."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from handscheck.agents._framework.registry import all_agents
from handscheck.config import Settings
from handscheck.contracts import Job, Result
from handscheck.contracts.export import default_contracts_dir
from handscheck.worker import job as job_module
from handscheck.worker.client import WorkerAPI, WorkerAPIError
from handscheck.worker.job import execute
from handscheck.worker.loop import run_worker
from tests.agents.conftest import guaranteed_keys
from tests.agents.fake_claude import ScriptedAPI, context, finding, is_verifier, text
from tests.agents.replay import ReplayRunner, replay_services
from tests.public_build import requires_prompts


def make_job(host: str = "lab-wp2", **extra: Any) -> Job:
    agents = [
        {"name": a.name, "version": a.definition.version, "site": None, "settings": {}}
        for a in all_agents().values()
        if a.definition.scope != "org"
    ]
    data: dict[str, Any] = {
        "job_id": "01JOB",
        "task_id": "01TASK",
        "kind": "scan",
        "host": {
            "host_id": "7",
            "name": host,
            "address": host,
            "user": "handscheck",
            "private_key": "not-used-by-the-replay-runner",
        },
        "agents": agents,
        "deadline": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    } | extra
    return Job.model_validate(data)


async def run(job: Job, api: Any = None) -> Result:
    host = job.host.name
    return await execute(
        job, services=replay_services(host), api=api, runner=ReplayRunner.load(host, strict=False)
    )


async def test_scan_job_produces_a_contract_result() -> None:
    result = await run(make_job())
    Result.model_validate(result.model_dump(mode="json"))  # round-trips through the contract
    agents = {s.agent for s in result.snapshots}
    assert {"sites", "system", "users", "persistence", "malware", "wordpress", "exposure"} <= agents
    assert result.job_id == "01JOB" and result.status in ("ok", "partial")
    assert (result.host_key_fingerprint or "").startswith("SHA256:")
    # Without Claude, only what the checks guarantee on lab-wp2, to be verified.
    assert {f.dedupe_key for f in result.findings} == await guaranteed_keys("lab-wp2")
    assert all(f.verification and f.verification.status == "pending" for f in result.findings)
    assert result.reviews == [] and result.claude_cost_usd == 0
    assert any(m.name == "run.duration_s" for m in result.metrics)


async def test_watch_job_runs_only_the_watch_agents_and_skips_open_findings() -> None:
    watch_agents = [
        {"name": a.name, "version": a.definition.version, "site": None, "settings": {}}
        for a in all_agents().values()
        if a.definition.cadence.watch
    ]
    assert {a["name"] for a in watch_agents} == {"activity", "health", "users", "persistence"}
    first = await run(make_job(kind="watch", agents=watch_agents))
    Result.model_validate(first.model_dump(mode="json"))
    assert {s.agent for s in first.snapshots} == {"sites", "activity", "health", "users", "persistence"}
    assert first.reviews == [] and first.claude_cost_usd == 0
    reported = {f.dedupe_key for f in first.findings}
    assert reported and all(
        k.split(":")[0] in ("users", "persistence", "activity", "health") for k in reported
    )
    # What is already open isn't reported again every pass.
    open_findings = [
        {
            "dedupe_key": f.dedupe_key,
            "agent": f.agent,
            "site": f.site,
            "title": f.title,
            "severity": f.severity.value,
            "status": "open",
        }
        for f in first.findings
    ]
    again = await run(make_job(kind="watch", agents=watch_agents, open_findings=open_findings))
    assert again.findings == []


async def test_previous_snapshots_disabled_sites_and_unknown_agents() -> None:
    first = await run(make_job())
    previous = {
        (s.agent if s.site is None else f"{s.agent}@{s.site}"): {
            "agent_version": s.agent_version,
            "facts": s.facts,
            "taken_at": first.finished_at.isoformat(),
        }
        for s in first.snapshots
    }
    job = make_job(previous_snapshots=previous, disabled_sites=["gamma.lab.test"])
    job.agents.append(job.agents[0].model_copy(update={"name": "nonexistent"}))
    second = await run(job)
    assert not second.change_events  # same facts as last time
    assert all(s.site != "gamma.lab.test" for s in second.snapshots)
    assert any("nonexistent is not in this worker's catalog" in e for e in second.errors)


@requires_prompts
async def test_claude_findings_and_reviews_are_reported() -> None:
    def claude(req: dict[str, Any], i: int) -> Any:
        if is_verifier(req):
            return text({"verdict": "confirmed", "reason": "uid 0", "checked": ["/etc/passwd"]})
        found = (
            [finding("uid0_account", "sysbackup", "critical")]
            if context(req).get("agent") == "system"
            else []
        )
        return text({"assessment": "reviewed", "findings": found})

    api = ScriptedAPI(claude)
    job = make_job(options={"use_claude": True, "claude_budget_usd": 2})
    result = await run(job, api)
    [f] = [f for f in result.findings if f.agent == "system" and "sysbackup" in f.dedupe_key]
    assert f.dedupe_key == "system:uid0_account:lab-wp2:-:sysbackup" and f.verification is not None
    assert f.verification.status == "confirmed" and f.confidence == "high"
    assert {(r.agent, r.mode) for r in result.reviews} >= {("system", "baseline")}
    assert all(r.agent != "verifier" for r in result.reviews)
    assert result.claude_cost_usd > 0 and result.claude_input_tokens > 0


async def test_claude_asked_without_credentials_is_reported() -> None:
    result = await run(make_job(options={"use_claude": True, "claude_budget_usd": 1}))
    assert any("no Anthropic credentials" in e for e in result.errors) and result.reviews == []


async def test_unreachable_host_is_a_failed_result(monkeypatch: pytest.MonkeyPatch) -> None:
    from handscheck.ssh.runner import SSHError

    class Down(ReplayRunner):
        async def run(self, *a: Any, **kw: Any) -> Any:
            raise SSHError("connection refused")

    result = await execute(make_job(), services=replay_services("lab-wp2"), api=None, runner=Down({}))
    assert result.status == "failed" and "connection refused" in result.errors[0]


def test_the_job_example_runs_with_this_catalog() -> None:
    example = json.loads((default_contracts_dir() / "examples" / "job.scan.json").read_text())
    job = Job.model_validate(example)
    agents, errors = job_module.agents_for(job)
    assert [a.name for a in agents] == ["system", "malware"] and errors == []
    assert isinstance(job.host.private_key, SecretStr) and "EXAMPLE-NOT-A-REAL-KEY" not in repr(job)


class FakeControlPlane:
    """The worker API side of the contract, enough for the loop."""

    def __init__(self, jobs: list[dict[str, Any]]) -> None:
        self.jobs = jobs
        self.calls: list[tuple[str, str]] = []
        self.results: list[dict[str, Any]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        assert request.headers["Authorization"] == "Bearer tok"
        path = request.url.path.removeprefix("/worker-api/v1")
        if path in ("/heartbeat", "/catalog"):
            return httpx.Response(204)
        if path == "/jobs/lease":
            return httpx.Response(200, json=self.jobs.pop(0)) if self.jobs else httpx.Response(204)
        if path.endswith("/results"):
            self.results.append(json.loads(request.content))
            return httpx.Response(202, json={"run_id": len(self.results)})
        return httpx.Response(404)


async def test_loop_leases_runs_and_posts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_execute(job: Job, **kw: Any) -> Result:
        return await run(job)

    monkeypatch.setattr("handscheck.worker.loop.execute", fake_execute)
    plane = FakeControlPlane(
        [
            make_job().model_dump(mode="json")
            | {"host": make_job().host.model_dump(mode="json") | {"private_key": "k"}}
        ]
    )
    api = WorkerAPI("http://control", "tok", transport=httpx.MockTransport(plane.handler))
    stats = await run_worker(Settings(state_dir=tmp_path), api=api, claude=None, once=True)
    await api.close()
    assert stats.jobs == 1 and stats.failed == 0 and stats.results == [{"run_id": 1}]
    assert plane.calls[:2] == [("POST", "/worker-api/v1/heartbeat"), ("PUT", "/worker-api/v1/catalog")]
    assert plane.results[0]["job_id"] == "01JOB" and "private_key" not in json.dumps(plane.results[0])


async def test_api_errors_are_explicit() -> None:
    api = WorkerAPI(
        "http://control",
        "tok",
        transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"message": "no"})),
    )
    with pytest.raises(WorkerAPIError, match="HTTP 401"):
        await api.lease()
    bad = WorkerAPI(
        "http://control", "tok", transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"x": 1}))
    )
    with pytest.raises(WorkerAPIError, match="not a valid contract Job"):
        await bad.lease()
    await api.close()
    await bad.close()
