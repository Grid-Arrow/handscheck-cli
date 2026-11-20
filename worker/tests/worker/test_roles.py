"""Role-agent jobs (verify, investigate, triage, compose) offline: scripted Claude, replayed lab output."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from handscheck.config import Settings
from handscheck.contracts import Job, Result
from handscheck.contracts.export import default_contracts_dir
from handscheck.ssh.runner import SSHError
from handscheck.worker.client import WorkerAPI
from handscheck.worker.job import execute, supported_kinds
from handscheck.worker.loop import run_worker
from tests.agents.fake_claude import ScriptedAPI, finding, is_verifier, section, text, tool
from tests.agents.replay import ReplayRunner, replay_services
from tests.public_build import requires_prompts

EXAMPLES = default_contracts_dir() / "examples"


def example(name: str, **changes: Any) -> Job:
    data = json.loads((EXAMPLES / f"{name}.json").read_text())
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key] = data[key] | value
        else:
            data[key] = value
    return Job.model_validate(data)


async def run(job: Job, api: Any = None, runner: Any = None) -> Result:
    result = await execute(
        job,
        services=replay_services("lab-wp2"),
        api=api,
        runner=runner if runner is not None else ReplayRunner.load("lab-wp2", strict=False),
    )
    Result.model_validate(result.model_dump(mode="json"))
    return result


def test_role_kinds_need_claude() -> None:
    # A remediate job needs no Claude: any worker can apply an approved fix. Recon works without Claude too
    # (code's proposals only); the planner doesn't.
    assert supported_kinds(claude=False) == ["scan", "watch", "remediate", "recon"]
    assert set(supported_kinds(claude=True)) == {
        "scan",
        "watch",
        "remediate",
        "recon",
        "plan",
        "verify",
        "investigate",
        "triage",
        "compose",
        "explain",
    }


def test_role_sections_are_tied_to_the_kind() -> None:
    with pytest.raises(ValueError, match="`verify` section"):
        example("job.verify", kind="triage")
    with pytest.raises(ValueError, match="need `host`"):
        example("job.investigate", host=None)


@requires_prompts
async def test_verify_job_returns_a_verdict_per_finding() -> None:
    def claude(req: dict[str, Any], i: int) -> Any:
        assert is_verifier(req)
        if i == 0:
            return tool("grep -n :0:0: /etc/passwd")
        assert "uid0_users" in section(req, "observed_facts") or "sysbackup" in section(req, "evidence")
        return text({"verdict": "confirmed", "reason": "second uid 0", "checked": ["/etc/passwd"]})

    api = ScriptedAPI(claude)
    result = await run(example("job.verify"), api)
    [verdict] = result.verdicts
    assert verdict.finding_id == "41" and verdict.status == "confirmed" and verdict.verifier_version == 2
    assert result.status == "ok" and result.claude_cost_usd > 0
    assert "summary" not in section(api.requests[0], "claim")  # the claim, not the specialist's reasoning
    assert api.requests[0]["tools"]  # host given: the read-only tool is offered


@requires_prompts
async def test_verify_without_a_host_has_no_tool() -> None:
    api = ScriptedAPI(
        lambda req, i: text({"verdict": "needs_more", "reason": "can't read it", "checked": []})
    )
    result = await run(example("job.verify", host=None), api)
    assert result.verdicts[0].status == "needs_more" and api.requests[0]["tools"] == []


async def test_verify_errors_become_error_verdicts() -> None:
    no_claude = await run(example("job.verify"), api=None)
    assert no_claude.status == "failed" and no_claude.verdicts[0].status == "error"
    assert "no Anthropic credentials" in no_claude.verdicts[0].reason

    no_budget = await run(
        example("job.verify", options={"use_claude": False}), ScriptedAPI(lambda r, i: 1 / 0)
    )
    assert "budget" in no_budget.verdicts[0].reason

    class Down(ReplayRunner):
        async def run(self, *a: Any, **kw: Any) -> Any:
            raise SSHError("connection refused")

        async def close(self) -> None:
            self.closed = True

    down = Down({})
    unreachable = await run(example("job.verify"), ScriptedAPI(lambda r, i: 1 / 0), runner=down)
    assert unreachable.status == "failed" and "host unreachable" in unreachable.verdicts[0].reason
    assert down.closed


@requires_prompts
async def test_triage_job_keeps_valid_decisions_only() -> None:
    def claude(req: dict[str, Any], i: int) -> Any:
        assert req["tools"] == [] and "You triage findings" in req["system"][0]["text"]
        decision = {
            "finding_id": "41",
            "severity": "critical",
            "action": "alert",
            "reason": "root backdoor",
            "related": ["users:new_account:lab-wp1:-:sysbackup", "made:up:key"],
            "follow_ups": [{"question": f"q{n}", "reason": "r"} for n in range(4)],
        }
        return text({"decisions": [decision, decision | {"finding_id": "999"}]})

    result = await run(example("job.triage"), ScriptedAPI(claude))
    [d] = result.triage
    assert d.action == "alert" and d.related == ["users:new_account:lab-wp1:-:sysbackup"]
    assert [f.question for f in d.follow_ups] == ["q0", "q1"]  # at most two
    assert result.status == "partial" and "999" in result.errors[0]

    at_limit = example("job.triage")
    assert at_limit.triage is not None
    at_limit.triage.chain.depth = 3
    capped = await run(at_limit, ScriptedAPI(claude))
    assert capped.triage[0].follow_ups == []  # depth limit, whatever Claude says


async def test_triage_claude_failure_is_a_failed_result() -> None:
    result = await run(example("job.triage"), ScriptedAPI(lambda r, i: text("not json")))
    assert result.status == "failed" and result.triage == [] and "triage" in result.errors[0]


@requires_prompts
async def test_compose_job_writes_one_message_per_alert() -> None:
    def claude(req: dict[str, Any], i: int) -> Any:
        assert req["tools"] == []
        return text({"messages": [{"alert_id": "7", "subject": " [Critical] x ", "body": "body"}]})

    result = await run(example("job.compose"), ScriptedAPI(claude))
    assert [(m.alert_id, m.subject) for m in result.messages] == [("7", "[Critical] x")]

    missing = await run(example("job.compose"), ScriptedAPI(lambda r, i: text({"messages": []})))
    assert missing.status == "partial" and "no message for alert(s) 7" in missing.errors[0]


@requires_prompts
async def test_investigate_job_reports_findings_for_verification() -> None:
    def claude(req: dict[str, Any], i: int) -> Any:
        assert "sysbackup" in section(req, "question")
        return text(
            {
                "answer": "created by root after a login from 203.0.113.9",
                "findings": [
                    finding("ssh_login", "203.0.113.9", "high"),
                    finding("note", "x", "low"),
                ],
            }
        )

    result = await run(example("job.investigate"), ScriptedAPI(claude))
    assert result.investigation is not None and "203.0.113.9" in result.investigation.answer
    statuses = {f.dedupe_key: f.verification.status for f in result.findings if f.verification}
    assert statuses == {
        "investigator:ssh_login:lab-wp2:-:203.0.113.9": "pending",
        "investigator:note:lab-wp2:-:x": "not_required",
    }


async def test_loop_leases_only_the_kinds_it_can_run(tmp_path: Path) -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/jobs/lease"):
            bodies.append(json.loads(request.content))
        return httpx.Response(204)

    api = WorkerAPI("http://control", "tok", transport=httpx.MockTransport(handler))
    await run_worker(Settings(state_dir=tmp_path), api=api, claude=None, once=True)
    await run_worker(Settings(state_dir=tmp_path), api=api, claude=ScriptedAPI(lambda r, i: None), once=True)
    await api.close()
    assert bodies[0]["kinds"] == ["scan", "watch", "remediate", "recon"] and "verify" in bodies[1]["kinds"]


@requires_prompts
async def test_explain_job_writes_the_team_message() -> None:
    def claude(req: dict[str, Any], i: int) -> Any:
        assert req["tools"] == [] and "handscheck team" in req["system"][0]["text"]
        assert "nyc3-1" in section(req, "issues")
        return text(
            {"messages": [{"alert_id": "16", "subject": " Worker nyc3-1 silent ", "body": "check systemd"}]}
        )

    result = await run(example("job.explain"), ScriptedAPI(claude))
    assert [(m.alert_id, m.subject) for m in result.messages] == [("16", "Worker nyc3-1 silent")]
    assert result.status == "ok"

    wrong = await run(example("job.explain"), ScriptedAPI(lambda r, i: text({"messages": []})))
    assert wrong.messages == [] and "no message for 16" in wrong.errors[0]
