"""Findings lifecycle and the M4 commands (check with agents, findings, investigate, correlate, report),
offline:
SSH is replayed from the lab captures and Claude is scripted."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from handscheck.cli import app
from handscheck.standalone import service
from tests.agents.conftest import guaranteed_keys
from tests.agents.fake_claude import ScriptedAPI, context, finding, is_verifier, section, text, tool
from tests.agents.replay import ReplayRunner
from tests.public_build import requires_prompts
from tests.standalone.test_checks import _Checksums, _Http

cli = CliRunner()
STATE: dict[str, Any] = {"system": [finding("uid0_account", "sysbackup", "critical")]}


def claude(req: dict[str, Any], i: int) -> Any:
    if is_verifier(req):
        return text({"verdict": "confirmed", "reason": "uid 0 in /etc/passwd", "checked": ["/etc/passwd"]})
    if "<question>" in req["messages"][0]["content"]:
        if len(req["messages"]) == 1:
            return tool("cat /etc/passwd")
        return text(
            {
                "answer": "sysbackup is a second root account.",
                "findings": [finding("uid0_account", "sysbackup", "critical")],
            }
        )
    if "<hosts>" in req["messages"][0]["content"]:
        return text({"assessment": "one campaign", "findings": [finding("shared_admin", "root", "high")]})
    agent = context(req).get("agent")
    return text({"assessment": "reviewed", "findings": STATE.get(agent, [])})


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ScriptedAPI:
    monkeypatch.setenv("HANDSCHECK_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-used")
    key = tmp_path / "key"
    key.write_text("unused\n")
    monkeypatch.setattr(service, "SSHRunner", lambda target, **kw: ReplayRunner.load(target.address))
    monkeypatch.setattr(service, "HttpxProber", _Http)
    monkeypatch.setattr(service, "WordPressOrgChecksums", _Checksums)
    api = ScriptedAPI(claude)

    async def close() -> None:
        return None

    monkeypatch.setattr(
        service, "new_client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=api), close=close)
    )
    STATE.clear()
    STATE["system"] = [finding("uid0_account", "sysbackup", "critical")]
    for host in ("lab-wp1", "lab-wp2"):
        assert cli.invoke(app, ["host", "add", host, "--address", host, "--key", str(key)]).exit_code == 0
    return api


def check(*args: str) -> dict[str, Any]:
    result = cli.invoke(app, ["check", *args, "--json"])
    assert result.exit_code == 0, result.output
    outcomes: list[dict[str, Any]] = json.loads(result.output)
    return outcomes[0]


def findings(*args: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = json.loads(cli.invoke(app, ["findings", "list", *args, "--json"]).output)
    return out


KEY = "system:uid0_account:lab-wp2:-:sysbackup"
GUARANTEED = asyncio.run(guaranteed_keys("lab-wp2")) - {"system:extra_uid0:lab-wp2:-:sysbackup"}
"""What the checks guarantee from lab-wp2's facts, less sysbackup (the fake Claude reports it as KEY)."""


def system_findings(*args: str) -> list[dict[str, Any]]:
    return [f for f in findings(*args) if f["dedupe_key"] == KEY]


@requires_prompts
def test_lifecycle(env: ScriptedAPI) -> None:
    first = check("--host", "lab-wp2")
    assert first["finding_status"] == {KEY: "new", **dict.fromkeys(GUARANTEED, "new")}
    [f] = system_findings()
    assert f["status"] == "new" and f["data"]["verification"]["status"] == "confirmed"

    # Nothing changed: no Claude calls, the finding stays as it was.
    calls = len(env.requests)
    check("--host", "lab-wp2")
    assert len(env.requests) == calls and system_findings()[0]["status"] == "new"

    acked = json.loads(
        cli.invoke(app, ["findings", "ack", "system:uid0", "--note", "on it", "--json"]).output
    )
    assert acked["status"] == "acknowledged" and acked["note"] == "on it"
    shown = cli.invoke(app, ["findings", "show", KEY])
    assert "sysbackup" in shown.output and "confirmed" in shown.output

    # Marking it resolved closes it (an agent reporting it again reopens it).
    STATE["system"] = []
    cli.invoke(app, ["findings", "resolve", KEY])
    assert system_findings() == [] and system_findings("--all")[0]["status"] == "resolved"
    fp = json.loads(cli.invoke(app, ["findings", "false-positive", KEY, "--json"]).output)
    assert fp["status"] == "false_positive"
    ambiguous = cli.invoke(app, ["findings", "show", "nope", "--json"])
    assert ambiguous.exit_code == 1 and "no finding" in json.loads(ambiguous.output)["error"]


@requires_prompts
def test_baseline_review_resolves_what_is_gone(env: ScriptedAPI) -> None:
    from handscheck.config import get_settings
    from handscheck.standalone.state import StandaloneState

    check("--host", "lab-wp2")
    STATE["system"] = []
    state = StandaloneState.open(get_settings().state_dir)
    # Simulate an agent version bump: drop the system snapshot so the next run is a baseline review.
    with state._db() as db:
        db.execute("DELETE FROM snapshots WHERE agent = 'system'")
    second = check("system", "--host", "lab-wp2")
    assert second["resolved"] == [KEY]
    assert system_findings() == []


@requires_prompts
def test_human_output_and_no_agents(env: ScriptedAPI) -> None:
    result = cli.invoke(app, ["check", "--host", "lab-wp2"])
    assert result.exit_code == 0, result.output
    assert "critical" in result.output and "confirmed" in result.output and "Claude:" in result.output
    calls = len(env.requests)
    plain = cli.invoke(app, ["check", "--host", "lab-wp1", "--no-agents"])
    assert plain.exit_code == 0 and len(env.requests) == calls and "Claude:" not in plain.output


def test_claude_needs_a_key(env: ScriptedAPI, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    result = cli.invoke(app, ["check", "--host", "lab-wp2", "--json"])
    assert result.exit_code == 1 and "ANTHROPIC_API_KEY" in json.loads(result.output)["error"]


@requires_prompts
def test_investigate(env: ScriptedAPI) -> None:
    check("--host", "lab-wp2", "--no-agents")
    invoked = cli.invoke(app, ["investigate", "who is sysbackup?", "--host", "lab-wp2", "--json"])
    assert invoked.exit_code == 0, (invoked.output, repr(invoked.exception))
    result = json.loads(invoked.output)
    assert (
        result["answer"].startswith("sysbackup is")
        and result["tool_calls"][0]["command"] == "cat /etc/passwd"
    )
    assert result["finding_status"] == {"investigator:uid0_account:lab-wp2:-:sysbackup": "new"}
    question_request = next(r for r in env.requests if "<question>" in r["messages"][0]["content"])
    assert section(question_request, "question") == "who is sysbackup?"


@requires_prompts
def test_correlate_and_report(env: ScriptedAPI, tmp_path: Path) -> None:
    check("--host", "lab-wp2")
    check("--host", "lab-wp1", "--no-agents")
    result = json.loads(cli.invoke(app, ["correlate", "--json"]).output)
    assert result["hosts"] == ["lab-wp1", "lab-wp2"]
    assert list(result["finding_status"]) == ["correlator:shared_admin:*:-:root"]
    request = next(r for r in env.requests if "<hosts>" in r["messages"][0]["content"])
    assert request["tools"] == [] and "wordpress_admins" in section(request, "hosts")

    md = tmp_path / "report.md"
    out = cli.invoke(app, ["report", "--markdown", str(md)])
    assert out.exit_code == 0, out.output
    text_md = md.read_text()
    # 8 critical on lab-wp2: sysbackup (Claude) and 7 the checks guarantee.
    assert "## lab-wp2" in text_md and "## Across hosts" in text_md and "8 critical" in text_md
    assert "| critical |" in text_md and "### Trend (recent runs)" in text_md
    data = json.loads(cli.invoke(app, ["report", "--host", "lab-wp2", "--json"]).output)
    assert data["hosts"][0]["host"] == "lab-wp2" and data["totals"]["critical"] == 8
