"""The Claude stage over a replayed lab host, with a scripted Claude (offline, no cost)."""

import json
from typing import Any

from handscheck.agents._framework.registry import all_agents
from handscheck.agents.malware.check import PREPEND_RULE as PREPEND
from handscheck.pipeline.claude_stage import ClaudeOptions, run_claude_stage
from handscheck.pipeline.run import PreviousSnapshot, run_host, snapshot_key
from tests.agents.conftest import guaranteed_keys
from tests.agents.fake_claude import ScriptedAPI, context, finding, is_verifier, section, text
from tests.agents.replay import ReplayRunner, replay_services
from tests.public_build import requires_prompts

PREPEND_KEY = "malware:prepend_backdoor:lab-wp2:gamma.lab.test:/var/www/gamma.lab.test/.user.ini"


def fake_claude(req: dict[str, Any], i: int) -> Any:
    if is_verifier(req):
        claim = json.loads(section(req, "claim"))
        verdict = "rejected" if "lookalike" in claim["subject"] else "confirmed"
        return text({"verdict": verdict, "reason": "checked", "checked": ["cat /etc/passwd"]})
    ctx = context(req)
    found = []
    if ctx["agent"] == "system":
        found = [
            finding("uid0_account", "sysbackup", "critical"),
            finding("lookalike", "/x/lookalike", "medium"),
        ]
    if ctx["agent"] == "wordpress" and ctx["site"] == "gamma.lab.test":
        found = [finding("rogue_admin", "root", "high"), finding("stale_note", "note", "low")]
    return text({"assessment": f"{ctx['agent']} reviewed", "findings": found})


async def run(host: str, options: ClaudeOptions, previous: dict[str, PreviousSnapshot] | None = None) -> Any:
    agents = {a.name: a for a in all_agents().values()}

    async def post(ctx: Any, r: Any) -> None:
        await run_claude_stage(ctx, r, agents, options)

    return await run_host(
        ReplayRunner.load(host),
        host,
        list(agents.values()),
        services=replay_services(host),
        previous=previous,
        post=post,
    )


@requires_prompts
async def test_baseline_review_with_verifier() -> None:
    api = ScriptedAPI(fake_claude)
    result = await run("lab-wp2", ClaudeOptions(api=api, budget_usd=5))
    assert result.claude
    by_key = {f.finding.dedupe_key: f for f in result.findings}
    claude = {
        "system:uid0_account:lab-wp2:-:sysbackup",
        "system:lookalike:lab-wp2:-:/x/lookalike",
        "wordpress:rogue_admin:lab-wp2:gamma.lab.test:root",
        "wordpress:stale_note:lab-wp2:gamma.lab.test:note",
    }
    # What the checks guarantee is added and verified like the rest, except what the fake Claude already
    # reported under its own key (sysbackup, the `root` admin).
    covered = {
        "system:extra_uid0:lab-wp2:-:sysbackup",
        "wordpress:suspicious_admin:lab-wp2:gamma.lab.test:root",
    }
    guaranteed = await guaranteed_keys("lab-wp2")
    assert covered <= guaranteed and PREPEND_KEY in guaranteed
    assert set(by_key) == claude | (guaranteed - covered)
    status = {k: f.verification.status for k, f in by_key.items()}
    assert status == {
        **dict.fromkeys(guaranteed - covered, "confirmed"),
        "system:uid0_account:lab-wp2:-:sysbackup": "confirmed",
        "system:lookalike:lab-wp2:-:/x/lookalike": "rejected",
        "wordpress:rogue_admin:lab-wp2:gamma.lab.test:root": "confirmed",
        "wordpress:stale_note:lab-wp2:gamma.lab.test:note": "not_required",
    }
    specialists = [
        i for i in result.claude_runs if i.agent not in ("verifier", "activity", "health")
    ]  # activity: no model
    # Every host agent and every site agent on both sites, each once; the correlator has no check.
    assert sorted((i.agent, i.site or "") for i in specialists) == sorted(
        [("persistence", ""), ("system", ""), ("users", "")]
        + [(a, s) for a in ("exposure", "malware", "wordpress") for s in ("delta.lab.test", "gamma.lab.test")]
    )
    assert all(i.mode == "baseline" and i.error is None for i in specialists)
    verifier_requests = [r for r in api.requests if is_verifier(r)]
    assert len(verifier_requests) == 3 + len(guaranteed - covered)
    # The verifier sees the claim and evidence, not the specialist's reasoning.
    assert all("summary" not in r["messages"][0]["content"] for r in verifier_requests)
    metrics = {m.name: m.value for m in result.metrics}
    assert (
        metrics["findings.confirmed"] == 2 + len(guaranteed - covered) and metrics["findings.rejected"] == 1
    )
    assert metrics["claude.calls"] == len(api.requests) and metrics["claude.cost_usd"] > 0
    # Secrets never leave: nothing that looks like a password hash or key in any request.
    blob = json.dumps([r["messages"][0]["content"] for r in api.requests])
    assert "BEGIN OPENSSH PRIVATE KEY" not in blob


@requires_prompts
async def test_agents_only_run_on_changed_facts() -> None:
    first = await run("lab-wp2", ClaudeOptions(api=ScriptedAPI(fake_claude)))
    previous = {
        snapshot_key(s.agent, s.site): PreviousSnapshot(version=s.agent_version, facts=s.facts)
        for s in first.snapshots()
    }
    # What the checks guarantee is open since the first run: not reported (nor verified) again.
    still_open = [
        {"dedupe_key": f.finding.dedupe_key, "agent": f.finding.agent, "site": f.finding.site}
        for f in first.findings
    ]
    api = ScriptedAPI(fake_claude)
    second = await run("lab-wp2", ClaudeOptions(api=api, open_findings=still_open), previous)
    assert api.requests == [] and second.findings == []
    assert all(
        i.mode == "skipped" and i.reason == "no changes since the last run" for i in second.claude_runs
    )

    previous["system"].facts["uid0_accounts"] = ["root"]  # pretend sysbackup is new
    api = ScriptedAPI(fake_claude)
    third = await run("lab-wp2", ClaudeOptions(api=api), previous)
    ran = [i for i in third.claude_runs if i.mode != "skipped" and i.agent != "verifier"]
    assert [(i.agent, i.mode) for i in ran] == [("system", "changes")]
    changes = json.loads(section(api.requests[0], "changes"))
    assert {"collection": "uid0_accounts", "key": "sysbackup", "op": "added"}.items() <= changes[0].items()


@requires_prompts
async def test_a_deep_review_from_the_plan_reads_all_facts_without_changes() -> None:
    first = await run("lab-wp2", ClaudeOptions(api=ScriptedAPI(fake_claude)))
    previous = {
        snapshot_key(s.agent, s.site): PreviousSnapshot(version=s.agent_version, facts=s.facts)
        for s in first.snapshots()
    }
    api = ScriptedAPI(fake_claude)
    options = ClaudeOptions(
        api=api,
        deep={"system": frozenset(), "wordpress": frozenset({"gamma.lab.test"})},
        deep_reasons={"system": "a root account appeared last week"},
    )
    second = await run("lab-wp2", options, previous)
    ran = sorted(
        (i.agent, i.site, i.mode) for i in second.claude_runs if i.mode != "skipped" and i.agent != "verifier"
    )
    assert ran == [("system", None, "deep"), ("wordpress", "gamma.lab.test", "deep")]  # not delta
    system = next(r for r in api.requests if context(r).get("agent") == "system")
    assert "Deep review" in section(system, "task") and section(system, "facts")
    assert "a root account" in section(system, "plan_reason") and section(system, "changes") == ""


async def test_baseline_review_off_and_budget() -> None:
    api = ScriptedAPI(fake_claude)
    off = await run("lab-wp2", ClaudeOptions(api=api, baseline_review=False))
    assert all(i.mode == "skipped" for i in off.claude_runs if i.agent != "verifier")
    # No specialist ran, but what the checks guarantee is new: reported and verified.
    assert all(is_verifier(r) for r in api.requests)
    assert {f.finding.dedupe_key for f in off.findings} == await guaranteed_keys("lab-wp2")
    assert any(PREPEND in f.finding.rule_ids for f in off.findings)
    broke = await run("lab-wp2", ClaudeOptions(api=ScriptedAPI(fake_claude), budget_usd=0))
    assert all(
        i.mode == "skipped" and "budget" in (i.reason or "")
        for i in broke.claude_runs
        if i.agent not in ("activity", "health")
    )


@requires_prompts
async def test_api_errors_are_reported_per_agent() -> None:
    import anthropic
    import httpx

    def failing(req: dict[str, Any], i: int) -> Any:
        if context(req).get("agent") == "users":
            raise anthropic.APIConnectionError(request=httpx.Request("POST", "https://api.anthropic.com"))
        return fake_claude(req, i)

    result = await run("lab-wp2", ClaudeOptions(api=ScriptedAPI(failing)))
    users = next(i for i in result.claude_runs if i.agent == "users")
    assert users.error and "APIConnectionError" in users.error
    assert any(f.finding.agent == "system" for f in result.findings)


def test_observed_facts_for_the_verifier() -> None:
    from handscheck.pipeline.claude_stage import observed_facts

    facts = {
        "administrators": [
            {"ID": 1, "user_login": "admin", "user_email": "admin@example.test"},
            {"ID": 3, "user_login": "tempuser_8f3a", "user_email": "t@example.test"},
        ],
        "plugins": [{"slug": "revslider", "version": "4.1.4"}],
        "php_in_uploads": ["/var/www/a/wp-content/uploads/2026/10/cache.php"],
        "note": "unrelated",
    }
    assert observed_facts(facts, "tempuser_8f3a") == [
        {"path": "administrators[1]", "value": facts["administrators"][1]}
    ]
    assert observed_facts(facts, "revslider")[0]["path"] == "plugins[0]"
    assert observed_facts(facts, "/var/www/a/wp-content/uploads/2026/10/cache.php") == [
        {"path": "php_in_uploads[0]", "value": "/var/www/a/wp-content/uploads/2026/10/cache.php"}
    ]
    # Short subjects only match exactly; nothing for unknown subjects or missing facts.
    assert observed_facts(facts, "ad") == [] and observed_facts(facts, "nobody") == []
    assert observed_facts(None, "revslider") == []
