"""The planner (M7c) offline: a scripted Claude's plan is kept only within what the job allows."""

from __future__ import annotations

from typing import Any

from tests.agents.fake_claude import ScriptedAPI, section, text
from tests.public_build import requires_prompts
from tests.worker.test_roles import example, run


def item(agent: str, depth: str = "deep", site: str | None = None, **settings: str) -> dict[str, Any]:
    return {
        "agent": agent,
        "site": site,
        "depth": depth,
        "settings": [{"field": k, "value_json": v} for k, v in settings.items()],
        "reason": f"{agent} because",
    }


@requires_prompts
async def test_plan_keeps_what_the_job_allows() -> None:
    def claude(req: dict[str, Any], i: int) -> Any:
        assert req["tools"] == [] and "You plan the next daily scan" in req["system"][0]["text"]
        assert "sysbackup" in section(req, "signals")
        return text(
            {
                "summary": "Look again for anything planted.",
                "items": [
                    item("malware", site="gamma.lab.test", max_extensionless_files="5000"),
                    item("system"),
                    item("wordpress"),  # not one of this host's agents in the job
                    item("malware", site="nope.test"),
                    item("system", "normal"),  # nothing changed: dropped
                    item("malware", min_siblings='"many"'),
                ],
            }
        )

    result = await run(example("job.plan"), ScriptedAPI(claude))
    p = result.plan
    assert p is not None and p.summary == "Look again for anything planted."
    assert [(i.agent, i.site, i.depth, i.settings) for i in p.items] == [
        ("malware", "gamma.lab.test", "deep", {"max_extensionless_files": 5000}),
        ("system", None, "deep", {}),
    ]
    assert result.status == "partial" and len(result.errors) == 3


@requires_prompts
async def test_plan_caps_deep_items_and_needs_claude() -> None:
    job = example("job.plan")
    assert job.plan is not None
    job.plan.max_deep = 1
    answer = {"summary": "s", "items": [item("system"), item("malware")]}
    result = await run(job, ScriptedAPI(lambda r, i: text(answer, model="claude-haiku-5-5")))
    assert result.plan is not None and [i.agent for i in result.plan.items] == ["system"]
    assert "at most 1" in result.errors[0]

    off = await run(example("job.plan", options={"use_claude": False}))
    assert off.status == "failed" and off.plan is None
