from typing import Any

import pytest

from handscheck.agents._framework.check import CheckContext, Facts, Output
from handscheck.agents._framework.registry import all_agents
from handscheck.pipeline.run import HostRun, run_host
from handscheck.sites.discovery import DISCOVERY
from tests.agents.replay import ReplayRunner, replay_services


def defaults(agent: str) -> dict[str, Any]:
    return all_agents()[agent].definition.effective_settings()


def replay_context(host: str, *, sudo_ok: bool = True) -> CheckContext:
    return CheckContext(
        runner=ReplayRunner.load(host),
        host=host,
        address=host,
        sudo_ok=sudo_ok,
        services=replay_services(host),
    )


async def collect_facts(host: str, agent: str, *, site: str | None = None, sudo_ok: bool = True) -> Facts:
    """Run one agent's real collector + parser against a captured lab host (and one of its sites)."""
    check = all_agents()[agent].check
    assert check is not None
    ctx = replay_context(host, sudo_ok=sudo_ok)
    if site is not None:
        inventory = await DISCOVERY.run(ctx, {})
        ctx = ctx.for_site(next(s for s in inventory.sites if s.name == site))
    return await check.run(ctx, defaults(agent))


async def replay_run(host: str, **kwargs: Any) -> HostRun:
    return await run_host(
        ReplayRunner.load(host), host, list(all_agents().values()), services=replay_services(host), **kwargs
    )


def out(stdout: str = "", exit_status: int | None = 0, **kwargs: Any) -> Output:
    return Output(stdout=stdout, exit_status=exit_status, **kwargs)


@pytest.fixture
def system_settings() -> dict[str, Any]:
    return defaults("system")


async def guaranteed_keys(host: str) -> set[str]:
    """Dedupe keys of what the checks guarantee on a captured lab host (a run without Claude)."""
    return {f.finding.dedupe_key for f in (await replay_run(host)).findings}
