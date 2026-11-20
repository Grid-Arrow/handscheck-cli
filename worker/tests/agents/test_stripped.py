"""Public builds (Track S): stripped prompts load as "no instructions"; no Claude call is made without them.

The first test guards the private repo: every AGENT.md here keeps its real instructions, so a stripped file
never gets committed by accident (scripts/public/export.py writes stripped copies only into an export folder).
"""

from pathlib import Path

import pytest

from handscheck.agents._framework import claude as claude_mod
from handscheck.agents._framework.claude import AgentCall, Budget, NoInstructions, preamble, run_agent
from handscheck.agents._framework.definition import parse_agent_md
from handscheck.agents._framework.findings import FindingOut, strict_schema
from handscheck.agents._framework.stripped import STRIPPED_MARKER
from tests.public_build import requires_prompts

SRC = Path(claude_mod.__file__).resolve().parents[2]


@requires_prompts
def test_this_repo_has_every_prompt() -> None:
    files = sorted(SRC.glob("**/AGENT.md"))
    assert len(files) >= 16
    for path in files:
        definition = parse_agent_md(path.read_text(), path.parent)
        assert len(definition.instructions) > 200, path
    assert len(preamble()) > 200 and STRIPPED_MARKER not in preamble()


def test_stripped_agent_md_loads_without_instructions(tmp_path: Path) -> None:
    text = (SRC / "agents" / "system" / "AGENT.md").read_text()
    front = text.split("\n---", 1)[0] + "\n---\n"
    definition = parse_agent_md(front + STRIPPED_MARKER + "\n", SRC / "agents" / "system")
    assert definition.instructions == "" and definition.name == "system"
    assert definition.settings  # the settings schema is still there (public front matter)


def test_stripped_preamble(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stripped = tmp_path / "PREAMBLE.md"
    stripped.write_text(STRIPPED_MARKER + "\n")
    monkeypatch.setattr(claude_mod, "PREAMBLE_PATH", stripped)
    preamble.cache_clear()
    try:
        assert preamble() == ""
    finally:
        preamble.cache_clear()


class _NoCalls:
    async def create(self, **kwargs: object) -> object:
        raise AssertionError("no Claude call without instructions")


async def test_no_claude_call_without_instructions() -> None:
    call = AgentCall(model="claude-opus-5-5", effort="medium", instructions="", max_tool_calls=0)
    with pytest.raises(NoInstructions, match="no agent instructions"):
        await run_agent(
            _NoCalls(), call, {}, FindingOut, ctx=None, budget=Budget(1), schema=strict_schema(FindingOut)
        )
