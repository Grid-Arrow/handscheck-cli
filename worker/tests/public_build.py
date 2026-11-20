"""Is this the public build? The public repo (Grid-Arrow/handscheck-cli) is an export of the private monorepo
without the prompts and with example rules only (scripts/public/export.py there). Tests that need either are
marked and skip themselves in the public build; the captured lab replays there lack the commands that carried
private rule data, so a replay answers those like a missing file instead of failing.
"""

import pytest

from handscheck.agents._framework.claude import preamble
from handscheck.agents._framework.registry import all_agents

PUBLIC_BUILD_PROMPTS = not preamble()
PUBLIC_BUILD_RULES = any(
    path.read_text().lstrip().startswith("# Example rule file")
    for agent in all_agents().values()
    for path in agent.definition.rule_paths()
)
requires_prompts = pytest.mark.skipif(PUBLIC_BUILD_PROMPTS, reason="public build: no agent prompts")
requires_rules = pytest.mark.skipif(PUBLIC_BUILD_RULES, reason="public build: example rules only")
