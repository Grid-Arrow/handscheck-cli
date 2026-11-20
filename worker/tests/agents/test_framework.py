from pathlib import Path

import pytest

from handscheck.agents._framework.definition import AgentDefinitionError, load_agent, parse_agent_md
from handscheck.agents._framework.registry import UnknownAgent, all_agents, catalog, get_agents
from handscheck.contracts import Catalog
from tests.public_build import requires_prompts

GOOD = """---
name: demo
title: Demo
description: A demo agent.
version: 2
scope: site
cadence: { full: daily, watch: true }
model: claude-haiku-5-5
rules: []
settings:
  ignore_paths: { type: list, items: str, default: [], description: Paths to skip. }
  max_file_kb:  { type: int, default: 512, min: 1, max: 4096 }
  alert_severity: { type: enum, values: [low, medium, high, critical], default: high }
  deep: { type: bool, default: false }
---

# Demo

Look for things.
"""


def parse(text: str = GOOD, folder: str = "demo"):  # type: ignore[no-untyped-def]
    return parse_agent_md(text, Path("/x") / folder)


def test_parses_front_matter_and_instructions() -> None:
    d = parse()
    assert (d.name, d.version, d.scope, d.model) == ("demo", 2, "site", "claude-haiku-5-5")
    assert d.cadence.full == "daily" and d.cadence.watch
    assert d.instructions.startswith("# Demo") and "Look for things." in d.instructions
    assert d.defaults() == {"ignore_paths": [], "max_file_kb": 512, "alert_severity": "high", "deep": False}


def test_effective_settings_merge_and_validate() -> None:
    d = parse()
    merged = d.effective_settings({"max_file_kb": 64, "ignore_paths": ["/var/www/x"]})
    assert merged["max_file_kb"] == 64 and merged["ignore_paths"] == ["/var/www/x"]
    assert merged["alert_severity"] == "high"
    for bad in ({"max_file_kb": 0}, {"max_file_kb": "64"}, {"alert_severity": "urgent"}, {"nope": 1}):
        with pytest.raises(AgentDefinitionError):
            d.effective_settings(bad)


def test_settings_json_schema() -> None:
    schema = parse().settings_json_schema()
    assert schema["type"] == "object" and schema["additionalProperties"] is False
    props = schema["properties"]
    assert props["ignore_paths"] == {
        "type": "array",
        "items": {"type": "string"},
        "default": [],
        "description": "Paths to skip.",
    }
    assert props["max_file_kb"] == {"type": "integer", "default": 512, "minimum": 1, "maximum": 4096}
    assert props["alert_severity"]["enum"] == ["low", "medium", "high", "critical"]
    assert props["deep"] == {"type": "boolean", "default": False}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("no front matter\n", "must start with YAML front matter"),
        (GOOD.replace("# Demo\n\nLook for things.\n", ""), "no instructions"),
        (GOOD.replace("version: 2", "version: 0"), "version"),
        (GOOD.replace("scope: site", "scope: planet"), "scope"),
        (GOOD.replace("name: demo", "name: Demo!"), "invalid agent name"),
        (GOOD.replace("model: claude-haiku-5-5", "model: x\nextra: 1"), "extra"),
        (GOOD.replace("values: [low, medium, high, critical], ", ""), "enum settings need"),
        (GOOD.replace("default: 512", "default: big"), "invalid settings"),
        (GOOD.replace("default: high", "default: urgent"), "invalid settings"),
        (GOOD.replace("full: daily", "full: sometimes"), "cadence"),
        (GOOD.replace("version: 2", "version: [2"), "invalid YAML"),
    ],
)
def test_rejects_broken_agent_md(text: str, message: str) -> None:
    with pytest.raises(AgentDefinitionError, match=message):
        parse(text)


def test_load_agent_checks_folder_name_and_rule_files(tmp_path: Path) -> None:
    folder = tmp_path / "other"
    folder.mkdir()
    (folder / "AGENT.md").write_text(GOOD)
    with pytest.raises(AgentDefinitionError, match="does not match its folder"):
        load_agent(folder)

    folder = tmp_path / "demo"
    folder.mkdir()
    (folder / "AGENT.md").write_text(GOOD.replace("rules: []", "rules: [rules/fingerprints.yaml]"))
    with pytest.raises(AgentDefinitionError, match="does not exist"):
        load_agent(folder)
    (folder / "rules").mkdir()
    (folder / "rules" / "fingerprints.yaml").write_text("[]\n")
    assert load_agent(folder).rule_paths() == [folder / "rules" / "fingerprints.yaml"]


@requires_prompts
def test_shipped_agents_load() -> None:
    agents = all_agents()
    assert set(agents) == {
        "activity",
        "correlator",
        "exposure",
        "health",
        "malware",
        "persistence",
        "system",
        "users",
        "wordpress",
    }
    for agent in agents.values():
        d = agent.definition
        if d.name == "correlator":  # org-wide, Claude only (`hc correlate`)
            assert agent.check is None and d.scope == "org" and d.max_tool_calls == 0
            continue
        assert agent.check is not None and agent.check.name == d.name
        assert d.scope == ("site" if d.name in ("exposure", "malware", "wordpress") else "host")
        if d.name in ("activity", "health"):  # the watch pass: rules only, no Claude review of its own
            assert d.model is None and d.cadence.watch
        else:
            assert d.model == "claude-opus-5-5" and d.effort in ("medium", "high")
        assert d.version >= 1
        assert all(p.is_file() for p in d.rule_paths())
        assert "Known false positives" in d.instructions
        d.effective_settings()  # defaults validate


def test_get_agents_keeps_catalog_order_and_rejects_unknown() -> None:
    assert [a.name for a in get_agents(["users", "system"])] == ["system", "users"]
    assert len(get_agents(None)) == len(all_agents())
    with pytest.raises(UnknownAgent, match="malwar"):
        get_agents(["malwar"])


def test_catalog_matches_the_contract() -> None:
    exported = catalog()
    again = Catalog.model_validate_json(exported.model_dump_json())
    entry = next(a for a in again.agents if a.name == "system")
    assert entry.cadence == "daily" and entry.settings_schema["properties"]["setid_scan"]["type"] == "boolean"


def test_last_lines_keeps_whole_newest_lines_of_a_sized_read() -> None:
    from handscheck.agents._framework.check import last_lines, tail_command

    assert tail_command("/var/log/auth.log") == ["tail", "-c", "4000000", "/var/log/auth.log"]
    full = "tial line cut by tail -c\nline 1\nline 2\nline 3\n"
    assert last_lines(full, 2, max_bytes=len(full)) == "line 2\nline 3\n"
    assert last_lines(full, 10, max_bytes=len(full)) == "line 1\nline 2\nline 3\n"  # partial first dropped
    short = "line 1\nline 2\n"  # the whole (small) log: nothing is partial
    assert last_lines(short, 10, max_bytes=1000) == "line 1\nline 2\n"
    assert last_lines(short, 0) == "" and last_lines("", 5) == ""
