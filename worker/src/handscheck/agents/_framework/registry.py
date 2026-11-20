"""The agents shipped with this worker: one folder per agent under `handscheck/agents/` with an `AGENT.md`.

An agent with a deterministic check has a `check.py` exposing `CHECK` (a `Check` subclass). The registry also
builds the agent catalog the worker reports to the control plane (`hc agents export`).
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from handscheck import __version__
from handscheck.agents._framework.check import Check, Facts
from handscheck.agents._framework.definition import AGENT_FILE, AgentDefinition, load_agent
from handscheck.contracts import AgentCatalogEntry, Catalog

AGENTS_DIR = Path(__file__).resolve().parents[1]


class UnknownAgent(Exception):
    pass


@dataclass(frozen=True)
class Agent:
    definition: AgentDefinition
    check: Check[Any] | None

    @property
    def name(self) -> str:
        return self.definition.name

    def catalog_entry(self) -> AgentCatalogEntry:
        d = self.definition
        return AgentCatalogEntry(
            name=d.name,
            title=d.title,
            description=d.description,
            version=d.version,
            scope=d.scope,
            cadence=d.cadence.full,
            watch=d.cadence.watch,
            model=d.model,
            settings_schema=d.settings_json_schema(),
        )


def _load(folder: Path) -> Agent:
    definition = load_agent(folder)
    check: Check[Facts] | None = None
    if (folder / "check.py").is_file():
        module = importlib.import_module(f"handscheck.agents.{folder.name}.check")
        check = module.CHECK()
        if check is not None and check.name != definition.name:
            raise ValueError(f"{folder}/check.py: CHECK.name {check.name!r} != {definition.name!r}")
    return Agent(definition=definition, check=check)


@cache
def all_agents() -> dict[str, Agent]:
    """Every agent, sorted by name. Raises AgentDefinitionError if any AGENT.md is broken."""
    folders = sorted(
        p
        for p in AGENTS_DIR.iterdir()
        if p.is_dir() and not p.name.startswith("_") and (p / AGENT_FILE).is_file()
    )
    return {folder.name: _load(folder) for folder in folders}


def get_agents(names: list[str] | None = None) -> list[Agent]:
    """The named agents (all when empty), in catalog order. Raises UnknownAgent."""
    agents = all_agents()
    if not names:
        return list(agents.values())
    unknown = [n for n in names if n not in agents]
    if unknown:
        raise UnknownAgent(f"unknown agent(s): {', '.join(unknown)} (known: {', '.join(agents)})")
    return [agents[n] for n in agents if n in names]


def catalog() -> Catalog:
    return Catalog(worker_version=__version__, agents=[a.catalog_entry() for a in all_agents().values()])
