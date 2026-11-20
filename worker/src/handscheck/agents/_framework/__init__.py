"""The agent framework: `AGENT.md` loader, the check interface (collect → parse → Facts) and the registry."""

from handscheck.agents._framework.check import Check, CheckContext, Facts, Output
from handscheck.agents._framework.definition import AgentDefinition, AgentDefinitionError, load_agent
from handscheck.agents._framework.registry import Agent, UnknownAgent, all_agents, catalog, get_agents

__all__ = [
    "Agent",
    "AgentDefinition",
    "AgentDefinitionError",
    "Check",
    "CheckContext",
    "Facts",
    "Output",
    "UnknownAgent",
    "all_agents",
    "catalog",
    "get_agents",
    "load_agent",
]
