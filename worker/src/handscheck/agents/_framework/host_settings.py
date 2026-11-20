"""Per-host agent settings (M7c): what recon may propose and the planner may override, checked against each
agent's settings schema in `AGENT.md`. The control plane checks them again against the catalog it stores.
"""

from __future__ import annotations

import json
from typing import Any

from handscheck.agents._framework.definition import AgentDefinition, AgentDefinitionError
from handscheck.contracts import SettingChange
from handscheck.ssh.policy import DEFAULT_SUDO_USERS

CORE_AGENTS = frozenset({"system", "users", "persistence"})
"""Host checks that always run: recon can't propose turning them off (the control plane refuses it too)."""

WP_CLI_USERS = DEFAULT_SUDO_USERS - {"root"}
"""Accounts wp-cli may run as: the command policy (and our sudoers rule) allow `sudo -u www-data` only."""


def check_overrides(definition: AgentDefinition, overrides: dict[str, Any]) -> str | None:
    """None when the overrides are valid for the agent, otherwise why not."""
    unknown = sorted(set(overrides) - set(definition.settings))
    if unknown:
        return f"{definition.name}: unknown setting(s) {', '.join(unknown)}"
    try:
        definition.effective_settings(overrides)
    except AgentDefinitionError as exc:
        return str(exc)
    return None


def validate_change(
    change: SettingChange, definitions: dict[str, AgentDefinition]
) -> tuple[SettingChange | None, str | None]:
    """(the change with no-op overrides removed, None) or (None, why it was dropped)."""
    d = definitions.get(change.agent)
    if d is None:
        return None, f"unknown agent {change.agent!r}"
    if change.enabled is False and change.agent in CORE_AGENTS:
        return None, f"{change.agent} always runs (it can't be turned off)"
    problem = check_overrides(d, change.settings)
    if problem is not None:
        return None, problem
    wp_cli = change.settings.get("wp_cli_user")
    if wp_cli is not None and wp_cli not in WP_CLI_USERS:
        return (
            None,
            f"{change.agent}: wp-cli can only run as {', '.join(sorted(WP_CLI_USERS))} (command policy)",
        )
    defaults = d.defaults()
    settings = {k: v for k, v in change.settings.items() if v != defaults.get(k)}
    if change.enabled is None and not settings:
        return None, f"{change.agent}: nothing differs from the defaults"
    return change.model_copy(update={"settings": settings}), None


def decode_values(pairs: list[tuple[str, str]]) -> tuple[dict[str, Any], list[str]]:
    """Claude returns settings as (field, JSON-encoded value) pairs (structured output has no free-form
    objects). Returns the decoded settings and the fields that weren't valid JSON."""
    out: dict[str, Any] = {}
    bad: list[str] = []
    for key, raw in pairs:
        try:
            out[key] = json.loads(raw)
        except ValueError:
            bad.append(key)
    return out, bad
