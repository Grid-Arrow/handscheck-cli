"""`AGENT.md` loader: YAML front matter (name, version, scope, cadence, model, rules, settings) and the
instructions.

The front matter is validated strictly; a broken `AGENT.md` fails at load time (and in the unit tests), never
halfway through a scan. The settings schema is a compact, user-facing description of what may be tuned:

    settings:
      ignore_paths:   { type: list, items: str, default: [], description: "..." }
      max_file_kb:    { type: int,  default: 512, min: 1 }
      alert_severity: { type: enum, values: [low, medium, high, critical], default: high }

It is exported as a JSON Schema (`settings_json_schema`) for the agent catalog, so the control plane can draw
a form and validate stored overrides (opis/json-schema) without reading the repo. `effective_settings()`
merges overrides over the defaults and validates them the same way here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    create_model,
    field_validator,
    model_validator,
)

from handscheck.agents._framework.rules import shared_rules_dir
from handscheck.agents._framework.stripped import STRIPPED_MARKER

AGENT_FILE = "AGENT.md"
SHARED_PREFIX = "shared:"
_NAME = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_FRONT_MATTER = re.compile(r"\A---[ \t]*\n(.*?)\n---[ \t]*\n?(.*)\Z", re.DOTALL)

Scope = Literal["host", "site", "org"]
SettingType = Literal["str", "int", "float", "bool", "enum", "list"]
ItemType = Literal["str", "int"]
CadenceFull = Literal["hourly", "daily", "weekly"]


class AgentDefinitionError(Exception):
    """An AGENT.md that can't be loaded (bad front matter, unknown field, bad default, missing rule file)."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SettingSpec(_Strict):
    type: SettingType
    default: Any
    description: str = ""
    values: list[str] | None = None
    """Allowed values (enum only)."""
    items: ItemType | None = None
    """Item type (list only; default str)."""
    min: float | None = None
    max: float | None = None

    @model_validator(mode="after")
    def _consistent(self) -> SettingSpec:
        if self.type == "enum" and not self.values:
            raise ValueError("enum settings need `values`")
        if self.type != "enum" and self.values is not None:
            raise ValueError("`values` is only for enum settings")
        if self.type != "list" and self.items is not None:
            raise ValueError("`items` is only for list settings")
        if (self.min is not None or self.max is not None) and self.type not in ("int", "float"):
            raise ValueError("`min`/`max` are only for int and float settings")
        return self

    def python_type(self) -> Any:
        if self.type == "enum":
            assert self.values is not None  # noqa: S101 - checked in _consistent
            return Literal[tuple(self.values)]
        if self.type == "list":
            return list[int] if self.items == "int" else list[str]
        return {"str": str, "int": int, "float": float, "bool": bool}[self.type]

    def json_schema(self) -> dict[str, Any]:
        schema: dict[str, Any] = {"default": self.default}
        if self.description:
            schema["description"] = self.description
        if self.type == "enum":
            schema.update(type="string", enum=list(self.values or []))
        elif self.type == "list":
            schema.update(type="array", items={"type": "integer" if self.items == "int" else "string"})
        else:
            schema["type"] = {"str": "string", "int": "integer", "float": "number", "bool": "boolean"}[
                self.type
            ]
        if self.min is not None:
            schema["minimum"] = self.min
        if self.max is not None:
            schema["maximum"] = self.max
        return schema


class Cadence(_Strict):
    full: CadenceFull = "daily"
    watch: bool = False
    """Whether the agent also runs in the 15-60 min watch pass (M7)."""


class AgentDefinition(_Strict):
    name: str
    title: str
    description: str
    version: int = Field(ge=1)
    """Bump on any change to the prompt, check or rules (CLAUDE.md checklist)."""
    scope: Scope
    cadence: Cadence = Cadence()
    model: str | None = None
    """Claude model for the agent run (M4). None = deterministic only."""
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "medium"
    """Claude effort for the agent run."""
    max_tool_calls: int = Field(default=12, ge=0, le=50)
    """Cap on `run_readonly` calls per agent run."""
    rules: list[str] = Field(default_factory=list)
    """Rule files relative to the agent folder, or `shared:<file>` in worker/rules/."""
    settings: dict[str, SettingSpec] = Field(default_factory=dict)
    instructions: str
    """The Markdown body: the instructions given to Claude. "" in a public build (prompts stripped)."""
    path: Path
    """The agent folder."""

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _NAME.match(value):
            raise ValueError(f"invalid agent name {value!r}")
        return value

    @field_validator("settings")
    @classmethod
    def _setting_names(cls, value: dict[str, SettingSpec]) -> dict[str, SettingSpec]:
        for key in value:
            if not _NAME.match(key):
                raise ValueError(f"invalid setting name {key!r}")
        return value

    def settings_model(self) -> type[BaseModel]:
        fields: dict[str, Any] = {}
        for key, spec in self.settings.items():
            constraints: dict[str, Any] = {}
            if spec.min is not None:
                constraints["ge"] = spec.min
            if spec.max is not None:
                constraints["le"] = spec.max
            fields[key] = (spec.python_type(), Field(default=spec.default, **constraints))
        model: type[BaseModel] = create_model(
            f"{self.name.title()}Settings",
            __config__=ConfigDict(extra="forbid", strict=True),
            **fields,
        )
        return model

    def settings_json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {key: spec.json_schema() for key, spec in self.settings.items()},
        }

    def defaults(self) -> dict[str, Any]:
        return {key: spec.default for key, spec in self.settings.items()}

    def effective_settings(self, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        """Defaults merged with overrides, validated against the schema. Raises AgentDefinitionError."""
        merged = {**self.defaults(), **(overrides or {})}
        try:
            return self.settings_model().model_validate(merged).model_dump()
        except ValidationError as exc:
            raise AgentDefinitionError(f"{self.name}: invalid settings: {_errors(exc)}") from exc

    def rule_paths(self) -> list[Path]:
        paths = []
        for rule in self.rules:
            if rule.startswith(SHARED_PREFIX):
                paths.append(shared_rules_dir() / rule.removeprefix(SHARED_PREFIX))
            else:
                paths.append(self.path / rule)
        return paths


def parse_agent_md(text: str, path: Path) -> AgentDefinition:
    """Parse the contents of an AGENT.md (pure; `path` is the agent folder, used for rule paths)."""
    match = _FRONT_MATTER.match(text)
    if not match:
        raise AgentDefinitionError(f"{path}: AGENT.md must start with YAML front matter between --- lines")
    try:
        front = yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:
        raise AgentDefinitionError(f"{path}: invalid YAML front matter: {exc}") from exc
    if not isinstance(front, dict):
        raise AgentDefinitionError(f"{path}: front matter must be a mapping")
    body = match.group(2).strip()
    if not body:
        raise AgentDefinitionError(f"{path}: AGENT.md has no instructions after the front matter")
    if body == STRIPPED_MARKER:
        body = ""  # a public build: the checks run, Claude calls are refused (NoInstructions)
    try:
        definition = AgentDefinition.model_validate({**front, "instructions": body, "path": path})
    except ValidationError as exc:
        raise AgentDefinitionError(f"{path}: {_errors(exc)}") from exc
    # Every default must satisfy its own schema.
    definition.effective_settings()
    return definition


def load_agent(folder: Path) -> AgentDefinition:
    file = folder / AGENT_FILE
    if not file.is_file():
        raise AgentDefinitionError(f"{folder}: no {AGENT_FILE}")
    definition = parse_agent_md(file.read_text(encoding="utf-8"), folder)
    if definition.name != folder.name:
        raise AgentDefinitionError(f"{file}: name {definition.name!r} does not match its folder")
    for rule in definition.rule_paths():
        if not rule.is_file():
            raise AgentDefinitionError(f"{file}: rule file {rule} does not exist")
    return definition


def _errors(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}" for err in exc.errors()
    )
