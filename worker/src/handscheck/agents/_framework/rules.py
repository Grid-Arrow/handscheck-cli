"""Rules are data (SPEC §3): versioned YAML with `id`, `description`, `severity`, matcher fields and
`references`. Agent-specific rules live in `agents/<name>/rules/`, shared ones in `worker/rules/`
(referenced as `shared:<file>` in AGENT.md).

Every rule carries `examples` (at least one input it must match and one it must not); `tests/agents/
test_rules.py` runs them for every rule, against Python's `re` and GNU `grep -E` where the pattern runs on the
host. A file is a mapping with a `rules:` list.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import date
from functools import cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from handscheck.config import repo_root
from handscheck.contracts import Severity

_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,79}$")


class RuleError(Exception):
    pass


class Examples(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    match: list[str] = Field(min_length=1)
    no_match: list[str] = Field(min_length=1)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    description: str
    severity: Severity
    references: list[str] = Field(default_factory=list)
    examples: Examples

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID.match(value):
            raise ValueError(f"invalid rule id {value!r}")
        return value


class PatternRule(Rule):
    """A regex that must behave the same in Python `re` and GNU `grep -E` (it runs on the host)."""

    pattern: str

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, value: str) -> str:
        if "(?" in value or "\\d" in value:
            raise ValueError("use plain ERE (no (?…) groups or \\d) so grep -E and Python agree")
        if "$(" in value or "`" in value:
            raise ValueError("no `$(` or backticks: the SSH command policy refuses them (write [$] instead)")
        re.compile(value)
        return value

    def matches(self, text: str) -> bool:
        return re.search(self.pattern, text) is not None


SuppressKind = Literal["php_in_uploads", "fingerprint", "php_in_non_php", "unexpected_php"]


class FalsePositiveRule(Rule):
    """A known-legitimate file: path globs (fnmatch on the full path) and optionally how it starts."""

    paths: list[str] = Field(min_length=1)
    """Shell patterns on the full path (`*` also matches `/`)."""
    content: str | None = None
    """Regex the start of the file must match (`re.match` on its first bytes, on the worker).
    None = path only.
    Only use content that keeps the file from running code (`<?php exit;`, `__halt_compiler();`) or that is
    the whole file (with `max_size`), so an attacker can't hide behind the rule."""
    max_size: int | None = None
    """Only files up to this many bytes."""
    suppresses: list[SuppressKind] = Field(min_length=1)

    def matches_path(self, path: str) -> bool:
        return any(fnmatch.fnmatchcase(path, p) for p in self.paths)

    @property
    def needs_content(self) -> bool:
        return self.content is not None

    def matches_file(self, path: str, size: int | None, head: str | None) -> bool:
        if not self.matches_path(path):
            return False
        if self.max_size is not None and (size is None or size > self.max_size):
            return False
        if self.content is None:
            return True
        return head is not None and re.match(self.content, head) is not None

    def matches(self, text: str) -> bool:
        """`text` is "<path>" or "<path>\\n<file content>" (size = length of the content)."""
        path, sep, content = text.partition("\n")
        return self.matches_file(path, len(content.encode()) if sep else None, content if sep else None)


class VulnerablePluginRule(Rule):
    slug: str
    affected: list[str] = Field(min_length=1)
    """Version ranges, each "*" or comma-separated comparisons, e.g. ">=3.6.0,<3.6.3"."""
    fixed_in: str | None = None

    @field_validator("affected")
    @classmethod
    def _ranges(cls, value: list[str]) -> list[str]:
        for spec in value:
            if spec != "*":
                for part in spec.split(","):
                    if not re.fullmatch(r"\s*(<=|>=|<|>|==)\s*[0-9][0-9A-Za-z.\-]*\s*", part):
                        raise ValueError(f"bad version range {spec!r}")
        return value

    def matches(self, text: str) -> bool:
        """`text` is "<slug> <version>"."""
        slug, _, version = text.partition(" ")
        return slug == self.slug and any(version_in(version.strip(), spec) for spec in self.affected)


class IocDomainRule(Rule):
    domain: str

    @property
    def pattern(self) -> str:
        return re.escape(self.domain).replace("\\-", "-")

    def matches(self, text: str) -> bool:
        return re.search(self.pattern, text) is not None


class EolRule(Rule):
    product: Literal["ubuntu", "php"]
    version: str
    eol: date
    """End of standard (free) support."""

    def matches(self, text: str) -> bool:
        """`text` is "<product> <version> <YYYY-MM-DD>": past EOL on that date."""
        product, version, day = (text.split() + ["", "", ""])[:3]
        return product == self.product and version == self.version and date.fromisoformat(day) > self.eol


class AccountRule(Rule):
    """A suspicious WordPress account: shell patterns on the login and/or the email (any must match)."""

    login: list[str] = Field(default_factory=list)
    email: list[str] = Field(default_factory=list)

    def matches(self, text: str) -> bool:
        """`text` is "<login> <email>"."""
        login, _, email = text.partition(" ")
        return any(fnmatch.fnmatchcase(login.lower(), p) for p in self.login) or any(
            fnmatch.fnmatchcase(email.lower().strip(), p) for p in self.email
        )


def shared_rules_dir() -> Path:
    """worker/rules/ (from a checkout), or the copy installed inside the package."""
    packaged = Path(__file__).resolve().parents[2] / "_shared_rules"
    if packaged.is_dir():
        return packaged
    root = repo_root()
    if root is None:
        raise RuleError("shared rules not found (no worker/rules/ and no packaged copy)")
    return root / "worker" / "rules"


@cache
def load_rules[R: Rule](path: Path, model: type[R]) -> tuple[R, ...]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuleError(f"{path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise RuleError(f"{path}: expected a mapping with a `rules:` list")
    rules: list[R] = []
    for i, item in enumerate(data["rules"]):
        try:
            rules.append(model.model_validate(item))
        except ValidationError as exc:
            raise RuleError(f"{path}: rule #{i + 1}: {exc}") from exc
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise RuleError(f"{path}: duplicate rule ids")
    return tuple(rules)


# ── versions ─────────────────────────────────────────────────────────────────


def _key(version: str) -> tuple[tuple[int, str], ...]:
    parts = re.findall(r"\d+|[A-Za-z]+", version)
    return tuple((int(p), "") if p.isdigit() else (-1, p.lower()) for p in parts)


def compare_versions(a: str, b: str) -> int:
    ka, kb = list(_key(a)), list(_key(b))
    while len(ka) < len(kb):
        ka.append((0, ""))
    while len(kb) < len(ka):
        kb.append((0, ""))
    return (ka > kb) - (ka < kb)


def version_in(version: str, spec: str) -> bool:
    if spec == "*":
        return True
    if not version:
        return False
    for part in spec.split(","):
        m = re.fullmatch(r"\s*(<=|>=|<|>|==)\s*(\S+)\s*", part)
        if not m:
            return False
        op, bound = m.groups()
        c = compare_versions(version, bound)
        ok = {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "==": c == 0}[op]
        if not ok:
            return False
    return True
