"""The diff engine: compare two snapshots' diff views (pure).

Each agent's `Facts.diff_view()` is a set of named collections of `key → value`. Between two runs we report
keys that were added, removed, or whose value changed. Two rules keep the diff quiet:

- A collection missing on either side (new in this agent version, or not collected this time, e.g. auth.log
  unreadable) is not compared: "couldn't look" is never reported as "everything disappeared".
- Append-only collections (log events in a sliding window) only report additions; old lines aging out of the
  window are not changes.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal

from pydantic import BaseModel

from handscheck.agents._framework.check import DiffView

ChangeOp = Literal["added", "removed", "changed"]


class Change(BaseModel):
    agent: str
    site: str | None = None
    collection: str
    key: str
    op: ChangeOp
    before: Any = None
    after: Any = None

    def describe(self) -> str:
        if self.op == "changed":
            return f"{self.collection}: {self.key}: {_short(self.before)} → {_short(self.after)}"
        value = self.after if self.op == "added" else self.before
        shown = "" if value is True or value is None else f" ({_short(value)})"
        return f"{self.collection}: {self.op} {self.key}{shown}"


def diff_views(
    agent: str,
    previous: DiffView,
    current: DiffView,
    *,
    append_only: Iterable[str] = (),
    site: str | None = None,
) -> list[Change]:
    append = set(append_only)
    changes: list[Change] = []
    for collection in sorted(previous.keys() & current.keys()):
        before, after = previous[collection], current[collection]
        for key in sorted(after.keys() - before.keys()):
            changes.append(
                Change(agent=agent, site=site, collection=collection, key=key, op="added", after=after[key])
            )
        if collection not in append:
            for key in sorted(before.keys() - after.keys()):
                changes.append(
                    Change(
                        agent=agent,
                        site=site,
                        collection=collection,
                        key=key,
                        op="removed",
                        before=before[key],
                    )
                )
        for key in sorted(before.keys() & after.keys()):
            if _normalize(before[key]) != _normalize(after[key]):
                changes.append(
                    Change(
                        agent=agent,
                        site=site,
                        collection=collection,
                        key=key,
                        op="changed",
                        before=before[key],
                        after=after[key],
                    )
                )
    return changes


def _normalize(value: Any) -> Any:
    """Compare JSON-equivalently (tuples vs lists after a round trip through the database)."""
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_normalize(v) for v in value]
    return value


def _short(value: Any, limit: int = 80) -> str:
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"
