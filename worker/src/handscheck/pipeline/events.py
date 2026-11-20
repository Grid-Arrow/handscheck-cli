"""Change events: operator-style changes derived from the diff (reboot, package changes, new or removed
sites).

They are not findings (CLAUDE.md: operator changes are change events unless a rule says otherwise); agents get
them as context in M4 so a reboot or an upgrade isn't reported as an attack.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from handscheck.contracts import ChangeEvent
from handscheck.pipeline.diff import Change


def change_events(changes: list[Change], observed_at: datetime) -> list[ChangeEvent]:
    events: list[ChangeEvent] = []
    events.extend(_reboot(changes, observed_at))
    events.extend(_packages(changes, observed_at))
    events.extend(_sites(changes, observed_at))
    events.extend(_wordpress(changes, observed_at))
    return events


def _reboot(changes: list[Change], at: datetime) -> list[ChangeEvent]:
    boot = [c for c in changes if c.agent == "system" and c.collection == "boot" and c.key == "boot_id"]
    if not boot or boot[0].op != "changed":
        return []
    detail: dict[str, Any] = {"boot_id": {"before": boot[0].before, "after": boot[0].after}}
    kernel = [
        c for c in changes if c.agent == "system" and c.collection == "attributes" and c.key == "kernel"
    ]
    summary = "host rebooted"
    if kernel and kernel[0].op == "changed":
        detail["kernel"] = {"before": kernel[0].before, "after": kernel[0].after}
        summary += f" into kernel {kernel[0].after}"
    return [ChangeEvent(kind="reboot", agent="system", summary=summary, detail=detail, observed_at=at)]


def _packages(changes: list[Change], at: datetime) -> list[ChangeEvent]:
    pkg = [c for c in changes if c.agent == "system" and c.collection == "packages"]
    if not pkg:
        return []
    installed = {c.key: c.after for c in pkg if c.op == "added"}
    removed = {c.key: c.before for c in pkg if c.op == "removed"}
    upgraded = {c.key: {"from": c.before, "to": c.after} for c in pkg if c.op == "changed"}
    parts = [
        f"{n} {label}"
        for n, label in (
            (len(upgraded), "upgraded"),
            (len(installed), "installed"),
            (len(removed), "removed"),
        )
        if n
    ]
    return [
        ChangeEvent(
            kind="package",
            agent="system",
            summary="packages " + ", ".join(parts),
            detail={"installed": installed, "upgraded": upgraded, "removed": removed},
            observed_at=at,
        )
    ]


def _sites(changes: list[Change], at: datetime) -> list[ChangeEvent]:
    events = []
    for c in changes:
        if c.agent != "sites" or c.collection != "sites" or c.op == "changed":
            continue
        value = c.after if c.op == "added" else c.before
        summary = f"new site discovered: {c.key}" if c.op == "added" else f"site no longer found: {c.key}"
        events.append(
            ChangeEvent(
                kind="site",
                agent="sites",
                site=c.key,
                summary=summary,
                detail={"op": c.op, **(value if isinstance(value, dict) else {})},
                observed_at=at,
            )
        )
    return events


def _wordpress(changes: list[Change], at: datetime) -> list[ChangeEvent]:
    """Core, plugin and theme installs/updates/removals on a WordPress site: one package event per site."""
    by_site: dict[str | None, list[Change]] = {}
    for c in changes:
        if c.agent == "wordpress" and c.collection in ("core", "plugins", "themes"):
            by_site.setdefault(c.site, []).append(c)
    events = []
    for site, items in by_site.items():
        detail: dict[str, Any] = {}
        parts = []
        for c in items:
            if c.collection == "core" and c.key == "version" and c.op == "changed":
                detail["core"] = {"from": c.before, "to": c.after}
                parts.append(f"core {c.before} → {c.after}")
                continue
            if c.collection == "core":
                continue
            kind = c.collection[:-1]  # plugin / theme
            verb = {"added": "installed", "removed": "removed", "changed": "updated"}[c.op]
            entry: Any = (
                c.after
                if c.op == "added"
                else c.before
                if c.op == "removed"
                else {
                    "from": c.before,
                    "to": c.after,
                }
            )
            detail.setdefault(f"{kind}s_{verb}", {})[c.key] = entry
        counts = {k: len(v) for k, v in detail.items() if k != "core"}
        parts += [f"{n} {k.replace('_', ' ')}" for k, n in sorted(counts.items())]
        if parts:
            events.append(
                ChangeEvent(
                    kind="package",
                    agent="wordpress",
                    site=site,
                    summary="WordPress: " + ", ".join(parts),
                    detail=detail,
                    observed_at=at,
                )
            )
    return events
