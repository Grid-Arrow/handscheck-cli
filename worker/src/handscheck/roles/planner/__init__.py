"""Planner role agent (M7c): what Claude must return (`PlanOut`). The control plane validates the plan."""

from typing import Literal

from pydantic import BaseModel, Field

from handscheck.roles.recon import SettingValue


class PlanItemOut(BaseModel):
    agent: str
    site: str | None = Field(description="A site from <sites>, or null for every site / a host agent.")
    depth: Literal["normal", "deep"] = Field(description="deep = review all facts, not only what changed.")
    settings: list[SettingValue] = Field(description="Overrides for this run only (may be empty).")
    reason: str = Field(description="One sentence tying the item to a signal.")


class PlanOut(BaseModel):
    summary: str = Field(description="One or two sentences: what this run looks at more closely, and why.")
    items: list[PlanItemOut] = Field(
        description="Only agents that need more than a normal run (may be empty)."
    )
