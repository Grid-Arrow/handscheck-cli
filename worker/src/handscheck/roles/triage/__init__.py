"""Triage role agent: what Claude must return (`TriageOut`)."""

from typing import Literal

from pydantic import BaseModel, Field

SeverityName = Literal["info", "low", "medium", "high", "critical"]


class FollowUpItem(BaseModel):
    question: str = Field(description="One precise read-only question for an investigator on this host.")
    reason: str = Field(description="Why the answer matters.")


class TriageItem(BaseModel):
    finding_id: str
    severity: SeverityName
    action: Literal["alert", "digest", "none"]
    reason: str = Field(description="One or two sentences.")
    related: list[str] = Field(description="dedupe_keys from <related> (may be empty).")
    follow_ups: list[FollowUpItem] = Field(description="At most two (may be empty).")


class TriageOut(BaseModel):
    decisions: list[TriageItem]
