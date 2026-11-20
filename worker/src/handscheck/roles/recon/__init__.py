"""Recon role agent (M7c): what Claude must return (`ReconOut`). The inventory is in `inventory.py`."""

from pydantic import BaseModel, Field


class SettingValue(BaseModel):
    field: str = Field(description="A setting name from the agent's settings schema.")
    value_json: str = Field(description='The value as JSON, e.g. "deploy" (with quotes), 120, ["a","b"].')


class ChangeItem(BaseModel):
    agent: str
    enabled: bool | None = Field(description="false to turn the agent off on this server; null to leave it.")
    settings: list[SettingValue] = Field(description="Overrides (may be empty).")
    reason: str = Field(description="One or two sentences citing the inventory or a command's output.")


class ReconOut(BaseModel):
    profile: str = Field(
        description="Two to four sentences: OS, web server and PHP, the sites and their CMS, anything "
        "unusual."
    )
    changes: list[ChangeItem] = Field(description="Setting changes; empty when the defaults fit.")
    notes: list[str] = Field(description="What a person should know or check (may be empty).")
