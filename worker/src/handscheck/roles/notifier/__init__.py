"""Notifier role agent: what Claude must return (`ComposeOut`). Delivery is plain Laravel code."""

from pydantic import BaseModel, Field


class MessageItem(BaseModel):
    alert_id: str
    subject: str = Field(description="Under 90 characters.")
    body: str = Field(description="Plain text with light Markdown.")


class ComposeOut(BaseModel):
    messages: list[MessageItem]
