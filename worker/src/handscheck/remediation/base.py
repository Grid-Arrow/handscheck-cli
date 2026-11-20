"""What every fix action is made of: its commands, a preview, and precheck → apply → verify → rollback."""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol

from pydantic import BaseModel, ConfigDict

from handscheck.agents._framework.services import HttpProber, HttpResponse
from handscheck.contracts import FixProposal, RemediationStep
from handscheck.remediation.policy import PlanPolicy, normalize
from handscheck.ssh.runner import CommandResult

QUARANTINE_ROOT = "/var/lib/handscheck-quarantine"
"""Root-only directory for anything a fix takes away (never deleted). One sub-directory per fix."""

PREVIEW_ID = "<fix id>"


class Stale(Exception):
    """The host no longer matches the proposal (fixed by hand, file gone, user changed): nothing changed."""


class FixFailed(Exception):
    """A step of the fix failed."""


@dataclass(frozen=True)
class Cmd:
    argv: tuple[str, ...]
    sudo_user: str | None = "root"
    """root, www-data, or None for a command without sudo."""

    def line(self) -> str:
        return normalize(self.argv, self.sudo_user)


@dataclass(frozen=True)
class FixContext:
    proposal_id: str = PREVIEW_ID


class Params(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass
class Preview:
    summary: str
    rollback: list[str]
    verify: list[str]
    notes: list[str] = field(default_factory=list)


class FixRunner(Protocol):
    """What a fix needs from the SSH runner (SSHRunner; tests use a fake)."""

    async def run(
        self,
        command: str | Sequence[str],
        *,
        sudo: bool = False,
        sudo_user: str | None = None,
        timeout: float | None = None,
        max_output: int | None = None,
        stdin: str | None = None,
    ) -> CommandResult: ...


class Executor:
    """Runs a fix's commands (each checked against the plan policy here too), records every step, and probes
    the host's sites over HTTP from the worker."""

    def __init__(self, runner: FixRunner, policy: PlanPolicy, http: HttpProber | None, address: str) -> None:
        self.runner = runner
        self.policy = policy
        self.http = http
        self.address = address
        self.phase = "precheck"
        self.steps: list[RemediationStep] = []

    async def run(self, cmd: Cmd, *, stdin: str | None = None, check: bool = True) -> CommandResult:
        self.policy.enforce(cmd.line())
        sudo_user = None if cmd.sudo_user in (None, "root") else cmd.sudo_user
        result = await self.runner.run(
            list(cmd.argv), sudo=cmd.sudo_user is not None, sudo_user=sudo_user, stdin=stdin
        )
        self.steps.append(
            RemediationStep(
                phase=self.phase,
                command=result.command,
                exit_status=result.exit_status,
                output_sha256=result.output_sha256,
                duration_s=result.duration_s,
            )
        )
        if check and not result.ok:
            detail = (result.stderr or result.stdout).strip()[:300]
            raise FixFailed(f"{result.command} failed (exit {result.exit_status}): {detail}")
        return result

    async def get(self, site: str, path: str) -> HttpResponse:
        if self.http is None:
            return HttpResponse(url=path, error="no HTTP client on this worker")
        return await self.http.get(self.address, site, path)


class Action[P: Params](ABC):
    name: ClassVar[str]
    version: ClassVar[int]
    risk: ClassVar[str]
    params_model: ClassVar[type[Params]]

    @abstractmethod
    def commands(self, p: P, ctx: FixContext) -> list[Cmd]:
        """Every command this fix may run with these parameters (all branches, apply and rollback)."""

    @abstractmethod
    def preview(self, p: P) -> Preview: ...

    @abstractmethod
    async def precheck(self, ex: Executor, p: P, ctx: FixContext) -> None:
        """Raise Stale when the host no longer matches the proposal. Read only."""

    @abstractmethod
    async def apply(self, ex: Executor, p: P, ctx: FixContext) -> dict[str, Any]:
        """Make the change; return what rollback needs."""

    @abstractmethod
    async def verify(self, ex: Executor, p: P, ctx: FixContext) -> list[str]:
        """Problems found after the change (empty = it worked)."""

    @abstractmethod
    async def rollback(self, ex: Executor, p: P, ctx: FixContext, data: dict[str, Any]) -> None: ...

    def params(self, raw: dict[str, Any]) -> P:
        return self.params_model.model_validate(raw)  # type: ignore[return-value]

    def proposal(self, p: P) -> FixProposal:
        preview = self.preview(p)
        raw = p.model_dump(mode="json")
        return FixProposal(
            action=self.name,
            action_version=self.version,
            params=raw,
            summary=preview.summary[:500],
            risk=self.risk,
            commands=[c.line() for c in self.commands(p, FixContext())],
            rollback=preview.rollback,
            verify=preview.verify,
            notes=preview.notes,
            plan_sha256=plan_sha256(self.name, self.version, raw),
        )


def plan_sha256(action: str, version: int, params: dict[str, Any]) -> str:
    """What an approval pins: the action, its version and the exact parameters."""
    canonical = json.dumps(
        {"action": action, "version": version, "params": params}, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()
