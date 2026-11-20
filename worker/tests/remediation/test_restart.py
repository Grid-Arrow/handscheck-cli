"""restart_service: only while the site is still unhealthy, verified by measuring again, never retried."""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import SecretStr

from handscheck.agents._framework.services import HttpResponse
from handscheck.contracts import Approval, Job, JobKind, RemediateInput
from handscheck.contracts.models import HostTarget
from handscheck.remediation.actions import ACTIONS
from handscheck.remediation.actions.restart_service import RestartService
from handscheck.remediation.handler import run_remediate
from handscheck.remediation.policy import normalize
from handscheck.ssh.runner import CommandResult


@dataclass
class Box:
    systemd: bool = True
    saturated: bool = True
    """The site is slow until the service restarts (the restart frees the workers)."""
    restart_helps: bool = True
    restarts: int = 0
    sent: list[str] = field(default_factory=list)


class Runner:
    def __init__(self, box: Box) -> None:
        self.box = box

    async def run(
        self,
        command: str | Sequence[str],
        *,
        sudo: bool = False,
        sudo_user: str | None = None,
        timeout: float | None = None,
        max_output: int | None = None,
        stdin: str | None = None,
    ) -> CommandResult:
        argv = list(command) if not isinstance(command, str) else shlex.split(command)
        line = normalize(argv, (sudo_user or "root") if sudo else None)
        self.box.sent.append(line)
        b = self.box
        match argv:
            case ["test", "-d", "/run/systemd/system"]:
                code, out = (0 if b.systemd else 1), ""
            case ["systemctl", "restart", _] | ["service", _, "restart"]:
                b.restarts += 1
                b.saturated = b.saturated and not b.restart_helps
                code, out = 0, ""
            case ["systemctl", "is-active", _]:
                code, out = (0, "active\n") if b.systemd else (1, "")
            case ["ps", "-eo", "args"]:
                code, out = 0, "php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)\n"
            case _:
                raise AssertionError(f"unexpected {argv}")
        return CommandResult(command=line, exit_status=code, stdout=out, stderr="")


class Http:
    def __init__(self, box: Box) -> None:
        self.box = box

    async def get(self, address: str, site: str, path: str) -> HttpResponse:
        if self.box.saturated:
            return HttpResponse(url=path, status=200, elapsed_s=9.5)
        return HttpResponse(url=path, status=200, elapsed_s=0.3)


def job(fix: Any) -> Job:
    return Job(
        job_id="01JOB",
        task_id="7",
        kind=JobKind.remediate,
        host=HostTarget(
            host_id="1", name="web1", address="10.0.0.2", user="handscheck-fix", private_key=SecretStr("k")
        ),
        remediate=RemediateInput(
            proposal_id="9",
            mode="apply",
            fix=fix,
            approval=Approval(user="owner@example.test", approved_at=datetime.now(UTC)),
            sites=["a.test"],
        ),
        deadline=datetime.now(UTC) + timedelta(hours=1),
    )


@pytest.fixture(autouse=True)
def fast_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(RestartService, "VERIFY_SECONDS", 0.02)
    monkeypatch.setattr(RestartService, "VERIFY_INTERVAL", 0.01)


def fix(service: str = "php8.3-fpm") -> Any:
    action = ACTIONS["restart_service"]
    return action.proposal(action.params({"site": "a.test", "service": service, "slow_s": 5.0}))


async def run(box: Box, f: Any = None) -> Any:
    result = await run_remediate(job(f or fix()), http=Http(box), runner=Runner(box))
    assert result.remediation is not None
    return result.remediation


def test_only_the_known_services() -> None:
    action = ACTIONS["restart_service"]
    for bad in ("mysql", "php8.3-fpm; reboot", "ssh", "apache2.service"):
        with pytest.raises(ValueError):
            action.params({"site": "a.test", "service": bad})
    assert "sudo -n -- systemctl restart php8.3-fpm.service" in fix().commands


async def test_restarts_and_checks_the_site_recovered() -> None:
    box = Box()
    out = await run(box)
    assert out.status == "succeeded", out.message
    assert box.restarts == 1 and "sudo -n -- systemctl restart php8.3-fpm.service" in box.sent
    assert out.rollback_data == {"restarted": "php8.3-fpm", "systemd": True}


async def test_without_systemd_it_uses_service() -> None:
    box = Box(systemd=False)
    out = await run(box)
    assert out.status == "succeeded", out.message
    assert "sudo -n -- service php8.3-fpm restart" in box.sent


async def test_nothing_restarted_once_the_site_recovered() -> None:
    box = Box(saturated=False)
    out = await run(box)
    assert out.status == "stale" and box.restarts == 0


async def test_a_restart_that_doesnt_help_is_reported_not_repeated() -> None:
    box = Box(restart_helps=False)
    out = await run(box)
    assert out.status == "failed" and box.restarts == 1
    assert "still unhealthy" in out.message and "escalate" in out.message
