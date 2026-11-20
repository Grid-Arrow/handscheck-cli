"""Restart a php-fpm pool or the web server, only to restore a site visitors can't use (2026 PHP-FPM
incident).

Offered by `propose.py` only for a `health` site_down/site_slow finding whose cause is visible in the facts
(the pool hit pm.max_children, or the service isn't running). Precheck probes the site again from the
worker: if it recovered, nothing is restarted (stale). Verify probes it until it answers normally (up to
VERIFY_SECONDS) and checks the service runs. A restart can't be undone, so there is no rollback: a failed
verify is reported for people to take over, never answered with another restart. The control plane withholds
a second restart of the same service on a host within 24 hours (`Proposals::offer`)."""

from __future__ import annotations

import asyncio
import re
from typing import Any, ClassVar

from pydantic import Field, field_validator

from handscheck.remediation.base import Action, Cmd, Executor, FixContext, FixFailed, Params, Preview, Stale

_SITE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_SERVICE = re.compile(r"^(php\d+(?:\.\d+)?-fpm|apache2|nginx)$")


class RestartServiceParams(Params):
    site: str = Field(description="The site whose homepage is checked before and after.")
    service: str = Field(description="php<version>-fpm, apache2 or nginx.")
    slow_s: float = Field(
        default=5.0, gt=0, le=60, description="Healthy = an answer below 500 within this time."
    )

    @field_validator("site")
    @classmethod
    def _site(cls, v: str) -> str:
        if not _SITE.match(v):
            raise ValueError("not a site name")
        return v

    @field_validator("service")
    @classmethod
    def _service(cls, v: str) -> str:
        if not _SERVICE.match(v):
            raise ValueError("only a php-fpm pool, apache2 or nginx can be restarted")
        return v


class RestartService(Action[RestartServiceParams]):
    name = "restart_service"
    version = 1
    risk = "medium"
    params_model = RestartServiceParams
    VERIFY_SECONDS: ClassVar[float] = 60.0
    VERIFY_INTERVAL: ClassVar[float] = 5.0

    def commands(self, p: RestartServiceParams, ctx: FixContext) -> list[Cmd]:
        return [
            Cmd(("test", "-d", "/run/systemd/system")),
            Cmd(("systemctl", "restart", f"{p.service}.service")),
            Cmd(("service", p.service, "restart")),
            Cmd(("systemctl", "is-active", f"{p.service}.service")),
            Cmd(("ps", "-eo", "args"), None),
        ]

    def preview(self, p: RestartServiceParams) -> Preview:
        return Preview(
            summary=f"Restart {p.service} to bring {p.site} back: it frees the PHP workers or starts the "
            "stopped service. Only if the site is still unhealthy when the fix runs.",
            rollback=["A restart can't be undone; if the site doesn't recover, nothing else is tried."],
            verify=[
                f"{p.site} answers normally (below HTTP 500, within {p.slow_s:g} s) within a minute.",
                f"{p.service} is running.",
            ],
            notes=[
                "Running requests on the restarted service are cut off.",
                "A restart treats the symptom: if the pool keeps running out of workers, it needs more "
                "capacity or the traffic needs limiting. A second restart of this service within 24 hours "
                "is not offered.",
            ],
        )

    async def precheck(self, ex: Executor, p: RestartServiceParams, ctx: FixContext) -> None:
        if await self._healthy(ex, p):
            raise Stale(f"{p.site} answers normally again: nothing restarted")

    async def apply(self, ex: Executor, p: RestartServiceParams, ctx: FixContext) -> dict[str, Any]:
        systemd = (await ex.run(Cmd(("test", "-d", "/run/systemd/system")), check=False)).ok
        if systemd:
            await ex.run(Cmd(("systemctl", "restart", f"{p.service}.service")))
        else:
            await ex.run(Cmd(("service", p.service, "restart")))
        return {"restarted": p.service, "systemd": systemd}

    async def verify(self, ex: Executor, p: RestartServiceParams, ctx: FixContext) -> list[str]:
        waited = 0.0
        while True:
            if await self._healthy(ex, p):
                break
            if waited >= self.VERIFY_SECONDS:
                return [f"{p.site} still isn't answering normally {waited:.0f} s after the restart"]
            await asyncio.sleep(self.VERIFY_INTERVAL)
            waited += self.VERIFY_INTERVAL
        if not await self._running(ex, p):
            return [f"{p.service} isn't running after the restart"]
        return []

    async def rollback(
        self, ex: Executor, p: RestartServiceParams, ctx: FixContext, data: dict[str, Any]
    ) -> None:
        raise FixFailed(
            f"{p.service} was restarted but {p.site} is still unhealthy; a restart can't be undone and no "
            "second one is tried: escalate to a person"
        )

    async def _healthy(self, ex: Executor, p: RestartServiceParams) -> bool:
        response = await ex.get(p.site, "/")
        return (
            response.status is not None
            and response.status < 500
            and response.elapsed_s is not None
            and response.elapsed_s <= p.slow_s
        )

    async def _running(self, ex: Executor, p: RestartServiceParams) -> bool:
        active = await ex.run(Cmd(("systemctl", "is-active", f"{p.service}.service")), check=False)
        if active.stdout.strip() == "active":
            return True
        ps = await ex.run(Cmd(("ps", "-eo", "args"), None), check=False)
        if p.service.endswith("-fpm"):
            version = p.service.removeprefix("php").removesuffix("-fpm")
            return f"/etc/php/{version}/fpm/" in ps.stdout
        return any(line.split(" ", 1)[0].endswith(f"/{p.service}") for line in ps.stdout.splitlines())
