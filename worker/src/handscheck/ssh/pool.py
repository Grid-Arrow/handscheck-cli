"""Reuse one SSHRunner (and so one connection) per host for the length of a job or CLI command."""

from __future__ import annotations

from types import TracebackType
from typing import Any, Self

from handscheck.ssh.runner import SSHRunner, SSHTarget


class RunnerPool:
    def __init__(self, **runner_options: Any) -> None:
        self._options = runner_options
        self._runners: dict[str, SSHRunner] = {}

    def get(self, target: SSHTarget) -> SSHRunner:
        runner = self._runners.get(target.name)
        if runner is None:
            runner = self._runners[target.name] = SSHRunner(target, **self._options)
        return runner

    async def close(self) -> None:
        runners, self._runners = list(self._runners.values()), {}
        for runner in runners:
            await runner.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.close()
