"""The SSH session a job runs on (SSHRunner; tests replay captured output)."""

from __future__ import annotations

from typing import Protocol

from handscheck.agents._framework.check import CommandRunner


class SessionRunner(CommandRunner, Protocol):
    @property
    def host_key_fingerprint(self) -> str | None: ...

    async def close(self) -> None: ...
