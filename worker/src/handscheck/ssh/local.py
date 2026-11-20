"""Local runner (Track S, self-hosted mode): the same checks, run on the machine `hc` is installed on.

It has the interface of `SSHRunner` (`run`, `close`, `host_key_fingerprint`, `commands_run`), so the pipeline
uses it unchanged, and it is held to the same rules:

- **Policy:** `run()` calls `CommandPolicy.enforce()` on exactly what `SSHRunner` would send (the sudo
  prefix comes from the shared `with_sudo`). A refused command never starts a process.
- **No shell at all:** the policy's parsed words (`Decision.argv`) are executed directly with
  `create_subprocess_exec`. Nothing is expanded, chained or redirected, even if the parser were wrong.
- **Fixed environment:** `LC_ALL=C` and a fixed `PATH` of system directories, nothing else inherited, so a
  user's `PATH` or `LD_PRELOAD` can't swap `cat` for something else. stdin is `/dev/null`.
- **Timeouts:** wrapped in coreutils `timeout -k` like the SSH wire command (it reaches a sudo child we may
  not signal ourselves), plus a local bound that kills our process group.
- **Output caps:** each stream is read up to a byte cap; past it the command is stopped and flagged
  `truncated`.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import time
from collections.abc import Sequence
from types import TracebackType
from typing import Self

from handscheck.ssh.policy import DEFAULT_POLICY, CommandPolicy
from handscheck.ssh.runner import (
    DEFAULT_MAX_OUTPUT,
    DEFAULT_TIMEOUT,
    CommandResult,
    detect_sudo_failure,
    with_sudo,
)

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_ENV = {"LC_ALL": "C", "LANG": "C", "PATH": SAFE_PATH}
_KILL_GRACE = 5  # seconds between TERM and KILL (coreutils timeout)
_LOCAL_GRACE = 10.0  # extra wait here beyond the command's own timeout


class LocalRunner:
    """Run policy-checked commands on this machine. No connection: `close()` does nothing."""

    def __init__(
        self,
        name: str,
        *,
        policy: CommandPolicy = DEFAULT_POLICY,
        default_timeout: float = DEFAULT_TIMEOUT,
        max_output: int = DEFAULT_MAX_OUTPUT,
    ) -> None:
        self.name = name
        self.policy = policy
        self.default_timeout = default_timeout
        self.max_output = max_output
        self.commands_run: list[str] = []
        """Every normalized command run, in order (as `SSHRunner.commands_run`)."""

    @property
    def host_key_fingerprint(self) -> str | None:
        return None  # no SSH, nothing to pin

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.close()

    async def close(self) -> None:
        return None

    async def run(
        self,
        command: str | Sequence[str],
        *,
        sudo: bool = False,
        sudo_user: str | None = None,
        timeout: float | None = None,
        max_output: int | None = None,
    ) -> CommandResult:
        """Run one read-only command the policy allows. Raises PolicyViolation (nothing runs) if refused."""
        decision = self.policy.enforce(with_sudo(command, sudo=sudo, sudo_user=sudo_user))
        timeout = self.default_timeout if timeout is None else timeout
        cap = self.max_output if max_output is None else max_output
        limit = max(1, int(timeout))
        argv = ["timeout", "-k", str(_KILL_GRACE), str(limit), *decision.argv]

        self.commands_run.append(decision.command)
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_ENV,
            cwd="/",
            start_new_session=True,  # its own process group, so a local timeout can stop all of it
        )
        assert process.stdout is not None and process.stderr is not None  # noqa: S101 - PIPE above
        out = _CappedReader(process.stdout, cap)
        err = _CappedReader(process.stderr, cap)
        timed_out = False
        exit_status: int | None = None
        try:
            async with asyncio.timeout(limit + _KILL_GRACE + _LOCAL_GRACE):

                async def pump(reader: _CappedReader) -> None:
                    await reader.read_all()
                    if reader.truncated:
                        _terminate(process)  # stop it now; the other stream may never see EOF otherwise

                await asyncio.gather(pump(out), pump(err))
                status = await process.wait()
                if not (out.truncated or err.truncated):
                    exit_status = status
        except TimeoutError:
            timed_out = True
            _terminate(process)
            try:
                async with asyncio.timeout(_KILL_GRACE):
                    await process.wait()
            except TimeoutError:
                _kill_group(process)
        if exit_status == 124:  # coreutils timeout fired
            timed_out = True
            exit_status = None
        stderr = err.text()
        is_sudo = decision.sudo_user is not None
        return CommandResult(
            command=decision.command,
            exit_status=exit_status,
            stdout=out.text(),
            stderr=stderr,
            stdout_truncated=out.truncated,
            stderr_truncated=err.truncated,
            timed_out=timed_out,
            duration_s=round(time.monotonic() - started, 3),
            sudo=is_sudo,
            sudo_failure=detect_sudo_failure(exit_status, stderr) if is_sudo else None,
        )


def _terminate(process: asyncio.subprocess.Process) -> None:
    """TERM to coreutils `timeout`, which passes it on to its command (and sudo relays it to a root child we
    could not signal ourselves)."""
    if process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            process.terminate()


def _kill_group(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)


class _CappedReader:
    def __init__(self, stream: asyncio.StreamReader, cap: int) -> None:
        self.stream = stream
        self.cap = cap
        self.buf = bytearray()
        self.truncated = False

    async def read_all(self) -> None:
        while True:
            chunk = await self.stream.read(65536)
            if not chunk:
                return
            room = self.cap - len(self.buf)
            if len(chunk) > room:
                self.buf.extend(chunk[: max(room, 0)])
                self.truncated = True
                return
            self.buf.extend(chunk)

    def text(self) -> str:
        return self.buf.decode("utf-8", errors="replace")
