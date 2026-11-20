"""Async SSH runner: one reusable connection per host, every command through the policy.

- **Policy:** `run()` calls `CommandPolicy.enforce()` and sends only the normalized command. There is no other
  way to send a command; the asyncssh connection is private to this class.
- **Timeouts:** the remote command is wrapped in coreutils `timeout` (so it dies on the host, not only here),
  and the local read is bounded too.
- **Output caps:** stdout and stderr are read up to a byte cap; past it the channel is closed and the result
  is flagged `truncated`.
- **sudo:** `sudo=True` runs `sudo -n -- CMD` (never prompts); a password prompt or a sudoers refusal is
  reported as `sudo_failure`, not as an empty result.
- **Host keys:** the server's key fingerprint is checked *before authentication*. With a pinned fingerprint, a
  different key aborts the connection (`HostKeyMismatch`). Without one, the key is accepted and exposed as
  `host_key_fingerprint` so the caller can pin it (trust on first use).
- **Keys:** a job's private key is imported from memory and never written to disk; standalone mode reads a key
  file.
"""

from __future__ import annotations

import asyncio
import hashlib
import shlex
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Literal, Self

import asyncssh
from pydantic import SecretStr

from handscheck.contracts import HostTarget
from handscheck.ssh.policy import DEFAULT_POLICY, CommandPolicy

DEFAULT_TIMEOUT = 60.0
DEFAULT_CONNECT_TIMEOUT = 15.0
DEFAULT_MAX_OUTPUT = 1_000_000  # bytes, per stream
MAX_CHANNELS = 4  # concurrent commands per connection (sshd's MaxSessions default is 10)
_KILL_GRACE = 5  # seconds between TERM and KILL on the host
_LOCAL_GRACE = 10.0  # extra local wait beyond the remote timeout

SudoFailure = Literal["password_required", "not_allowed"]
"""password_required: sudo -n would have prompted. sudo also reports this (rather than "not allowed") when the
user has NOPASSWD rules but the command isn't one of them."""


class SSHError(Exception):
    """Could not connect or authenticate."""


class HostKeyMismatch(SSHError):
    def __init__(self, host: str, expected: str, actual: str) -> None:
        super().__init__(
            f"host key for {host} changed: pinned {expected}, server presented {actual}. "
            "Refusing to connect. If the host was rebuilt, verify the new key out of band and re-pin it."
        )
        self.expected = expected
        self.actual = actual


@dataclass(frozen=True)
class SSHTarget:
    name: str
    address: str
    user: str
    port: int = 22
    private_key: SecretStr | None = None
    """OpenSSH private key text (from a job). Held in memory only."""
    key_path: Path | None = None
    """Private key file (standalone mode)."""
    host_key_fingerprint: str | None = None
    """Pinned SHA256 fingerprint; None = trust on first use."""

    @classmethod
    def from_host_target(cls, target: HostTarget) -> SSHTarget:
        return cls(
            name=target.name,
            address=target.address,
            port=target.port,
            user=target.user,
            private_key=target.private_key,
            host_key_fingerprint=target.host_key_fingerprint,
        )

    def load_key(self) -> asyncssh.SSHKey:
        if self.private_key is not None:
            return asyncssh.import_private_key(self.private_key.get_secret_value())
        if self.key_path is not None:
            return asyncssh.read_private_key(self.key_path)
        raise SSHError(f"no private key for host {self.name}")


@dataclass(frozen=True)
class CommandResult:
    command: str
    """The normalized command as sent (before the runner's `timeout` wrapper)."""
    exit_status: int | None
    """None when the command timed out or its output was cut off before it finished."""
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    duration_s: float = 0.0
    sudo: bool = False
    sudo_failure: SudoFailure | None = None

    @property
    def ok(self) -> bool:
        return self.exit_status == 0 and not self.timed_out and self.sudo_failure is None

    @property
    def truncated(self) -> bool:
        return self.stdout_truncated or self.stderr_truncated

    @property
    def output_sha256(self) -> str:
        """Hash of what the command printed, for the audit log (the output itself isn't kept there)."""
        return hashlib.sha256(f"{self.stdout}\0{self.stderr}".encode()).hexdigest()


def detect_sudo_failure(exit_status: int | None, stderr: str) -> SudoFailure | None:
    """Recognize sudo's own refusals (English messages; the runner asks for LC_ALL=C)."""
    if exit_status == 0:
        return None
    text = stderr.lower()
    if "a password is required" in text or "a terminal is required" in text:
        return "password_required"
    if (
        "is not allowed to execute" in text
        or "is not in the sudoers file" in text
        or "may not run sudo" in text
        or "not allowed to run sudo" in text
    ):
        return "not_allowed"
    return None


def with_sudo(command: str | Sequence[str], *, sudo: bool, sudo_user: str | None) -> str | Sequence[str]:
    """`sudo -n [-u USER] -- COMMAND` (never prompts). Shared by the SSH and local runners, so both hand the
    policy the same command."""
    if not sudo:
        return command
    prefix = ["sudo", "-n", *(["-u", sudo_user] if sudo_user else []), "--"]
    # A string stays a string so the policy still sees (and refuses) unquoted shell operators.
    return f"{shlex.join(prefix)} {command}" if isinstance(command, str) else [*prefix, *command]


class _HostKeyClient(asyncssh.SSHClient):
    """Checks the server key before we authenticate, and remembers what it saw."""

    def __init__(self, expected: str | None) -> None:
        self.expected = expected
        self.seen: str | None = None

    def validate_host_public_key(self, host: str, addr: str, port: int, key: asyncssh.SSHKey) -> bool:
        self.seen = key.get_fingerprint("sha256")
        return self.expected is None or self.seen == self.expected


class SSHRunner:
    """Run policy-checked commands on one host over a single reused connection.

    Use as an async context manager, or call `close()`.
    """

    def __init__(
        self,
        target: SSHTarget,
        *,
        policy: CommandPolicy = DEFAULT_POLICY,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        default_timeout: float = DEFAULT_TIMEOUT,
        max_output: int = DEFAULT_MAX_OUTPUT,
    ) -> None:
        self.target = target
        self.policy = policy
        self.connect_timeout = connect_timeout
        self.default_timeout = default_timeout
        self.max_output = max_output
        self._conn: asyncssh.SSHClientConnection | None = None
        self._connect_lock = asyncio.Lock()
        self._channels = asyncio.Semaphore(MAX_CHANNELS)
        self._host_key_fingerprint: str | None = None
        self.commands_run: list[str] = []
        """Every normalized command sent, in order (for the audit log)."""

    @property
    def host_key_fingerprint(self) -> str | None:
        """The fingerprint the server presented (after connecting)."""
        return self._host_key_fingerprint

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.close()

    async def connect(self) -> None:
        async with self._connect_lock:
            if self._conn is not None:
                return
            key = self.target.load_key()
            client = _HostKeyClient(self.target.host_key_fingerprint)
            try:
                conn, _ = await asyncio.wait_for(
                    asyncssh.create_connection(
                        lambda: client,
                        self.target.address,
                        port=self.target.port,
                        username=self.target.user,
                        client_keys=[key],
                        known_hosts=([], [], []),  # no file trust: every key goes through _HostKeyClient
                        config=[],  # ignore ~/.ssh/config
                        agent_path=None,
                        agent_forwarding=False,
                        password=None,
                        kbdint_auth=False,
                        preferred_auth="publickey",
                        keepalive_interval=30,
                    ),
                    timeout=self.connect_timeout,
                )
            except asyncssh.HostKeyNotVerifiable as exc:
                expected = self.target.host_key_fingerprint
                if expected and client.seen and client.seen != expected:
                    raise HostKeyMismatch(self.target.name, expected, client.seen) from exc
                raise SSHError(f"{self.target.name}: host key not verifiable: {exc}") from exc
            except asyncssh.PermissionDenied as exc:
                raise SSHError(f"{self.target.name}: authentication failed for {self.target.user}") from exc
            except (OSError, asyncssh.Error, TimeoutError) as exc:
                raise SSHError(f"{self.target.name}: cannot connect: {exc or type(exc).__name__}") from exc
            self._conn = conn
            self._host_key_fingerprint = client.seen

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            await self._conn.wait_closed()
            self._conn = None

    async def _drop_connection(self) -> None:
        """Forget a broken connection so the next command reconnects (pinning still applies)."""
        conn, self._conn = self._conn, None
        if conn is not None:
            conn.abort()

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
        """Run one command the policy allows: read-only for scans, an approved fix's own commands for
        remediation (which may pass `stdin`, e.g. to `tee`). Raises PolicyViolation (nothing is sent) if
        the policy refuses it."""
        decision = self.policy.enforce(with_sudo(command, sudo=sudo, sudo_user=sudo_user))
        timeout = self.default_timeout if timeout is None else timeout
        cap = self.max_output if max_output is None else max_output

        remote_timeout = max(1, int(timeout))
        wire = f"timeout -k {_KILL_GRACE} {remote_timeout} {decision.command}"

        await self.connect()
        assert self._conn is not None  # noqa: S101 - connect() sets it or raises
        self.commands_run.append(decision.command)
        started = time.monotonic()
        async with self._channels:
            try:
                process = await self._conn.create_process(wire, encoding=None, env={"LC_ALL": "C"})
            except (OSError, asyncssh.Error) as exc:
                await self._drop_connection()
                raise SSHError(f"{self.target.name}: cannot open a channel: {exc}") from exc
            if stdin is not None:
                process.stdin.write(stdin.encode())
            process.stdin.write_eof()
            out = _CappedReader(process.stdout, cap)
            err = _CappedReader(process.stderr, cap)
            timed_out = False
            exit_status: int | None = None
            try:
                async with asyncio.timeout(remote_timeout + _KILL_GRACE + _LOCAL_GRACE):

                    async def pump(reader: _CappedReader) -> None:
                        await reader.read_all()
                        if reader.truncated:
                            # Stop the command now; otherwise the other stream never sees EOF (flow control).
                            process.close()

                    await asyncio.gather(pump(out), pump(err))
                    if not (out.truncated or err.truncated):
                        completed = await process.wait()
                        exit_status = completed.exit_status
            except TimeoutError:
                timed_out = True
                process.close()
            if exit_status == 124:  # coreutils timeout fired on the host
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


class _CappedReader:
    def __init__(self, stream: asyncssh.SSHReader[bytes], cap: int) -> None:
        self.stream = stream
        self.cap = cap
        self.buf = bytearray()
        self.truncated = False

    async def read_all(self) -> None:
        while True:
            try:
                chunk = await self.stream.read(65536)
            except (asyncssh.Error, BrokenPipeError, ConnectionError):
                return  # channel closed (e.g. the other stream hit its cap)
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
