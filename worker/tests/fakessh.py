"""An in-process SSH server for tests (no Docker). Commands are matched on their parsed words."""

import asyncio
import shlex
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import asyncssh
from pydantic import SecretStr

from handscheck.ssh import runner as runner_mod
from handscheck.ssh.runner import SSHTarget

OS_RELEASE = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\n'


@dataclass
class FakeHost:
    port: int
    host_key: asyncssh.SSHKey
    client_key: asyncssh.SSHKey
    received: list[str] = field(default_factory=list)
    connections: int = 0
    auth_attempts: int = 0
    birth: str = "1700000000 1700000001"
    """What `stat -c '%W %Z' /etc/passwd` prints (16.04 prints `0 <ctime>`)."""
    sudo_works: bool = True


def _strip_timeout(argv: list[str]) -> list[str]:
    assert argv[:3] == ["timeout", "-k", str(runner_mod._KILL_GRACE)], argv
    int(argv[3])
    return argv[4:]


async def _handle(host: FakeHost, process: asyncssh.SSHServerProcess[str]) -> None:
    command = process.command or ""
    host.received.append(command)
    argv = _strip_timeout(shlex.split(command))
    if argv[:3] == ["sudo", "-n", "--"]:
        argv = argv[3:]
        if not host.sudo_works:
            process.stderr.write("sudo: a password is required\n")
            process.exit(1)
            return
        if argv[0] == "id":
            process.stderr.write("sudo: a password is required\n")
            process.exit(1)
            return
        if argv[0] == "whoami":
            process.stderr.write(
                "Sorry, user handscheck is not allowed to execute '/usr/bin/whoami' as root.\n"
            )
            process.exit(1)
            return
    match argv:
        case ["id", "-un"]:
            process.stdout.write("handscheck\n")
            process.exit(0)
        case ["which", "wp"]:
            process.stdout.write("/usr/local/bin/wp\n")
            process.exit(0)
        case ["/usr/local/bin/wp", "--version"]:
            process.stdout.write("WP-CLI 2.11.0\n")
            process.exit(0)
        case ["stat", "-c", "%W %Z", "/etc/passwd"]:
            process.stdout.write(host.birth + "\n")
            process.exit(0)
        case ["cat", "/etc/os-release"]:
            process.stdout.write(OS_RELEASE)
            process.exit(0)
        case ["cat", "/big"]:
            for _ in range(40):
                process.stdout.write("x" * 100_000)
            process.exit(0)
        case ["cat", "/slow"]:
            await asyncio.sleep(30)
            process.exit(0)
        case ["cat", "/timeout-on-host"]:
            process.exit(124)
        case ["cat", "/missing"]:
            process.stderr.write("cat: /missing: No such file or directory\n")
            process.exit(1)
        case _:
            process.stdout.write(shlex.join(argv) + "\n")
            process.exit(0)


@asynccontextmanager
async def start_fake_host() -> AsyncIterator[FakeHost]:
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    state: dict[str, FakeHost] = {}

    class Server(asyncssh.SSHServer):
        def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
            state["host"].connections += 1

        def begin_auth(self, username: str) -> bool:
            return True

        def public_key_auth_supported(self) -> bool:
            return True

        def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
            state["host"].auth_attempts += 1
            return username == "handscheck" and key.public_data == client_key.public_data

    async def handle(process: asyncssh.SSHServerProcess[str]) -> None:
        await _handle(state["host"], process)

    server = await asyncssh.create_server(
        Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=handle
    )
    port = server.sockets[0].getsockname()[1]
    state["host"] = FakeHost(port=port, host_key=host_key, client_key=client_key)
    try:
        yield state["host"]
    finally:
        server.close()
        await server.wait_closed()


def target(host: FakeHost, **overrides: object) -> SSHTarget:
    key_text = host.client_key.export_private_key("openssh").decode()
    values: dict[str, object] = {
        "name": "fake",
        "address": "127.0.0.1",
        "port": host.port,
        "user": "handscheck",
        "private_key": SecretStr(key_text),
    }
    values.update(overrides)
    return SSHTarget(**values)  # type: ignore[arg-type]
