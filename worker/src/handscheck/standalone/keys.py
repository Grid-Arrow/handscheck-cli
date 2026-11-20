"""The standalone SSH key (`hc setup`). Production keys come from the control plane, per job, in memory."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import asyncssh

DEFAULT_KEY_NAME = "id_ed25519_handscheck"
KEY_COMMENT = "handscheck"
# Restrict what the key can do even if it leaks: no forwarding, no pty.
AUTHORIZED_KEYS_OPTIONS = "no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty"
FROM_PLACEHOLDER = "YOUR.WORKER.IP"


@dataclass(frozen=True)
class LocalKey:
    path: Path
    public_path: Path
    public_line: str
    """`ssh-ed25519 AAAA... handscheck` (the .pub contents)."""
    fingerprint: str
    created: bool


def ensure_key(key_dir: Path, name: str = DEFAULT_KEY_NAME) -> LocalKey:
    """Load the key at key_dir/name, or generate an ed25519 key there. Never overwrites an existing key."""
    path = key_dir / name
    public_path = key_dir / f"{name}.pub"
    created = False
    if path.exists():
        key = asyncssh.read_private_key(path)
    else:
        key_dir.mkdir(parents=True, exist_ok=True)
        key = asyncssh.generate_private_key("ssh-ed25519", comment=KEY_COMMENT)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.export_private_key("openssh"))
        created = True
    public_line = key.export_public_key("openssh").decode().strip()
    if created or not public_path.exists():
        public_path.write_text(public_line + "\n")
    return LocalKey(
        path=path,
        public_path=public_path,
        public_line=public_line,
        fingerprint=key.get_fingerprint("sha256"),
        created=created,
    )


def authorized_keys_line(public_line: str, from_addrs: list[str] | None = None) -> str:
    """The line to paste into ~handscheck/.ssh/authorized_keys on a real host."""
    sources = ",".join(from_addrs) if from_addrs else FROM_PLACEHOLDER
    return f'from="{sources}",{AUTHORIZED_KEYS_OPTIONS} {public_line}'
