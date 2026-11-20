"""The command policy for a remediate job: read-only commands as for scans, plus exactly the commands of the
approved fix's plan. Anything else is refused before it is sent, like the read-only policy does."""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field

from handscheck.ssh.policy import CommandPolicy, Decision, _command_name, _Refuse


def normalize(argv: Sequence[str], sudo_user: str | None) -> str:
    """The command line as the runner sends it: `sudo -n [-u USER] -- argv…` (no -u for root), quoted."""
    if sudo_user is None:
        return shlex.join(argv)
    prefix = ["sudo", "-n", *(["-u", sudo_user] if sudo_user != "root" else []), "--"]
    return shlex.join([*prefix, *argv])


@dataclass(frozen=True)
class PlanPolicy(CommandPolicy):
    allowed: frozenset[str] = field(default_factory=frozenset)
    """Normalized command lines (see `normalize`) the approved plan may run."""

    def check(self, command: str | Sequence[str]) -> Decision:
        readonly = super().check(command)
        if readonly.allowed:
            return readonly
        try:
            argv = self._tokenize(command)
            sudo_user: str | None = None
            if _command_name(argv[0]) == "sudo":
                sudo_user, inner = self._parse_sudo(argv[1:])
                argv = ["sudo", "-n", *(["-u", sudo_user] if sudo_user != "root" else []), "--", *inner]
        except _Refuse as refusal:
            return Decision(allowed=False, reason=refusal.reason)
        if shlex.join(argv) in self.allowed:
            return Decision(
                allowed=True, reason="in the approved plan", argv=tuple(argv), sudo_user=sudo_user
            )
        return Decision(allowed=False, reason=f"not in the approved plan ({readonly.reason})")
