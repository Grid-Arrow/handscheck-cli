"""SSH access to target hosts: the command policy, the runner, and a per-host connection pool.

Everything sent to a host goes through `SSHRunner.run`, which enforces `CommandPolicy`.
"""

from handscheck.ssh.policy import DEFAULT_POLICY, CommandPolicy, Decision, PolicyViolation
from handscheck.ssh.pool import RunnerPool
from handscheck.ssh.runner import (
    CommandResult,
    HostKeyMismatch,
    SSHError,
    SSHRunner,
    SSHTarget,
    detect_sudo_failure,
)

__all__ = [
    "DEFAULT_POLICY",
    "CommandPolicy",
    "CommandResult",
    "Decision",
    "HostKeyMismatch",
    "PolicyViolation",
    "RunnerPool",
    "SSHError",
    "SSHRunner",
    "SSHTarget",
    "detect_sudo_failure",
]
