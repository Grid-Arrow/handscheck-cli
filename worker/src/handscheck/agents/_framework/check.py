"""The deterministic half of an agent: collect (read-only commands) → parse (pure) → typed `Facts`.

A check is a class with a `name`, an async `collect(ctx)` that runs read-only commands through the context
(which goes through `SSHRunner.run` and so the command policy) and returns the raw outputs, and a pure
`parse(raw, settings)` that turns those outputs into a pydantic `Facts` model. Parsing never touches the
network, so it is unit-tested with captured output (`worker/tests/agents/<name>/captured/`).

Facts expose a `diff_view()`: named collections of `key → value` that the diff engine compares between runs
(volatile values such as uptime stay out of it), plus `metrics()` for per-run numbers.
"""

from __future__ import annotations

import shlex
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

from pydantic import BaseModel, ConfigDict

from handscheck.agents._framework.services import Services
from handscheck.ssh.policy import MAX_COMMAND_LENGTH
from handscheck.ssh.runner import CommandResult

if TYPE_CHECKING:
    from handscheck.agents._framework.findings import FindingItem
    from handscheck.sites.discovery import Site

DiffView = dict[str, dict[str, Any]]
"""collection name → {stable key → JSON-able value}."""


@dataclass(frozen=True)
class Output:
    """One command's captured output: what `parse()` sees. Built from a CommandResult or from a test file."""

    stdout: str = ""
    exit_status: int | None = 0
    stderr: str = ""
    truncated: bool = False
    timed_out: bool = False
    sudo_failure: str | None = None
    sudo: bool = False
    unprivileged: bool = False
    """A privileged read that ran without sudo (sudo unavailable): root-only files are missing from it."""
    command: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_status == 0 and not self.timed_out and self.sudo_failure is None

    @property
    def ran(self) -> bool:
        """The command ran to completion (any exit status). False on timeout, truncation or sudo refusal."""
        return self.exit_status is not None and self.sudo_failure is None

    def lines(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.strip()]

    @classmethod
    def from_result(cls, result: CommandResult) -> Output:
        return cls(
            stdout=result.stdout,
            exit_status=result.exit_status,
            stderr=result.stderr,
            truncated=result.truncated,
            timed_out=result.timed_out,
            sudo_failure=result.sudo_failure,
            sudo=result.sudo,
            command=result.command,
        )

    @classmethod
    def missing(cls) -> Output:
        """A placeholder for a command that was not run (e.g. nothing to look up)."""
        return cls(stdout="", exit_status=None)


Raw = Mapping[str, Output]


class CommandRunner(Protocol):
    """What a check needs from the SSH runner (SSHRunner satisfies it; tests use a fake)."""

    async def run(
        self,
        command: str | Sequence[str],
        *,
        sudo: bool = False,
        sudo_user: str | None = None,
        timeout: float | None = None,
        max_output: int | None = None,
    ) -> CommandResult: ...


@dataclass
class CheckContext:
    """Per-host run context shared by all checks: the runner, sudo availability, and a command cache."""

    runner: CommandRunner
    host: str
    address: str = ""
    """How the worker reaches the host (for HTTP probes of its sites)."""
    scan_user: str | None = None
    sudo_ok: bool = True
    """False when read-only sudo does not work (e.g. sudo locked out): privileged reads run without sudo."""
    timeout: float = 60.0
    site: Site | None = None
    """The site a site-scoped check is looking at (see `for_site`)."""
    sites: list[Site] = field(default_factory=list)
    """Every site discovery found (after the job's site filters): for host checks that look across sites."""
    services: Services = field(default_factory=lambda: Services())
    _cache: dict[tuple[tuple[str, ...], bool, str | None, int | None], Output] = field(default_factory=dict)
    commands: list[str] = field(default_factory=list)
    """Every command run for this host (after policy normalization), in order."""

    def for_site(self, site: Site) -> CheckContext:
        """The same host context (shared command cache and log) focused on one site."""
        return replace(self, site=site)

    async def run(
        self,
        argv: Sequence[str],
        *,
        sudo: bool = False,
        sudo_user: str | None = None,
        timeout: float | None = None,
        max_output: int | None = None,
    ) -> Output:
        """Run a read-only command (memoized per host run, so two agents can share a collector)."""
        key = (tuple(argv), sudo, sudo_user, max_output)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        result = await self.runner.run(
            list(argv),
            sudo=sudo,
            sudo_user=sudo_user,
            timeout=self.timeout if timeout is None else timeout,
            max_output=max_output,
        )
        self.commands.append(result.command)
        out = Output.from_result(result)
        self._cache[key] = out
        return out

    async def run_privileged(
        self, argv: Sequence[str], *, timeout: float | None = None, max_output: int | None = None
    ) -> Output:
        """Run with read-only sudo when it works, else without (best effort, e.g. on a locked-out host)."""
        if self.sudo_ok:
            out = await self.run(argv, sudo=True, timeout=timeout, max_output=max_output)
            if out.sudo_failure is None:
                return out
        out = await self.run(argv, timeout=timeout, max_output=max_output)
        return replace(out, unprivileged=True)

    async def run_batched(
        self,
        prefix: Sequence[str],
        paths: Sequence[str],
        *,
        privileged: bool = False,
        separator: bool = True,
        timeout: float | None = None,
        max_output: int | None = None,
    ) -> Output:
        """Run `prefix [--] path…` in batches that stay under the policy's command length, and merge the
        output (stdout concatenated; the worst exit status; any truncation, timeout or sudo problem kept)."""
        if not paths:
            return Output.missing()
        outs: list[Output] = []
        for batch in batch_args(list(prefix), list(paths)):
            argv = [*prefix, *(["--"] if separator else []), *batch]
            if privileged:
                outs.append(await self.run_privileged(argv, timeout=timeout, max_output=max_output))
            else:
                outs.append(await self.run(argv, timeout=timeout, max_output=max_output))
        return merge_outputs(outs)


class Facts(BaseModel):
    """Base for every agent's facts (the snapshot). Subclasses define the fields and the diff view."""

    model_config = ConfigDict(extra="forbid")

    warnings: list[str] = []
    """Collection problems (a command failed, output truncated, sudo unavailable): partial facts."""

    append_only: ClassVar[frozenset[str]] = frozenset()
    """Diff-view collections where a key disappearing is not a change (e.g. log lines leaving the window)."""

    def diff_view(self) -> DiffView:
        return {}

    def metrics(self) -> dict[str, float]:
        return {}


class Check[F: Facts](ABC):
    name: ClassVar[str]
    facts_model: type[F]

    @abstractmethod
    async def collect(self, ctx: CheckContext, settings: dict[str, Any]) -> dict[str, Output]:
        """Run read-only commands; return raw outputs keyed by a stable name."""

    @abstractmethod
    def parse(self, raw: Raw, settings: dict[str, Any]) -> F:
        """Pure: raw outputs → facts. Must not raise on odd output; record a warning instead."""

    async def run(self, ctx: CheckContext, settings: dict[str, Any]) -> F:
        return self.parse(await self.collect(ctx, settings), settings)

    def carry(self, previous: dict[str, Any], facts: F) -> F:
        """Carry state from the previous snapshot of the same version into these facts (pure), e.g. the IPs
        an account has logged in from before. Called only when such a snapshot exists. Default: nothing."""
        return facts

    def guaranteed_findings(self, facts: dict[str, Any]) -> list[FindingItem]:
        """Findings that must be reported whenever the facts show them, with or without Claude (pure). The
        pipeline adds them unless Claude already reported the same subject. Default: none."""
        return []


# ── helpers shared by collectors and parsers ─────────────────────────────────

_BATCH_BUDGET = MAX_COMMAND_LENGTH - 1024  # room for quoting, `sudo -n --` and the runner's `timeout` wrapper


def batch_args(prefix: list[str], paths: list[str], budget: int = _BATCH_BUDGET) -> list[list[str]]:
    """Split paths into batches whose quoted command line (prefix + paths) stays under the budget."""
    base = len(shlex.join([*prefix, "--"])) + 1
    batches: list[list[str]] = []
    current: list[str] = []
    size = base
    for path in paths:
        cost = len(shlex.quote(path)) + 1
        if current and size + cost > budget:
            batches.append(current)
            current, size = [], base
        current.append(path)
        size += cost
    if current:
        batches.append(current)
    return batches


def merge_outputs(outs: list[Output]) -> Output:
    if not outs:
        return Output.missing()
    statuses = [o.exit_status for o in outs]
    status = None if any(s is None for s in statuses) else max(s for s in statuses if s is not None)
    return Output(
        stdout="".join(
            o.stdout if o.stdout.endswith("\n") or not o.stdout else o.stdout + "\n" for o in outs
        ),
        exit_status=status,
        stderr="".join(o.stderr for o in outs),
        truncated=any(o.truncated for o in outs),
        timed_out=any(o.timed_out for o in outs),
        sudo_failure=next((o.sudo_failure for o in outs if o.sudo_failure), None),
        sudo=any(o.sudo for o in outs),
        unprivileged=any(o.unprivileged for o in outs),
        command=outs[0].command,
    )


def output_warning(key: str, out: Output) -> str | None:
    """A human-readable warning when a command didn't give complete output, else None."""
    if out.sudo_failure:
        return f"{key}: sudo refused ({out.sudo_failure})"
    if out.timed_out:
        return f"{key}: timed out"
    if out.truncated:
        return f"{key}: output truncated at the size cap"
    if out.unprivileged:
        return f"{key}: read without sudo (unavailable), so root-only files are missing"
    return None


LOG_TAIL_BYTES = 4_000_000
"""How much of the end of a log a check reads (`tail -c`): well under the output cap, so a log with very long
lines (sudo logs every command in full, including handscheck's own) never comes back truncated."""


def tail_command(path: str, max_bytes: int = LOG_TAIL_BYTES) -> list[str]:
    """Read the end of a log by size, newest lines included (`tail -n` output cut at the cap loses those)."""
    return ["tail", "-c", str(max_bytes), path]


def last_lines(text: str, max_lines: int, max_bytes: int = LOG_TAIL_BYTES) -> str:
    """The last `max_lines` whole lines of a `tail -c max_bytes` read. When the read filled `max_bytes`, its
    first line starts mid-line and is dropped."""
    lines = text.splitlines()
    if lines and len(text.encode()) >= max_bytes:
        lines = lines[1:]
    return "\n".join(lines[-max_lines:] if max_lines > 0 else []) + ("\n" if lines and max_lines > 0 else "")


def split_fields(line: str, n: int, sep: str = "\t") -> list[str] | None:
    """Split a `find -printf` style line into exactly n fields (the last one keeps any extra separators)."""
    parts = line.split(sep, n - 1)
    return parts if len(parts) == n else None


def grep_h_lines(stdout: str) -> dict[str, list[str]]:
    """Parse `grep -H '' FILES` output (path:line) into {path: [lines]} (paths must not contain ':')."""
    files: dict[str, list[str]] = {}
    for line in stdout.splitlines():
        path, sep, rest = line.partition(":")
        if not sep:
            continue
        files.setdefault(path, []).append(rest)
    return files


_USR_MERGED = ("/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/")


def canonical_path(path: str) -> str:
    """Fold the /usr merge: /usr/lib/x and /lib/x are the same file on 24.04 (and dpkg may know either name).

    `dpkg -S /usr/lib/systemd/system/foo.service` fails when the package lists /lib/systemd/system/foo.service
    (the "/lib ↔ /usr/lib quirk"); comparing canonical paths avoids reporting such units as unpackaged.
    """
    for prefix in _USR_MERGED:
        if path.startswith("/usr" + prefix):
            return path[len("/usr") :]
    return path


def path_aliases(path: str) -> list[str]:
    """The path's names with and without the /usr merge prefix (canonical name first)."""
    canon = canonical_path(path)
    if canon.startswith(_USR_MERGED):
        return [canon, "/usr" + canon]
    return [canon]


def parse_dpkg_search(stdout: str) -> dict[str, list[str]]:
    """`dpkg-query -S PATTERN|PATH…` → {canonical path: [packages]}. Skips diversion lines."""
    owned: dict[str, list[str]] = {}
    for line in stdout.splitlines():
        if line.startswith(("diversion by", "local diversion")) or ": " not in line:
            continue
        pkgs, _, path = line.partition(": ")
        path = path.strip()
        if not path.startswith("/"):
            continue
        names = [p.strip().split(":")[0] for p in pkgs.split(",") if p.strip()]
        owned.setdefault(canonical_path(path), []).extend(names)
    return owned
