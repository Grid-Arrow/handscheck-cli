"""Record real command output from the lab and replay it offline, still through the policy.

`ReplayRunner` answers each command from a capture file (keyed by the policy-normalized command), so unit
tests run the real collectors, parsers and pipeline without SSH, and prove every command they send is allowed
by the policy. Captures are made from the synthetic lab hosts with `tests/agents/capture.py`.
"""

from __future__ import annotations

import gzip
import json
import shlex
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from handscheck.agents._framework.services import (
    ChecksumSource,
    HttpProber,
    HttpResponse,
    Services,
    check_probe_path,
)
from handscheck.ssh.policy import DEFAULT_POLICY
from handscheck.ssh.runner import CommandResult, SSHRunner

CAPTURED = Path(__file__).parent / "captured"


def _argv(command: str | Sequence[str], sudo: bool, sudo_user: str | None) -> str | list[str]:
    if not sudo:
        return command if isinstance(command, str) else list(command)
    prefix = ["sudo", "-n", *(["-u", sudo_user] if sudo_user else []), "--"]
    return f"{shlex.join(prefix)} {command}" if isinstance(command, str) else [*prefix, *command]


def load_capture(host: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(gzip.decompress((CAPTURED / f"{host}.json.gz").read_bytes()))
    return data


class ReplayRunner:
    def __init__(
        self,
        results: dict[str, CommandResult],
        *,
        host_key_fingerprint: str | None = None,
        strict: bool = True,
    ) -> None:
        self.results = results
        self.strict = strict
        """Non-strict: commands that weren't captured (an agent's own tool calls) fail like a missing file."""
        self.commands_run: list[str] = []
        self.host_key_fingerprint = host_key_fingerprint

    @classmethod
    def load(cls, host: str, *, strict: bool | None = None) -> ReplayRunner:
        """`strict` defaults to True, except in the public build (tests/public_build.py)."""
        data = load_capture(host)
        results = {r["command"]: CommandResult(**r) for r in data["commands"]}
        if strict is None:
            from tests.public_build import PUBLIC_BUILD_RULES

            strict = not PUBLIC_BUILD_RULES
        return cls(results, host_key_fingerprint=data.get("host_key_fingerprint"), strict=strict)

    async def run(
        self,
        command: str | Sequence[str],
        *,
        sudo: bool = False,
        sudo_user: str | None = None,
        timeout: float | None = None,
        max_output: int | None = None,
    ) -> CommandResult:
        decision = DEFAULT_POLICY.enforce(_argv(command, sudo, sudo_user))  # raises PolicyViolation
        self.commands_run.append(decision.command)
        try:
            return self.results[decision.command]
        except KeyError:
            if not self.strict:
                return CommandResult(
                    command=decision.command,
                    exit_status=1,
                    stdout="",
                    stderr="(not available in this replayed lab capture)\n",
                )
            raise AssertionError(
                f"no captured output for {decision.command!r}: re-capture (tests/agents/capture.py)"
            ) from None

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None


class RecordingRunner:
    """Wraps a real SSHRunner and keeps every result."""

    def __init__(self, inner: SSHRunner) -> None:
        self.inner = inner
        self.records: list[dict[str, Any]] = []

    async def run(
        self,
        command: str | Sequence[str],
        *,
        sudo: bool = False,
        sudo_user: str | None = None,
        timeout: float | None = None,
        max_output: int | None = None,
    ) -> CommandResult:
        result = await self.inner.run(
            command, sudo=sudo, sudo_user=sudo_user, timeout=timeout, max_output=max_output
        )
        record = asdict(result)
        record["duration_s"] = 0.0
        self.records.append(record)
        return result


# ── worker-side services ─────────────────────────────────────────────────────


class ReplayHttp:
    def __init__(self, responses: dict[str, dict[str, Any]]) -> None:
        self.responses = responses
        self.requests: list[str] = []

    async def get(self, address: str, site: str, path: str) -> HttpResponse:
        check_probe_path(path)
        key = f"{site} {path}"
        self.requests.append(key)
        if key not in self.responses:
            raise AssertionError(f"no captured HTTP response for {key!r}: re-capture")
        return HttpResponse.model_validate(self.responses[key])


class ReplayChecksums:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    async def core(self, version: str, locale: str) -> dict[str, str] | None:
        result: dict[str, str] | None = self.data[f"core {version} {locale}"]
        return result

    async def plugin(self, slug: str, version: str) -> dict[str, list[str]] | None:
        result: dict[str, list[str]] | None = self.data[f"plugin {slug} {version}"]
        return result


def replay_services(host: str) -> Services:
    data = load_capture(host)
    return Services(
        http=ReplayHttp(data.get("http", {})), checksums=ReplayChecksums(data.get("checksums", {}))
    )


class RecordingHttp:
    def __init__(self, inner: HttpProber) -> None:
        self.inner = inner
        self.responses: dict[str, dict[str, Any]] = {}

    async def get(self, address: str, site: str, path: str) -> HttpResponse:
        response = await self.inner.get(address, site, path)
        self.responses[f"{site} {path}"] = response.model_dump()
        return response


class RecordingChecksums:
    """Keeps what the checks asked for; core checksums are trimmed to .php files (all the checks use)."""

    def __init__(self, inner: ChecksumSource) -> None:
        self.inner = inner
        self.data: dict[str, Any] = {}

    async def core(self, version: str, locale: str) -> dict[str, str] | None:
        result = await self.inner.core(version, locale)
        trimmed = {k: v for k, v in result.items() if k.endswith(".php")} if result else result
        self.data[f"core {version} {locale}"] = trimmed
        return trimmed

    async def plugin(self, slug: str, version: str) -> dict[str, list[str]] | None:
        result = await self.inner.plugin(slug, version)
        self.data[f"plugin {slug} {version}"] = result
        return result
