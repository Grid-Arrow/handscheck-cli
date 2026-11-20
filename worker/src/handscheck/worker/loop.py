"""`hc worker`: heartbeat and catalog on start, then lease → run → post until stopped."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field

import anthropic

from handscheck.agents._framework.claude import MessagesAPI, SDKMessages
from handscheck.agents._framework.registry import catalog
from handscheck.agents._framework.services import HttpxProber, Services, WordPressOrgChecksums
from handscheck.config import Settings
from handscheck.worker.client import WorkerAPI, WorkerAPIError
from handscheck.worker.job import JobError, execute, supported_kinds

log = logging.getLogger("handscheck.worker")


@dataclass
class LoopStats:
    jobs: int = 0
    failed: int = 0
    results: list[dict[str, object]] = field(default_factory=list)


async def run_worker(
    settings: Settings,
    *,
    api: WorkerAPI,
    claude: MessagesAPI | None,
    once: bool = False,
    poll_seconds: float = 10.0,
    timeout: float = 60.0,
    stop: Callable[[], bool] = lambda: False,
) -> LoopStats:
    """Process jobs until `stop()` (or, with `once`, until the queue is empty)."""
    stats = LoopStats()
    await api.heartbeat()
    await api.put_catalog(catalog())
    http = HttpxProber()
    checksums = WordPressOrgChecksums(cache_dir=settings.state_dir / "cache" / "checksums")
    services = Services(http=http, checksums=checksums)
    kinds = supported_kinds(claude=claude is not None)
    try:
        while not stop():
            job = await api.lease(kinds)
            if job is None:
                if once:
                    break
                await asyncio.sleep(poll_seconds)
                await api.heartbeat()
                continue
            stats.jobs += 1
            log.info("job %s: %s on %s", job.job_id, job.kind, job.host.name if job.host else "-")
            try:
                result = await execute(job, services=services, api=claude, timeout=timeout)
            except JobError as exc:
                stats.failed += 1
                log.error("job %s: %s", job.job_id, exc)
                continue
            try:
                stats.results.append(await api.post_result(result))
            except WorkerAPIError as exc:
                stats.failed += 1
                log.error("job %s: posting the result failed: %s", job.job_id, exc)
    finally:
        await http.close()
        await checksums.close()
    return stats


def claude_api() -> tuple[MessagesAPI | None, anthropic.AsyncAnthropic | None]:
    """An Anthropic client when credentials are present (a job must also ask for Claude to use it)."""
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return None, None
    client = anthropic.AsyncAnthropic(max_retries=4)
    return SDKMessages(client), client


class WorkerConfigError(Exception):
    pass


def serve(settings: Settings, *, api_url: str | None, once: bool, poll_seconds: float) -> LoopStats:
    """`hc worker`: blocking entry point (Ctrl-C to stop)."""
    url = api_url or settings.api
    if not url:
        raise WorkerConfigError("no control plane URL: pass --api URL or set HANDSCHECK_API")
    if not settings.worker_token:
        raise WorkerConfigError(
            "no worker token: set HANDSCHECK_WORKER_TOKEN (php artisan handscheck:worker-token)"
        )

    async def main() -> LoopStats:
        api = WorkerAPI(url, settings.worker_token or "")
        claude, client = claude_api()
        try:
            return await run_worker(settings, api=api, claude=claude, once=once, poll_seconds=poll_seconds)
        finally:
            await api.close()
            if client is not None:
                await client.close()

    return asyncio.run(main())
