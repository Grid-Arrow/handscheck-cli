"""The worker API client (Sanctum bearer token). Workers only ever talk to the control plane over HTTPS."""

from __future__ import annotations

from typing import Any

import httpx
from pydantic import ValidationError

from handscheck import __version__
from handscheck.contracts import Catalog, Job, Result

API_PREFIX = "/worker-api/v1"


class WorkerAPIError(Exception):
    """The control plane rejected a request (or answered with something that isn't a valid job)."""


class WorkerAPI:
    def __init__(
        self, base_url: str, token: str, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + API_PREFIX,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": f"handscheck-worker/{__version__}",
            },
            timeout=httpx.Timeout(30.0, connect=10.0),
            transport=transport,
        )

    async def close(self) -> None:
        await self._http.aclose()

    async def heartbeat(self) -> None:
        await self._send("POST", "/heartbeat", json={"worker_version": __version__})

    async def put_catalog(self, catalog: Catalog) -> None:
        await self._send("PUT", "/catalog", json=catalog.model_dump(mode="json"))

    async def lease(self, kinds: list[str] | None = None) -> Job | None:
        """The next job of one of `kinds` for this worker, or None when the queue is empty. Without `kinds`
        the control plane only hands out scans (what workers before M5c could run)."""
        body: dict[str, Any] = {"worker_version": __version__}
        if kinds is not None:
            body["kinds"] = kinds
        response = await self._send("POST", "/jobs/lease", json=body)
        if response.status_code == 204:
            return None
        try:
            return Job.model_validate(response.json())
        except (ValidationError, ValueError) as exc:
            raise WorkerAPIError(f"the leased job is not a valid contract Job: {exc}") from exc

    async def post_result(self, result: Result) -> dict[str, Any]:
        response = await self._send(
            "POST", f"/jobs/{result.job_id}/results", json=result.model_dump(mode="json")
        )
        body: dict[str, Any] = response.json() if response.content else {}
        return body

    async def _send(self, method: str, path: str, *, json: Any) -> httpx.Response:
        response = await self._http.request(method, path, json=json)
        if response.status_code >= 400:
            detail = response.text[:500]
            raise WorkerAPIError(f"{method} {path}: HTTP {response.status_code}: {detail}")
        return response
