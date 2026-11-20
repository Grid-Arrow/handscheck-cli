"""Worker-side services for checks: HTTP probes of a host's sites, and WordPress.org checksums.

Both run **on the worker**, never on the target host (CLAUDE.md safety rule 1: no network fetches from a
target). - `HttpProber` sends a few GET requests to a site, addressed to the host itself (the Host header /
SNI carry the   site name), like a visitor would. No credentials, no POST, no query strings with payloads,
bodies capped. - `ChecksumSource` fetches the official md5 checksums for a WordPress core version or a
wordpress.org plugin   version; the host only runs `md5sum` on its own files and the comparison happens here.

Checks get them through `CheckContext.services`; tests pass fakes or recorded responses.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

import httpx
from pydantic import BaseModel

from handscheck import __version__

USER_AGENT = f"handscheck/{__version__} (+https://handscheck.ai; read-only check)"
MAX_BODY = 16_384
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~/%-]*(?:\?action=handscheck_[a-z0-9_]+)?$")
"""A plain path. The only query allowed is `?action=handscheck_…`: an AJAX action of our own (the virtual
patch's check), never one that could reach site code such as a web shell's `?cmd=`."""


class HttpResponse(BaseModel):
    url: str
    status: int | None = None
    """None when the request failed (see `error`)."""
    body: str = ""
    """At most MAX_BODY characters."""
    location: str | None = None
    content_type: str | None = None
    error: str | None = None
    elapsed_s: float | None = None
    """Total time for the request (headers and the body read, capped at MAX_BODY), from the worker."""
    ttfb_s: float | None = None
    """Time until the response headers arrived."""


class HttpProber(Protocol):
    async def get(self, address: str, site: str, path: str) -> HttpResponse: ...


class ChecksumUnavailable(Exception):
    """The checksum service could not be reached (network error, rate limit): try again next run."""


class ChecksumSource(Protocol):
    async def core(self, version: str, locale: str) -> dict[str, str] | None:
        """{relative path: md5} for a core release, or None if wordpress.org has none for it."""
        ...

    async def plugin(self, slug: str, version: str) -> dict[str, list[str]] | None:
        """{path inside the plugin: [md5, …]} for a wordpress.org plugin version, or None if not hosted there
        (premium and custom plugins)."""
        ...


@dataclass
class Services:
    http: HttpProber | None = None
    checksums: ChecksumSource | None = None


# ── real implementations ─────────────────────────────────────────────────────


def check_probe_path(path: str) -> str:
    if not _SAFE_PATH.match(path) or ".." in path.split("?", 1)[0].split("/"):
        raise ValueError(f"refusing to probe {path!r}: plain paths only")
    return path


@dataclass
class HttpxProber:
    """GET http://<address><path> with Host: <site>; on a redirect to https, retry with SNI <site>."""

    timeout: float = 10.0
    _client: httpx.AsyncClient | None = field(default=None, repr=False)

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                verify=False,  # noqa: S501 - we probe the host directly by address; trust is not the point
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"},
            )
        return self._client

    async def get(self, address: str, site: str, path: str) -> HttpResponse:
        check_probe_path(path)
        response = await self._get(f"http://{_host(address)}{quote(path, safe='/%~?=&')}", site)
        if response.status in (301, 302, 307, 308) and (response.location or "").startswith("https://"):
            response = await self._get(
                f"https://{_host(address)}{quote(path, safe='/%~?=&')}", site, sni=site
            )
        return response

    async def _get(self, url: str, site: str, sni: str | None = None) -> HttpResponse:
        extensions = {"sni_hostname": sni} if sni else {}
        started = time.monotonic()
        try:
            async with self._http().stream("GET", url, headers={"Host": site}, extensions=extensions) as r:
                ttfb = time.monotonic() - started
                body = b""
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY:
                        break
                return HttpResponse(
                    url=url,
                    status=r.status_code,
                    body=body[:MAX_BODY].decode("utf-8", errors="replace"),
                    location=r.headers.get("location"),
                    content_type=r.headers.get("content-type"),
                    elapsed_s=round(time.monotonic() - started, 3),
                    ttfb_s=round(ttfb, 3),
                )
        except httpx.HTTPError as exc:
            return HttpResponse(
                url=url,
                error=f"{type(exc).__name__}: {exc}"[:300],
                elapsed_s=round(time.monotonic() - started, 3),
            )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _host(address: str) -> str:
    return f"[{address}]" if ":" in address and not address.startswith("[") else address


@dataclass
class WordPressOrgChecksums:
    """Official checksums from api.wordpress.org / downloads.wordpress.org, cached on disk."""

    cache_dir: Path | None = None
    timeout: float = 20.0
    retries: int = 3
    backoff_s: float = 2.0
    _client: httpx.AsyncClient | None = field(default=None, repr=False)

    async def core(self, version: str, locale: str) -> dict[str, str] | None:
        url = f"https://api.wordpress.org/core/checksums/1.0/?version={quote(version)}&locale={quote(locale)}"
        data = await self._fetch(url)
        if not data:
            return None
        checksums = data.get("checksums")
        if isinstance(checksums, dict) and version in checksums and isinstance(checksums[version], dict):
            checksums = checksums[version]  # older API shape: keyed by version
        if not isinstance(checksums, dict) or not checksums:
            return None
        return {str(k): str(v) for k, v in checksums.items()}

    async def plugin(self, slug: str, version: str) -> dict[str, list[str]] | None:
        if not re.fullmatch(r"[a-z0-9_-]{1,100}", slug) or not re.fullmatch(
            r"[0-9A-Za-z.+_-]{1,40}", version
        ):
            return None
        data = await self._fetch(f"https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json")
        files = data.get("files") if data else None
        if not isinstance(files, dict) or not files:
            return None
        out: dict[str, list[str]] = {}
        for path, entry in files.items():
            md5 = entry.get("md5") if isinstance(entry, dict) else None
            out[str(path)] = [str(m) for m in md5] if isinstance(md5, list) else [str(md5)] if md5 else []
        return out

    async def _fetch(self, url: str) -> dict[str, Any] | None:
        cached = self._cache_path(url)
        if cached and cached.is_file():
            data: Any = json.loads(cached.read_text())
            return data if isinstance(data, dict) else None
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout, headers={"User-Agent": USER_AGENT})
        r = await self._get_with_backoff(url)
        if r.status_code == 404:
            result: dict[str, Any] | None = None
        elif r.status_code != 200:
            raise ChecksumUnavailable(f"{url}: HTTP {r.status_code}")
        else:
            try:
                parsed = r.json()
            except ValueError as exc:
                raise ChecksumUnavailable(f"{url}: invalid JSON") from exc
            result = parsed if isinstance(parsed, dict) else None
        if cached:
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_text(json.dumps(result))
        return result

    async def _get_with_backoff(self, url: str) -> httpx.Response:
        """wordpress.org rate-limits bursts (HTTP 429): wait (Retry-After, capped) and retry a few times."""
        assert self._client is not None  # noqa: S101 - set by _fetch
        attempt = 0
        while True:
            try:
                r = await self._client.get(url)
            except httpx.HTTPError as exc:
                raise ChecksumUnavailable(f"{url}: {type(exc).__name__}") from exc
            if r.status_code not in (429, 503) or attempt >= self.retries:
                return r
            try:
                wait = float(r.headers.get("retry-after", ""))
            except ValueError:
                wait = self.backoff_s * 2**attempt
            await asyncio.sleep(min(max(wait, 0.0), 30.0))
            attempt += 1

    def _cache_path(self, url: str) -> Path | None:
        if self.cache_dir is None:
            return None
        return self.cache_dir / (hashlib.sha256(url.encode()).hexdigest()[:32] + ".json")

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
