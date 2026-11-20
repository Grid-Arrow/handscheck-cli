from pathlib import Path

import httpx
import pytest

from handscheck.agents._framework.check import CheckContext, Output, batch_args, merge_outputs
from handscheck.agents._framework.services import (
    ChecksumUnavailable,
    HttpxProber,
    WordPressOrgChecksums,
    check_probe_path,
)
from handscheck.sites.discovery import DISCOVERY
from handscheck.ssh.policy import DEFAULT_POLICY, MAX_COMMAND_LENGTH
from tests.agents.replay import ReplayRunner


async def test_prober_sends_host_header_and_follows_https_redirect() -> None:
    seen: list[tuple[str, str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers["host"], request.extensions.get("sni_hostname")))
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://shop.example.test/x/"})
        return httpx.Response(200, text="<title>Index of /x</title>" + "a" * 100_000)

    prober = HttpxProber()
    prober._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    response = await prober.get("10.0.0.5", "shop.example.test", "/x/")
    await prober.close()
    assert seen == [
        ("http://10.0.0.5/x/", "shop.example.test", None),
        ("https://10.0.0.5/x/", "shop.example.test", "shop.example.test"),
    ]
    assert response.status == 200 and response.body.startswith("<title>Index of")
    assert len(response.body) <= 16_384


async def test_prober_reports_errors_and_refuses_odd_paths() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    prober = HttpxProber()
    prober._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    response = await prober.get("10.0.0.5", "s", "/")
    assert response.status is None and response.error and "ConnectError" in response.error
    for path in (
        "relative",
        "/a/../etc/passwd",
        "/x?cmd=id",
        "/a b",
        "http://evil/",
        "/x?action=revslider_ajax",
    ):
        with pytest.raises(ValueError):
            check_probe_path(path)
    assert check_probe_path("/wp-admin/admin-ajax.php?action=handscheck_virtual_patch_check")
    await prober.close()


async def test_checksums_fetch_parse_and_cache(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "core/checksums" in str(request.url):
            return httpx.Response(200, json={"checksums": {"wp-load.php": "abc", "index.php": "def"}})
        if "/akismet/5.3.json" in str(request.url):
            return httpx.Response(
                200, json={"files": {"akismet.php": {"md5": "123"}, "a.php": {"md5": ["4", "5"]}}}
            )
        if "/premium/" in str(request.url):
            return httpx.Response(404)
        return httpx.Response(503)

    source = WordPressOrgChecksums(cache_dir=tmp_path, backoff_s=0)
    source._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert await source.core("6.7.2", "en_US") == {"wp-load.php": "abc", "index.php": "def"}
    assert await source.plugin("akismet", "5.3") == {"akismet.php": ["123"], "a.php": ["4", "5"]}
    assert await source.plugin("premium", "1.0") is None
    assert await source.plugin("../etc", "1.0") is None  # not a slug: no request
    with pytest.raises(ChecksumUnavailable):
        await source.plugin("down", "1.0")
    before = len(calls)
    assert await source.core("6.7.2", "en_US")  # from the cache
    assert await source.plugin("premium", "1.0") is None  # a cached 404
    assert len(calls) == before
    assert len(list(tmp_path.iterdir())) == 3  # noqa: ASYNC240  # core, akismet, premium (404 cached as null)
    await source.close()


def test_batches_stay_under_the_policy_limit() -> None:
    paths = [
        f"/var/www/site/wp-content/plugins/plugin-{i:04d}/includes/class-something-{i}.php"
        for i in range(500)
    ]
    batches = batch_args(["md5sum"], paths)
    assert [p for b in batches for p in b] == paths and len(batches) > 3
    for batch in batches:
        decision = DEFAULT_POLICY.check(["sudo", "-n", "--", "md5sum", "--", *batch])
        assert decision.allowed and len(decision.command) < MAX_COMMAND_LENGTH - 100


def test_merge_outputs() -> None:
    merged = merge_outputs(
        [
            Output(stdout="a\n"),
            Output(stdout="b", exit_status=1, stderr="x\n"),
            Output(stdout="", truncated=True),
        ]
    )
    assert (
        merged.stdout == "a\nb\n" and merged.exit_status == 1 and merged.truncated and merged.stderr == "x\n"
    )
    assert merge_outputs([]).exit_status is None


async def test_for_site_shares_the_command_cache() -> None:
    ctx = CheckContext(runner=ReplayRunner.load("lab-wp1"), host="lab-wp1")
    first = await ctx.run(["id", "-un"])
    inventory = await DISCOVERY.run(ctx, {})
    site_ctx = ctx.for_site(inventory.sites[0])
    assert site_ctx.site is inventory.sites[0] and ctx.site is None
    assert await site_ctx.run(["id", "-un"]) is first
    assert site_ctx.commands is ctx.commands


async def test_checksums_back_off_on_rate_limits() -> None:
    responses = iter(
        [
            httpx.Response(429, headers={"retry-after": "0"}),
            httpx.Response(429),
            httpx.Response(200, json={"files": {"a.php": {"md5": "1"}}}),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    source = WordPressOrgChecksums(backoff_s=0)
    source._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert await source.plugin("akismet", "5.3") == {"a.php": ["1"]}
    always = WordPressOrgChecksums(backoff_s=0, retries=1)
    always._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(429)))
    with pytest.raises(ChecksumUnavailable, match="429"):
        await always.plugin("akismet", "5.3")
    await source.close()
    await always.close()
