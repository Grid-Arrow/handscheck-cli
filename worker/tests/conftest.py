from collections.abc import AsyncIterator

import pytest

from tests.fakessh import FakeHost, start_fake_host


@pytest.fixture
async def fake_host() -> AsyncIterator[FakeHost]:
    async with start_fake_host() as host:
        yield host
