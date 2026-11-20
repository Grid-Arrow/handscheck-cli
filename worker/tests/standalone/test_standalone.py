"""Standalone state, keys and services (no Docker; host tests use the in-process SSH server)."""

import stat
from datetime import UTC, datetime
from pathlib import Path

import asyncssh
import pytest

from handscheck.config import Settings
from handscheck.standalone import service
from handscheck.standalone.keys import DEFAULT_KEY_NAME, authorized_keys_line, ensure_key
from handscheck.standalone.service import StandaloneError
from handscheck.standalone.state import HostExists, StandaloneState, StoredHost
from tests.fakessh import FakeHost


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(state_dir=tmp_path / "state", key_dir=tmp_path / "keys")


def test_state_crud(tmp_path: Path) -> None:
    state = StandaloneState.open(tmp_path)
    host = StoredHost(name="web1", address="10.0.0.5", user="handscheck", added_at=datetime.now(UTC))
    state.add_host(host)
    with pytest.raises(HostExists):
        state.add_host(host)
    state.pin_host_key("web1", "SHA256:abc")
    state.record_test("web1", ok=True)
    again = StandaloneState.open(tmp_path).get_host("web1")  # reopen: persisted, schema not re-created
    assert again is not None
    assert again.host_key_fingerprint == "SHA256:abc" and again.last_test_ok is True
    assert [h.name for h in state.list_hosts()] == ["web1"]
    assert state.remove_host("web1") and not state.remove_host("web1")
    assert state.get_host("web1") is None


def test_ensure_key_creates_once_with_private_permissions(tmp_path: Path) -> None:
    first = ensure_key(tmp_path / "keys")
    assert first.created
    assert stat.S_IMODE(first.path.stat().st_mode) == 0o600
    assert first.public_path.read_text().startswith("ssh-ed25519 ")
    assert first.public_line.endswith(" handscheck")
    second = ensure_key(tmp_path / "keys")
    assert not second.created
    assert second.fingerprint == first.fingerprint  # never overwritten


def test_authorized_keys_line() -> None:
    line = authorized_keys_line("ssh-ed25519 AAAA handscheck", ["203.0.113.7", "203.0.113.8"])
    assert line == (
        'from="203.0.113.7,203.0.113.8",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty '
        "ssh-ed25519 AAAA handscheck"
    )
    assert authorized_keys_line("ssh-ed25519 AAAA x").startswith('from="YOUR.WORKER.IP",')


def test_setup_and_host_management(settings: Settings) -> None:
    result = service.setup(settings, from_addrs=["198.51.100.1"])
    assert result.created and Path(result.key_path).name == DEFAULT_KEY_NAME
    assert 'from="198.51.100.1"' in result.authorized_keys_line

    host = service.add_host(settings, "lab-wp1", address="lab-wp1")
    assert host.key_path == result.key_path and host.user == "handscheck" and host.port == 22
    with pytest.raises(StandaloneError, match="already exists"):
        service.add_host(settings, "lab-wp1", address="lab-wp1")
    assert [h.name for h in service.list_hosts(settings)] == ["lab-wp1"]
    service.remove_host(settings, "lab-wp1")
    with pytest.raises(StandaloneError, match="unknown host"):
        service.remove_host(settings, "lab-wp1")


@pytest.mark.parametrize(
    ("name", "address", "user", "port", "match"),
    [
        ("Bad Name", "h", "handscheck", 22, "invalid host name"),
        ("ok", "-oProxyCommand=x", "handscheck", 22, "invalid address"),
        ("ok", "h h", "handscheck", 22, "invalid address"),
        ("ok", "h", "root;id", 22, "invalid SSH user"),
        ("ok", "h", "handscheck", 70000, "invalid port"),
    ],
)
def test_add_host_validates(
    settings: Settings, name: str, address: str, user: str, port: int, match: str
) -> None:
    service.setup(settings)
    with pytest.raises(StandaloneError, match=match):
        service.add_host(settings, name, address=address, user=user, port=port)


def test_add_host_needs_a_key(settings: Settings) -> None:
    with pytest.raises(StandaloneError, match="run `hc setup` first"):
        service.add_host(settings, "web1", address="10.0.0.5")


async def test_host_test_pins_on_first_contact(
    settings: Settings, fake_host: FakeHost, tmp_path: Path
) -> None:
    key_path = tmp_path / "client_key"
    fake_host.client_key.write_private_key(key_path)
    service.add_host(settings, "fake", address="127.0.0.1", port=fake_host.port, key_path=key_path)

    report = await service.run_host_test_async(settings, "fake")
    assert report.ok, report.errors
    stored = service.get_host(settings, "fake")
    assert stored.host_key_fingerprint == fake_host.host_key.get_fingerprint("sha256")
    assert stored.last_test_ok is True

    again = await service.run_host_test_async(settings, "fake")
    assert again.ok and again.host_key_pinned


async def test_host_test_detects_changed_host_key(
    settings: Settings, fake_host: FakeHost, tmp_path: Path
) -> None:
    key_path = tmp_path / "client_key"
    fake_host.client_key.write_private_key(key_path)
    service.add_host(settings, "fake", address="127.0.0.1", port=fake_host.port, key_path=key_path)
    other = asyncssh.generate_private_key("ssh-ed25519").get_fingerprint("sha256")
    service.open_state(settings).pin_host_key("fake", other)

    report = await service.run_host_test_async(settings, "fake")
    assert not report.ok and "changed" in report.errors[0]
    assert service.get_host(settings, "fake").host_key_fingerprint == other  # pin kept, not overwritten
    assert service.get_host(settings, "fake").last_test_ok is False
