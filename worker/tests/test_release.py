"""Signed releases (Track S1): minisign-compatible signatures, `hc verify`, and `hc version`'s own hash.

`tests/data/minisign/` holds a file signed by the real minisign 0.11 tool (Debian bookworm) with a throwaway
key, so the verifier is checked against minisign's own output, not only against our signer.
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from handscheck import release
from handscheck.cli import app
from handscheck.release import SignatureError, parse_public_key, public_key_text, sign, verify

DATA = Path(__file__).parent / "data" / "minisign"
cli = CliRunner()


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    path = tmp_path / "handscheck-0.1.0-linux-amd64.tar.gz"
    path.write_bytes(b"\x1f\x8b pretend this is a bundle" * 1000)
    return path


def _comment(name: str) -> str:
    return f"timestamp:1763640000 file:{name} version:0.1.0 arch:amd64 source:26294f60d10e"


def test_real_minisign_signature_verifies() -> None:
    result = verify(
        DATA / "real.txt", (DATA / "real.txt.minisig").read_text(), [(DATA / "real.pub").read_text()]
    )
    assert result.fields == {"file": "real.txt", "version": "test"}
    assert result.key_id == parse_public_key((DATA / "real.pub").read_text()).key_id_hex


def test_real_minisign_signature_of_other_content_fails(tmp_path: Path) -> None:
    other = tmp_path / "real.txt"
    other.write_text("a different file with the same name\n")
    with pytest.raises(SignatureError, match="does not match the file"):
        verify(other, (DATA / "real.txt.minisig").read_text(), [(DATA / "real.pub").read_text()])


def test_sign_then_verify(key: Ed25519PrivateKey, bundle: Path) -> None:
    sig = sign(bundle, key, _comment(bundle.name))
    result = verify(bundle, sig, [public_key_text(key)])
    assert result.fields["version"] == "0.1.0" and result.fields["source"] == "26294f60d10e"
    assert sig.splitlines()[1].startswith("RUT") or sig.splitlines()[1][:2] == "RU"  # base64 of "ED"


def test_public_key_matches_minisign_layout(key: Ed25519PrivateKey) -> None:
    text = public_key_text(key)
    comment, line = text.strip().splitlines()
    assert comment.startswith("untrusted comment: minisign public key ")
    assert line.startswith("RW") and len(line) == 56  # base64 of "Ed" + id + key, as minisign's .pub files
    assert parse_public_key(line).key_id_hex == comment.rsplit(" ", 1)[1]


def test_tampering_is_caught(key: Ed25519PrivateKey, bundle: Path, tmp_path: Path) -> None:
    pub = [public_key_text(key)]
    sig = sign(bundle, key, _comment(bundle.name))
    bundle.write_bytes(bundle.read_bytes() + b"x")
    with pytest.raises(SignatureError, match="does not match"):
        verify(bundle, sig, pub)

    fresh = tmp_path / "fresh" / bundle.name
    fresh.parent.mkdir()
    fresh.write_bytes(b"content")
    sig = sign(fresh, key, _comment(fresh.name))
    lines = sig.splitlines()
    forged = "\n".join([lines[0], lines[1], lines[2].replace("0.1.0", "9.9.9"), lines[3]])
    with pytest.raises(SignatureError, match="trusted comment was modified"):
        verify(fresh, forged, pub)


def test_wrong_key_name_and_garbage(key: Ed25519PrivateKey, bundle: Path, tmp_path: Path) -> None:
    sig = sign(bundle, key, _comment(bundle.name))
    with pytest.raises(SignatureError, match="unknown key"):
        verify(bundle, sig, [public_key_text(Ed25519PrivateKey.generate())])
    renamed = tmp_path / "handscheck-0.1.0-linux-arm64.tar.gz"
    renamed.write_bytes(bundle.read_bytes())
    with pytest.raises(SignatureError, match="is for"):
        verify(renamed, sig, [public_key_text(key)])
    with pytest.raises(SignatureError, match="no release key"):
        verify(bundle, sig, [])
    for bad in ["", "untrusted comment: x\n!!!\ntrusted comment: y\nzz\n", "just text"]:
        with pytest.raises(SignatureError):
            verify(bundle, bad, [public_key_text(key)])
    legacy = sig.splitlines()
    legacy[1] = "RW" + legacy[1][2:]  # claims the legacy (non-prehashed) algorithm
    with pytest.raises(SignatureError):
        verify(bundle, "\n".join(legacy), [public_key_text(key)])


def test_hc_verify(key: Ed25519PrivateKey, bundle: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release, "RELEASE_KEYS", (public_key_text(key),))
    monkeypatch.setattr(release.verify, "__defaults__", ((public_key_text(key),),))
    Path(f"{bundle}.minisig").write_text(sign(bundle, key, _comment(bundle.name)))
    ok = cli.invoke(app, ["verify", str(bundle), "--json"])
    assert ok.exit_code == 0, ok.output
    assert json.loads(ok.output)["verified"] is True and json.loads(ok.output)["arch"] == "amd64"
    human = cli.invoke(app, ["verify", str(bundle)])
    assert "verified" in human.output and "0.1.0 amd64" in human.output

    bundle.write_bytes(b"tampered")
    bad = cli.invoke(app, ["verify", str(bundle), "--json"])
    assert bad.exit_code == 1 and "NOT verified" in json.loads(bad.output)["error"]
    missing = cli.invoke(app, ["verify", str(bundle.with_name("nope.tar.gz"))])
    assert missing.exit_code == 1 and "no such file" in missing.output


def test_hc_version_reports_bundle_and_code_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = json.loads(cli.invoke(app, ["version", "--json"]).output)
    assert out["bundle"] is None and len(out["code_sha256"]) == 64
    assert out["code_sha256"] == release.code_hash()  # stable between calls

    prefix = tmp_path / "handscheck" / "python"
    prefix.mkdir(parents=True)
    (tmp_path / "handscheck" / "RELEASE").write_text(
        json.dumps({"version": "0.1.0", "arch": "arm64", "source": "26294f60d10efa70"})
    )
    monkeypatch.setattr(release.sys, "prefix", str(prefix))
    out = json.loads(cli.invoke(app, ["version", "--json"]).output)
    assert out["bundle"] == {"version": "0.1.0", "arch": "arm64", "source": "26294f60d10efa70"}
    human = cli.invoke(app, ["version"]).output
    assert human.splitlines()[0].startswith("handscheck ") and "bundle: 0.1.0 arm64" in human


def test_built_in_release_key() -> None:
    """The CLI's key is the one we publish (public/overlay here, the repository root in the public repo)."""
    assert [parse_public_key(k).key_id_hex for k in release.RELEASE_KEYS] == ["CE11AE108DF0E04D"]
    root = Path(__file__).resolve().parents[2]
    published = [
        p
        for p in (root / "public/overlay/handscheck-release.pub", root / "handscheck-release.pub")
        if p.is_file()
    ]
    assert published
    for path in published:
        assert parse_public_key(path.read_text()).key_id == parse_public_key(release.RELEASE_KEYS[0]).key_id
