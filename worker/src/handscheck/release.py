"""Signed releases (Track S1): verify a release bundle against our key, and report this build's own hash.

Release bundles are signed with our Ed25519 key in minisign's format, so they verify with
`minisign -Vm FILE -P <key>` as well as with `hc verify FILE`:

- public key: base64("Ed" || key id (8 bytes) || Ed25519 public key (32 bytes))
- FILE.minisig: an untrusted comment line; base64("ED" || key id || Ed25519 signature of BLAKE2b-512(FILE));
  "trusted comment: …"; base64(Ed25519 signature of (signature || trusted comment)).

The trusted comment names the file, version, architecture and source commit, so a valid signature of one
bundle can't be passed off as another (`verify` checks the file name).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

RELEASE_KEYS: tuple[str, ...] = (
    # Key CE11AE108DF0E04D, generated 2026-11-20 (scripts/release/keygen.py in the private repo).
    "RWRN4PCNEK4Rzl4GQU1utXYD5YAHSdpv0ttLO9P0BqjdP/CyUU1mTeEj",
)
"""Our release signing public keys (minisign format); more than one while a key is being rotated (add the new
key next to the old one for a release, then drop the old one)."""

_PREHASHED = b"ED"
_LEGACY = b"Ed"


class SignatureError(Exception):
    """The bundle is not signed by one of our keys (or the signature or key is malformed)."""


@dataclass(frozen=True)
class PublicKey:
    key_id: bytes
    key: Ed25519PublicKey

    @property
    def key_id_hex(self) -> str:
        return self.key_id[::-1].hex().upper()  # how minisign prints it (a little-endian number)


@dataclass(frozen=True)
class Verified:
    key_id: str
    trusted_comment: str
    fields: dict[str, str]
    """The trusted comment's `name:value` fields (file, version, arch, source, timestamp)."""


def _b64(text: str, what: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureError(f"{what} is not valid base64") from exc


def parse_public_key(text: str) -> PublicKey:
    """A minisign public key: the `RW…` line alone, or the .pub file (comment line + key line)."""
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    line = next((ln for ln in lines if not ln.startswith("untrusted comment:")), "")
    raw = _b64(line, "public key")
    if len(raw) != 42 or raw[:2] != _LEGACY:
        raise SignatureError("not a minisign Ed25519 public key")
    return PublicKey(key_id=raw[2:10], key=Ed25519PublicKey.from_public_bytes(raw[10:]))


def parse_comment(comment: str) -> dict[str, str]:
    fields = {}
    for part in comment.replace("\t", " ").split():
        name, sep, value = part.partition(":")
        if sep:
            fields[name] = value
    return fields


def verify(path: Path, signature: str, keys: tuple[str, ...] | list[str] = RELEASE_KEYS) -> Verified:
    """Check `path` against its minisign signature text and our keys. Raises SignatureError."""
    if not keys:
        raise SignatureError("this build has no release key to verify against")
    lines = signature.strip().splitlines()
    if len(lines) != 4 or not lines[0].startswith("untrusted comment:"):
        raise SignatureError("not a minisign signature file")
    if not lines[2].startswith("trusted comment: "):
        raise SignatureError("signature has no trusted comment")
    sig_raw = _b64(lines[1], "signature")
    if len(sig_raw) != 74:
        raise SignatureError("signature has the wrong length")
    algorithm, key_id, sig = sig_raw[:2], sig_raw[2:10], sig_raw[10:]
    if algorithm != _PREHASHED:
        raise SignatureError("only prehashed (ED) signatures are accepted")
    by_id = {k.key_id: k for k in (parse_public_key(text) for text in keys)}
    public = by_id.get(key_id)
    if public is None:
        raise SignatureError(f"signed with an unknown key ({key_id[::-1].hex().upper()})")
    try:
        public.key.verify(sig, _blake2b(path))
    except InvalidSignature as exc:
        raise SignatureError(
            f"{path.name}: the signature does not match the file (modified or replaced)"
        ) from exc
    trusted = lines[2].removeprefix("trusted comment: ")
    global_sig = _b64(lines[3], "global signature")
    try:
        public.key.verify(global_sig, sig + trusted.encode())
    except InvalidSignature as exc:
        raise SignatureError("the trusted comment was modified") from exc
    fields = parse_comment(trusted)
    if fields.get("file") not in (None, path.name):
        raise SignatureError(f"the signature is for {fields['file']!r}, not {path.name!r}")
    return Verified(key_id=public.key_id_hex, trusted_comment=trusted, fields=fields)


# ── signing (used by the release workflow and the tests; the key itself never ships) ────────────────────────


def key_id_for(private: Ed25519PrivateKey) -> bytes:
    """A stable 8-byte key id derived from the public key (minisign picks random ids; any 8 bytes work)."""
    return hashlib.sha256(_raw_public(private)).digest()[:8]


def public_key_text(private: Ed25519PrivateKey) -> str:
    """The minisign public key file (.pub) for a private key."""
    key_id = key_id_for(private)
    line = base64.b64encode(_LEGACY + key_id + _raw_public(private)).decode()
    return f"untrusted comment: minisign public key {key_id[::-1].hex().upper()}\n{line}\n"


def sign(path: Path, private: Ed25519PrivateKey, trusted_comment: str) -> str:
    """A prehashed minisign signature of `path` (the .minisig file's text)."""
    if "\n" in trusted_comment or "\r" in trusted_comment:
        raise ValueError("the trusted comment must be one line")
    key_id = key_id_for(private)
    sig = private.sign(_blake2b(path))
    global_sig = private.sign(sig + trusted_comment.encode())
    return (
        f"untrusted comment: handscheck release signature (verify: hc verify, or minisign -Vm)\n"
        f"{base64.b64encode(_PREHASHED + key_id + sig).decode()}\n"
        f"trusted comment: {trusted_comment}\n"
        f"{base64.b64encode(global_sig).decode()}\n"
    )


def _raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _blake2b(path: Path) -> bytes:
    h = hashlib.blake2b(digest_size=64)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


# ── this build ───────────────────────────────────────────────────────────────


def code_hash() -> str:
    """sha256 over the installed handscheck package (each file's path and bytes, in order), so a run can
    report exactly which code it was. Compiled caches are left out."""
    package = Path(__file__).resolve().parent
    h = hashlib.sha256()
    for path in sorted(p for p in package.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        h.update(path.relative_to(package).as_posix().encode() + b"\0")
        h.update(path.read_bytes())
    return h.hexdigest()


def bundle_info() -> dict[str, str] | None:
    """The RELEASE file a self-hosted bundle carries next to its Python (/opt/handscheck/RELEASE), or None
    when this isn't a bundle (development, the worker)."""
    release = Path(sys.prefix).resolve().parent / "RELEASE"
    try:
        data = json.loads(release.read_text())
    except (OSError, ValueError):
        return None
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else None
