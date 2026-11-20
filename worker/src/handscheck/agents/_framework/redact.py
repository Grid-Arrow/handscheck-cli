"""Redact secrets and minimize PII before anything is sent to the Claude API (CLAUDE.md safety rule 6).

Applied to every string that leaves the worker for Claude: facts, diffs, change events, rules context and the
output of `run_readonly`. Redaction is conservative: it removes values, keeps the shape
("password = [REDACTED]") so the model can still reason about *where* a secret is, and never removes the
evidence a finding needs (paths,
usernames, IPs, code fingerprints).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]]] = [
    # Private keys (PEM/OpenSSH): the whole block.
    (
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S),
        "-----BEGIN PRIVATE KEY----- " + REDACTED + " -----END PRIVATE KEY-----",
    ),
    # Provider tokens with well-known prefixes.
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}"), "sk-ant-" + REDACTED),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    (re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{10,}"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), REDACTED),  # JWT
    # HTTP auth headers and cookies.
    (re.compile(r"(?i)\b(authorization|proxy-authorization)\s*:\s*\S+(\s+\S+)?"), r"\1: " + REDACTED),
    (re.compile(r"(?i)\b(cookie|set-cookie)\s*:\s*[^\n]+"), r"\1: " + REDACTED),
    (
        re.compile(r"(?i)\b(wordpress_logged_in_[a-f0-9]+|wordpress_sec_[a-f0-9]+|PHPSESSID)=[^;\s]+"),
        r"\1=" + REDACTED,
    ),
    # Credentials in URLs: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+):[^\s@/]+@"), r"\1:" + REDACTED + "@"),
    # WordPress config: define('DB_PASSWORD', '...'), salts and keys.
    (
        re.compile(
            r"""(?i)(define\s*\(\s*['"](?:DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|"""
            r"""AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT|[A-Z_]*(?:SECRET|TOKEN|API_KEY|PASSWORD))"""
            r"""['"]\s*,\s*)(['"]).*?\2"""
        ),
        r"\1\2" + REDACTED + r"\2",
    ),
    # key = value / key: value / KEY=value for secret-looking names (env files, ini, yaml, CLI flags).
    (
        re.compile(
            r"""(?i)\b([A-Z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"""
            r"""access[_-]?key|client[_-]?secret|auth[_-]?key|salt))(\s*[=:]\s*|=)(["']?)[^\s"',;]{3,}\3"""
        ),
        lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED}{m.group(3)}",
    ),
    (re.compile(r"(?i)(--password[= ])(\S+)"), r"\1" + REDACTED),
    (re.compile(r"(?i)\b(mysql|mysqldump|mysqladmin)\b([^\n]*?\s)-p(\S{3,})"), r"\1\2-p" + REDACTED),
    # Password hashes (shadow, bcrypt, phpass/WordPress).
    (re.compile(r"\$(?:1|2[aby]?|5|6|y|P|H)\$[./A-Za-z0-9$]{20,}"), REDACTED),
]

# PII minimization: keep the domain of an email (useful: admin@wordpress.com), mask most of the local part.
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])([A-Za-z0-9._%+-]*)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_KEEP_EMAIL_LOCAL = frozenset(
    {"admin", "root", "webmaster", "postmaster", "info", "noreply", "no-reply", "support"}
)


def _mask_email(m: re.Match[str]) -> str:
    local = m.group(1) + m.group(2)
    if local.lower() in _KEEP_EMAIL_LOCAL or local.lower().startswith("tempuser"):
        return m.group(0)
    return f"{m.group(1)}***@{m.group(3)}"


def redact_text(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return _EMAIL.sub(_mask_email, text)


def redact(value: Any) -> Any:
    """Redact every string in a JSON-like structure (dict keys are kept)."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value
