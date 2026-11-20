"""Standalone state: a SQLite file under HANDSCHECK_STATE_DIR. Dev/admin only, never the product's data."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from handscheck.contracts import HostAgentState, SettingChange

STATE_FILE = "handscheck.sqlite3"
SCHEMA_VERSION = 7

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    name TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    user TEXT NOT NULL,
    key_path TEXT,
    host_key_fingerprint TEXT,
    added_at TEXT NOT NULL,
    last_tested_at TEXT,
    last_test_ok INTEGER,
    local INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    status TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_host ON runs (host, id);
CREATE TABLE IF NOT EXISTS snapshots (
    run_id INTEGER NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    agent TEXT NOT NULL,
    site TEXT NOT NULL DEFAULT '',
    agent_version INTEGER NOT NULL,
    taken_at TEXT NOT NULL,
    facts TEXT NOT NULL,
    PRIMARY KEY (run_id, agent, site)
);
CREATE INDEX IF NOT EXISTS snapshots_lookup ON snapshots (host, agent, site, run_id);
CREATE TABLE IF NOT EXISTS findings (
    host TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    agent TEXT NOT NULL,
    site TEXT,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_run_id INTEGER,
    data TEXT NOT NULL,
    note TEXT,
    PRIMARY KEY (host, dedupe_key)
);
CREATE INDEX IF NOT EXISTS findings_status ON findings (status, host);
CREATE TABLE IF NOT EXISTS host_settings (
    host TEXT NOT NULL,
    agent TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    settings TEXT NOT NULL,
    source TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (host, agent)
);
CREATE TABLE IF NOT EXISTS fix_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fix_id TEXT NOT NULL,
    host TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    event TEXT NOT NULL,
    mode TEXT NOT NULL,
    action TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL,
    user TEXT NOT NULL,
    at TEXT NOT NULL,
    status TEXT,
    message TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS fix_log_lookup ON fix_log (host, dedupe_key, id);
CREATE TRIGGER IF NOT EXISTS fix_log_no_update BEFORE UPDATE ON fix_log
    BEGIN SELECT RAISE(ABORT, 'fix_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS fix_log_no_delete BEFORE DELETE ON fix_log
    BEGIN SELECT RAISE(ABORT, 'fix_log is append-only'); END;
"""

# v2 → v3: snapshots gain `site` ('' for host-level agents) and it joins the primary key.
_MIGRATE_V2 = """
ALTER TABLE snapshots RENAME TO snapshots_v2;
CREATE TABLE snapshots (
    run_id INTEGER NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    agent TEXT NOT NULL,
    site TEXT NOT NULL DEFAULT '',
    agent_version INTEGER NOT NULL,
    taken_at TEXT NOT NULL,
    facts TEXT NOT NULL,
    PRIMARY KEY (run_id, agent, site)
);
INSERT INTO snapshots (run_id, host, agent, site, agent_version, taken_at, facts)
    SELECT run_id, host, agent, '', agent_version, taken_at, facts FROM snapshots_v2;
DROP TABLE snapshots_v2;
"""


class StoredHost(BaseModel):
    name: str
    address: str
    port: int = 22
    user: str
    key_path: str | None = None
    host_key_fingerprint: str | None = None
    added_at: datetime
    last_tested_at: datetime | None = None
    last_test_ok: bool | None = None
    local: bool = False
    """Checked on this machine by `hc check --local` (no SSH), not over SSH."""


class HostExists(Exception):
    pass


class StoredSnapshot(BaseModel):
    run_id: int
    agent: str
    site: str | None = None
    agent_version: int
    taken_at: datetime
    facts: dict[str, Any]


FindingStatus = Literal["new", "open", "acknowledged", "resolved", "false_positive"]
ACTIVE = ("new", "open", "acknowledged")


class StoredFinding(BaseModel):
    host: str
    dedupe_key: str
    agent: str
    site: str | None = None
    severity: str
    title: str
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    last_run_id: int | None = None
    data: dict[str, Any]
    """The latest ReportedFinding (finding, confidence, verification)."""
    note: str | None = None


class FixEvent(BaseModel):
    """One line of the local fix log (append-only): a fix approved on this terminal, its outcome, an undo."""

    id: int
    fix_id: str
    host: str
    dedupe_key: str
    event: Literal["approved", "finished"]
    mode: Literal["apply", "rollback"]
    action: str
    plan_sha256: str
    user: str
    at: datetime
    status: str | None = None
    message: str | None = None
    data: dict[str, Any]
    """approved: the fix proposal; finished: the RemediationOutcome."""


class StoredRun(BaseModel):
    id: int
    host: str
    started_at: datetime
    finished_at: datetime
    status: str
    data: dict[str, Any]
    """The full HostRun as JSON."""


class StandaloneState:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version < SCHEMA_VERSION:
                if version == 2:
                    db.executescript(_MIGRATE_V2)
                db.executescript(_SCHEMA)
                columns = {row[1] for row in db.execute("PRAGMA table_info(hosts)")}
                if "local" not in columns:  # v7: hosts checked by `hc check --local` (Track S)
                    db.execute("ALTER TABLE hosts ADD COLUMN local INTEGER NOT NULL DEFAULT 0")
                db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @classmethod
    def open(cls, state_dir: Path) -> StandaloneState:
        return cls(state_dir / STATE_FILE)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        try:
            with db:  # commit or roll back
                yield db
        finally:
            db.close()

    def add_host(self, host: StoredHost) -> None:
        try:
            with self._db() as db:
                db.execute(
                    "INSERT INTO hosts (name, address, port, user, key_path, host_key_fingerprint, added_at,"
                    " local) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        host.name,
                        host.address,
                        host.port,
                        host.user,
                        host.key_path,
                        host.host_key_fingerprint,
                        host.added_at.isoformat(),
                        int(host.local),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise HostExists(host.name) from exc

    def get_host(self, name: str) -> StoredHost | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM hosts WHERE name = ?", (name,)).fetchone()
        return _host(row) if row else None

    def list_hosts(self) -> list[StoredHost]:
        with self._db() as db:
            rows = db.execute("SELECT * FROM hosts ORDER BY name").fetchall()
        return [_host(r) for r in rows]

    def remove_host(self, name: str) -> bool:
        """Remove a host and its runs and snapshots."""
        with self._db() as db:
            db.execute("DELETE FROM snapshots WHERE host = ?", (name,))
            db.execute("DELETE FROM runs WHERE host = ?", (name,))
            return db.execute("DELETE FROM hosts WHERE name = ?", (name,)).rowcount > 0

    # ── runs and snapshots ──

    def save_run(
        self,
        host: str,
        *,
        started_at: datetime,
        finished_at: datetime,
        status: str,
        data: dict[str, Any],
        snapshots: list[tuple[str, str | None, int, dict[str, Any]]],
    ) -> int:
        """Store a run and its snapshots (agent, site, version, facts) in one transaction; return its id."""
        with self._db() as db:
            cur = db.execute(
                "INSERT INTO runs (host, started_at, finished_at, status, data) VALUES (?, ?, ?, ?, ?)",
                (host, started_at.isoformat(), finished_at.isoformat(), status, json.dumps(data)),
            )
            run_id = cur.lastrowid
            assert run_id is not None  # noqa: S101 - set by INSERT
            db.executemany(
                "INSERT INTO snapshots (run_id, host, agent, site, agent_version, taken_at, facts)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (run_id, host, agent, site or "", version, finished_at.isoformat(), json.dumps(facts))
                    for agent, site, version, facts in snapshots
                ],
            )
        return run_id

    def latest_snapshots(self, host: str) -> list[StoredSnapshot]:
        """The most recent snapshot of each agent (and site) on a host; they may come from different runs."""
        with self._db() as db:
            rows = db.execute(
                "SELECT s.* FROM snapshots s WHERE s.host = ? AND s.run_id = "
                "(SELECT MAX(run_id) FROM snapshots"
                " WHERE host = s.host AND agent = s.agent AND site = s.site)"
                " ORDER BY s.agent, s.site",
                (host,),
            ).fetchall()
        return [_snapshot(row) for row in rows]

    def recent_runs(self, host: str, limit: int = 10) -> list[StoredRun]:
        """Most recent first."""
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM runs WHERE host = ? ORDER BY id DESC LIMIT ?", (host, limit)
            ).fetchall()
        return [_run(row) for row in rows]

    def host_settings(self, host: str) -> list[HostAgentState]:
        """Per-host agent settings (M7c: accepted from `hc recon --apply`)."""
        with self._db() as db:
            rows = db.execute(
                "SELECT agent, enabled, settings FROM host_settings WHERE host = ? ORDER BY agent", (host,)
            ).fetchall()
        return [
            HostAgentState(agent=r["agent"], enabled=bool(r["enabled"]), settings=json.loads(r["settings"]))
            for r in rows
        ]

    def apply_setting_changes(self, host: str, changes: list[SettingChange], source: str) -> None:
        """Merge changes into the stored settings (overrides add up; `enabled` only when given)."""
        current = {s.agent: s for s in self.host_settings(host)}
        now = datetime.now(UTC).isoformat()
        with self._db() as db:
            for c in changes:
                old = current.get(c.agent, HostAgentState(agent=c.agent))
                enabled = old.enabled if c.enabled is None else c.enabled
                db.execute(
                    "INSERT INTO host_settings (host, agent, enabled, settings, source, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (host, agent) DO UPDATE SET "
                    "enabled = excluded.enabled, settings = excluded.settings, source = excluded.source, "
                    "updated_at = excluded.updated_at",
                    (host, c.agent, int(enabled), json.dumps({**old.settings, **c.settings}), source, now),
                )

    def pin_host_key(self, name: str, fingerprint: str) -> None:
        with self._db() as db:
            db.execute("UPDATE hosts SET host_key_fingerprint = ? WHERE name = ?", (fingerprint, name))

    def record_test(self, name: str, ok: bool, at: datetime | None = None) -> None:
        at = at or datetime.now(UTC)
        with self._db() as db:
            db.execute(
                "UPDATE hosts SET last_tested_at = ?, last_test_ok = ? WHERE name = ?",
                (at.isoformat(), int(ok), name),
            )

    # ── findings ──

    def upsert_finding(
        self,
        host: str,
        *,
        key: str,
        agent: str,
        site: str | None,
        severity: str,
        title: str,
        data: dict[str, Any],
        run_id: int | None,
        at: datetime,
    ) -> FindingStatus:
        """Record a finding seen in a run. New → `new`; seen again → `open` (a resolved one reopens);
        acknowledged and false-positive marks are kept. Returns the status after the update."""
        with self._db() as db:
            row = db.execute(
                "SELECT status FROM findings WHERE host = ? AND dedupe_key = ?", (host, key)
            ).fetchone()
            if row is None:
                status: FindingStatus = "new"
                db.execute(
                    "INSERT INTO findings (host, dedupe_key, agent, site, severity, title, status,"
                    " first_seen, last_seen, last_run_id, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        host,
                        key,
                        agent,
                        site,
                        severity,
                        title,
                        status,
                        at.isoformat(),
                        at.isoformat(),
                        run_id,
                        json.dumps(data),
                    ),
                )
                return status
            previous = row["status"]
            status = previous if previous in ("acknowledged", "false_positive") else "open"
            db.execute(
                "UPDATE findings SET severity = ?, title = ?, status = ?, last_seen = ?, last_run_id = ?,"
                " data = ? WHERE host = ? AND dedupe_key = ?",
                (severity, title, status, at.isoformat(), run_id, json.dumps(data), host, key),
            )
            return status

    def resolve_absent(
        self, host: str, agent: str, site: str | None, seen: set[str], at: datetime
    ) -> list[str]:
        """After a full (baseline) review of one agent and site: active findings it didn't report again are
        resolved. Returns their keys."""
        with self._db() as db:
            rows = db.execute(
                "SELECT dedupe_key FROM findings WHERE host = ? AND agent = ? AND IFNULL(site, '') = ?"
                " AND status IN ('new', 'open')",
                (host, agent, site or ""),
            ).fetchall()
            gone = [r["dedupe_key"] for r in rows if r["dedupe_key"] not in seen]
            db.executemany(
                "UPDATE findings SET status = 'resolved', last_seen = ? WHERE host = ? AND dedupe_key = ?",
                [(at.isoformat(), host, key) for key in gone],
            )
        return gone

    def list_findings(
        self, *, host: str | None = None, statuses: tuple[str, ...] = ACTIVE
    ) -> list[StoredFinding]:
        marks = ",".join("?" * len(statuses))  # placeholders only; values are bound
        query = f"SELECT * FROM findings WHERE status IN ({marks})"  # noqa: S608
        params: list[Any] = list(statuses)
        if host is not None:
            query += " AND host = ?"
            params.append(host)
        with self._db() as db:
            rows = db.execute(query + " ORDER BY host, last_seen DESC", params).fetchall()
        return [_finding(r) for r in rows]

    def get_finding(self, key: str) -> list[StoredFinding]:
        """By dedupe key (or a unique prefix of it), across hosts."""
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM findings WHERE dedupe_key = ? OR dedupe_key LIKE ? ESCAPE '\\'",
                (key, key.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"),
            ).fetchall()
        exact = [r for r in rows if r["dedupe_key"] == key]
        return [_finding(r) for r in (exact or rows)]

    def log_fix(
        self,
        *,
        fix_id: str | None,
        host: str,
        dedupe_key: str,
        event: str,
        mode: str,
        action: str,
        plan_sha256: str,
        user: str,
        data: dict[str, Any],
        status: str | None = None,
        message: str | None = None,
    ) -> FixEvent:
        """Append to the fix log. A new fix (fix_id None) gets `local-<row id>`, used on the host for its
        quarantine folder and backups; its later events reuse that id."""
        at = datetime.now(UTC).isoformat()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")  # no other writer between reading the next id and the insert
            if fix_id is None:
                seq = db.execute("SELECT seq FROM sqlite_sequence WHERE name = 'fix_log'").fetchone()
                fix_id = f"local-{(seq[0] if seq else 0) + 1}"
            cur = db.execute(
                "INSERT INTO fix_log (fix_id, host, dedupe_key, event, mode, action, plan_sha256, user, at, "
                "status, message, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    fix_id,
                    host,
                    dedupe_key,
                    event,
                    mode,
                    action,
                    plan_sha256,
                    user,
                    at,
                    status,
                    message,
                    json.dumps(data),
                ),
            )
            row = db.execute("SELECT * FROM fix_log WHERE id = ?", (cur.lastrowid,)).fetchone()
        return _fix_event(row)

    def fix_events(self, host: str, dedupe_key: str) -> list[FixEvent]:
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM fix_log WHERE host = ? AND dedupe_key = ? ORDER BY id", (host, dedupe_key)
            ).fetchall()
        return [_fix_event(r) for r in rows]

    def set_finding_status(self, host: str, key: str, status: FindingStatus, note: str | None) -> None:
        with self._db() as db:
            db.execute(
                "UPDATE findings SET status = ?, note = COALESCE(?, note) WHERE host = ? AND dedupe_key = ?",
                (status, note, host, key),
            )


def _fix_event(row: sqlite3.Row) -> FixEvent:
    data = dict(row)
    data["data"] = json.loads(data["data"])
    return FixEvent.model_validate(data)


def _host(row: sqlite3.Row) -> StoredHost:
    data = dict(row)
    if data["last_test_ok"] is not None:
        data["last_test_ok"] = bool(data["last_test_ok"])
    data["local"] = bool(data.get("local", 0))
    return StoredHost.model_validate(data)


def _snapshot(row: sqlite3.Row) -> StoredSnapshot:
    return StoredSnapshot(
        run_id=row["run_id"],
        agent=row["agent"],
        site=row["site"] or None,
        agent_version=row["agent_version"],
        taken_at=row["taken_at"],
        facts=json.loads(row["facts"]),
    )


def _run(row: sqlite3.Row) -> StoredRun:
    return StoredRun(
        id=row["id"],
        host=row["host"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        status=row["status"],
        data=json.loads(row["data"]),
    )


def _finding(row: sqlite3.Row) -> StoredFinding:
    data = dict(row)
    data["data"] = json.loads(data["data"])
    return StoredFinding.model_validate(data)
