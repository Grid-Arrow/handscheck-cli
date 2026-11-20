"""Quarantine files a scan flagged (web shells, PHP in uploads): move them out of the web root into the fix's
root-only quarantine folder, never delete them.

Each file goes to `<quarantine>/<fix id>/files/<n>-<name>`, next to a `MANIFEST.json` with its original path,
owner, mode, size, mtime and sha256. Rollback moves each file back (refusing when something new sits at its
path). A file already gone is skipped; a symlink is never followed or moved. Verify checks that each path is
empty and its file is in quarantine; the handler's HTTP baseline rolls the fix back if the
site stops answering (a file the site still loads)."""

from __future__ import annotations

import json
import posixpath
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from handscheck.remediation.base import (
    QUARANTINE_ROOT,
    Action,
    Cmd,
    Executor,
    FixContext,
    FixFailed,
    Params,
    Preview,
    Stale,
)

MAX_FILES = 20
_SITE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_STAT = "%U:%G %a %s %Y"


class QuarantineFileParams(Params):
    site: str
    root: str = Field(description="The site's document root on the host; every file must be under it.")
    files: list[str] = Field(min_length=1, max_length=MAX_FILES, description="Absolute paths to quarantine.")

    @field_validator("site")
    @classmethod
    def _site(cls, v: str) -> str:
        if not _SITE.match(v):
            raise ValueError("not a site name")
        return v

    @field_validator("root")
    @classmethod
    def _root(cls, v: str) -> str:
        if not v.startswith("/") or posixpath.normpath(v) != v or v == "/":
            raise ValueError("root must be an absolute, normalized path")
        return v

    @field_validator("files")
    @classmethod
    def _files(cls, v: list[str]) -> list[str]:
        for path in v:
            if not path.startswith("/") or posixpath.normpath(path) != path or _CONTROL.search(path):
                raise ValueError(f"not an absolute, normalized path: {path!r}")
        return sorted(set(v))

    @model_validator(mode="after")
    def _under_root(self) -> QuarantineFileParams:
        for path in self.files:
            if not path.startswith(self.root + "/"):
                raise ValueError(f"{path} is not under {self.root}")
        return self


def _quarantine(ctx: FixContext) -> str:
    return f"{QUARANTINE_ROOT}/{ctx.proposal_id}"


def _stored(ctx: FixContext, index: int, path: str) -> str:
    return f"{_quarantine(ctx)}/files/{index}-{posixpath.basename(path)}"


class QuarantineFile(Action[QuarantineFileParams]):
    name = "quarantine_file"
    version = 1
    risk = "medium"
    params_model = QuarantineFileParams

    def commands(self, p: QuarantineFileParams, ctx: FixContext) -> list[Cmd]:
        q = _quarantine(ctx)
        cmds = [
            Cmd(("install", "-d", "-m", "700", q)),
            Cmd(("install", "-d", "-m", "700", f"{q}/files")),
            Cmd(("tee", f"{q}/MANIFEST.json")),
        ]
        for i, path in enumerate(p.files):
            stored = _stored(ctx, i, path)
            cmds += [
                Cmd(("test", "-f", path)),
                Cmd(("test", "-h", path)),
                Cmd(("test", "-e", path)),
                Cmd(("stat", "-c", _STAT, path)),
                Cmd(("sha256sum", path)),
                Cmd(("sha256sum", stored)),
                Cmd(("mv", path, stored)),
                Cmd(("mv", stored, path)),
            ]
        return cmds

    def preview(self, p: QuarantineFileParams) -> Preview:
        shown = ", ".join(p.files[:5]) + (f" and {len(p.files) - 5} more" if len(p.files) > 5 else "")
        what = "this file" if len(p.files) == 1 else f"these {len(p.files)} files"
        return Preview(
            summary=f"Move {what} on {p.site} out of the web root into quarantine (kept, not deleted): "
            f"{shown}.",
            rollback=[f"Move each file back from {QUARANTINE_ROOT}/<fix id>/files/ to where it was."],
            verify=[
                "Each path is empty and its file is in the quarantine folder.",
                f"{p.site} still answers as before (otherwise the files are moved back).",
            ],
            notes=[
                f"The quarantine folder is root-only; {QUARANTINE_ROOT}/<fix id>/MANIFEST.json records each "
                "file's path, owner, mode, size, time and sha256.",
                "If the site loads one of these files, it errors without it and the fix is rolled back "
                "automatically. Remove whatever loads it first.",
                "Quarantine removes what was found, not how it got there: look for the way in (an outdated "
                "plugin, a stolen password) and for other backdoors.",
            ],
        )

    async def precheck(self, ex: Executor, p: QuarantineFileParams, ctx: FixContext) -> None:
        present = [path for path in p.files if await self._regular(ex, path)]
        if not present:
            raise Stale("none of the files are there any more (as regular files)")

    async def apply(self, ex: Executor, p: QuarantineFileParams, ctx: FixContext) -> dict[str, Any]:
        q = _quarantine(ctx)
        await ex.run(Cmd(("install", "-d", "-m", "700", q)))
        await ex.run(Cmd(("install", "-d", "-m", "700", f"{q}/files")))
        moved: list[dict[str, Any]] = []
        skipped: list[str] = []
        try:
            for i, path in enumerate(p.files):
                if not await self._regular(ex, path):
                    skipped.append(path)
                    continue
                entry = _stat_entry((await ex.run(Cmd(("stat", "-c", _STAT, path)))).stdout)
                entry["sha256"] = _hash((await ex.run(Cmd(("sha256sum", path)))).stdout)
                stored = _stored(ctx, i, path)
                await ex.run(Cmd(("mv", path, stored)))
                moved.append({"path": path, "stored": stored, **entry})
        except FixFailed:
            await self._restore(ex, p, ctx, moved)
            raise
        manifest = {
            "fix": ctx.proposal_id,
            "action": self.name,
            "site": p.site,
            "quarantined_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "files": moved,
            "skipped": skipped,
        }
        await ex.run(Cmd(("tee", f"{q}/MANIFEST.json")), stdin=json.dumps(manifest, indent=2) + "\n")
        data: dict[str, Any] = {"moved": moved}
        if skipped:
            data["skipped"] = skipped
        return data

    async def verify(self, ex: Executor, p: QuarantineFileParams, ctx: FixContext) -> list[str]:
        problems = []
        for i, path in enumerate(p.files):
            if not (await ex.run(Cmd(("sha256sum", _stored(ctx, i, path))), check=False)).ok:
                continue  # skipped: it was already gone
            if (await ex.run(Cmd(("test", "-e", path)), check=False)).ok:
                problems.append(f"{path} is still there")
        return problems

    async def rollback(
        self, ex: Executor, p: QuarantineFileParams, ctx: FixContext, data: dict[str, Any]
    ) -> None:
        await self._restore(ex, p, ctx, list(data.get("moved") or []))

    async def _restore(
        self, ex: Executor, p: QuarantineFileParams, ctx: FixContext, moved: list[dict[str, Any]]
    ) -> None:
        planned = {path: _stored(ctx, i, path) for i, path in enumerate(p.files)}
        blocked = []
        for entry in moved:
            path = str(entry.get("path", ""))
            if path not in planned:  # only files this plan could have moved
                continue
            if (await ex.run(Cmd(("test", "-e", path)), check=False)).ok:
                blocked.append(path)
                continue
            await ex.run(Cmd(("mv", planned[path], path)))
        if blocked:
            raise FixFailed(
                "something new is at "
                + ", ".join(blocked)
                + f"; the quarantined copies stay in {_quarantine(ctx)}/files/"
            )

    @staticmethod
    async def _regular(ex: Executor, path: str) -> bool:
        """A regular file that isn't a symlink (a link could point anywhere on the host)."""
        if (await ex.run(Cmd(("test", "-h", path)), check=False)).ok:
            return False
        return (await ex.run(Cmd(("test", "-f", path)), check=False)).ok


def _stat_entry(out: str) -> dict[str, Any]:
    parts = out.strip().split(" ")
    if len(parts) != 4:
        return {}
    owner, mode, size, mtime = parts
    entry: dict[str, Any] = {"owner": owner, "mode": mode}
    if size.isdigit():
        entry["size"] = int(size)
    if mtime.isdigit():
        entry["mtime"] = int(mtime)
    return entry


def _hash(out: str) -> str:
    first = out.strip().split(" ", 1)[0]
    return first if re.fullmatch(r"[0-9a-f]{64}", first) else ""
