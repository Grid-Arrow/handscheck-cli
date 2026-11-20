"""Turn off Apache directory listings for a site (`dir` = /, its web root) or one folder of it: `Options
-Indexes` in that folder's .htaccess.

An existing .htaccess is kept (backed up first, the line is appended). Rollback restores the backup, or
moves a .htaccess the fix created into quarantine. Verify re-requests every listed folder under it from the
worker; a server that ignores .htaccess (nginx, AllowOverride None) or answers with an error is rolled
back."""

from __future__ import annotations

import posixpath
import re
from typing import Any

from pydantic import Field, field_validator

from handscheck.agents.exposure.check import LISTING
from handscheck.remediation.base import (
    QUARANTINE_ROOT,
    Action,
    Cmd,
    Executor,
    FixContext,
    Params,
    Preview,
    Stale,
)

_SITE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_URL_DIR = re.compile(r"^/(?:[A-Za-z0-9._~/-]*/)?$")


class DisableIndexesParams(Params):
    site: str
    root: str = Field(description="The site's document root on the host.")
    dir: str = Field(description="URL path of the folder, with a trailing slash, e.g. /wp-content/uploads/.")
    listings: list[str] = Field(min_length=1, description="Listed folders under it, checked afterwards.")

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

    @field_validator("dir")
    @classmethod
    def _dir(cls, v: str) -> str:
        if not _URL_DIR.match(v) or ".." in v.split("/"):
            raise ValueError("dir must be a plain URL path ending in /")
        return v

    @field_validator("listings")
    @classmethod
    def _listings(cls, v: list[str]) -> list[str]:
        for path in v:
            if not _URL_DIR.match(path) or ".." in path.split("/"):
                raise ValueError(f"not a plain URL folder: {path!r}")
        return sorted(set(v))[:20]


def _paths(p: DisableIndexesParams, url_dir: str | None = None) -> tuple[str, str, str]:
    folder = posixpath.normpath(posixpath.join(p.root, (url_dir or p.dir).lstrip("/")))
    htaccess = posixpath.join(folder, ".htaccess")
    return folder, htaccess, htaccess + ".handscheck-backup"


def _below(p: DisableIndexesParams) -> list[str]:
    """Listed folders below `dir`: their own .htaccess may turn listings back on (`Options +Indexes`)."""
    return [path for path in p.listings if path != p.dir and path.startswith(p.dir)]


def _enables_indexes(content: str) -> bool:
    """Whether a .htaccess leaves listings on: its last `Options` line that touches them has `+Indexes`,
    `Indexes` or `All` (an unsigned list without them, or `-Indexes`, turns them off)."""
    on = False
    for line in content.splitlines():
        words = [w.lower() for w in line.split("#", 1)[0].split()]
        if not words or words[0] != "options":
            continue
        opts = words[1:]
        if "-indexes" in opts:
            on = False
        elif {"+indexes", "indexes", "all"} & set(opts):
            on = True
        elif any(not o.startswith(("+", "-")) for o in opts):
            on = False  # an unsigned list replaces the options
    return on


def _block(proposal_id: str) -> str:
    return (
        f"# Added by handscheck.ai (approved fix {proposal_id}): no directory listings.\nOptions -Indexes\n"
    )


class DisableIndexes(Action[DisableIndexesParams]):
    name = "disable_indexes"
    version = 1
    risk = "low"
    params_model = DisableIndexesParams

    def commands(self, p: DisableIndexesParams, ctx: FixContext) -> list[Cmd]:
        folder, htaccess, backup = _paths(p)
        quarantine = f"{QUARANTINE_ROOT}/{ctx.proposal_id}"
        cmds = [
            Cmd(("test", "-d", folder)),
            Cmd(("test", "-f", htaccess)),
            Cmd(("cp", "-p", htaccess, backup)),
            Cmd(("tee", htaccess)),
            Cmd(("mv", "-f", backup, htaccess)),
            Cmd(("install", "-d", "-m", "700", quarantine)),
            Cmd(("mv", htaccess, f"{quarantine}/.htaccess")),
        ]
        for path in _below(p):  # only an existing .htaccess that turns listings back on is changed
            _, sub, sub_backup = _paths(p, path)
            cmds += [
                Cmd(("test", "-f", sub)),
                Cmd(("cp", "-p", sub, sub_backup)),
                Cmd(("tee", sub)),
                Cmd(("mv", "-f", sub_backup, sub)),
            ]
        return cmds

    def preview(self, p: DisableIndexesParams) -> Preview:
        _, htaccess, backup = _paths(p)
        where = "any folder" if p.dir == "/" else f"{p.dir} (and folders below it)"
        return Preview(
            summary=f"Stop {p.site} from showing file lists for {where} by adding `Options -Indexes` to "
            f"{htaccess}.",
            rollback=[
                f"Restore the previous .htaccess from {backup}, or move the new one to "
                f"{QUARANTINE_ROOT}/<fix id>/."
            ],
            verify=[
                f"Request {path} on {p.site}: it must no longer show a file list." for path in p.listings
            ],
            notes=[
                "Works on Apache with AllowOverride allowing Options; otherwise verification fails "
                "and the fix is rolled back automatically.",
                "An existing .htaccess is kept: it is backed up and the line is added at the end "
                "(after WordPress's own section, which WordPress rewrites only between its markers).",
                "A listed folder whose own .htaccess turns listings back on (`Options +Indexes`) gets "
                "the same line added to that file (backed up first, restored on undo).",
            ],
        )

    async def precheck(self, ex: Executor, p: DisableIndexesParams, ctx: FixContext) -> None:
        folder, _, _ = _paths(p)
        if not (await ex.run(Cmd(("test", "-d", folder)), check=False)).ok:
            raise Stale(f"{folder} no longer exists")
        if not [path for path in p.listings if await self._lists(ex, p.site, path)]:
            raise Stale(f"{p.site} no longer shows file lists for {', '.join(p.listings)}")

    async def apply(self, ex: Executor, p: DisableIndexesParams, ctx: FixContext) -> dict[str, Any]:
        _, htaccess, backup = _paths(p)
        existed = (await ex.run(Cmd(("test", "-f", htaccess)), check=False)).ok
        content = ""
        if existed:
            content = (await ex.run(Cmd(("cat", htaccess)))).stdout
            await ex.run(Cmd(("cp", "-p", htaccess, backup)))
        new = (content.rstrip("\n") + "\n\n" if content.strip() else "") + _block(ctx.proposal_id)
        await ex.run(Cmd(("tee", htaccess)), stdin=new)
        overrides = []
        for path in _below(p):
            _, sub, sub_backup = _paths(p, path)
            if not (await ex.run(Cmd(("test", "-f", sub)), check=False)).ok:
                continue
            sub_content = (await ex.run(Cmd(("cat", sub)))).stdout
            if not _enables_indexes(sub_content):
                continue
            await ex.run(Cmd(("cp", "-p", sub, sub_backup)))
            await ex.run(Cmd(("tee", sub)), stdin=sub_content.rstrip("\n") + "\n\n" + _block(ctx.proposal_id))
            overrides.append(sub)
        data: dict[str, Any] = {"existed": existed, "htaccess": htaccess}
        if overrides:
            data["overrides"] = overrides
        return data

    async def verify(self, ex: Executor, p: DisableIndexesParams, ctx: FixContext) -> list[str]:
        problems = []
        for path in p.listings:
            response = await ex.get(p.site, path)
            if response.status is not None and response.status >= 500:
                problems.append(f"{path} now answers HTTP {response.status}")
            elif await self._lists(ex, p.site, path, response.status, response.body):
                problems.append(f"{path} still shows a file list (the server may ignore .htaccess)")
        return problems

    async def rollback(
        self, ex: Executor, p: DisableIndexesParams, ctx: FixContext, data: dict[str, Any]
    ) -> None:
        _, htaccess, backup = _paths(p)
        below = {_paths(p, path)[1]: _paths(p, path)[2] for path in _below(p)}
        for sub in data.get("overrides") or []:
            if sub in below:  # only files this plan could have changed
                await ex.run(Cmd(("mv", "-f", below[sub], sub)))
        if data.get("existed"):
            await ex.run(Cmd(("mv", "-f", backup, htaccess)))
        else:
            quarantine = f"{QUARANTINE_ROOT}/{ctx.proposal_id}"
            await ex.run(Cmd(("install", "-d", "-m", "700", quarantine)))
            await ex.run(Cmd(("mv", htaccess, f"{quarantine}/.htaccess")))

    @staticmethod
    async def _lists(
        ex: Executor, site: str, path: str, status: int | None = None, body: str | None = None
    ) -> bool:
        if body is None:
            response = await ex.get(site, path)
            status, body = response.status, response.body
        return status == 200 and bool(LISTING.search(body or ""))
