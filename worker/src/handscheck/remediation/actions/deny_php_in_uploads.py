"""Stop PHP files in a WordPress uploads folder from running (Apache): a `<FilesMatch>` rule that denies them
in the uploads folder's .htaccess. WordPress never serves PHP from uploads, so nothing legitimate breaks; a
web shell dropped there later can't be run from the web.

An existing .htaccess is kept (backed up, the rule is appended). Rollback restores the backup, or moves a
.htaccess the fix created into quarantine. Precheck and verify request a PHP file name that doesn't exist in
the folder, from the worker: without the rule it is a 404, with it a 403. A server that ignores .htaccess
(nginx, AllowOverride None) or errors on the rule fails verification and the fix is rolled back."""

from __future__ import annotations

import posixpath
import re
from typing import Any

from pydantic import Field, field_validator

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
MARKER = "handscheck.ai (approved fix"


class DenyPhpInUploadsParams(Params):
    site: str
    root: str = Field(description="The site's document root on the host.")
    uploads: str = Field(description="URL path of the uploads folder, e.g. /wp-content/uploads/.")

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

    @field_validator("uploads")
    @classmethod
    def _uploads(cls, v: str) -> str:
        if not _URL_DIR.match(v) or ".." in v.split("/") or not v.rstrip("/").endswith("/uploads"):
            raise ValueError("uploads must be a plain URL path ending in /uploads/")
        return v


def _paths(p: DenyPhpInUploadsParams, ctx: FixContext) -> tuple[str, str, str]:
    folder = posixpath.normpath(posixpath.join(p.root, p.uploads.lstrip("/")))
    htaccess = posixpath.join(folder, ".htaccess")
    return folder, htaccess, f"{htaccess}.handscheck-backup-{ctx.proposal_id}"


def _probe(p: DenyPhpInUploadsParams, ctx: FixContext) -> str:
    """A PHP file name that doesn't exist in the folder (requested, never created)."""
    safe = re.sub(r"[^A-Za-z0-9-]", "-", ctx.proposal_id)
    return f"{p.uploads}handscheck-check-{safe}.php"


def rule(proposal_id: str) -> str:
    return (
        f"# Added by {MARKER} {proposal_id}): PHP files in uploads never run.\n"
        '<FilesMatch "(?i)\\.(php[0-9]*|phtml|phar|pht|phps)$">\n'
        "    Require all denied\n"
        "</FilesMatch>\n"
    )


class DenyPhpInUploads(Action[DenyPhpInUploadsParams]):
    name = "deny_php_in_uploads"
    version = 1
    risk = "low"
    params_model = DenyPhpInUploadsParams

    def commands(self, p: DenyPhpInUploadsParams, ctx: FixContext) -> list[Cmd]:
        folder, htaccess, backup = _paths(p, ctx)
        quarantine = f"{QUARANTINE_ROOT}/{ctx.proposal_id}"
        return [
            Cmd(("test", "-d", folder)),
            Cmd(("test", "-f", htaccess)),
            Cmd(("cp", "-p", htaccess, backup)),
            Cmd(("tee", htaccess)),
            Cmd(("mv", "-f", backup, htaccess)),
            Cmd(("install", "-d", "-m", "700", quarantine)),
            Cmd(("mv", htaccess, f"{quarantine}/uploads.htaccess")),
        ]

    def preview(self, p: DenyPhpInUploadsParams) -> Preview:
        _, htaccess, _ = _paths(p, FixContext())
        return Preview(
            summary=f"Stop PHP files in {p.uploads} on {p.site} from running, with a rule in {htaccess}.",
            rollback=[
                "Restore the previous .htaccess from its backup, or move the new one to "
                f"{QUARANTINE_ROOT}/<fix id>/."
            ],
            verify=[
                f"Request a PHP file name in {p.uploads} on {p.site}: it must be refused (403).",
                f"{p.site} still answers as before.",
            ],
            notes=[
                "WordPress never runs PHP from uploads; images and documents there are served as before.",
                "Works on Apache when .htaccess may set access rules (AllowOverride AuthConfig or All); "
                "otherwise verification fails and the fix is rolled back automatically.",
                "This blocks PHP that is there now and any dropped later, but doesn't remove it: quarantine "
                "the files too.",
            ],
        )

    async def precheck(self, ex: Executor, p: DenyPhpInUploadsParams, ctx: FixContext) -> None:
        folder, _, _ = _paths(p, ctx)
        if not (await ex.run(Cmd(("test", "-d", folder)), check=False)).ok:
            raise Stale(f"{folder} no longer exists")
        response = await ex.get(p.site, _probe(p, ctx))
        if response.status == 403:
            raise Stale(f"{p.uploads} on {p.site} already refuses PHP files")
        if response.status is None or response.status >= 500:
            raise Stale(
                f"{p.uploads} on {p.site} answers {response.status or response.error}: check it first"
            )

    async def apply(self, ex: Executor, p: DenyPhpInUploadsParams, ctx: FixContext) -> dict[str, Any]:
        _, htaccess, backup = _paths(p, ctx)
        existed = (await ex.run(Cmd(("test", "-f", htaccess)), check=False)).ok
        content = ""
        if existed:
            content = (await ex.run(Cmd(("cat", htaccess)))).stdout
            await ex.run(Cmd(("cp", "-p", htaccess, backup)))
        new = (content.rstrip("\n") + "\n\n" if content.strip() else "") + rule(ctx.proposal_id)
        await ex.run(Cmd(("tee", htaccess)), stdin=new)
        return {"existed": existed, "htaccess": htaccess}

    async def verify(self, ex: Executor, p: DenyPhpInUploadsParams, ctx: FixContext) -> list[str]:
        response = await ex.get(p.site, _probe(p, ctx))
        if response.status == 403:
            return []
        if response.status is not None and response.status >= 500:
            return [f"{p.uploads} now answers HTTP {response.status} (the server may not allow the rule)"]
        return [
            f"a PHP file name in {p.uploads} answers {response.status or response.error}, not 403 "
            "(the server may ignore .htaccess)"
        ]

    async def rollback(
        self, ex: Executor, p: DenyPhpInUploadsParams, ctx: FixContext, data: dict[str, Any]
    ) -> None:
        _, htaccess, backup = _paths(p, ctx)
        if data.get("existed"):
            await ex.run(Cmd(("mv", "-f", backup, htaccess)))
        else:
            quarantine = f"{QUARANTINE_ROOT}/{ctx.proposal_id}"
            await ex.run(Cmd(("install", "-d", "-m", "700", quarantine)))
            await ex.run(Cmd(("mv", htaccess, f"{quarantine}/uploads.htaccess")))
