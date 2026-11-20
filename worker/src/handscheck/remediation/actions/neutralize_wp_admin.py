"""Neutralize a rogue WordPress administrator without deleting it: remove all its roles, give it a random
password nobody knows, and end its sessions. The roles are saved so rollback can give them back (the old
password and sessions can't be restored; nobody should need them). wp-cli runs as www-data, without plugins
or themes."""

from __future__ import annotations

import posixpath
import re
from typing import Any

from pydantic import Field, field_validator

from handscheck.remediation.base import Action, Cmd, Executor, FixContext, FixFailed, Params, Preview, Stale

STANDARD_ROLES = ("administrator", "editor", "author", "contributor", "subscriber")
_SITE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_LOGIN = re.compile(r"^[A-Za-z0-9 _.@-]{1,60}$")


class NeutralizeWpAdminParams(Params):
    site: str
    wp_path: str = Field(description="WordPress directory on the host.")
    user_id: int = Field(ge=1)
    login: str

    @field_validator("site")
    @classmethod
    def _site(cls, v: str) -> str:
        if not _SITE.match(v):
            raise ValueError("not a site name")
        return v

    @field_validator("wp_path")
    @classmethod
    def _path(cls, v: str) -> str:
        if not v.startswith("/") or posixpath.normpath(v) != v or v == "/":
            raise ValueError("wp_path must be an absolute, normalized path")
        return v

    @field_validator("login")
    @classmethod
    def _login(cls, v: str) -> str:
        if not _LOGIN.match(v):
            raise ValueError("unexpected characters in the login")
        return v


def _wp(p: NeutralizeWpAdminParams, *args: str) -> Cmd:
    return Cmd(("wp", f"--path={p.wp_path}", "--skip-plugins", "--skip-themes", "user", *args), "www-data")


def _roles(text: str) -> list[str]:
    return [r.strip() for r in text.replace("\n", ",").split(",") if r.strip()]


class NeutralizeWpAdmin(Action[NeutralizeWpAdminParams]):
    name = "neutralize_wp_admin"
    version = 1
    risk = "medium"
    params_model = NeutralizeWpAdminParams

    def commands(self, p: NeutralizeWpAdminParams, ctx: FixContext) -> list[Cmd]:
        uid = str(p.user_id)
        return [
            _wp(p, "get", uid, "--field=user_login"),
            _wp(p, "get", uid, "--field=roles"),
            _wp(p, "remove-role", uid),
            _wp(p, "reset-password", uid, "--skip-email"),
            _wp(p, "session", "destroy", uid, "--all"),
            *(_wp(p, "set-role", uid, role) for role in STANDARD_ROLES),
            *(_wp(p, "add-role", uid, role) for role in STANDARD_ROLES),
        ]

    def preview(self, p: NeutralizeWpAdminParams) -> Preview:
        return Preview(
            summary=f"Disable the WordPress administrator '{p.login}' (ID {p.user_id}) on {p.site}: "
            "remove its roles, set a random password nobody knows, and end its sessions. The account and "
            "its content stay.",
            rollback=[f"Give '{p.login}' its previous roles back."],
            verify=[f"'{p.login}' has no roles left."],
            notes=[
                "Rollback restores the roles only; the old password and sessions can't be restored.",
                "Also rotate the other admins' passwords and the salts in wp-config.php: an attacker "
                "who made this account may have more access.",
            ],
        )

    async def precheck(self, ex: Executor, p: NeutralizeWpAdminParams, ctx: FixContext) -> None:
        login = await ex.run(_wp(p, "get", str(p.user_id), "--field=user_login"), check=False)
        if not login.ok or login.stdout.strip() != p.login:
            raise Stale(f"user {p.user_id} is no longer '{p.login}' on {p.site}")
        roles = _roles((await ex.run(_wp(p, "get", str(p.user_id), "--field=roles"))).stdout)
        if "administrator" not in roles:
            raise Stale(f"'{p.login}' is no longer an administrator (roles: {', '.join(roles) or 'none'})")

    async def apply(self, ex: Executor, p: NeutralizeWpAdminParams, ctx: FixContext) -> dict[str, Any]:
        uid = str(p.user_id)
        roles = _roles((await ex.run(_wp(p, "get", uid, "--field=roles"))).stdout)
        data: dict[str, Any] = {"roles": roles}
        await ex.run(_wp(p, "remove-role", uid))
        await ex.run(_wp(p, "reset-password", uid, "--skip-email"))
        await ex.run(_wp(p, "session", "destroy", uid, "--all"))
        return data

    async def verify(self, ex: Executor, p: NeutralizeWpAdminParams, ctx: FixContext) -> list[str]:
        left = _roles((await ex.run(_wp(p, "get", str(p.user_id), "--field=roles"))).stdout)
        return [f"'{p.login}' still has roles: {', '.join(left)}"] if left else []

    async def rollback(
        self, ex: Executor, p: NeutralizeWpAdminParams, ctx: FixContext, data: dict[str, Any]
    ) -> None:
        roles = [r for r in data.get("roles", []) if r in STANDARD_ROLES]
        unknown = [r for r in data.get("roles", []) if r not in STANDARD_ROLES]
        uid = str(p.user_id)
        for i, role in enumerate(roles):
            await ex.run(_wp(p, "set-role" if i == 0 else "add-role", uid, role))
        if unknown:
            raise FixFailed(f"custom roles not restored (restore them by hand): {', '.join(unknown)}")
