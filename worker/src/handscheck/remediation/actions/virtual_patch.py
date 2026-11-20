"""Virtual patch for a WordPress plugin with a known exploit: a root-owned mu-plugin that refuses the
plugin's AJAX actions for visitors who aren't logged in, and its REST routes for anonymous requests, until the
plugin is updated or removed. Logged-in use (the admin) keeps working.

The file is generated from the parameters (the actions and namespaces the scan found in the plugin's code),
written to the fix's quarantine folder, checked with `php -l`, and only then installed into `mu-plugins/` as
root:root 0644 (the site user can't change it). It also refuses one AJAX action of its own,
`handscheck_virtual_patch_check`: verify requests that one, so checking the patch never calls the vulnerable
handler. Rollback moves the mu-plugin into quarantine."""

from __future__ import annotations

import posixpath
import re
from typing import Any

from pydantic import Field, field_validator, model_validator

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

CHECK_ACTION = "handscheck_virtual_patch_check"
MARKER = "Blocked by a handscheck.ai virtual patch."
_SITE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}$")
_ACTION = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
_NAMESPACE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
_RULE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class VirtualPatchParams(Params):
    site: str
    wp_path: str = Field(description="WordPress directory on the host.")
    slug: str = Field(description="The plugin's folder name.")
    rule: str = Field(description="The vulnerable-plugin rule that flagged it.")
    ajax_actions: list[str] = Field(default_factory=list, max_length=50)
    rest_namespaces: list[str] = Field(default_factory=list, max_length=50)

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

    @field_validator("slug")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not _SLUG.match(v):
            raise ValueError("not a plugin slug")
        return v

    @field_validator("rule")
    @classmethod
    def _rule(cls, v: str) -> str:
        if not _RULE.match(v):
            raise ValueError("not a rule id")
        return v

    @field_validator("ajax_actions")
    @classmethod
    def _actions(cls, v: list[str]) -> list[str]:
        if any(not _ACTION.match(a) for a in v):
            raise ValueError("unexpected characters in an AJAX action")
        return sorted(set(v))

    @field_validator("rest_namespaces")
    @classmethod
    def _namespaces(cls, v: list[str]) -> list[str]:
        if any(not _NAMESPACE.match(n) for n in v):
            raise ValueError("unexpected characters in a REST namespace")
        return sorted(set(v))

    @model_validator(mode="after")
    def _something(self) -> VirtualPatchParams:
        if not self.ajax_actions and not self.rest_namespaces:
            raise ValueError("nothing to block")
        return self


def _paths(p: VirtualPatchParams, ctx: FixContext) -> tuple[str, str, str, str]:
    mu = posixpath.join(p.wp_path, "wp-content", "mu-plugins")
    name = f"handscheck-virtual-patch-{p.slug}.php"
    quarantine = f"{QUARANTINE_ROOT}/{ctx.proposal_id}"
    return mu, posixpath.join(mu, name), f"{quarantine}/staged-{name}", quarantine


def _php_list(items: list[str]) -> str:
    return (
        "array(" + ", ".join(f"'{i}'" for i in items) + ")"
    )  # items are validated: no quotes or backslashes


def mu_plugin(p: VirtualPatchParams, proposal_id: str) -> str:
    actions = [*p.ajax_actions, CHECK_ACTION]
    return f"""<?php
/**
 * Plugin Name: handscheck.ai virtual patch: {p.slug}
 * Description: Refuses anonymous AJAX actions and REST routes of the {p.slug} plugin, which has a
 *   known exploit ({p.rule}). Added by handscheck.ai (approved fix {proposal_id}). Undo the fix (or delete
 *   this file) once the plugin is updated or removed.
 */

if (!defined('ABSPATH')) {{
    exit;
}}

add_action('admin_init', static function () {{
    if (!wp_doing_ajax() || is_user_logged_in()) {{
        return;
    }}
    $action = isset($_REQUEST['action']) ? (string) $_REQUEST['action'] : '';
    if (in_array($action, {_php_list(actions)}, true)) {{
        status_header(403);
        nocache_headers();
        exit('{MARKER}');
    }}
}}, 0);

add_filter('rest_pre_dispatch', static function ($result, $server, $request) {{
    if (is_user_logged_in()) {{
        return $result;
    }}
    $route = ltrim((string) $request->get_route(), '/');
    foreach ({_php_list(p.rest_namespaces)} as $namespace) {{
        if ($route === $namespace || strpos($route, $namespace . '/') === 0) {{
            return new WP_Error('handscheck_virtual_patch', '{MARKER}', array('status' => 403));
        }}
    }}
    return $result;
}}, 0, 3);
"""


class VirtualPatch(Action[VirtualPatchParams]):
    name = "virtual_patch"
    version = 1
    risk = "medium"
    params_model = VirtualPatchParams

    def commands(self, p: VirtualPatchParams, ctx: FixContext) -> list[Cmd]:
        mu, target, staged, quarantine = _paths(p, ctx)
        return [
            Cmd(("test", "-e", target)),
            Cmd(("install", "-d", "-m", "700", quarantine)),
            Cmd(("tee", staged)),
            Cmd(("php", "-l", staged)),
            Cmd(("install", "-d", "-m", "755", mu)),
            Cmd(("install", "-o", "root", "-g", "root", "-m", "644", staged, target)),
            Cmd(("mv", target, f"{quarantine}/{posixpath.basename(target)}")),
        ]

    def preview(self, p: VirtualPatchParams) -> Preview:
        _, target, _, _ = _paths(p, FixContext())
        blocked = []
        if p.ajax_actions:
            blocked.append(f"{len(p.ajax_actions)} AJAX action(s) ({', '.join(p.ajax_actions[:8])})")
        if p.rest_namespaces:
            blocked.append(f"REST routes under {', '.join(p.rest_namespaces[:8])}")
        return Preview(
            summary=f"Virtual patch for {p.slug} on {p.site}: refuse its {' and '.join(blocked)} to "
            f"visitors who aren't logged in, with a root-owned mu-plugin ({target}), until the plugin is "
            "updated.",
            rollback=[f"Move {target} to {QUARANTINE_ROOT}/<fix id>/."],
            verify=[
                f"An anonymous request to admin-ajax.php?action={CHECK_ACTION} on {p.site} is refused (403), "
                "which shows the patch is loaded (the vulnerable handlers themselves are never called).",
                f"{p.site} still answers as before.",
            ],
            notes=[
                "Features of this plugin that visitors use without logging in (for example content it loads "
                "over AJAX on public pages) stop working while the patch is on. Logged-in use keeps working.",
                "It closes the anonymous entry points found in the plugin's code, not every possible "
                "vulnerability: update or remove the plugin, then undo this fix.",
                "The file is checked with `php -l` before it is installed, and is owned by root so the site "
                "user can't change it.",
            ],
        )

    async def precheck(self, ex: Executor, p: VirtualPatchParams, ctx: FixContext) -> None:
        _, target, _, _ = _paths(p, ctx)
        if (await ex.run(Cmd(("test", "-e", target)), check=False)).ok:
            raise Stale(f"{target} is already there")

    async def apply(self, ex: Executor, p: VirtualPatchParams, ctx: FixContext) -> dict[str, Any]:
        mu, target, staged, quarantine = _paths(p, ctx)
        await ex.run(Cmd(("install", "-d", "-m", "700", quarantine)))
        await ex.run(Cmd(("tee", staged)), stdin=mu_plugin(p, ctx.proposal_id))
        await ex.run(Cmd(("php", "-l", staged)))  # a syntax error stops here, before anything is installed
        await ex.run(Cmd(("install", "-d", "-m", "755", mu)))
        await ex.run(Cmd(("install", "-o", "root", "-g", "root", "-m", "644", staged, target)))
        return {"installed": target}

    async def verify(self, ex: Executor, p: VirtualPatchParams, ctx: FixContext) -> list[str]:
        response = await ex.get(p.site, f"/wp-admin/admin-ajax.php?action={CHECK_ACTION}")
        if response.status == 403 and MARKER in (response.body or ""):
            return []
        return [
            f"the patch doesn't answer on {p.site} (admin-ajax.php gave "
            f"{response.status or response.error}): WordPress may not load mu-plugins from {target_dir(p)}"
        ]

    async def rollback(
        self, ex: Executor, p: VirtualPatchParams, ctx: FixContext, data: dict[str, Any]
    ) -> None:
        _, target, _, quarantine = _paths(p, ctx)
        await ex.run(Cmd(("install", "-d", "-m", "700", quarantine)))
        await ex.run(Cmd(("mv", target, f"{quarantine}/{posixpath.basename(target)}")))


def target_dir(p: VirtualPatchParams) -> str:
    return posixpath.join(p.wp_path, "wp-content", "mu-plugins")
