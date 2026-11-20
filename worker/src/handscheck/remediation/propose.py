"""Which fix to propose for a finding, decided by code from the scan's own facts (never by Claude): the
finding names a subject (a folder, a login), and the fix is offered only when the facts confirm it on that
site. The control plane shows it to people only after the verifier has confirmed the finding."""

from __future__ import annotations

import posixpath
from typing import Any

from pydantic import ValidationError

from handscheck.agents.malware.check import UPLOADS_PHP_KIND, is_known_waf_loader, prepend_target
from handscheck.contracts import Finding, FixProposal
from handscheck.remediation.actions import ACTIONS


def subject_of(finding: Finding) -> str:
    """The subject part of `agent:kind:host:site:subject`."""
    parts = finding.dedupe_key.split(":", 4)
    return parts[4] if len(parts) == 5 else ""


def kind_of(finding: Finding) -> str:
    parts = finding.dedupe_key.split(":", 4)
    return parts[1] if len(parts) == 5 else ""


def propose_fix(finding: Finding, facts: dict[str, Any] | None) -> FixProposal | None:
    if facts and finding.agent == "health":  # host-scoped: the site is in the subject
        try:
            return _restart_service(finding, facts)
        except ValidationError:
            return None
    if not facts or not finding.site:
        return None
    try:
        if finding.agent == "exposure":
            return _disable_indexes(finding, facts)
        if finding.agent == "wordpress":
            if kind_of(finding) == "vulnerable_plugin":
                return _virtual_patch(finding, facts)
            return _neutralize_admin(finding, facts)
        if finding.agent == "malware":
            if kind_of(finding) == UPLOADS_PHP_KIND:
                return _deny_php_in_uploads(finding, facts)
            return _quarantine(finding, facts)
    except ValidationError:
        return None
    return None


def url_dir(subject: str, root: str) -> str | None:
    """A folder as a URL path ending in /, from a URL path or a path under the document root."""
    path = subject.strip()
    if path.startswith(root.rstrip("/") + "/"):
        path = path[len(root.rstrip("/")) :]
    if not path.startswith("/"):
        return None
    return posixpath.normpath(path).rstrip("/") + "/" if path != "/" else "/"


def _disable_indexes(finding: Finding, facts: dict[str, Any]) -> FixProposal | None:
    root = facts.get("root")
    listings = [p if p.endswith("/") else p + "/" for p in facts.get("directory_listings") or []]
    if not isinstance(root, str) or not listings:
        return None
    folder = url_dir(subject_of(finding), root)
    covered = [p for p in listings if folder and p.startswith(folder)]
    kind = kind_of(finding)
    if folder is None and ("listing" in kind or "index" in kind or "browsable" in kind):
        # A finding about several listed folders: the closest folder that holds them all.
        folder = posixpath.commonpath(listings).rstrip("/") + "/"
        covered = listings
    if not covered or folder is None:
        return None
    action = ACTIONS["disable_indexes"]
    params = action.params({"site": finding.site, "root": root, "dir": folder, "listings": covered})
    return action.proposal(params)


def _neutralize_admin(finding: Finding, facts: dict[str, Any]) -> FixProposal | None:
    if "admin" not in kind_of(finding):
        return None
    admins = facts.get("admins") or []
    subject = subject_of(finding).strip()
    target = next((a for a in admins if subject in (a.get("login"), a.get("email"))), None)
    wp_path = facts.get("path")
    # Never the only administrator: the site would be left without one.
    if target is None or not isinstance(wp_path, str) or len(admins) < 2:
        return None
    action = ACTIONS["neutralize_wp_admin"]
    params = action.params(
        {"site": finding.site, "wp_path": wp_path, "user_id": target["id"], "login": target["login"]}
    )
    return action.proposal(params)


def quarantine_candidates(facts: dict[str, Any]) -> list[str]:
    """Files the malware facts flag that are safe to move away: PHP in uploads (also hidden in non-PHP
    names), PHP in wp-content outside plugins/themes/uploads, and fingerprinted files in uploads. Never a
    file in a plugin or theme (the fix there is a clean copy), never a suppressed look-alike (the parser
    already left those out), and never a file a prepend directive loads (every page would break: the
    directive has to go first)."""
    uploads = "/wp-content/uploads/"
    paths = {str(f.get("path", "")) for f in facts.get("php_in_uploads") or []}
    paths |= {str(f.get("path", "")) for f in facts.get("unexpected_php") or []}
    paths |= {str(p) for p in facts.get("php_in_non_php") or [] if uploads in str(p)}
    paths |= {
        str(h.get("path", "")) for h in facts.get("fingerprint_hits") or [] if uploads in str(h.get("path"))
    }
    loaded = set()
    for d in facts.get("php_directives") or []:
        target = prepend_target(str(d.get("text", "")))
        if target and not is_known_waf_loader(target):
            loaded.add(target)
    return sorted(p for p in paths if p.startswith("/") and p not in loaded)


def _quarantine(finding: Finding, facts: dict[str, Any]) -> FixProposal | None:
    root = facts.get("root")
    if not isinstance(root, str):
        return None
    subject = subject_of(finding).strip()
    if not subject:
        return None
    rel = subject.lstrip("/")
    candidates = [p for p in quarantine_candidates(facts) if p.startswith(root.rstrip("/") + "/")]
    files = [p for p in candidates if p == subject or p.endswith("/" + rel)]
    if not files and "." not in posixpath.basename(subject.rstrip("/")):
        # A finding about a folder: the flagged files in it.
        folder = "/" + rel.rstrip("/") + "/"
        files = [p for p in candidates if folder in p + "/" and p != folder.rstrip("/")]
    if not files:
        return None
    action = ACTIONS["quarantine_file"]
    params = action.params({"site": finding.site, "root": root, "files": files[:20]})
    return action.proposal(params)


def _deny_php_in_uploads(finding: Finding, facts: dict[str, Any]) -> FixProposal | None:
    root, content = facts.get("root"), facts.get("wp_content")
    if not isinstance(root, str) or not isinstance(content, str) or facts.get("server") != "apache":
        return None
    if not content.startswith(root.rstrip("/") + "/") and content != root:
        return None  # wp-content outside the web root: no URL to check the rule with
    uploads = content[len(root.rstrip("/")) :].rstrip("/") + "/uploads/"
    action = ACTIONS["deny_php_in_uploads"]
    params = action.params({"site": finding.site, "root": root, "uploads": uploads})
    return action.proposal(params)


def _virtual_patch(finding: Finding, facts: dict[str, Any]) -> FixProposal | None:
    """A plugin with a known exploit whose code offers anonymous entry points: refuse them until it's
    updated."""
    slug = subject_of(finding).strip()
    wp_path = facts.get("path")
    match = next((v for v in facts.get("vulnerable_plugins") or [] if v.get("slug") == slug), None)
    if match is None or not isinstance(wp_path, str):
        return None
    if not match.get("ajax_nopriv") and not match.get("rest_namespaces"):
        return None
    action = ACTIONS["virtual_patch"]
    params = action.params(
        {
            "site": finding.site,
            "wp_path": wp_path,
            "slug": slug,
            "rule": match.get("rule"),
            "ajax_actions": match.get("ajax_nopriv") or [],
            "rest_namespaces": match.get("rest_namespaces") or [],
        }
    )
    return action.proposal(params)


def _restart_service(finding: Finding, facts: dict[str, Any]) -> FixProposal | None:
    """A site visitors can't use (health site_down/site_slow) whose cause the facts show: its php-fpm pool ran
    out of workers, or its pool or the web server isn't running. No visible cause, no restart."""
    if kind_of(finding) not in ("site_down", "site_slow"):
        return None
    site = subject_of(finding).split("@", 1)[0]
    pool = (facts.get("site_pools") or {}).get(site)
    services = {str(s.get("name")): bool(s.get("active")) for s in facts.get("services") or []}
    stopped = sorted(name for name, active in services.items() if not active)
    service = None
    if pool and pool in stopped:
        service = pool
    elif web := [s for s in stopped if s in ("apache2", "nginx")]:
        service = web[0]
    elif pool and pool in services and (facts.get("max_children") or {}).get(pool):
        service = pool
    if service is None:
        return None
    slow_s = float((facts.get("rule_settings") or {}).get("slow_s", 5.0))
    action = ACTIONS["restart_service"]
    return action.proposal(action.params({"site": site, "service": service, "slow_s": slow_s}))
