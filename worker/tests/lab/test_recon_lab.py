"""M7c against the Docker lab: `hc recon` (no Claude) maps lab-wp2 and stores what it proposes.

A second PHP-FPM pool running as `handscheck` is planted through the fix user (test-only `PlanPolicy`), so the
inventory has something the defaults don't cover: recon proposes adding that account to `web_users`, `--apply`
stores it, and the next `hc check` uses it. The pool file is moved aside afterwards (php-fpm isn't reloaded).

Run: docker compose up -d lab-db lab-wp2 && docker compose run --rm worker pytest -m lab
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from handscheck.config import Settings
from handscheck.standalone import service
from handscheck.standalone.state import StandaloneState

from .test_health_lab import _as_fix_user
from .test_lab_hosts import _lab_key

pytestmark = pytest.mark.lab

POOL = "/etc/php/7.0/fpm/pool.d/zz-lab-recon.conf"
POOL_TEXT = (
    "[labrecon]\nuser = handscheck\ngroup = handscheck\nlisten = /run/php/lab-recon.sock\n"
    "pm = ondemand\npm.max_children = 1\n"
)


def test_recon_maps_the_host_and_applies_its_proposal(tmp_path: Path) -> None:
    key = _lab_key()
    settings = Settings(state_dir=tmp_path)
    service.add_host(settings, "lab-wp2", address="lab-wp2", key_path=key)

    quiet = service.recon(settings, "lab-wp2", use_claude=False, apply=True)
    assert quiet.recon is not None and "Ubuntu 16.04" in quiet.recon.profile
    assert quiet.recon.changes == [] and not quiet.applied  # the lab's defaults fit

    asyncio.run(_as_fix_user(key, ("tee", POOL), stdin=POOL_TEXT))
    try:
        out = service.recon(settings, "lab-wp2", use_claude=False, apply=True)
    finally:
        asyncio.run(_as_fix_user(key, ("mv", "-f", POOL, "/tmp/zz-lab-recon.conf")))  # aside, not deleted
    assert out.recon is not None and out.recon.inventory["pool_users"]["php7.0-fpm"] == [
        "handscheck",
        "www-data",
    ]
    proposed = {c.agent: c.settings for c in out.recon.changes}
    assert proposed["persistence"]["web_users"][-1] == "handscheck" and out.applied
    stored = {s.agent: s.settings for s in StandaloneState.open(tmp_path).host_settings("lab-wp2")}
    assert stored["persistence"]["web_users"] == proposed["persistence"]["web_users"]

    checked = service.run_checks(settings, ["persistence"], host_names=["lab-wp2"])
    persistence = next(r for r in checked[0].run.results() if r.agent == "persistence")
    assert persistence.status in ("ok", "partial") and persistence.facts is not None
