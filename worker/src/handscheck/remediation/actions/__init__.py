"""The fix actions this worker can apply, by name. M6a: disable_indexes, neutralize_wp_admin. M6b:
quarantine_file, deny_php_in_uploads. M6c: virtual_patch. M7b: restart_service (with the health agent)."""

from __future__ import annotations

from typing import Any

from handscheck.remediation.actions.deny_php_in_uploads import DenyPhpInUploads
from handscheck.remediation.actions.disable_indexes import DisableIndexes
from handscheck.remediation.actions.neutralize_wp_admin import NeutralizeWpAdmin
from handscheck.remediation.actions.quarantine_file import QuarantineFile
from handscheck.remediation.actions.restart_service import RestartService
from handscheck.remediation.actions.virtual_patch import VirtualPatch
from handscheck.remediation.base import Action

ACTIONS: dict[str, Action[Any]] = {
    a.name: a
    for a in (
        DisableIndexes(),
        NeutralizeWpAdmin(),
        QuarantineFile(),
        DenyPhpInUploads(),
        VirtualPatch(),
        RestartService(),
    )
}
