"""Approved fixes (M6). The only code that changes a target host (CLAUDE.md safety rule 2).

- An **action** (`actions/`) is a code template: for a set of parameters it lists every command it may
  run, and implements precheck → apply → verify → rollback. Claude never writes commands; findings get a
  fix proposal from `propose.py`, built from the scan's facts.
- A person approves the proposal in the web app. The approval pins `plan_sha256` (action, version, params).
- The `remediate` job (`handler.py`) refuses to run without an approval or when the plan hash doesn't
  match, uses the remediate key and the fix user, takes an HTTP baseline of the host's sites from the
  worker, runs the action through `PlanPolicy` (only that plan's commands, plus read-only ones), verifies,
  rolls back on a regression, and reports every command with an output hash for the audit log.
- Quarantine, never delete: what an action takes away goes to a root-only directory.
"""
