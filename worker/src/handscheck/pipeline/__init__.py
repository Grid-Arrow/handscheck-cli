"""Run agents for a host: collect → diff → (Claude, M4) → findings. See `run.py`."""

from handscheck.pipeline.diff import Change, diff_views
from handscheck.pipeline.run import AgentResult, HostRun, PreviousSnapshot, run_host

__all__ = ["AgentResult", "Change", "HostRun", "PreviousSnapshot", "diff_views", "run_host"]
