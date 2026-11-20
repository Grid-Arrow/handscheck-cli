"""Worker settings, read from HANDSCHECK_* environment variables."""

import os
import pwd
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_state_dir() -> Path:
    # The running user's own home from the password database, not $HOME: `sudo -u handscheck hc …` can keep
    # root's HOME (e.g. Ubuntu 16.04), where the handscheck user can't write.
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except KeyError:
        home = Path.home()
    return home / ".local" / "share" / "handscheck"


def repo_root() -> Path | None:
    """The monorepo root when running from a source checkout (worker/src/handscheck → repo), else None."""
    root = Path(__file__).resolve().parents[3]
    return root if (root / "worker" / "pyproject.toml").is_file() else None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HANDSCHECK_")

    state_dir: Path = _default_state_dir()
    """Standalone state (SQLite, local inventory). Dev/admin only, never the product's data."""

    key_dir: Path | None = None
    """Where `hc setup` keeps the standalone SSH key. Default: the repo's .local/keys/ (the lab hosts install
    every *.pub there), or <state_dir>/keys outside a checkout."""

    api: str | None = None
    """Control plane base URL for `hc worker`."""

    worker_token: str | None = None
    """Sanctum token for the worker API. Never logged."""

    claude_budget_usd: float = 5.0
    """Dollar ceiling for the Claude calls of one `hc check` host run (or one investigate/correlate)."""

    def resolved_key_dir(self) -> Path:
        if self.key_dir is not None:
            return self.key_dir
        root = repo_root()
        return root / ".local" / "keys" if root else self.state_dir / "keys"


def get_settings() -> Settings:
    return Settings()
