"""handscheck.ai scanning engine."""

from importlib import import_module
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("handscheck")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0"

try:  # a release bundle knows its commit (written by the Deploy workflow): 0.1.0+f3c8f9e33900
    __version__ += "+" + str(import_module("handscheck._release").COMMIT)[:12]
except ImportError:
    pass
