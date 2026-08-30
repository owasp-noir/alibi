"""Cross-check the views of your attack surface."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("noir-alibi")
except PackageNotFoundError:  # running from a source tree, never installed
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
