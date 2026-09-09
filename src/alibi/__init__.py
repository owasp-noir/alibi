"""Cross-check the views of your attack surface."""

__all__ = ["__version__"]


def __getattr__(name: str) -> str:
    """Read the installed version the first time somebody asks for it.

    Reading it eagerly imports importlib.metadata, which costs 19 ms of the
    70 ms an `alibi --version` takes and is paid by every invocation --
    including every scan, which never reads the value. Only `--version` and
    the SARIF report do.

    Still derived from the package metadata rather than written down here:
    a literal would be a second answer to what version this is, and
    scripts/version.py fails the build if one appears.
    """
    if name != "__version__":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("noir-alibi")
    except PackageNotFoundError:  # running from a source tree, never installed
        return "0.0.0+unknown"
