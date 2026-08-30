"""Run noir and hand back its endpoints, one view at a time.

Alibi parses no API formats of its own. OpenAPI, HAR, nginx.conf, Terraform --
noir already reads all of them and emits one normalized endpoint list, so the
contract here is exactly one thing: noir's `-f json` on stdout.

**Why one scan per view rather than one scan total.** Noir deduplicates its
results by (method, url) across every analyzer, so when a Flask route and an
OpenAPI path are spelled identically, the two collapse into a single endpoint
carrying a single `details.technology`. That is correct for a discovery tool --
it is one endpoint -- but it destroys precisely the signal this one needs: an
endpoint corroborated by two views becomes indistinguishable from one that only
ever appeared in whichever analyzer won. Worse, it fails silently and in the
wrong direction, because the better the two views agree, the more of them
disappear. Casdoor scans as 372 code endpoints and 9 documented ones; scan its
`swagger/` directory alone and the specification has 235.

`--only-techs` restricts the detector pool, so a scan per view keeps each one
whole. It costs a handful of noir invocations, each narrower than a full scan.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path


class NoirNotFound(RuntimeError):
    pass


class NoirFailed(RuntimeError):
    pass


@dataclass
class Source:
    """One place to point noir at."""

    path: str
    name: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            self.name = Path(self.path).name or self.path


@dataclass(frozen=True)
class ScanError:
    """Something noir could not read.

    Noir reports these in an `errors` key and they change what its silence
    means. NetBox ships a 12.35MB OpenAPI document with 308 paths; noir skips
    it for exceeding the file-size cap and says so. Discard that and alibi
    concludes there is "no doc source in this scan" -- which is not merely
    incomplete but the wrong conclusion drawn confidently.
    """

    tech: str
    message: str
    source: str = ""


@dataclass
class ScanResult:
    endpoints: list["RawEndpoint"]
    errors: list[ScanError]


@dataclass
class RawEndpoint:
    """A noir endpoint plus where alibi got it from."""

    url: str
    method: str
    technology: str
    source: str
    tags: tuple[str, ...] = ()
    params: tuple[dict, ...] = ()
    code_paths: tuple[dict, ...] = ()
    internal: bool = False
    protocol: str = "http"
    raw: dict = field(default_factory=dict)


def find_noir(explicit: str | None = None) -> str:
    """Locate the noir binary, preferring an explicit path."""
    if explicit:
        if Path(explicit).is_file():
            return explicit
        raise NoirNotFound(f"no noir binary at {explicit}")
    found = shutil.which("noir")
    if not found:
        raise NoirNotFound(
            "noir is not on PATH. Install it (https://github.com/owasp-noir/noir) "
            "or point at a binary with --noir-bin."
        )
    return found


def scan(source: Source, noir_bin: str, extra_args: list[str] | None = None,
         timeout: int = 900, only_techs: list[str] | None = None) -> ScanResult:
    """Run one noir scan and return its endpoints.

    Noir writes its logs to stderr and the JSON document to stdout, so the two
    never need separating here. `--nolog` is deliberately not passed: it
    suppresses the `-f json` document along with the logs, which would leave
    this function parsing an empty string and reporting a clean, empty scan.
    """
    cmd = [noir_bin, "-b", source.path, "-f", "json"]
    if only_techs:
        cmd += ["--only-techs", ",".join(only_techs)]
    cmd += extra_args or []
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise NoirFailed(f"noir timed out after {timeout}s on {source.path}") from exc

    if proc.returncode != 0 and not proc.stdout.strip():
        detail = (proc.stderr or "").strip().splitlines()
        tail = detail[-1] if detail else f"exit status {proc.returncode}"
        raise NoirFailed(f"noir failed on {source.path}: {tail}")

    try:
        document = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise NoirFailed(
            f"noir produced no JSON for {source.path}. "
            f"Check that the path exists and that this noir build supports `-f json`."
        ) from exc

    return ScanResult(
        endpoints=[_convert(item, source.name)
                   for item in document.get("endpoints", [])],
        errors=[
            ScanError(
                tech=str(item.get("tech", "")),
                message=str(item.get("message", "")),
                source=source.name,
            )
            for item in (document.get("errors") or [])
        ],
    )


def scan_views(source: Source, noir_bin: str, techs_by_view: dict[str, list[str]],
               extra_args: list[str] | None = None, workers: int = 4) -> ScanResult:
    """Scan one source once per view, so corroboration survives.

    The runs are independent processes waiting on I/O, so they overlap. Noir
    parallelises internally too, which is why the pool is small.
    """
    endpoints: list[RawEndpoint] = []
    errors: list[ScanError] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan, source, noir_bin, extra_args, only_techs=techs): view
            for view, techs in techs_by_view.items()
            if techs
        }
        for future in as_completed(futures):
            result = future.result()
            endpoints.extend(result.endpoints)
            errors.extend(result.errors)

    # One unreadable file is reported by every view's scan that walked past it,
    # so the same skip arrives up to five times. It is one fact.
    return ScanResult(endpoints=endpoints, errors=list(dict.fromkeys(errors)))


def _convert(item: dict, source_name: str) -> RawEndpoint:
    details = item.get("details") or {}
    return RawEndpoint(
        url=item.get("url", ""),
        method=item.get("method", ""),
        technology=details.get("technology", ""),
        source=source_name,
        tags=tuple(_tag_names(item.get("tags") or [])),
        params=tuple(item.get("params") or []),
        code_paths=tuple(details.get("code_paths") or []),
        internal=bool(item.get("internal", False)),
        protocol=item.get("protocol", "http"),
        raw=item,
    )


def _tag_names(tags: list) -> list[str]:
    """Noir tags are objects; some formats flatten them to plain strings."""
    names = []
    for tag in tags:
        if isinstance(tag, dict):
            name = tag.get("name") or tag.get("tag")
            if name:
                names.append(str(name))
        elif tag:
            names.append(str(tag))
    return names


def list_techs(noir_bin: str, timeout: int = 60) -> dict:
    """Read noir's own technology catalog -- the authority for view drift."""
    proc = subprocess.run(
        [noir_bin, "list", "techs", "-f", "json"],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise NoirFailed("could not read `noir list techs -f json`") from exc
