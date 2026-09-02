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
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path


class NoirNotFound(RuntimeError):
    pass


class NoirFailed(RuntimeError):
    pass


class NoirTooOld(RuntimeError):
    pass


# `noir list techs` is a v1.0.0 subcommand -- before it, the catalog was read
# with `--list-techs`, and v1 only keeps that spelling as a silent alias going
# the other way. Since the catalog is what assigns every technology to a view,
# an older noir does not fail in some degraded corner; it fails at the first
# thing alibi asks. So the floor is stated once, here, and checked before a
# scan rather than discovered as "could not read `noir list techs -f json`".
MINIMUM_NOIR = (1, 0, 0)

_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")


@dataclass
class Source:
    """One place to point noir at."""

    path: str
    name: str = ""
    # The path the user actually named. A file source is staged into a
    # temporary directory before noir sees it, and `path` becomes that
    # directory -- but a report has to speak in terms of what was asked for.
    root: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            self.name = Path(self.path).name or self.path
        if not self.root:
            self.root = self.path


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

    # Reasons noir gives for passing over something *on purpose*. A symlink
    # whose target the walk already covered, a file whose bytes are binary,
    # an image: none of those was ever going to yield an endpoint, and
    # alarming about them trains the reader to skip the section that matters.
    #
    # Noir's own wording, from the `first error:` half of the message it
    # builds in `Noir::SkippedFiles`. It has been stable across releases, and
    # a phrase that drifts fails safe here -- see `consequential`.
    DECLINED_ON_PURPOSE = (
        "symbolic link",
        "not a regular file",
        "binary content",
        "media file",
    )

    @property
    def consequential(self) -> bool:
        """Might this have cost the scan endpoints?

        An allow-list of the benign reasons, not a watch-list of the alarming
        ones. That direction is the whole point: noir keeps growing the set of
        losses it reports -- noir 1.3.0 added an unparsable specification
        document and an entry it could not stat, which between them cover a
        whole doc view and a whole subtree -- and a watch-list files every
        loss it has not been taught about under "skipped media, binaries or
        symlinks". Silence about a lost view is the one failure this class
        exists to prevent, so an unrecognised reason has to read as a loss.

        The cost of the inversion is a benign skip occasionally reported as a
        loss, which is a line of noise. The cost of the other direction is
        `0 endpoints` presented as a clean result.
        """
        message = self.message.lower()
        return not any(mark in message for mark in self.DECLINED_ON_PURPOSE)


@dataclass
class ScanResult:
    endpoints: list[RawEndpoint]
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
    source_root: str = ""
    raw: dict = field(default_factory=dict)


def sources(paths: list[str]) -> list[Source]:
    """One Source per path the user named, each with a name of its own.

    The name is the basename, because that is what fits in a report column.
    But a monorepo laid out the usual way gives `services/billing` and
    `services/search` the same one, and the per-source table then prints two
    rows reading `service` that each claim the other's endpoints -- the exact
    opposite of what the table is for, which is telling the reader which path
    came back empty.

    A basename shared by more than one path falls back to the path as typed.
    """
    built = [Source(path=path) for path in paths]
    taken: dict[str, int] = {}
    for source in built:
        taken[source.name] = taken.get(source.name, 0) + 1
    for source, path in zip(built, paths, strict=True):
        if taken[source.name] > 1:
            source.name = path
    return built


@contextmanager
def scannable(source: Source):
    """Hand noir a directory, whichever kind of path was named.

    Noir scans directories, and a single file is a reasonable thing to point
    alibi at -- one HAR or one OpenAPI document holds an entire view. Scanning
    the file's real parent instead would quietly pull in everything beside it,
    which for a `captures/` directory is every other capture and for a repo
    root is the repo.

    So a file source is staged alone in a temporary directory. A hard link
    keeps a large capture from being copied; crossing a filesystem falls back
    to a copy. A path that does not exist is passed through untouched, because
    noir's own error message is better than any this could invent.
    """
    path = Path(source.path)
    if path.is_dir() or not path.exists():
        yield source
        return

    with tempfile.TemporaryDirectory(prefix="alibi-") as staging:
        staged = Path(staging) / path.name
        try:
            os.link(path, staged)
        except OSError:
            shutil.copy2(path, staged)
        yield Source(path=staging, name=source.name, root=source.root)


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


def noir_version(noir_bin: str, timeout: int = 30) -> tuple[int, int, int] | None:
    """Read the binary's version, or None when it will not say.

    `--version` rather than the v1 `version` subcommand: the whole point is to
    recognise a noir too old to have subcommands, and v1 accepts both.
    """
    try:
        proc = subprocess.run(
            [noir_bin, "--version"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    found = _VERSION.search(proc.stdout or proc.stderr or "")
    if not found:
        return None
    return tuple(int(part) for part in found.groups())


def require_version(noir_bin: str) -> tuple[int, int, int] | None:
    """Refuse a noir known to be too old; say nothing about one that will not say.

    A binary that reports no version is not evidence of an old one -- a wrapper
    script or a build from source can both be current -- and refusing to run on
    an absence would block installations that work. Only a version that reads
    below the floor is grounds to stop.
    """
    found = noir_version(noir_bin)
    if found is not None and found < MINIMUM_NOIR:
        raise NoirTooOld(
            f"noir {'.'.join(str(part) for part in found)} is too old; alibi "
            f"needs {'.'.join(str(part) for part in MINIMUM_NOIR)} or newer "
            f"for `noir list techs`. Upgrade it "
            f"(https://github.com/owasp-noir/noir)."
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
    # `-T` runs noir's taggers. They are off by default there, and alibi's
    # whole severity ladder is built on what they find: whether an endpoint
    # touches personal data, accepts an upload, or shows any sign of an
    # authentication check. Without it every finding is graded on its HTTP verb
    # alone -- on Casdoor that collapsed 139 findings into 64 "high" and 62
    # "medium" separated by nothing but POST-versus-GET, which the method column
    # already says. With it, the same scan surfaces pii, file_upload, oauth and
    # payment tags on 108 endpoints.
    cmd = [noir_bin, "-b", source.path, "-f", "json", "-T"]
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
        endpoints=[_convert(item, source.name, source.root)
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


def _convert(item: dict, source_name: str, source_root: str = "") -> RawEndpoint:
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
        source_root=source_root,
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
