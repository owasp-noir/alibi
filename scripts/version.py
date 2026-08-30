#!/usr/bin/env python3
"""Version consistency across the files that carry one.

`pyproject.toml` is the source of truth -- it is what the build reads and what
release.yml compares the tag against. Everything else has to agree with it.

`src/alibi/__init__.py` is deliberately not one of those places: it reads the
version back out of the installed package metadata, so there is nothing there
to drift. This script asserts that it stays that way, because the moment
someone writes a literal into it there are two answers to what version this is
and no reason for them to agree.

Usage:
    python scripts/version.py check          # just version-check
    python scripts/version.py update 0.2.0   # just version-update 0.2.0

Exit codes: 0 consistent, 1 not.
"""

from __future__ import annotations

import re
import sys
import tomllib
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
INIT = ROOT / "src" / "alibi" / "__init__.py"
REPO = "https://github.com/owasp-noir/alibi"

SEMVER = re.compile(r"^\d+\.\d+\.\d+([-+].+)?$")
# A literal version string in __init__.py, as opposed to the metadata lookup.
HARDCODED = re.compile(r'''^__version__\s*=\s*["']\d''', re.MULTILINE)


def packaged() -> str:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]


def changelog_section(version: str) -> str | None:
    """The dated heading for this version, if the changelog has one."""
    found = re.search(rf"^## \[{re.escape(version)}\] - (\S+)\s*$",
                      CHANGELOG.read_text(encoding="utf-8"), re.MULTILINE)
    return found.group(1) if found else None


def changelog_links(version: str) -> list[str]:
    """Which of the two link definitions a release needs are missing."""
    text = CHANGELOG.read_text(encoding="utf-8")
    missing = []
    if not re.search(rf"^\[{re.escape(version)}\]: \S+$", text, re.MULTILINE):
        missing.append(f"[{version}]")
    if f"compare/v{version}...HEAD" not in text:
        missing.append("[Unreleased] pointing at this version")
    return missing


def check() -> int:
    version = packaged()
    rows: list[tuple[str, str, bool]] = []

    rows.append(("pyproject.toml", version, bool(SEMVER.match(version))))

    dated = changelog_section(version)
    rows.append(("CHANGELOG.md section", dated or "not found", dated is not None))

    missing = changelog_links(version)
    rows.append(("CHANGELOG.md links",
                 "ok" if not missing else "missing " + ", ".join(missing),
                 not missing))

    derived = not HARDCODED.search(INIT.read_text(encoding="utf-8"))
    rows.append(("src/alibi/__init__.py",
                 "derived from metadata" if derived else "HARDCODED",
                 derived))

    width = max(len(label) for label, _, _ in rows)
    print(f"Version: {version}\n")
    for label, value, ok in rows:
        print(f"  {'ok ' if ok else 'BAD'}  {label.ljust(width)}  {value}")
    print()

    bad = [label for label, _, ok in rows if not ok]
    if bad:
        print(f"Inconsistent in {len(bad)} place(s): {', '.join(bad)}")
        print("Run `just version-update <VERSION>` to set them together.")
        return 1
    print(f"Consistent. `git tag v{version}` publishes it.")
    return 0


def update(version: str) -> int:
    if not SEMVER.match(version):
        print(f"not a version: {version}", file=sys.stderr)
        return 1

    previous = packaged()
    if version == previous:
        print(f"already {version}", file=sys.stderr)
        return 1

    text = PYPROJECT.read_text(encoding="utf-8")
    bumped, count = re.subn(rf'^version = "{re.escape(previous)}"$',
                            f'version = "{version}"', text, count=1,
                            flags=re.MULTILINE)
    if count != 1:
        print("could not find the version line in pyproject.toml", file=sys.stderr)
        return 1
    PYPROJECT.write_text(bumped, encoding="utf-8")

    log = CHANGELOG.read_text(encoding="utf-8")
    if changelog_section(version):
        print(f"CHANGELOG.md already has a {version} section", file=sys.stderr)
        return 1

    # Everything written under Unreleased becomes this release, and Unreleased
    # is left empty for what comes next.
    today = date.today().isoformat()
    log, count = re.subn(r"^## \[Unreleased\]\n",
                         f"## [Unreleased]\n\n## [{version}] - {today}\n",
                         log, count=1, flags=re.MULTILINE)
    if count != 1:
        print("could not find the Unreleased heading in CHANGELOG.md", file=sys.stderr)
        return 1

    log = log.replace(
        f"[Unreleased]: {REPO}/compare/v{previous}...HEAD",
        f"[Unreleased]: {REPO}/compare/v{version}...HEAD\n"
        f"[{version}]: {REPO}/compare/v{previous}...v{version}")
    CHANGELOG.write_text(log, encoding="utf-8")

    print(f"{previous} -> {version}")
    print("  pyproject.toml")
    print(f"  CHANGELOG.md   (Unreleased rolled into {version}, dated {today})")
    print()
    print("Write the release notes under that heading, commit, then:")
    print(f"  git tag v{version} && git push origin v{version}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 1 and argv[0] == "check":
        return check()
    if len(argv) == 2 and argv[0] == "update":
        return update(argv[1])
    print(__doc__, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
