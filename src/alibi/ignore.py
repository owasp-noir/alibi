"""Per-project suppression.

Some gaps are the intended state. An internal admin surface is not documented
on purpose, a debug endpoint is unreachable on purpose, and a scan that keeps
reporting them teaches the reader to skim past everything else too.

Suppressed findings are counted and the count is printed. A tool that quietly
drops findings is worse than one that prints too many, because there is no
longer any way to tell what it decided not to say.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Looked for beside the scanned source, then in the working directory, so a
# project can carry its own suppressions in version control.
CONFIG_NAMES = (".alibi.yml", ".alibi.yaml")


class IgnoreError(RuntimeError):
    """A suppression list that cannot be read. Reported, never raised at the user.

    Every input here is hand-written -- a regex on the command line, a YAML
    file in the repository -- so getting one wrong is ordinary, and a
    traceback is the wrong way to say `[` is missing its `]`.
    """


@dataclass
class IgnoreEntry:
    path: re.Pattern[str] | None = None
    rule: str | None = None
    view: str | None = None
    why: str = ""

    def covers(self, finding) -> bool:
        if self.rule and finding.rule_id != self.rule:
            return False
        if self.view and self.view not in finding.entry.views:
            return False
        if self.path and not self.path.search(finding.key.path):
            return False
        # An entry with no condition at all would silence everything, which is
        # never what someone meant to write.
        return bool(self.rule or self.view or self.path)


@dataclass
class IgnoreList:
    entries: list[IgnoreEntry] = field(default_factory=list)
    source: str = ""

    @classmethod
    def load(cls, path: str | Path) -> IgnoreList:
        source = Path(path)
        try:
            with source.open(encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except OSError as exc:
            raise IgnoreError(f"cannot read {source}: {exc.strerror or exc}") from exc
        except yaml.YAMLError as exc:
            raise IgnoreError(f"{source} is not valid YAML: {exc}") from exc

        if not isinstance(data, dict):
            raise IgnoreError(
                f"{source} should be a mapping with an `ignore:` list, "
                f"not {type(data).__name__}")
        listed = data.get("ignore") or []
        if not isinstance(listed, list):
            raise IgnoreError(f"`ignore:` in {source} should be a list, "
                              f"not {type(listed).__name__}")
        return cls(entries=[_entry(item, source) for item in listed],
                   source=str(source))

    @classmethod
    def discover(cls, search_paths: list[str]) -> IgnoreList:
        """Find a project's own suppressions without being told where."""
        candidates = [Path(p) for p in search_paths] + [Path.cwd()]
        for base in candidates:
            directory = base if base.is_dir() else base.parent
            for name in CONFIG_NAMES:
                found = directory / name
                if found.is_file():
                    return cls.load(found)
        return cls()

    @classmethod
    def from_patterns(cls, patterns: list[str]) -> IgnoreList:
        return cls(entries=[
            IgnoreEntry(path=_pattern(p, "--ignore"), why="given on the command line")
            for p in patterns
        ], source="--ignore")

    def extend(self, other: IgnoreList) -> IgnoreList:
        return IgnoreList(entries=self.entries + other.entries,
                          source=self.source or other.source)

    def __len__(self) -> int:
        return len(self.entries)

    def matching(self, finding) -> IgnoreEntry | None:
        for entry in self.entries:
            if entry.covers(finding):
                return entry
        return None

    def apply(self, findings: list) -> tuple[list, list[tuple]]:
        """Split findings into what is reported and what was suppressed."""
        kept, dropped = [], []
        for finding in findings:
            entry = self.matching(finding)
            if entry is None:
                kept.append(finding)
            else:
                dropped.append((finding, entry))
        return kept, dropped


def _entry(item, source) -> IgnoreEntry:
    if not isinstance(item, dict):
        raise IgnoreError(f"every entry under `ignore:` in {source} should be a "
                          f"mapping with a path, rule or view -- found "
                          f"{type(item).__name__}")
    pattern = item.get("path")
    return IgnoreEntry(
        path=_pattern(pattern, source) if pattern else None,
        rule=item.get("rule"),
        view=item.get("view"),
        why=item.get("why", ""),
    )


def _pattern(pattern, source) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except (re.error, TypeError) as exc:
        raise IgnoreError(f"{pattern!r} in {source} is not a valid regular "
                          f"expression: {exc}") from exc
