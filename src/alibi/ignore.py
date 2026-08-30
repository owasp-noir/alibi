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
        with source.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return cls(entries=[_entry(item) for item in (data.get("ignore") or [])],
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
            IgnoreEntry(path=re.compile(p), why="given on the command line")
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


def _entry(item: dict) -> IgnoreEntry:
    pattern = item.get("path")
    return IgnoreEntry(
        path=re.compile(pattern) if pattern else None,
        rule=item.get("rule"),
        view=item.get("view"),
        why=item.get("why", ""),
    )
