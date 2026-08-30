"""Turn view membership into findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .index import Entry, Index

_RULES_FILE = Path(__file__).with_name("rules.yml")


@dataclass
class Adjustment:
    shift: int
    why: str


@dataclass
class Finding:
    rule_id: str
    name: str
    summary: str
    detail: str
    severity: str
    base_severity: str
    entry: Entry
    adjustments: list[Adjustment] = field(default_factory=list)

    @property
    def key(self):
        return self.entry.key

    @property
    def grade(self) -> str:
        return self.entry.grade

    @property
    def uncertain(self) -> bool:
        return bool(self.entry.near_misses)


@dataclass
class Skipped:
    """A rule that could not run, and why. Reported, never silently dropped."""

    rule_id: str
    missing: list[str]


class RuleSet:
    def __init__(self, data: dict) -> None:
        self.severities: list[str] = data.get(
            "severities", ["info", "low", "medium", "high", "critical"]
        )
        self.rules: list[dict] = data.get("rules", [])
        self.adjustments: list[dict] = data.get("adjustments", [])
        self.suppressions: list[dict] = data.get("suppress", [])

    @classmethod
    def load(cls, path: Path | None = None) -> "RuleSet":
        source = path or _RULES_FILE
        with source.open(encoding="utf-8") as handle:
            return cls(yaml.safe_load(handle))

    def _shift(self, severity: str, steps: int) -> str:
        try:
            position = self.severities.index(severity)
        except ValueError:
            return severity
        moved = max(0, min(len(self.severities) - 1, position + steps))
        return self.severities[moved]

    def evaluate(self, index: Index, present_views: set[str]) -> tuple[list[Finding], list[Skipped]]:
        findings: list[Finding] = []
        skipped: list[Skipped] = []
        runnable = []
        signals = self._available_signals(index)

        for rule in self.rules:
            missing = [v for v in rule.get("needs", []) if v not in present_views]
            if missing:
                skipped.append(Skipped(rule["id"], missing))
                continue
            runnable.append(rule)

        for entry in index.entries.values():
            for rule in runnable:
                if not self._matches(entry, rule):
                    continue
                if self._suppressed(entry):
                    continue
                findings.append(self._build(entry, rule, signals))

        findings.sort(
            key=lambda f: (-self.severities.index(f.severity), f.key.path, f.key.method)
        )
        return findings, skipped

    def _available_signals(self, index: Index) -> set[str]:
        """Which absence-based adjustments have evidence that they mean anything.

        An adjustment keyed on a missing tag is only informative when that tag
        appears *somewhere* in the scan -- that is what proves the tagger runs
        on this stack at all. Recording which signals are live once per scan
        keeps the per-finding check to a set lookup.
        """
        every_tag = {tag for entry in index.entries.values() for tag in entry.tags}
        live: set[str] = set()
        for adjustment in self.adjustments:
            needs = adjustment.get("needs_signal")
            if not needs:
                continue
            pattern = needs.get("tag_matching")
            if pattern and any(re.search(pattern, tag, re.IGNORECASE) for tag in every_tag):
                live.add(adjustment["id"])
        return live

    def _matches(self, entry: Entry, rule: dict) -> bool:
        views = entry.views
        if not all(v in views for v in rule.get("present", [])):
            return False
        if any(v in views for v in rule.get("absent", [])):
            return False
        return True

    def _suppressed(self, entry: Entry) -> bool:
        return any(self._condition(entry, s["when"]) for s in self.suppressions)

    def _build(self, entry: Entry, rule: dict, signals: set[str]) -> Finding:
        base = rule.get("severity", "medium")
        severity = base
        applied: list[Adjustment] = []

        for adjustment in self.adjustments:
            scope = adjustment.get("rules")
            if scope and rule["id"] not in scope:
                continue
            if adjustment.get("needs_signal") and adjustment["id"] not in signals:
                continue
            if self._condition(entry, adjustment["when"]):
                shift = int(adjustment["shift"])
                severity = self._shift(severity, shift)
                applied.append(Adjustment(shift, adjustment.get("why", "")))

        return Finding(
            rule_id=rule["id"],
            name=rule.get("name", rule["id"]),
            summary=rule.get("summary", ""),
            detail=(rule.get("detail") or "").strip(),
            severity=severity,
            base_severity=base,
            entry=entry,
            adjustments=applied,
        )

    def _condition(self, entry: Entry, when: dict) -> bool:
        if "tag" in when and when["tag"] not in entry.tags:
            return False
        if "no_tag_matching" in when:
            pattern = re.compile(when["no_tag_matching"], re.IGNORECASE)
            if any(pattern.search(tag) for tag in entry.tags):
                return False
        if "method_in" in when and entry.key.method not in when["method_in"]:
            return False
        if "internal" in when and entry.internal != bool(when["internal"]):
            return False
        if "near_miss" in when and bool(entry.near_misses) != bool(when["near_miss"]):
            return False
        if "non_http" in when:
            non_http = any(o.normalized.non_http for o in entry.observations)
            if non_http != bool(when["non_http"]):
                return False
        return True
