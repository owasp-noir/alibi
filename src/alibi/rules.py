"""Turn view membership into findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .cover import Rule as CoverRule
from .index import Entry, Index

_RULES_FILE = Path(__file__).with_name("rules.yml")


@dataclass
class Adjustment:
    shift: int
    why: str
    # Names a column the reader can already see, when this reason only restates
    # it. The text report leaves those out; machine formats keep everything.
    restates: str | None = None


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


# A routing view reaching less of the code than this is probably not the one
# fronting it. Measured across five repositories: NetBox's real nginx config
# reaches 100% of its code, Argo CD's e2e test fixture 39%, authentik's gateway
# 37% -- and authentik's "infrastructure", which is its documentation site's
# Netlify redirect map, reaches 3%. The threshold sits in that gap.
#
# It demotes rather than suppresses. The reasoning is the one `needs_signal`
# already makes for tags: an absence is only evidence when the thing could have
# been present, and "no gateway rule reaches this" says nothing when that
# gateway demonstrably does not front this codebase.
THIN_COVERAGE = 0.25

# How many findings a disconnected rule has to be about to produce before
# holding it back does more good than harm.
#
# This guard exists to stop a flood -- "every endpoint would qualify" is what
# its own message says -- so it is keyed on the size of the flood rather than
# on how many endpoints the views hold. Keying it on population put a cliff in
# the middle of ordinary work: a five-endpoint project gained one route, its
# code view crossed the line, and DRIFT switched off. The next `alibi history`
# then reported the rule as no longer compared, over one added endpoint.
#
# Below this, letting the findings through costs a handful of lines and keeps
# behaviour stable; above it, the report is unreadable without the guard.
MAX_UNCORROBORATED_FINDINGS = 10


@dataclass
class Skipped:
    """A rule that could not run, and why. Reported, never silently dropped."""

    rule_id: str
    reason: str
    detail: str


class RuleSet:
    def __init__(self, data: dict) -> None:
        self.severities: list[str] = data.get(
            "severities", ["info", "low", "medium", "high", "critical"]
        )
        self.rules: list[dict] = data.get("rules", [])
        self.adjustments: list[dict] = data.get("adjustments", [])
        self.suppressions: list[dict] = data.get("suppress", [])

    @classmethod
    def load(cls, path: Path | None = None) -> RuleSet:
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

    def evaluate(self, index: Index,
                 present_views: set[str]) -> tuple[list[Finding], list[Skipped]]:
        findings: list[Finding] = []
        skipped: list[Skipped] = []
        runnable = []
        signals = self._available_signals(index)

        for rule in self.rules:
            missing = [v for v in rule.get("needs", []) if v not in present_views]
            if missing:
                skipped.append(Skipped(
                    rule["id"], "missing-view",
                    f"no {', '.join(missing)} source in this scan",
                ))
                continue

            unwitnessed = [
                view for view in rule.get("needs_observed", [])
                if not any(e.observed_in(view) for e in index.entries.values())
            ]
            if unwitnessed:
                skipped.append(Skipped(
                    rule["id"], "not-observed",
                    f"the {', '.join(unwitnessed)} view holds only hand-written "
                    f"collections in this scan, and what nobody watched cannot "
                    f"show what is live or unused",
                ))
                continue

            runnable.append(rule)

        per_rule: dict[str, list[Finding]] = {rule["id"]: [] for rule in runnable}
        for entry in index.entries.values():
            for rule in runnable:
                if not self._matches(entry, rule, index):
                    continue
                if self._suppressed(entry, index):
                    continue
                per_rule[rule["id"]].append(
                    self._build(entry, rule, signals, index))

        # Whether the views connected is only worth acting on once it is known
        # how much the answer costs. A rule producing three findings from
        # unconnected views is three lines; one producing three hundred is the
        # report.
        for rule in runnable:
            produced = per_rule[rule["id"]]
            if len(produced) > MAX_UNCORROBORATED_FINDINGS:
                disconnected = self._disconnected(index, rule)
                if disconnected:
                    skipped.append(disconnected)
                    continue
            findings.extend(produced)

        findings.sort(
            key=lambda f: (-self.severities.index(f.severity), f.key.path, f.key.method)
        )
        return findings, skipped

    def _disconnected(self, index: Index, rule: dict) -> Skipped | None:
        """Refuse to report when the views a rule compares never met.

        A rule like SHADOW is only meaningful if code and documentation
        describe the same surface at the same granularity. When noir reads a
        mount point on one side and a generated specification on the other, or
        cannot read one stack at all, the two populations are disjoint and
        every endpoint qualifies -- Argo CD produces 58 shadow APIs and 198
        phantom contracts that way, none of them real.

        Zero corroboration between two populated views is a fact about the
        scan, not about the repository, so it is reported as one diagnostic
        instead of hundreds of findings.
        """
        views = list(rule.get("needs", []))
        if len(views) != 2:
            return None

        left, right = views
        left_size = index.population(left)
        right_size = index.population(right)

        # Two endpoint sets connect by sharing members. A routing view connects
        # by reaching them -- one `location /api/` legitimately shares no key
        # with anything while covering the whole API, so counting shared keys
        # there would call every healthy gateway disconnected.
        connection = self._connection(index, left, right)
        if connection > 0:
            return None

        return Skipped(
            rule["id"], "no-overlap",
            f"{left_size} {left} and {right_size} {right} endpoints, and not one "
            f"of them lines up -- the two views never met, so every endpoint "
            f"would qualify. Check whether one side is a mount point standing "
            f"in for the routes beneath it, or a stack noir could not read.",
        )

    def _connection(self, index: Index, left: str, right: str) -> int:
        """How much two views actually have to do with each other."""
        left_cover = index.coverages.get(left)
        right_cover = index.coverages.get(right)

        if left_cover is not None and right_cover is None:
            return sum(1 for key in index.keys_in(right) if left_cover.covers(key))
        if right_cover is not None and left_cover is None:
            return sum(1 for key in index.keys_in(left) if right_cover.covers(key))
        if left_cover is not None and right_cover is not None:
            # Two routing views. Neither enumerates endpoints, so the only
            # honest test is whether their rules describe the same paths.
            return index.overlap(left, right)
        return index.overlap(left, right)

    def _thin(self, index: Index, rule: dict | None) -> bool:
        """Does this rule lean on a routing view that barely touches the code?"""
        if rule is None:
            return False
        views = [v for v in rule.get("needs", []) if v in index.coverages]
        stats = index.coverage_stats()
        for view in views:
            if view not in stats:
                continue
            _, reached, total = stats[view]
            if total and reached / total < THIN_COVERAGE:
                return True
        return False

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

    def _matches(self, entry: Entry, rule: dict, index: Index) -> bool:
        # Every rule here reasons about the web surface. A CLI command, a Kafka
        # topic and a mobile deep link are all real attack surface that noir
        # reports, but no OpenAPI document describes them and no nginx rule
        # routes to them, so they would produce a finding for every endpoint.
        if entry.key.protocol not in rule.get("protocols", ["http"]):
            return False

        views = entry.views
        if not all(v in views for v in rule.get("present", [])):
            return False
        if any(v in views for v in rule.get("absent", [])):
            return False
        extra = rule.get("when")
        if extra and not self._condition(entry, extra, index):
            return False
        return True

    def _suppressed(self, entry: Entry, index: Index) -> bool:
        return any(self._condition(entry, s["when"], index) for s in self.suppressions)

    def _build(self, entry: Entry, rule: dict, signals: set[str], index: Index) -> Finding:
        base = rule.get("severity", "medium")
        severity = base
        applied: list[Adjustment] = []

        for adjustment in self.adjustments:
            scope = adjustment.get("rules")
            if scope and rule["id"] not in scope:
                continue
            if adjustment.get("needs_signal") and adjustment["id"] not in signals:
                continue
            if self._condition(entry, adjustment["when"], index, rule):
                shift = int(adjustment["shift"])
                severity = self._shift(severity, shift)
                applied.append(Adjustment(shift, adjustment.get("why", ""),
                                          adjustment.get("restates")))

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

    # Every key a condition may use. An unrecognised one is a mistake, and it
    # is the dangerous kind: a condition made only of keys nothing checks passes
    # every time, so a typo in rules.yml does not disable an adjustment -- it
    # applies it to everything. That is exactly how `tag_matching`, written
    # before it was implemented, silently demoted every finding by a step.
    CONDITIONS = frozenset({
        "tag", "tag_matching", "method_in", "internal", "near_miss", "non_http",
        "catch_all", "observed_in", "not_observed_in", "not_covered_by",
        "covers_nothing_in", "thin_routing_view",
    })

    def _condition(self, entry: Entry, when: dict, index: Index,
                   rule: dict | None = None) -> bool:
        unknown = set(when) - self.CONDITIONS
        if unknown:
            raise ValueError(
                f"unknown condition {', '.join(sorted(unknown))} in rules.yml -- "
                f"known conditions are {', '.join(sorted(self.CONDITIONS))}"
            )

        if "thin_routing_view" in when and not self._thin(index, rule):
            return False

        if "not_covered_by" in when:
            view = when["not_covered_by"]
            coverage = index.coverages.get(view)
            if coverage is None or coverage.covers(entry.key):
                return False

        if "covers_nothing_in" in when:
            # Asked of a routing rule, not an endpoint: does anything this rule
            # reaches actually exist? A prefix that matches half the codebase
            # is not a dangling route, however little it resembles any single
            # endpoint key.
            target = when["covers_nothing_in"]
            reach = CoverRule(key=entry.key, view="", prefix=True)
            if any(reach.reaches(key) for key in index.keys_in(target)):
                return False

        if "catch_all" in when and entry.key.catch_all != bool(when["catch_all"]):
            return False

        if "observed_in" in when and not entry.observed_in(when["observed_in"]):
            return False

        if "not_observed_in" in when and entry.observed_in(when["not_observed_in"]):
            return False

        if "tag" in when and when["tag"] not in entry.tags:
            return False

        if "tag_matching" in when:
            pattern = re.compile(when["tag_matching"], re.IGNORECASE)
            if not any(pattern.search(tag) for tag in entry.tags):
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
