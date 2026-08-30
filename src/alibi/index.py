"""Group normalized endpoints by key and record which views vouch for each.

The output of this module is the whole input to rule evaluation: for every
endpoint identity, which views contain it, with what evidence.

It also does the one piece of self-criticism the tool cannot skip. A finding
like "in code, not in the docs" is indistinguishable from "in code, and in the
docs, but normalization failed to line the two up." The second is a bug in
alibi being reported as a problem in the user's repository, so every endpoint
that lands in exactly one view is checked against the other views for a
near miss before it is allowed to become a finding.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .collect import RawEndpoint
from .normalize import Key, Normalized, normalize
from .views import TechView, ViewMap

# Match grades, reported alongside every finding.
GRADE_EXACT = "G1"       # the originals already agreed
GRADE_TEMPLATE = "G2"    # agreement required rewriting parameter syntax
GRADE_LONE = "G0"        # only one view has it -- nothing was matched


@dataclass
class Observation:
    """One view's sighting of an endpoint."""

    normalized: Normalized
    raw: RawEndpoint
    view: str
    tech: TechView


@dataclass
class Entry:
    """Every sighting of one endpoint identity, across all views."""

    key: Key
    observations: list[Observation] = field(default_factory=list)
    near_misses: list["NearMiss"] = field(default_factory=list)

    @property
    def views(self) -> set[str]:
        return {obs.view for obs in self.observations}

    @property
    def tags(self) -> set[str]:
        return {tag for obs in self.observations for tag in obs.raw.tags}

    @property
    def techs(self) -> set[str]:
        return {obs.raw.technology for obs in self.observations}

    @property
    def internal(self) -> bool:
        """Only internal when nothing that saw it thought otherwise."""
        return bool(self.observations) and all(o.raw.internal for o in self.observations)

    @property
    def observed_views(self) -> set[str]:
        """Views backed by a real capture rather than a hand-kept collection."""
        return {o.view for o in self.observations if o.tech.observed or o.view != "traffic"}

    @property
    def grade(self) -> str:
        if len(self.views) < 2:
            return GRADE_LONE
        originals = {o.normalized.original_path for o in self.observations}
        return GRADE_EXACT if len(originals) == 1 else GRADE_TEMPLATE

    def code_paths(self) -> list[dict]:
        return [cp for obs in self.observations for cp in obs.raw.code_paths]


@dataclass
class NearMiss:
    """An endpoint in another view that this one nearly matched.

    A near miss is a warning about alibi, not about the repository: it means
    two rows probably describe the same endpoint and normalization did not say
    so. Findings carrying one are demoted rather than reported at face value.
    """

    other: Key
    other_views: set[str]
    reason: str


@dataclass
class Index:
    entries: dict[Key, Entry] = field(default_factory=dict)
    unmapped_techs: set[str] = field(default_factory=set)

    def by_view(self, view: str) -> list[Entry]:
        return [e for e in self.entries.values() if view in e.views]

    @property
    def near_miss_count(self) -> int:
        return sum(1 for e in self.entries.values() if e.near_misses)


def build(raw_endpoints: list[RawEndpoint], view_map: ViewMap) -> Index:
    index = Index()

    for raw in raw_endpoints:
        tech = view_map.lookup(raw.technology)
        normalized = normalize(raw.url, raw.method)
        entry = index.entries.get(normalized.key)
        if entry is None:
            entry = Entry(key=normalized.key)
            index.entries[normalized.key] = entry
        entry.observations.append(
            Observation(normalized=normalized, raw=raw, view=tech.view, tech=tech)
        )

    _find_near_misses(index)
    return index


def _find_near_misses(index: Index) -> None:
    """Flag lone entries that look like a failed match rather than a real gap."""
    by_path: dict[str, list[Entry]] = defaultdict(list)
    by_shape: dict[tuple[str, int], list[Entry]] = defaultdict(list)

    for entry in index.entries.values():
        by_path[entry.key.path].append(entry)
        segments = entry.key.path.count("/")
        by_shape[(entry.key.method, segments)].append(entry)

    for entry in index.entries.values():
        if len(entry.views) != 1:
            continue
        mine = entry.views

        # Same path, different verb. Usually genuine -- a GET-only endpoint is
        # a real thing -- but worth surfacing, because a spec that documents
        # only GET while the code also serves POST is a common shape and the
        # POST finding reads better next to its sibling.
        for other in by_path[entry.key.path]:
            if other is entry or other.views <= mine:
                continue
            entry.near_misses.append(
                NearMiss(other.key, other.views, "same path, different method")
            )

        # Same verb and the same number of segments, differing in exactly one
        # position where one side has a parameter and the other has a literal.
        # That is the signature of a parameter noir could not see -- or of a
        # captured request whose concrete value was never templated.
        segments = entry.key.path.count("/")
        for other in by_shape[(entry.key.method, segments)]:
            if other is entry or other.views <= mine:
                continue
            reason = _one_segment_apart(entry.key.path, other.key.path)
            if reason:
                entry.near_misses.append(NearMiss(other.key, other.views, reason))


def _one_segment_apart(left: str, right: str) -> str | None:
    """Describe a single-segment difference between two canonical paths."""
    lhs = left.split("/")
    rhs = right.split("/")
    if len(lhs) != len(rhs):
        return None

    differing = [i for i, (a, b) in enumerate(zip(lhs, rhs)) if a != b]
    if len(differing) != 1:
        return None

    i = differing[0]
    a, b = lhs[i], rhs[i]
    placeholders = {"{}", "*"}
    if a in placeholders and b not in placeholders:
        return f"segment {i} is a parameter here, the literal {b!r} there"
    if b in placeholders and a not in placeholders:
        return f"segment {i} is the literal {a!r} here, a parameter there"
    return None
