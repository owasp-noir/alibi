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
from .cover import Coverage
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
    # Other verbs answering on this same path, and which views know them.
    # Context, never doubt -- see `_find_siblings`.
    siblings: list[tuple[str, frozenset[str]]] = field(default_factory=list)

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

    def observed_in(self, view: str) -> bool:
        """Was this endpoint *witnessed* in that view, not just written down?

        The distinction only bites for traffic: a request in a HAR capture
        happened, a request in a Postman collection is one somebody intended.
        Rules that call an endpoint live, or call it unused, depend on this.
        """
        return any(o.view == view and o.tech.observed for o in self.observations)

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
    # Gateways and infrastructure declare routing rules rather than endpoints,
    # so they are kept as coverage predicates as well as entries. The entries
    # are what "this gateway rule matches nothing" is asked about; the coverage
    # is what "is this code route reachable" is asked of.
    coverages: dict[str, Coverage] = field(default_factory=dict)

    def by_view(self, view: str) -> list[Entry]:
        return [e for e in self.entries.values() if view in e.views]

    def keys_in(self, view: str) -> list[Key]:
        return [e.key for e in self.entries.values() if view in e.views]

    def population(self, view: str) -> int:
        return sum(1 for e in self.entries.values() if view in e.views)

    def overlap(self, left: str, right: str) -> int:
        """How many endpoints both views vouch for.

        Zero, between two populated views, is the single most useful number
        this tool computes. It does not mean every endpoint is a defect; it
        means the two views never met, and something upstream -- a mount point
        standing in for the routes beneath it, a stack noir cannot read, two
        unrelated services in one repository -- has to be fixed before any
        finding here is worth reading.
        """
        return sum(1 for e in self.entries.values() if left in e.views and right in e.views)

    @property
    def near_miss_count(self) -> int:
        return sum(1 for e in self.entries.values() if e.near_misses)

    def coverage_stats(self, target: str = "code") -> dict[str, tuple[int, int, int]]:
        """Per routing view: how many rules, how much of `target` they reach.

        Whether "34 endpoints no gateway reaches" is a real finding or an
        artefact depends entirely on whether the gateway config in the scan is
        the one that actually fronts the service. A config checked in as e2e
        test data reaches some of the code and misses the rest, and looks from
        here exactly like a production config with holes in it.

        No threshold separates those honestly -- Argo CD's test fixture covers
        39% of its code, NetBox's real config covers 100%, and picking a line
        between them would be a guess dressed as a rule. So the numbers are
        reported and the reader decides.
        """
        targets = [key for key in self.keys_in(target) if key.http]
        if not targets:
            # "0 of 0" answers nothing. With no web surface to reach, how much
            # of it a gateway reaches is not a number worth printing.
            return {}

        stats: dict[str, tuple[int, int, int]] = {}
        for view, coverage in self.coverages.items():
            if not len(coverage):
                continue
            reached = sum(1 for key in targets if coverage.covers(key))
            stats[view] = (len(coverage), reached, len(targets))
        return stats

    @property
    def corroborated(self) -> int:
        """Endpoints more than one view vouches for.

        The headline number. Findings are the endpoints that failed to
        corroborate, so this is what says whether the comparison worked at all
        -- a report of 147 findings means something different next to 230
        corroborated endpoints than next to none.
        """
        return sum(1 for e in self.entries.values() if len(e.views) > 1)


def build(raw_endpoints: list[RawEndpoint], view_map: ViewMap) -> Index:
    index = Index()

    for raw in raw_endpoints:
        tech = view_map.lookup(raw.technology)
        normalized = normalize(raw.url, raw.method, raw.protocol)
        entry = index.entries.get(normalized.key)
        if entry is None:
            entry = Entry(key=normalized.key)
            index.entries[normalized.key] = entry
        entry.observations.append(
            Observation(normalized=normalized, raw=raw, view=tech.view, tech=tech)
        )

    for view in view_map.views:
        if view_map.is_predicate(view):
            index.coverages[view] = Coverage.from_entries(index.entries.values(), view)

    _find_near_misses(index)
    return index


# How many *distinct paths* have to sit beneath a path before it is read as a
# mount rather than an endpoint of its own.
#
# Distinct paths, not endpoints: a REST collection has an item beneath it, and
# that item answers on four or five verbs. Counting endpoints made
# `/api/circuits/circuit-groups` look like a mount because
# `/api/circuits/circuit-groups/{}` exists in GET, PUT, PATCH and DELETE --
# which is what a collection endpoint is supposed to look like. On NetBox that
# mislabelled 377 endpoints and demoted the findings on them. A real mount has
# many different paths beneath it: Argo CD's `/api` has 106.
MOUNT_THRESHOLD = 3


def _find_near_misses(index: Index) -> None:
    """Flag lone entries that look like a failed match rather than a real gap."""
    by_path: dict[str, list[Entry]] = defaultdict(list)
    by_shape: dict[tuple[str, int], list[Entry]] = defaultdict(list)

    for entry in index.entries.values():
        by_path[entry.key.path].append(entry)
        segments = entry.key.path.count("/")
        by_shape[(entry.key.method, segments)].append(entry)

    _find_siblings(index, by_path)

    for entry in index.entries.values():
        if len(entry.views) != 1:
            continue
        mine = entry.views

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

        mount = _looks_like_a_mount(entry, index)
        if mount:
            entry.near_misses.append(mount)


def _looks_like_a_mount(entry: Entry, index: Index) -> NearMiss | None:
    """Detect a registration that stands in for everything beneath it.

    Frameworks that hand a whole subtree to another router -- a gRPC gateway,
    a mounted sub-application, a catch-all handler -- give noir one route where
    the specification gives dozens. Argo CD registers `/api` in Go and
    documents 198 paths under `/api/v1/...`; read as endpoints, that is one
    false shadow API and 198 false phantoms.

    A path is read as a mount when endpoints from *other* views live beneath
    it and none of them is it. Findings on it are demoted and labelled rather
    than dropped, because a genuine endpoint can also have children.
    """
    prefix = entry.key.path.rstrip("/")
    if prefix in ("", "/"):
        # Everything lives under `/`. True, and useless as evidence.
        return None

    beneath: set[str] = set()
    paths: set[str] = set()
    for other in index.entries.values():
        if other is entry or other.key.path == entry.key.path:
            continue
        if not other.key.path.startswith(prefix + "/"):
            continue
        if other.views <= entry.views:
            continue
        beneath |= other.views
        paths.add(other.key.path)

    if len(paths) < MOUNT_THRESHOLD:
        return None

    return NearMiss(
        entry.key,
        beneath,
        f"looks like a mount: {len(paths)} paths in {', '.join(sorted(beneath))} "
        f"live beneath this one",
    )


def _find_siblings(index: Index, by_path: dict[str, list[Entry]]) -> None:
    """Record the other verbs answering on the same path.

    This used to be filed as a near miss, which was wrong twice over.
    Normalization never touches the method, so a verb difference cannot be a
    matching failure -- and treating it as doubt demoted 380 of NetBox's 746
    findings for the crime of having a sibling.

    What it is, is context. NetBox's specification carries bulk PUT, PATCH and
    DELETE on collections its code does not implement; knowing that the GET on
    the same path *is* corroborated turns 397 phantom endpoints into "the bulk
    verbs on collections that exist", which is a different and much smaller
    thing to go and check.
    """
    for entry in index.entries.values():
        for other in by_path[entry.key.path]:
            if other is entry or other.key.method == entry.key.method:
                continue
            if other.views <= entry.views:
                continue
            entry.siblings.append((other.key.method, frozenset(other.views)))
        entry.siblings.sort()


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
