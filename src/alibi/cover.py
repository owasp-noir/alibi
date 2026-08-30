"""Answer what a routing rule reaches.

Gateways and infrastructure declarations are not endpoint lists. One nginx
`location /api/` stands for every path beneath it, and a Kubernetes Ingress
rule does the same. Comparing them to code as plain sets produces nonsense in
both directions: every prefix rule looks like a route nobody implemented, and
every implemented route looks unreachable.

So these views answer a different question -- *does this rule reach that
endpoint?* -- and this module is where that question is asked.

The conservative direction matters and it is not symmetric. Noir reports the
path a rule matches but not the modifier that decides how (`location = /exact`
against plain `location`, an Ingress `pathType: Exact` against `Prefix`), so
coverage cannot be computed exactly. Treating every rule as a prefix therefore
covers more than it should, which *suppresses* findings rather than inventing
them. Guessing the other way would report reachable endpoints as unreachable.
"""

from __future__ import annotations

from dataclasses import dataclass

from .normalize import WILDCARD_METHOD, Key

# Placeholder tokens produced by normalization.
_ONE = "{}"    # exactly one segment, or part of one
_MANY = "*"    # zero or more segments


def segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s != ""]


def matches(pattern: str, path: str) -> bool:
    """Does `pattern` describe `path`, treating `{}` and `*` as placeholders?

    `{}` stands for one segment and `*` for any number, so this is a glob over
    path segments rather than characters. Two patterns can also be compared
    with it -- `/users/{}` matches `/users/{}` -- which is what lets a
    documented template line up with a captured concrete URL.
    """
    return _match(segments(pattern), segments(path))


def _match(pattern: list[str], path: list[str]) -> bool:
    if not pattern:
        return not path

    head, *rest = pattern

    if head == _MANY:
        # Zero or more segments. Try every split, shortest first.
        for take in range(len(path) + 1):
            if _match(rest, path[take:]):
                return True
        return False

    if not path:
        return False

    if head == _ONE or path[0] == _ONE or head == path[0]:
        return _match(rest, path[1:])

    # A segment can be partly literal: `/{}-{}` against `/12-34`.
    if _ONE in head and _segment_matches(head, path[0]):
        return _match(rest, path[1:])

    return False


def _segment_matches(pattern: str, actual: str) -> bool:
    """Match one segment where `{}` stands for a run of characters."""
    parts = pattern.split(_ONE)
    if len(parts) == 1:
        return pattern == actual

    if not actual.startswith(parts[0]):
        return False
    position = len(parts[0])

    for part in parts[1:-1]:
        if not part:
            continue
        found = actual.find(part, position)
        if found == -1:
            return False
        position = found + len(part)

    tail = parts[-1]
    return actual.endswith(tail) and len(actual) - len(tail) >= position


@dataclass(frozen=True)
class Rule:
    """One routing rule, and what it reaches."""

    key: Key
    view: str
    prefix: bool

    def reaches(self, target: Key) -> bool:
        if self.key.method != WILDCARD_METHOD and self.key.method != target.method:
            return False
        if matches(self.key.path, target.path):
            return True
        if self.prefix:
            base = self.key.path.rstrip("/")
            if base in ("", "/"):
                # `location /` reaches everything. True, and no use as evidence
                # of anything, so it is not treated as coverage.
                return False
            return matches(base + "/*", target.path)
        return False


class Coverage:
    """The routing rules from one predicate view."""

    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules

    @classmethod
    def from_entries(cls, entries, view: str) -> "Coverage":
        rules = [
            Rule(key=entry.key, view=view, prefix=True)
            for entry in entries
            if view in entry.views
        ]
        return cls(rules)

    def __len__(self) -> int:
        return len(self._rules)

    def reaching(self, target: Key) -> Rule | None:
        for rule in self._rules:
            if rule.reaches(target):
                return rule
        return None

    def covers(self, target: Key) -> bool:
        return self.reaching(target) is not None
