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


def _plain_pattern(parts: list[str]) -> bool:
    """Does this pattern match only itself, segment for segment?

    A rule path with no placeholder anywhere -- no `*` segment, no `{}` in
    any segment -- reaches a path exactly when the segments are equal, or
    when it is a prefix of them. That is a set lookup, and it is what nearly
    every gateway rule is.
    """
    return all(part != _MANY and _ONE not in part for part in parts)


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


class _Node:
    """One segment deep in a trie of paths, and what ends or passes here."""

    __slots__ = ("children", "ends", "beneath")

    def __init__(self) -> None:
        self.children: dict[str, _Node] = {}
        # Methods of the rules or keys whose path ends exactly here.
        self.ends: set[str] = set()
        # Coverage: methods of the prefix rules ending here, which reach every
        # path that passes through. KeySet: methods of every key at or below
        # here, which is what a prefix rule passing through reaches.
        self.beneath: set[str] = set()


def _reaches_any(methods: set[str], wanted: set[str] | None) -> bool:
    """`wanted` is None for a rule on any verb, which reaches every method."""
    return bool(methods) if wanted is None else not methods.isdisjoint(wanted)


class Coverage:
    """The routing rules from one predicate view.

    Asked once per code endpoint by three different callers -- the coverage
    statistics, the "no gateway reaches this" rule, and the check that the
    views connected at all -- so every answer is kept. And the rules without
    a placeholder, which is nearly all of them, are held in a trie keyed by
    segment, so a path is answered by walking its own segments rather than by
    running the glob matcher over every rule. At 5,000 synthetic endpoints
    the matcher was called 1.2 million times; the pattern rules that still
    need it are a handful.
    """

    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules
        self._answers: dict[Key, bool] = {}
        self._root = _Node()
        self._patterned: list[Rule] = []
        for rule in rules:
            parts = segments(rule.key.path)
            if not _plain_pattern(parts):
                self._patterned.append(rule)
                continue
            node = self._root
            for part in parts:
                node = node.children.setdefault(part, _Node())
            base = rule.key.path.rstrip("/")
            if rule.prefix and base not in ("", "/"):
                node.beneath.add(rule.key.method)
            else:
                # `location /` reaches everything, and is not counted as
                # reaching anything -- see `Rule.reaches`. Exact only.
                node.ends.add(rule.key.method)

    @classmethod
    def from_entries(cls, entries, view: str) -> Coverage:
        rules = [
            Rule(key=entry.key, view=view, prefix=True)
            for entry in entries
            if view in entry.views
        ]
        return cls(rules)

    def __len__(self) -> int:
        return len(self._rules)

    def covers(self, target: Key) -> bool:
        answer = self._answers.get(target)
        if answer is None:
            answer = self._covers(target)
            self._answers[target] = answer
        return answer

    def _covers(self, target: Key) -> bool:
        wanted = {WILDCARD_METHOD, target.method}
        # Every rule path the target's segments could be spelling. One node
        # until a `{}` in the target, which matches any rule segment and so
        # fans out to every child -- the same reading `_match` gives it.
        nodes = [self._root]
        for part in segments(target.path):
            if any(not node.beneath.isdisjoint(wanted) for node in nodes):
                return True
            if part == _ONE:
                nodes = [child for node in nodes for child in node.children.values()]
            else:
                nodes = [child for node in nodes
                         if (child := node.children.get(part)) is not None]
            if not nodes:
                break
        if any(not (node.ends | node.beneath).isdisjoint(wanted) for node in nodes):
            return True
        return any(rule.reaches(target) for rule in self._patterned)


class KeySet:
    """The endpoint keys of one view, arranged to answer what a rule reaches.

    The mirror of `Coverage`: there a path asks which rules reach it, here a
    rule asks whether it reaches anything. The keys sit in a trie keyed by
    segment, and a rule without a placeholder walks it -- following both the
    literal child and the `{}` child at each step, because a parameter in a
    key path matches any rule segment -- and asks whether a key ends where it
    stops, or lies anywhere beneath.
    """

    def __init__(self, keys: list[Key]) -> None:
        self._keys = keys
        self._root = _Node()
        for key in keys:
            node = self._root
            node.beneath.add(key.method)
            for part in segments(key.path):
                node = node.children.setdefault(part, _Node())
                node.beneath.add(key.method)
            node.ends.add(key.method)

    def reached_by(self, rule: Rule) -> bool:
        parts = segments(rule.key.path)
        if not _plain_pattern(parts):
            return any(rule.reaches(key) for key in self._keys)

        wanted = None if rule.key.method == WILDCARD_METHOD else {rule.key.method}
        nodes = [self._root]
        for part in parts:
            nodes = [child for node in nodes
                     for child in (node.children.get(part), node.children.get(_ONE))
                     if child is not None]
            if not nodes:
                return False
        base = rule.key.path.rstrip("/")
        prefix = rule.prefix and base not in ("", "/")
        return any(_reaches_any(node.ends, wanted)
                   or (prefix and _reaches_any(node.beneath, wanted))
                   for node in nodes)
