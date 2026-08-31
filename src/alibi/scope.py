"""Notice when a scan is holding two surfaces at once.

NetBox keeps a server-rendered web UI and a REST API in one repository, and
only the second has a contract. Compared whole, 746 findings come back and 345
of them say a web page is not in an API specification -- true, and not what
anyone asked. One `--ignore` collapses that to the three findings worth
reading.

The observation that makes this visible is cheap: NetBox's specification lives
entirely under `/api`, while 30% of its code does not. A view that concentrates
under one prefix has told you what it was scoped to describe, and endpoints
outside that prefix were never in its remit.

What this deliberately does **not** do is recommend the fix. Casdoor's
specification is 97% under `/api` too, but its `/cas/`, `/scim/` and
`/caswaf-handler` routes are real API surface the document simply omits --
exactly the shadow APIs the tool exists to find. Paths alone cannot separate
"a different surface" from "the surface, undocumented", so the reader is given
the measurement and the command, and makes the call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .index import Index

# How concentrated a view must be before its prefix reads as a deliberate
# scope rather than a coincidence of naming.
CONCENTRATION = 0.90

# Below this many findings outside the prefix, there is nothing to save anyone.
MIN_OUTSIDE = 10

# Directory names that mean "this is not the shipped surface". Naming test
# directories is about as settled as software conventions get, which is why
# this is a list of names rather than a guess about content.
TEST_DIRECTORIES = (
    "test", "tests", "spec", "specs", "__tests__", "e2e",
    "fixture", "fixtures", "testdata", "mock", "mocks",
)

_TEST_SEGMENT = re.compile(
    r"(^|/)(" + "|".join(TEST_DIRECTORIES) + r")(/|$)", re.IGNORECASE)

# A share this small is not worth a paragraph, however many findings it is.
TEST_SHARE = 0.20
MIN_TEST_FINDINGS = 10


@dataclass(frozen=True)
class Hint:
    view: str
    prefix: str
    concentration: float
    inside: int
    outside: int

    @property
    def ignore_pattern(self) -> str:
        """The command that suppresses exactly what `outside` counted.

        `(/|$)` rather than a bare `/`, so the prefix path itself survives.
        The measurement treats an endpoint at `/api` as inside the surface the
        contract describes; `^/(?!api/)` suppressed it, so the report said
        "37 findings are outside it" and handed over a command that removed
        38. The one it disagreed about is the mount point -- the endpoint most
        worth keeping in the gRPC-gateway shape this hint appears in.
        """
        return f"^/(?!{self.prefix.lstrip('/')}(/|$))"

    @property
    def share(self) -> int:
        return round(self.concentration * 100)


def _dominant_prefix(paths: list[str]) -> tuple[str, float] | None:
    """The first segment that most of these paths share, and how much of them."""
    if not paths:
        return None
    counts: dict[str, int] = {}
    for path in paths:
        head = path.split("/")
        prefix = f"/{head[1]}" if len(head) > 1 and head[1] else "/"
        counts[prefix] = counts.get(prefix, 0) + 1

    prefix, count = max(counts.items(), key=lambda kv: kv[1])
    if prefix in ("/", "/*", "/{}"):
        # Everything is under `/`, and a leading parameter is not a namespace.
        return None
    return prefix, count / len(paths)


def suggest(index: Index, findings: list, ruleset=None,
            view: str = "doc") -> Hint | None:
    """Is one view scoped to a prefix that many findings fall outside of?

    Only findings from rules that reason about `view` count. Authentik's
    specification is 100% under `/api` while 192 of its findings sit outside
    it -- but those are all UNEXPOSED and DRIFT, about gateways and
    infrastructure, and narrowing the scan because the *contract* stops at
    `/api` would be answering a question nobody asked.
    """
    if ruleset is not None:
        about_view = {rule["id"] for rule in ruleset.rules
                      if view in rule.get("needs", [])}
        findings = [f for f in findings if f.rule_id in about_view]

    paths = [key.path for key in index.keys_in(view) if key.http]
    dominant = _dominant_prefix(paths)
    if dominant is None:
        return None

    prefix, concentration = dominant
    if concentration < CONCENTRATION:
        return None

    marker = f"{prefix}/"
    outside = [f for f in findings if not f.key.path.startswith(marker)
               and f.key.path != prefix]
    if len(outside) < MIN_OUTSIDE:
        return None

    return Hint(
        view=view,
        prefix=prefix,
        concentration=concentration,
        inside=len(findings) - len(outside),
        outside=len(outside),
    )


@dataclass(frozen=True)
class TestHint:
    findings: int
    total: int
    directories: list[str]

    @property
    def share(self) -> int:
        return round(self.findings / self.total * 100)

    @property
    def exclude_globs(self) -> list[str]:
        return [f"**/{name}/**" for name in self.directories]


def from_tests(findings: list, index=None) -> TestHint | None:
    """Are most of these findings about code that never ships?

    Directus keeps e2e snapshots listing every collection its test suite
    creates, and noir reads them as endpoints: `/items/articles_1234` beside
    the documented `/items/{collection}`. 145 of its 281 findings came from
    test directories, and every one of them near-missed a real endpoint.

    A directory another view depends on is never suggested. Directus keeps its
    OpenAPI document in `packages/specs/`, and `specs` is on the list of names
    that usually mean fixtures -- excluding it would have deleted the contract
    the comparison runs against, on this tool's own advice.

    Reported, not acted on, like the scope hint. Some projects genuinely serve
    routes defined under a directory named `spec`, and no reading of a path can
    tell that from a fixture.
    """
    if not findings:
        return None

    seen: set[str] = set()
    from_test = 0
    for finding in findings:
        matched = False
        for code_path in finding.entry.code_paths():
            path = code_path.get("path") or ""
            for match in _TEST_SEGMENT.finditer(path.replace("\\", "/")):
                seen.add(match.group(2).lower())
                matched = True
        if matched:
            from_test += 1

    if from_test < MIN_TEST_FINDINGS:
        return None
    if from_test / len(findings) < TEST_SHARE:
        return None

    suggestable = sorted(seen - _load_bearing(index))
    if not suggestable:
        return None

    return TestHint(findings=from_test, total=len(findings),
                    directories=suggestable)


def _load_bearing(index) -> set[str]:
    """Directory names some view other than code is reached through."""
    if index is None:
        return set()

    names: set[str] = set()
    for entry in index.entries.values():
        for observation in entry.observations:
            if observation.view == "code":
                continue
            for code_path in observation.raw.code_paths:
                path = (code_path.get("path") or "").replace("\\", "/")
                for match in _TEST_SEGMENT.finditer(path):
                    names.add(match.group(2).lower())
    return names


def applies(pattern: str, path: str) -> bool:
    """Used by the tests to confirm a suggested pattern does what it says."""
    return bool(re.search(pattern, path))
