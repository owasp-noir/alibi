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


@dataclass(frozen=True)
class Hint:
    view: str
    prefix: str
    concentration: float
    inside: int
    outside: int

    @property
    def ignore_pattern(self) -> str:
        return f"^/(?!{self.prefix.lstrip('/')}/)"

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


def suggest(index: Index, findings: list, view: str = "doc") -> Hint | None:
    """Is one view scoped to a prefix that many findings fall outside of?"""
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


def applies(pattern: str, path: str) -> bool:
    """Used by the tests to confirm a suggested pattern does what it says."""
    return bool(re.search(pattern, path))
