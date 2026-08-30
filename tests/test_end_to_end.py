"""One test that actually runs noir, because everything else mocks it away."""

from pathlib import Path

import pytest

from alibi import collect
from alibi.index import build
from alibi.rules import RuleSet
from alibi.views import ViewMap

FIXTURE = Path(__file__).parent / "fixtures" / "matched"


def _noir():
    try:
        return collect.find_noir()
    except collect.NoirNotFound:
        return None


requires_noir = pytest.mark.skipif(_noir() is None, reason="noir is not installed")


@requires_noir
def test_a_real_scan_matches_across_the_notation_boundary():
    """Flask writes `<int:user_id>`, OpenAPI writes `{userId}`, one endpoint.

    The fixture pairs three Flask routes with a three-path OpenAPI document.
    Two of each describe the same endpoint in different syntax and must cancel
    out; the leftovers are one undocumented route and one unbuilt contract.
    """
    result = collect.scan(collect.Source(str(FIXTURE)), _noir())
    index = build(result.endpoints, ViewMap.load())
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, skipped = RuleSet.load().evaluate(index, views)

    assert views == {"code", "doc"}
    # The six rules about traffic, gateways and infrastructure have no source
    # here and correctly sit out; the two this fixture exercises must run.
    assert not [s for s in skipped if s.rule_id in {"SHADOW", "PHANTOM"}]
    assert index.near_miss_count == 0

    reported = {(f.rule_id, f.key.method, f.key.path) for f in findings}
    assert reported == {
        ("SHADOW", "GET", "/internal/metrics"),
        ("PHANTOM", "GET", "/reports/{}"),
    }


@requires_noir
def test_the_view_map_covers_this_noir_build():
    """Fails when noir ships a specification analyzer alibi has not placed."""
    catalog = collect.list_techs(_noir())
    unmapped = {
        name for name, spec in catalog.items()
        if "language" not in spec and name not in ViewMap.load().mapped_techs
    }
    assert unmapped == set(), (
        "add these to views.yml under the view they speak for: "
        + ", ".join(sorted(unmapped))
    )
