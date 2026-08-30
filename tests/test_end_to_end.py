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


FIVE_VIEWS = Path(__file__).parent / "fixtures" / "five_views"


@requires_noir
def test_all_five_views_compared_against_each_other():
    """Every rule, on one tree holding all five kinds of source.

    The fixture is built so each rule has exactly one thing to find, and so the
    endpoints that *are* corroborated cancel out despite being written three
    different ways: `/api/users/<int:user_id>` in Flask, `/api/users/{userId}`
    in the specification, and the concrete `/api/users/42` in the capture.

    This is the test that would catch a regression in any single piece --
    normalization, view mapping, coverage, the observed/curated split -- by the
    finding that appears or disappears.
    """
    catalog = collect.list_techs(_noir())
    view_map = ViewMap.load()
    result = collect.scan_views(
        collect.Source(str(FIVE_VIEWS)), _noir(), view_map.techs_by_view(catalog)
    )
    index = build(result.endpoints, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, skipped = RuleSet.load().evaluate(index, views)

    assert views == {"code", "doc", "traffic", "gateway", "infra"}
    assert skipped == [], "every rule has the views it needs in this fixture"

    reported = {(f.rule_id, f.key.path) for f in findings}
    assert reported == {
        # Answering requests, accounted for by neither the code nor a contract.
        ("ORPHAN", "/api/v0/old-billing"),
        ("LIVE_UNDOC", "/api/v0/old-billing"),
        # Implemented, undocumented.
        ("SHADOW", "/api/reports"),
        ("SHADOW", "/internal/debug"),
        # Documented, unimplemented.
        ("PHANTOM", "/api/legacy-export"),
        # An nginx location pointing at a service that is gone.
        ("DANGLING", "/removed-service"),
        # Declared in Terraform, implemented nowhere.
        ("DRIFT", "/ghost-function"),
        # Only `location /api/` exists, so this one is behind no gateway.
        ("UNEXPOSED", "/internal/debug"),
        # Never seen in the capture.
        ("COLD", "/api/reports"),
        ("COLD", "/internal/debug"),
    }


@requires_noir
def test_the_corroborated_endpoints_raise_nothing():
    """Three spellings of two endpoints, and not one finding between them."""
    catalog = collect.list_techs(_noir())
    view_map = ViewMap.load()
    result = collect.scan_views(
        collect.Source(str(FIVE_VIEWS)), _noir(), view_map.techs_by_view(catalog)
    )
    index = build(result.endpoints, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, _ = RuleSet.load().evaluate(index, views)

    corroborated = {"/api/users/{}", "/api/users/{}/avatar"}
    assert not [f for f in findings if f.key.path in corroborated]
    assert index.corroborated == 2

    # The one near miss is `location /api/` being recognised for what it is.
    # Nothing else in the fixture is ambiguous, so this doubles as a check that
    # mount detection stays specific -- it must not start labelling the real
    # endpoints beneath it as mounts too.
    flagged = {
        str(entry.key): entry.near_misses[0].reason
        for entry in index.entries.values() if entry.near_misses
    }
    assert len(flagged) == 1
    assert "looks like a mount" in next(iter(flagged.values()))
