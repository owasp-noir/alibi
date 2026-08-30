"""One test that actually runs noir, because everything else mocks it away."""

import json
from pathlib import Path

import pytest

from alibi import cli, collect
from alibi.index import build
from alibi.rules import RuleSet
from alibi.views import ViewMap

FIXTURE = Path(__file__).parent / "fixtures" / "matched"
SARIF_SCHEMA = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


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
    endpoints = collect.scan(collect.Source(str(FIXTURE)), _noir())
    index = build(endpoints, ViewMap.load())
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, skipped = RuleSet.load().evaluate(index, views)

    assert views == {"code", "doc"}
    assert skipped == []
    assert index.near_miss_count == 0

    reported = {(f.rule_id, f.key.method, f.key.path) for f in findings}
    assert reported == {
        ("SHADOW", "GET", "/internal/metrics"),
        ("PHANTOM", "GET", "/reports/{}"),
    }


@requires_noir
def test_sarif_from_a_real_scan_validates(capsys):
    """Hand-built findings cannot produce the paths noir actually emits.

    Every other SARIF test writes its own code paths. This one takes whatever
    noir reports for a real tree -- the base path it was handed, a
    specification with no line number -- and holds the result to the schema.
    """
    jsonschema = pytest.importorskip("jsonschema")

    assert cli.main(["scan", str(FIXTURE), "-f", "sarif"]) == cli.EXIT_OK

    document = json.loads(capsys.readouterr().out)
    schema = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))
    assert list(jsonschema.Draft4Validator(schema).iter_errors(document)) == []
    assert {r["ruleId"] for r in document["runs"][0]["results"]} == {
        "SHADOW", "PHANTOM"
    }


@requires_noir
def test_two_identical_scans_leave_nothing_for_the_history_to_report(
    tmp_path, capsys
):
    """The wiring from `--snapshot` through to `alibi history`.

    A repository that did not change between two scans must produce an empty
    history. Anything else means the recorded identity of a finding depends on
    something other than the finding.
    """
    database = tmp_path / "snapshots.db"
    for _ in range(2):
        assert cli.main(
            ["scan", str(FIXTURE), "--snapshot", str(database)]
        ) == cli.EXIT_OK

    capsys.readouterr()
    assert cli.main(["history", str(database)]) == cli.EXIT_OK
    assert "No finding appeared or disappeared" in capsys.readouterr().out


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
