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


GRPC_FIXTURE = Path(__file__).parent / "fixtures" / "grpc_gateway"


@requires_noir
def test_a_proto_with_http_annotations_corroborates_the_document_generated_from_it():
    """The gRPC-gateway shape, and why `grpc` speaks for the code view.

    The fixture is a .proto whose two rpcs carry `option (google.api.http)`,
    one Flask route, and an OpenAPI document listing the two proto routes and
    one more. Filed as doc, the proto and the document corroborated each
    other and every route the Go or Python code did not hold read as a
    phantom -- which on flipt and Argo CD was every documented route, and
    both were held back as views that never met.

    Run through the real pipeline rather than one noir call, because the
    whole point is per-view scanning: in a single scan noir deduplicates the
    proto's `/v1/flags/{key}` against the document's, and the corroboration
    this test is about is exactly what that erases.
    """
    view_map = ViewMap.load()
    catalog = collect.list_techs(_noir())
    source = collect.Source(str(GRPC_FIXTURE))
    result = collect.scan_views(source, _noir(), view_map.techs_by_view(catalog))
    index = build(result.endpoints, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, skipped = RuleSet.load().evaluate(index, views)

    assert views == {"code", "doc"}
    assert not [s for s in skipped if s.rule_id in {"SHADOW", "PHANTOM"}]

    corroborated = {str(e.key) for e in index.entries.values() if len(e.views) > 1}
    assert corroborated == {"GET /v1/flags/{}", "POST /v1/flags"}
    for entry in index.entries.values():
        if len(entry.views) > 1:
            assert entry.techs == {"grpc", "oas3"}

    reported = {(f.rule_id, f.key.method, f.key.path) for f in findings}
    assert reported == {
        ("SHADOW", "GET", "/healthz"),
        ("PHANTOM", "GET", "/v1/segments"),
    }


@requires_noir
def test_a_scan_of_a_real_tree_can_be_debugged_from_the_json_alone(tmp_path, capsys):
    """Follow the advice: the prefix diagnosis, recomputed from the report.

    Gitea's specification carries a `basePath` its code does not, and that
    was found by re-running noir by hand. With the lists in the report, the
    same conclusion comes out of one scan -- which is the whole claim the
    flag makes.
    """
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text(
        "from flask import Flask\n\napp = Flask(__name__)\n\n\n"
        '@app.route("/repos/<owner>")\ndef repos(owner):\n    return owner\n',
        encoding="utf-8")
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "openapi.yaml").write_text(
        "openapi: 3.0.0\ninfo:\n  title: t\n  version: '1'\n"
        "servers:\n  - url: /PLACEHOLDER/api/v1\n"
        "paths:\n  /repos/{owner}:\n    get:\n"
        "      parameters:\n        - name: owner\n          in: path\n"
        "          required: true\n          schema:\n            type: string\n"
        "      responses:\n        '200':\n          description: ok\n",
        encoding="utf-8")

    assert cli.main(["scan", str(tmp_path), "-f", "json", "--endpoints"]) in (
        cli.EXIT_OK, cli.EXIT_FINDINGS)
    document = json.loads(capsys.readouterr().out)

    code = {(row["method"], row["path"]) for row in document["endpoints"]["code"]}
    doc = {(row["method"], row["path"]) for row in document["endpoints"]["doc"]}
    assert code and doc and not (code & doc)

    # The reader's own arithmetic, on nothing but the report.
    stripped = {(method, "/" + path.split("/", 4)[4])
                for method, path in doc if path.count("/") >= 4}
    assert stripped & code
