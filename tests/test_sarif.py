import json
from pathlib import Path

import pytest

from alibi.index import build
from alibi.report import sarif
from alibi.rules import RuleSet

# The OASIS SARIF 2.1.0 schema, fetched from the specification repository and
# kept here so the guarantee holds without a network.
SCHEMA = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


def emit(endpoints, view_map):
    ruleset = RuleSet.load()
    index = build(endpoints, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, skipped = ruleset.evaluate(index, views)
    return sarif.build(index, findings, skipped, ["fixture"], ruleset)


def results(document):
    return document["runs"][0]["results"]


def parts(endpoints, view_map):
    """The pieces `sarif.build` takes, for tests that pass extra arguments."""
    ruleset = RuleSet.load()
    index = build(endpoints, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, skipped = ruleset.evaluate(index, views)
    return index, findings, skipped, ruleset


def schema_errors(document):
    """Every way `document` departs from the SARIF 2.1.0 schema.

    Structure only. The schema declares `artifactLocation.uri` as a
    `uri-reference`, and jsonschema can only check that format with a GPL
    dependency this project will not take on, so the URI shape is asserted
    directly by the tests below instead.
    """
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    return list(jsonschema.Draft4Validator(schema).iter_errors(document))


def test_the_document_validates_against_the_sarif_2_1_0_schema(endpoint, view_map):
    """The only check that means anything for a format nobody here reads.

    Nothing in this repository consumes SARIF, so a field with the wrong name
    or a region numbered from zero looks perfectly fine in review and is
    rejected on upload. The schema is the reviewer.
    """
    document = emit(
        [
            endpoint("/kept/{id}", "GET", "python_flask",
                     code_paths=[{"path": "app/main.py", "line": 6}]),
            endpoint("/kept/{id}", "GET", "oas3",
                     code_paths=[{"path": "contracts/openapi.yaml"}]),
            endpoint("/undocumented", "DELETE", "python_flask",
                     tags=["pii"], code_paths=[{"path": "app/main.py", "line": 20}]),
            # No code path at all, as a capture or a gateway rule arrives.
            endpoint("/from-a-capture", "GET", "har"),
            endpoint("/never-built", "GET", "oas3"),
        ],
        view_map,
    )

    assert schema_errors(document) == []


def test_a_document_with_no_findings_validates_too(endpoint, view_map):
    """The empty-results shape is a different document, and CI sees it most."""
    document = emit([endpoint("/only-code", "GET", "python_flask")], view_map)

    assert results(document) == []
    assert schema_errors(document) == []


def test_every_rule_in_the_ruleset_is_described_whether_or_not_it_fired(
    endpoint, view_map
):
    """rules.yml is data, so the rule catalog cannot be a list in Python.

    Adding the traffic, gateway and infra rules is supposed to be an edit to
    YAML. A hardcoded catalog would emit results whose `ruleId` the run does
    not describe, which is invalid SARIF as well as unhelpful.
    """
    document = emit([endpoint("/only-code", "GET", "python_flask")], view_map)

    described = {r["id"] for r in document["runs"][0]["tool"]["driver"]["rules"]}
    assert described == {rule["id"] for rule in RuleSet.load().rules}


def test_a_result_points_at_the_line_noir_found_it_on(endpoint, view_map):
    document = emit(
        [
            endpoint("/undocumented", "GET", "python_flask",
                     code_paths=[{"path": "app/main.py", "line": 52}]),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )

    shadow = next(r for r in results(document) if r["ruleId"] == "SHADOW")
    physical = shadow["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "app/main.py"
    assert physical["region"]["startLine"] == 52


def test_a_document_with_no_line_gets_a_file_and_no_region(endpoint, view_map):
    """Noir names the specification but not the line inside it.

    SARIF numbers lines from one, so a missing line cannot be written as zero,
    and inventing line 1 would send the reader to the wrong place in a file
    that may be thousands of paths long.
    """
    document = emit(
        [
            endpoint("/never-built", "GET", "oas3",
                     code_paths=[{"path": "contracts/openapi.yaml"}]),
            endpoint("/anchor", "GET", "python_flask"),
        ],
        view_map,
    )

    phantom = next(r for r in results(document) if r["ruleId"] == "PHANTOM")
    physical = phantom["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "contracts/openapi.yaml"
    assert "region" not in physical


def test_a_finding_with_no_file_is_located_by_its_endpoint(endpoint, view_map):
    """A gap has to survive the trip even when there is nothing to open.

    A capture or a gateway rule carries no code path, and every consumer of
    this format wants a location. Naming a file that does not describe the
    finding would be worse than naming none, so the endpoint identity is the
    location -- which is what SARIF's logical locations are for.
    """
    document = emit(
        [
            endpoint("/never-built", "GET", "oas3"),
            endpoint("/anchor", "GET", "python_flask"),
        ],
        view_map,
    )

    phantom = next(r for r in results(document) if r["ruleId"] == "PHANTOM")
    location = phantom["locations"][0]
    assert "physicalLocation" not in location
    assert location["logicalLocations"][0]["name"] == "GET /never-built"


def test_the_five_step_severity_survives_the_four_level_flattening(
    endpoint, view_map
):
    """`warning` for both medium and high would erase the adjustments.

    The whole point of the pii, upload, no-auth and write adjustments is to
    separate findings that SARIF's vocabulary cannot. Keeping the original
    severity in the property bag is what stops that work being thrown away at
    the last step.
    """
    document = emit(
        [
            endpoint("/profile", "GET", "python_flask", tags=["pii"]),
            endpoint("/plain", "GET", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )

    by_path = {
        r["message"]["text"].split()[1]: r
        for r in results(document) if r["ruleId"] == "SHADOW"
    }
    assert by_path["/profile"]["level"] == "error"
    assert by_path["/profile"]["properties"]["severity"] == "high"
    assert by_path["/plain"]["level"] == "warning"
    assert by_path["/plain"]["properties"]["severity"] == "medium"


def test_a_demoted_finding_says_so_where_a_reader_will_see_it(endpoint, view_map):
    """A near miss demotes the level, and the level alone does not explain why.

    Reported at face value this is a shadow API; it is probably alibi failing
    to line two rows up. A consumer that only reads `level` would take the
    demotion as a judgement about the endpoint rather than about the tool.
    """
    document = emit(
        [
            endpoint("/users/123", "GET", "python_flask"),
            endpoint("/users/{userId}", "GET", "oas3"),
        ],
        view_map,
    )

    shadow = next(r for r in results(document) if r["ruleId"] == "SHADOW")
    assert shadow["properties"]["uncertain"] is True
    assert "matching failure inside alibi" in shadow["message"]["text"]


def test_a_rule_that_never_ran_is_reported_rather_than_dropped(endpoint, view_map):
    """Zero findings and "nothing was compared" must not look the same.

    Argo CD produces no findings because the two views never met. A SARIF
    consumer seeing an empty results array would read that as agreement, which
    is the one conclusion the whole tool is built to refuse.
    """
    endpoints = [endpoint(f"/code/{i}", "GET", "python_flask") for i in range(15)]
    endpoints += [endpoint(f"/spec/{i}", "GET", "oas3") for i in range(15)]

    document = emit(endpoints, view_map)

    assert results(document) == []
    notifications = document["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    held_back = [n for n in notifications
                 if n["properties"]["reason"] == "no-overlap"]
    assert {n["associatedRule"]["id"] for n in held_back} == {"SHADOW", "PHANTOM"}
    assert all(n["level"] == "warning" for n in held_back)


def test_an_absolute_path_is_made_relative_to_the_working_directory(
    endpoint, view_map, tmp_path, monkeypatch
):
    """Noir echoes back the base path it was given, and CI passes absolute ones.

    Code scanning lines results up against the repository by path, so an
    absolute one matches nothing.
    """
    monkeypatch.chdir(tmp_path)
    document = emit(
        [
            endpoint("/undocumented", "GET", "python_flask",
                     code_paths=[{"path": str(tmp_path / "src" / "app.py"),
                                  "line": 3}]),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )

    shadow = next(r for r in results(document) if r["ruleId"] == "SHADOW")
    uri = shadow["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/app.py"


def test_a_path_outside_the_working_directory_stays_addressable(
    endpoint, view_map, tmp_path, monkeypatch
):
    """Scanning a checkout elsewhere is normal; a broken URI is not."""
    monkeypatch.chdir(tmp_path)
    document = emit(
        [
            endpoint("/undocumented", "GET", "python_flask",
                     code_paths=[{"path": "/opt/other service/app.py"}]),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )

    shadow = next(r for r in results(document) if r["ruleId"] == "SHADOW")
    uri = shadow["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "file:///opt/other%20service/app.py"


def test_one_endpoint_seen_twice_is_one_alert_not_two_edits(endpoint, view_map):
    """SARIF reads a second `locations` entry as "change this one as well".

    Two files registering one route corroborate each other; they are not a
    checklist of edits, and code scanning would raise the alert twice.
    """
    document = emit(
        [
            endpoint("/undocumented", "GET", "python_flask",
                     code_paths=[{"path": "a.py", "line": 1}]),
            endpoint("/undocumented", "GET", "python_django",
                     code_paths=[{"path": "b.py", "line": 2}]),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )

    shadow = next(r for r in results(document) if r["ruleId"] == "SHADOW")
    assert len(shadow["locations"]) == 1
    assert len(shadow["relatedLocations"]) == 1


def test_the_totals_travel_with_the_findings(endpoint, view_map):
    """147 findings mean something different beside 230 corroborated endpoints.

    A SARIF file is often the only artifact a CI run keeps, and a findings list
    with no denominator is exactly the report this tool refuses to produce.
    """
    document = emit(
        [
            endpoint("/kept", "GET", "python_flask"),
            endpoint("/kept", "GET", "oas3"),
            endpoint("/undocumented", "GET", "python_flask"),
        ],
        view_map,
    )

    properties = document["runs"][0]["properties"]
    assert properties["endpoints"] == 2
    assert properties["corroborated"] == 1
    assert properties["sources"] == ["fixture"]


def test_a_scan_that_could_not_read_everything_is_not_a_successful_run(
    endpoint, view_map
):
    """SARIF is often the only artifact a CI run keeps.

    A rule held back is a conclusion. A file noir could not read is not: the
    scan did not see everything it was pointed at, and a consumer treating the
    result as a complete picture of the surface is being misled.
    """
    from alibi.collect import ScanError

    index, findings, skipped, rules = parts(
        [
            endpoint("/thing", "GET", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )
    errors = [ScanError(tech="detect", message="skipped 1 file: openapi.json")]

    document = sarif.build(index, findings, skipped, ["t"], rules, errors)
    invocation = document["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is False
    assert document["runs"][0]["properties"]["degraded"] is True
    assert any("could not read" in n["message"]["text"]
               for n in invocation["toolExecutionNotifications"])

    clean = sarif.build(index, findings, skipped, ["t"], rules)
    assert clean["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_a_suppressed_finding_is_reported_as_suppressed_not_dropped(
    endpoint, view_map
):
    """Code scanning shows it dismissed, with the project's reason attached."""
    from alibi.ignore import IgnoreEntry

    index, findings, skipped, rules = parts(
        [
            endpoint("/internal/admin", "GET", "python_flask"),
            endpoint("/public", "GET", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )
    hidden = [f for f in findings if f.key.path == "/internal/admin"]
    shown = [f for f in findings if f.key.path != "/internal/admin"]
    entry = IgnoreEntry(why="internal-only admin surface")

    document = sarif.build(index, shown, skipped, ["t"], rules,
                           suppressed=[(f, entry) for f in hidden])
    results = document["runs"][0]["results"]

    suppressed = [r for r in results if "suppressions" in r]
    assert len(suppressed) == len(hidden)
    assert suppressed[0]["suppressions"][0]["kind"] == "external"
    assert suppressed[0]["suppressions"][0]["justification"] == (
        "internal-only admin surface")
    assert document["runs"][0]["properties"]["suppressed"] == len(hidden)
    # And the reported ones carry no suppression at all.
    assert all("suppressions" not in r for r in results if r not in suppressed)


def _with_root(endpoint, url, method, tech, path, root, line=None):
    """A finding whose code path carries the root its scan was given."""
    from alibi.collect import RawEndpoint

    return RawEndpoint(
        url=url, method=method, technology=tech, source="svc",
        source_root=root,
        code_paths=({"path": path, "line": line},) if line
        else ({"path": path},),
    )


def test_a_location_is_relative_to_the_checkout_not_the_machine(view_map):
    """The field code scanning matches an alert to its source file by.

    It matches on a path relative to the repository checkout, so an absolute
    `file://` URI matches nothing and the alert arrives with no code behind
    it -- which is most of what code scanning is for. Every one of Casdoor's
    139 results was absolute.
    """
    root = "/build/checkout"
    endpoints = [
        _with_root(None, "/api/thing", "GET", "go_http",
                   f"{root}/routers/router.go", root, line=87),
        _with_root(None, "/anchor", "GET", "oas3", f"{root}/openapi.json", root),
    ]

    document = emit(endpoints, view_map)
    artifact = results(document)[0]["locations"][0]["physicalLocation"]["artifactLocation"]

    assert artifact["uri"] == "routers/router.go"
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert document["runs"][0]["originalUriBaseIds"] == {
        "%SRCROOT%": {"uri": "file:///build/checkout/"}
    }


def test_a_path_outside_every_root_is_named_absolutely(view_map):
    """Inventing a relative path for it would describe a layout that is not there."""
    endpoints = [
        _with_root(None, "/api/thing", "GET", "go_http",
                   "/elsewhere/vendor/lib.go", "/build/checkout", line=3),
        _with_root(None, "/anchor", "GET", "oas3",
                   "/build/checkout/openapi.json", "/build/checkout"),
    ]

    document = emit(endpoints, view_map)
    uris = [
        location["physicalLocation"]["artifactLocation"]["uri"]
        for result in results(document)
        for location in result.get("locations", [])
        if "physicalLocation" in location
    ]

    assert "file:///elsewhere/vendor/lib.go" in uris


def test_several_roots_leave_the_base_undeclared(view_map):
    """Pointing one base id at one of them would be wrong for the rest."""
    endpoints = [
        _with_root(None, "/api/thing", "GET", "go_http",
                   "/a/routers/router.go", "/a", line=1),
        _with_root(None, "/api/other", "GET", "go_http",
                   "/b/handlers/h.go", "/b", line=1),
        _with_root(None, "/anchor", "GET", "oas3", "/a/openapi.json", "/a"),
    ]

    document = emit(endpoints, view_map)

    assert "originalUriBaseIds" not in document["runs"][0]
    uris = [
        location["physicalLocation"]["artifactLocation"]["uri"]
        for result in results(document)
        for location in result.get("locations", [])
        if "physicalLocation" in location
    ]
    assert "routers/router.go" in uris
    assert "handlers/h.go" in uris
