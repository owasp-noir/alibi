from alibi import cli
from alibi.index import build
from alibi.report import json_report
from alibi.rules import RuleSet


def report(raw, view_map, **kwargs):
    ruleset = RuleSet.load()
    index = build(raw, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, skipped = ruleset.evaluate(index, views)
    return json_report.build(index, findings, skipped, ["test"],
                             ruleset=ruleset, **kwargs)


def test_the_default_payload_carries_no_endpoint_lists(endpoint, view_map):
    """The lists are several times the rest of it on a real repository."""
    document = report(
        [
            endpoint("/kept", "GET", "python_flask"),
            endpoint("/kept", "GET", "oas3"),
            endpoint("/undocumented", "GET", "python_flask"),
        ],
        view_map,
    )
    assert "endpoints" not in document
    assert document["summary"]["views"] == {"code": 2, "doc": 1}


def test_endpoints_lists_what_each_view_held_with_the_evidence(endpoint, view_map):
    """The question the report could not answer: what was in each view?

    Debugging any finding meant re-running noir once per view by hand with
    the same `--only-techs` lists and joining the results -- the whole tool,
    at a shell prompt, before the question could be asked.

    The unnormalized spelling is the load-bearing field. When two views hold
    what should be one endpoint and did not match, the difference is always
    in the original and never in the key.
    """
    document = report(
        [
            endpoint("/users/<int:uid>", "GET", "python_flask"),
            endpoint("/users/{userId}", "GET", "oas3"),
            endpoint("/undocumented", "GET", "python_flask"),
        ],
        view_map,
        endpoints=True,
    )

    listing = document["endpoints"]
    assert sorted(listing) == ["code", "doc"]
    assert [row["path"] for row in listing["code"]] == ["/undocumented", "/users/{}"]

    matched = next(row for row in listing["code"] if row["path"] == "/users/{}")
    assert matched["views"] == ["code", "doc"]
    assert matched["originals"] == ["/users/<int:uid>"]
    assert matched["technologies"] == ["python_flask"]
    # The same key from the other side, spelled the other way.
    assert next(row for row in listing["doc"]
                if row["path"] == "/users/{}")["originals"] == ["/users/{userId}"]

    lone = next(row for row in listing["code"] if row["path"] == "/undocumented")
    assert lone["views"] == ["code"]


def test_a_routing_view_is_listed_too(endpoint, view_map):
    """Coverage is where the least is visible: a gateway holds rules, and
    the summary counts them without ever saying what they were."""
    document = report(
        [
            endpoint("/api", "ANY", "nginx"),
            endpoint("/api/thing", "GET", "python_flask"),
        ],
        view_map,
        endpoints=True,
    )
    assert [row["path"] for row in document["endpoints"]["gateway"]] == ["/api"]
    assert document["endpoints"]["gateway"][0]["technologies"] == ["nginx"]


def test_endpoints_without_json_is_refused_rather_than_ignored(capsys):
    """A flag that silently does nothing sends the reader looking for output
    that was never going to be there."""
    assert cli.main(["scan", ".", "--endpoints"]) == cli.EXIT_ERROR
    assert "-f json" in capsys.readouterr().err


def test_the_listing_holds_every_endpoint_the_summary_counted(endpoint, view_map):
    """The lists and the counts must not be able to disagree."""
    endpoints = [endpoint(f"/api/thing{i}", "GET", "python_flask") for i in range(6)]
    endpoints += [endpoint(f"/api/thing{i}", "GET", "oas3") for i in range(4)]
    endpoints.append(endpoint("/spec-only", "GET", "oas3"))

    document = report(endpoints, view_map, endpoints=True)

    for view, count in document["summary"]["views"].items():
        assert len(document["endpoints"][view]) == count
