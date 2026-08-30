from alibi.index import build
from alibi.rules import RuleSet
from alibi.scope import suggest


def scan(endpoints, view_map):
    ruleset = RuleSet.load()
    index = build(endpoints, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, _ = ruleset.evaluate(index, views)
    return index, findings


def test_a_contract_scoped_to_one_prefix_is_reported_as_such(endpoint, view_map):
    """NetBox: the specification is entirely under /api, 30% of the code is not.

    A view that concentrates under one prefix has said what it was scoped to
    describe, and endpoints outside it were never in its remit. Comparing them
    anyway produced 345 findings saying a web page is not in an API document.
    """
    endpoints = [endpoint(f"/api/thing{i}", "GET", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/api/thing{i}", "GET", "python_flask") for i in range(20)]
    endpoints += [endpoint(f"/ui/page{i}", "GET", "python_flask") for i in range(15)]

    index, findings = scan(endpoints, view_map)
    hint = suggest(index, findings)

    assert hint is not None
    assert hint.prefix == "/api"
    assert hint.share == 100
    assert hint.outside == 15
    assert hint.ignore_pattern == "^/(?!api/)"


def test_no_hint_when_the_contract_is_spread_across_the_surface(endpoint, view_map):
    """Nothing to say when the document was never scoped to a corner."""
    endpoints = [endpoint(f"/api/thing{i}", "GET", "oas3") for i in range(10)]
    endpoints += [endpoint(f"/other/thing{i}", "GET", "oas3") for i in range(10)]
    endpoints += [endpoint(f"/ui/page{i}", "GET", "python_flask") for i in range(15)]

    index, findings = scan(endpoints, view_map)
    assert suggest(index, findings) is None


def test_no_hint_when_barely_anything_falls_outside(endpoint, view_map):
    """A suggestion that saves two lines is noise."""
    endpoints = [endpoint(f"/api/thing{i}", "GET", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/api/thing{i}", "GET", "python_flask") for i in range(20)]
    endpoints += [endpoint("/health", "GET", "python_flask")]

    index, findings = scan(endpoints, view_map)
    assert suggest(index, findings) is None


def test_a_leading_parameter_is_not_a_namespace(endpoint, view_map):
    """`/{tenant}/...` concentrates on a placeholder, which scopes nothing."""
    endpoints = [endpoint(f"/{{tenant}}/thing{i}", "GET", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/ui/page{i}", "GET", "python_flask") for i in range(15)]

    index, findings = scan(endpoints, view_map)
    assert suggest(index, findings) is None
