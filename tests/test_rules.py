from alibi.index import build
from alibi.rules import RuleSet


def evaluate(endpoints, view_map):
    index = build(endpoints, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    rules = RuleSet.load()
    return rules.evaluate(index, views)


def test_shadow_and_phantom_are_reported_from_the_same_scan(endpoint, view_map):
    findings, _ = evaluate(
        [
            endpoint("/kept/{id}", "GET", "python_flask"),
            endpoint("/kept/{id}", "GET", "oas3"),
            endpoint("/undocumented", "GET", "python_flask"),
            endpoint("/never-built", "GET", "oas3"),
        ],
        view_map,
    )

    found = {(f.rule_id, f.key.path) for f in findings}
    assert ("SHADOW", "/undocumented") in found
    assert ("PHANTOM", "/never-built") in found
    assert not [f for f in findings if f.key.path == "/kept/{}"]


def test_no_contract_in_the_scan_means_no_shadow_findings(endpoint, view_map):
    """The guard that decides whether this tool is usable at all.

    Without it, pointing alibi at a codebase and nothing else reports every
    endpoint as an undocumented shadow API -- hundreds of findings that only
    say the user did not supply any documentation.
    """
    findings, skipped = evaluate(
        [
            endpoint("/a", "GET", "python_flask"),
            endpoint("/b", "POST", "python_flask"),
        ],
        view_map,
    )

    assert findings == []
    assert {s.rule_id for s in skipped} == {"SHADOW", "PHANTOM"}
    assert skipped[0].missing == ["doc"]


def test_writes_outrank_reads(endpoint, view_map):
    findings, _ = evaluate(
        [
            endpoint("/thing", "GET", "python_flask"),
            endpoint("/thing", "DELETE", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )

    by_method = {f.key.method: f.severity for f in findings if f.rule_id == "SHADOW"}
    assert by_method["GET"] == "medium"
    assert by_method["DELETE"] == "high"


def test_personal_data_raises_severity(endpoint, view_map):
    findings, _ = evaluate(
        [
            endpoint("/profile", "GET", "python_flask", tags=["pii"]),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )
    shadow = next(f for f in findings if f.key.path == "/profile")
    assert shadow.severity == "high"
    assert any("personal data" in a.why for a in shadow.adjustments)


def test_missing_auth_only_counts_where_noir_tags_auth_at_all(endpoint, view_map):
    """An absence is only evidence when the signal exists somewhere.

    Noir's auth taggers cover the frameworks they know. In a stack they do not
    cover, no endpoint carries an auth tag, and promoting all of them would
    drain the severity column of meaning.
    """
    untagged, _ = evaluate(
        [
            endpoint("/thing", "GET", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )
    assert next(f for f in untagged if f.key.path == "/thing").severity == "medium"

    tagged, _ = evaluate(
        [
            endpoint("/thing", "GET", "python_flask"),
            endpoint("/guarded", "GET", "python_flask", tags=["flask_auth"]),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )
    assert next(f for f in tagged if f.key.path == "/thing").severity == "high"


def test_auth_adjustment_never_applies_to_phantom(endpoint, view_map):
    """Asking whether an unimplemented endpoint authenticates is incoherent."""
    findings, _ = evaluate(
        [
            endpoint("/guarded", "GET", "python_flask", tags=["flask_auth"]),
            endpoint("/never-built", "DELETE", "oas3"),
        ],
        view_map,
    )
    phantom = next(f for f in findings if f.rule_id == "PHANTOM")
    assert phantom.severity == phantom.base_severity
    assert phantom.adjustments == []


def test_a_near_miss_demotes_rather_than_reports_at_face_value(endpoint, view_map):
    findings, _ = evaluate(
        [
            endpoint("/users/123", "GET", "python_flask"),
            endpoint("/users/{userId}", "GET", "oas3"),
        ],
        view_map,
    )
    shadow = next(f for f in findings if f.rule_id == "SHADOW")
    assert shadow.uncertain is True
    assert shadow.severity == "low"


def test_internal_endpoints_are_suppressed(endpoint, view_map):
    findings, _ = evaluate(
        [
            endpoint("/internal", "GET", "python_flask", internal=True),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )
    assert not [f for f in findings if f.key.path == "/internal"]


def test_websocket_verbs_are_not_measured_against_http_contracts(endpoint, view_map):
    findings, _ = evaluate(
        [
            endpoint("/app/chat/{roomId}", "SEND", "java_spring"),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )
    assert not [f for f in findings if f.key.method == "SEND"]
