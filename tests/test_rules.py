from alibi.collect import RawEndpoint
from alibi.index import build
from alibi.rules import RuleSet


def evaluate(endpoints, view_map):
    index = build(endpoints, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    rules = RuleSet.load()
    return rules.evaluate(index, views)


def reasons(skipped, *rule_ids):
    """Why the named rules sat out.

    Every rule the scan lacks a view for is reported as skipped, so a scan of
    code and documentation alone legitimately holds back the six rules about
    traffic, gateways and infrastructure. Tests assert about the rules they are
    actually exercising rather than the whole set, which would otherwise have
    to be rewritten every time a rule is added.
    """
    return {s.reason for s in skipped if s.rule_id in rule_ids}


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
    assert reasons(skipped, "SHADOW", "PHANTOM") == {"missing-view"}


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


def test_views_that_never_met_hold_the_rules_back(endpoint, view_map):
    """The guard that survives contact with a real repository.

    Argo CD registers `/api` in Go and documents 198 paths beneath it, so code
    and docs share not one endpoint. Read literally that is 58 shadow APIs and
    198 phantom contracts; read honestly it is one fact about the scan. Zero
    corroboration between two populated views means the comparison did not
    work, and reporting hundreds of findings on top of it buries that.
    """
    endpoints = [endpoint(f"/code/{i}", "GET", "python_flask") for i in range(8)]
    endpoints += [endpoint(f"/spec/{i}", "GET", "oas3") for i in range(8)]

    findings, skipped = evaluate(endpoints, view_map)

    assert findings == []
    assert reasons(skipped, "SHADOW", "PHANTOM") == {"no-overlap"}
    assert "never met" in next(s.detail for s in skipped if s.rule_id == "SHADOW")


def test_one_shared_endpoint_is_enough_to_trust_the_comparison(endpoint, view_map):
    endpoints = [endpoint(f"/code/{i}", "GET", "python_flask") for i in range(8)]
    endpoints += [endpoint(f"/spec/{i}", "GET", "oas3") for i in range(8)]
    endpoints += [
        endpoint("/shared", "GET", "python_flask"),
        endpoint("/shared", "GET", "oas3"),
    ]

    findings, skipped = evaluate(endpoints, view_map)

    assert reasons(skipped, "SHADOW", "PHANTOM") == set()
    assert len(findings) == 16


def test_a_tiny_scan_is_not_second_guessed(endpoint, view_map):
    """Two endpoints that miss each other are not evidence of a broken tool."""
    findings, skipped = evaluate(
        [
            endpoint("/only-code", "GET", "python_flask"),
            endpoint("/only-doc", "GET", "oas3"),
        ],
        view_map,
    )
    assert {f.rule_id for f in findings} == {"SHADOW", "PHANTOM"}
    assert reasons(skipped, "SHADOW", "PHANTOM") == set()


def test_a_populated_view_sharing_nothing_is_disconnected_however_small_the_other(
    endpoint, view_map
):
    """Flipt: noir reads 2 Go routes and 42 documented paths, sharing none.

    The smaller side being tiny is not a reason to trust the comparison. A view
    holding forty endpoints that corroborates none of them is the surprising
    fact, and reporting 44 findings on top of it says nothing.
    """
    endpoints = [endpoint("/only-code", "GET", "go_http")]
    endpoints += [endpoint(f"/spec/{i}", "GET", "oas3") for i in range(12)]

    findings, skipped = evaluate(endpoints, view_map)

    assert findings == []
    assert reasons(skipped, "SHADOW", "PHANTOM") == {"no-overlap"}


# --- the traffic, gateway and infrastructure rules ---------------------------

def test_a_route_taking_real_requests_with_no_code_is_an_orphan(endpoint, view_map):
    findings, _ = evaluate(
        [
            endpoint("/legacy/export", "GET", "har"),
            endpoint("/current", "GET", "har"),
            endpoint("/current", "GET", "python_flask"),
        ],
        view_map,
    )
    orphans = {f.key.path for f in findings if f.rule_id == "ORPHAN"}
    assert orphans == {"/legacy/export"}


def test_a_postman_collection_cannot_prove_an_endpoint_is_live(endpoint, view_map):
    """Nobody watched it. Somebody wrote it down.

    Treating a hand-kept request collection as evidence of live traffic would
    let a stale Postman file manufacture high-severity orphan routes.
    """
    findings, skipped = evaluate(
        [
            endpoint("/legacy/export", "GET", "postman"),
            endpoint("/current", "GET", "postman"),
            endpoint("/current", "GET", "python_flask"),
        ],
        view_map,
    )
    assert not [f for f in findings if f.rule_id == "ORPHAN"]
    assert reasons(skipped, "ORPHAN") == {"not-observed"}


def test_a_gateway_prefix_does_not_look_like_a_dangling_route(endpoint, view_map):
    """The whole reason gateways cannot be compared as sets.

    One `location /api/` shares no key with any endpoint while reaching all of
    them. Read as a set difference it is a route pointing at nothing.
    """
    endpoints = [endpoint("/api", "ANY", "nginx")]
    endpoints += [
        endpoint(f"/api/v1/thing{i}", "GET", "python_flask") for i in range(4)
    ]

    findings, _ = evaluate(endpoints, view_map)
    assert not [f for f in findings if f.rule_id == "DANGLING"]


def test_a_gateway_rule_reaching_nothing_is_dangling(endpoint, view_map):
    endpoints = [endpoint("/removed-service", "ANY", "nginx")]
    endpoints += [endpoint(f"/api/thing{i}", "GET", "python_flask") for i in range(4)]

    findings, _ = evaluate(endpoints, view_map)
    dangling = {f.key.path for f in findings if f.rule_id == "DANGLING"}
    assert dangling == {"/removed-service"}


def test_an_endpoint_behind_a_gateway_prefix_is_not_unexposed(endpoint, view_map):
    endpoints = [endpoint("/api", "ANY", "nginx")]
    endpoints += [
        endpoint(f"/api/v1/thing{i}", "GET", "python_flask") for i in range(4)
    ]
    endpoints.append(endpoint("/debug/pprof", "GET", "python_flask"))

    findings, _ = evaluate(endpoints, view_map)
    unexposed = {f.key.path for f in findings if f.rule_id == "UNEXPOSED"}
    assert unexposed == {"/debug/pprof"}


def test_code_never_seen_taking_a_request_is_cold(endpoint, view_map):
    endpoints = [endpoint(f"/used{i}", "GET", "python_flask") for i in range(3)]
    endpoints += [endpoint(f"/used{i}", "GET", "har") for i in range(3)]
    endpoints.append(endpoint("/quarterly-report", "GET", "python_flask"))

    findings, _ = evaluate(endpoints, view_map)
    cold = {f.key.path for f in findings if f.rule_id == "COLD"}
    assert cold == {"/quarterly-report"}
    assert next(f for f in findings if f.rule_id == "COLD").severity == "info"


def test_infrastructure_declaring_what_no_code_serves_is_drift(endpoint, view_map):
    endpoints = [endpoint("/api/ghost", "ANY", "terraform")]
    endpoints += [endpoint(f"/api/real{i}", "GET", "python_flask") for i in range(4)]

    findings, _ = evaluate(endpoints, view_map)
    drift = {f.key.path for f in findings if f.rule_id == "DRIFT"}
    assert drift == {"/api/ghost"}


def test_non_web_surface_never_generates_web_findings(endpoint, view_map):
    """Argo CD reports 3 CLI entry points; none of them is an undocumented API.

    Every rule here compares against OpenAPI documents and gateway config.
    Neither describes a command line, so a CLI endpoint would qualify for all
    of them at once.
    """
    endpoints = [
        RawEndpoint(url="cli://argocd/agent", method="CLI", technology="go_cli",
                    source="t", protocol="cli"),
        RawEndpoint(url="/api/real", method="GET", technology="go_http",
                    source="t", protocol="http"),
    ]
    endpoints += [endpoint(f"/spec/{i}", "GET", "oas3") for i in range(6)]
    endpoints += [endpoint(f"/spec/{i}", "GET", "go_http") for i in range(6)]

    findings, _ = evaluate(endpoints, view_map)

    assert not [f for f in findings if f.key.protocol != "http"]
    assert {f.key.path for f in findings if f.rule_id == "SHADOW"} == {"/api/real"}
