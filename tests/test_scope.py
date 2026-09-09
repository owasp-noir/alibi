from alibi.index import build
from alibi.rules import RuleSet
from alibi.scope import suggest


def scan(endpoints, view_map):
    ruleset = RuleSet.load()
    index = build(endpoints, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, _ = ruleset.evaluate(index, views)
    return index, findings, ruleset


def test_a_contract_scoped_to_one_prefix_is_reported_as_such(endpoint, view_map):
    """NetBox: the specification is entirely under /api, 30% of the code is not.

    A view that concentrates under one prefix has said what it was scoped to
    describe, and endpoints outside it were never in its remit. Comparing them
    anyway produced 345 findings saying a web page is not in an API document.
    """
    endpoints = [endpoint(f"/api/thing{i}", "GET", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/api/thing{i}", "GET", "python_flask") for i in range(20)]
    endpoints += [endpoint(f"/ui/page{i}", "GET", "python_flask") for i in range(15)]

    index, findings, ruleset = scan(endpoints, view_map)
    hint = suggest(index, findings, ruleset)

    assert hint is not None
    assert hint.prefix == "/api"
    assert hint.share == 100
    assert hint.outside == 15
    assert hint.ignore_pattern == "^/(?!api(/|$))"


def test_no_hint_when_the_contract_is_spread_across_the_surface(endpoint, view_map):
    """Nothing to say when the document was never scoped to a corner."""
    endpoints = [endpoint(f"/api/thing{i}", "GET", "oas3") for i in range(10)]
    endpoints += [endpoint(f"/other/thing{i}", "GET", "oas3") for i in range(10)]
    endpoints += [endpoint(f"/ui/page{i}", "GET", "python_flask") for i in range(15)]

    index, findings, ruleset = scan(endpoints, view_map)
    assert suggest(index, findings, ruleset) is None


def test_no_hint_when_barely_anything_falls_outside(endpoint, view_map):
    """A suggestion that saves two lines is noise."""
    endpoints = [endpoint(f"/api/thing{i}", "GET", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/api/thing{i}", "GET", "python_flask") for i in range(20)]
    endpoints += [endpoint("/health", "GET", "python_flask")]

    index, findings, ruleset = scan(endpoints, view_map)
    assert suggest(index, findings, ruleset) is None


def test_a_leading_parameter_is_not_a_namespace(endpoint, view_map):
    """`/{tenant}/...` concentrates on a placeholder, which scopes nothing."""
    endpoints = [endpoint(f"/{{tenant}}/thing{i}", "GET", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/ui/page{i}", "GET", "python_flask") for i in range(15)]

    index, findings, ruleset = scan(endpoints, view_map)
    assert suggest(index, findings, ruleset) is None


def test_findings_about_other_views_do_not_drive_the_hint(endpoint, view_map):
    """authentik: its contract stops at /api and 192 findings sit outside it.

    All 192 are UNEXPOSED and DRIFT -- about gateways and infrastructure -- and
    SHADOW is held back there because code and docs share nothing. The
    contract's scope says nothing about a gateway finding, and narrowing the
    scan on that basis would answer a question nobody asked.
    """
    # Code and docs describe disjoint surfaces, so SHADOW and PHANTOM are held
    # back. The gateway reaches the API half of the code and none of the
    # internal half, so what survives is UNEXPOSED -- all of it outside /api.
    endpoints = [endpoint(f"/api/documented{i}", "GET", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/api/impl{i}", "GET", "python_flask") for i in range(10)]
    endpoints += [endpoint(f"/internal/job{i}", "GET", "python_flask")
                  for i in range(15)]
    endpoints += [endpoint("/api", "ANY", "nginx")]

    index, findings, ruleset = scan(endpoints, view_map)

    assert {f.rule_id for f in findings} == {"UNEXPOSED"}
    assert all(not f.key.path.startswith("/api/") for f in findings)
    assert suggest(index, findings, ruleset) is None


def test_findings_that_are_mostly_test_fixtures_are_reported_as_such(
    endpoint, view_map
):
    """Directus keeps e2e snapshots listing every collection its suite creates.

    Noir reads them as endpoints -- `/items/articles_1234` beside the
    documented `/items/{collection}` -- and 145 of its 281 findings came from
    test directories, each one near-missing a real endpoint.
    """
    from alibi.scope import from_tests

    endpoints = [
        endpoint(f"/items/fixture_{i}", "GET", "python_flask",
                 code_paths=({"path": f"tests/e2e/snapshot_{i}.json"},))
        for i in range(15)
    ]
    endpoints += [endpoint("/anchor", "GET", "oas3"),
                  endpoint("/anchor", "GET", "python_flask")]

    index, findings, _ = scan(endpoints, view_map)
    hint = from_tests(findings, index)

    assert hint is not None
    assert hint.directories == ["tests"]
    assert hint.exclude_globs == ["**/tests/**"]


def test_a_directory_another_view_needs_is_never_suggested(endpoint, view_map):
    """Directus keeps its OpenAPI document in `packages/specs/`.

    `specs` is on the list of names that usually mean fixtures, and suggesting
    it would have deleted the contract the comparison runs against -- on this
    tool's own advice.
    """
    from alibi.scope import from_tests

    endpoints = [
        endpoint(f"/items/fixture_{i}", "GET", "python_flask",
                 code_paths=({"path": f"specs/e2e/snapshot_{i}.json"},))
        for i in range(15)
    ]
    endpoints += [
        endpoint("/anchor", "GET", "oas3",
                 code_paths=({"path": "packages/specs/src/openapi.yaml"},)),
        endpoint("/anchor", "GET", "python_flask"),
    ]

    index, findings, _ = scan(endpoints, view_map)

    assert from_tests(findings, index) is None


def test_a_handful_of_test_findings_is_not_worth_a_paragraph(endpoint, view_map):
    from alibi.scope import from_tests

    endpoints = [
        endpoint("/items/one", "GET", "python_flask",
                 code_paths=({"path": "tests/x.py"},)),
    ]
    endpoints += [endpoint(f"/real/{i}", "GET", "python_flask") for i in range(20)]
    endpoints += [endpoint("/anchor", "GET", "oas3"),
                  endpoint("/anchor", "GET", "python_flask")]

    index, findings, _ = scan(endpoints, view_map)
    assert from_tests(findings, index) is None


def test_the_suggested_command_suppresses_exactly_what_was_counted(endpoint, view_map):
    """The report prints a number and a command. They have to agree.

    `^/(?!api/)` also suppressed the endpoint at `/api` itself, which the
    count treats as inside the surface the contract describes -- so the report
    said "12 findings are outside it" and handed over a command that removed
    13. The one they disagreed about is the mount point, which in the
    gRPC-gateway shape this hint appears in is the endpoint most worth
    keeping.
    """
    from alibi.ignore import IgnoreList

    endpoints = [endpoint(f"/api/thing{i}", "GET", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/api/thing{i}", "GET", "python_flask") for i in range(20)]
    endpoints += [endpoint(f"/api/shadow{i}", "GET", "python_flask") for i in range(5)]
    endpoints += [endpoint(f"/ui/page{i}", "GET", "python_flask") for i in range(12)]
    endpoints += [endpoint("/api", "GET", "python_flask"),
                  endpoint("/apifoo", "GET", "python_flask")]

    index, findings, ruleset = scan(endpoints, view_map)
    hint = suggest(index, findings, ruleset)
    kept, dropped = IgnoreList.from_patterns([hint.ignore_pattern]).apply(findings)

    assert (hint.inside, hint.outside) == (len(kept), len(dropped))
    assert "/api" in {f.key.path for f in kept}
    # A different top-level segment that merely starts with the same letters
    # is still outside.
    assert "/apifoo" in {f.key.path for f, _ in dropped}


# --- when the views part company along a prefix ------------------------------

def test_views_that_line_up_once_a_prefix_comes_off_are_told_so(endpoint, view_map):
    """Gitea: the spec declares `basePath: /GITEA-API-APP-SUBURL/api/v1`.

    Noir prefixes every documented path with it, its Go reader drops the
    `/api/v1` mount, and the two views share nothing. "Check whether one
    side is a mount point" is true and no help; "154 of 535 doc paths match
    a code path once three segments come off" names the prefix and the side.
    """
    from alibi.scope import realign

    endpoints = [
        endpoint(f"/SUBURL/api/v1/repos/{{owner}}/thing{i}", "GET", "oas3")
        for i in range(15)
    ]
    endpoints += [endpoint(f"/repos/{{owner}}/thing{i}", "GET", "go_chi") for i in range(15)]
    endpoints += [endpoint(f"/SUBURL/api/v1/other{i}", "GET", "oas3") for i in range(5)]

    index, findings, ruleset = scan(endpoints, view_map)
    lead = realign(index, "code", "doc", floor=10)

    assert lead is not None
    assert (lead.view, lead.other) == ("doc", "code")
    assert lead.prefix == "/SUBURL/api/v1"
    assert lead.segments == 3
    assert (lead.aligned, lead.total) == (15, 20)
    # It reaches the report through the held-back detail, since SHADOW and
    # PHANTOM were rightly held back for never meeting.
    _, skipped = ruleset.evaluate(index, {"code", "doc"})
    detail = next(s.detail for s in skipped if s.rule_id == "PHANTOM")
    assert "15 of the 20 doc paths under /SUBURL/api/v1" in detail
    assert "3 leading segments" in detail


def test_two_unrelated_surfaces_are_not_told_they_line_up(endpoint, view_map):
    """authentik: a Django API under /api/v3 and a Rust outpost noir reads.

    Nothing lines up at any depth, and a diagnostic that offered a prefix
    anyway would send the reader after a bug that is not there. Measured on
    the corpus, the unrelated pairs align 0 paths; gitea aligns 154.
    """
    from alibi.scope import realign

    endpoints = [endpoint(f"/api/v3/core/thing{i}", "GET", "oas3") for i in range(30)]
    endpoints += [endpoint(f"/outpost/route{i}", "GET", "rust_axum") for i in range(30)]

    index, _, ruleset = scan(endpoints, view_map)
    assert realign(index, "code", "doc", floor=10) is None
    _, skipped = ruleset.evaluate(index, {"code", "doc"})
    assert "mount point" in next(s.detail for s in skipped if s.rule_id == "SHADOW")


def test_a_parameter_is_not_a_prefix_and_a_bare_parameter_is_not_a_match(
    endpoint, view_map
):
    """`/{}` stripped of anything matches every `/{}`, and says nothing."""
    from alibi.scope import realign

    endpoints = [endpoint(f"/{{tenant}}/x{i}/{{id}}", "GET", "oas3") for i in range(15)]
    endpoints += [endpoint(f"/x{i}/{{id}}", "GET", "go_chi") for i in range(15)]
    endpoints += [endpoint(f"/v1/things{i}/{{id}}", "GET", "oas3") for i in range(15)]
    endpoints += [endpoint("/{id}", "GET", "go_chi")]

    index, _, _ = scan(endpoints, view_map)
    assert realign(index, "code", "doc", floor=10) is None


def test_a_flood_that_is_one_missing_subtree_is_named_as_one(endpoint, view_map):
    """NodeBB documents 207 paths under /api/v3; noir reads none of the
    Express routers mounted there. Listed one by one that is 207 phantom
    contracts; named as a subtree it is one question."""
    from alibi.scope import missing_subtree

    endpoints = [endpoint(f"/api/v3/users/{i}", "POST", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/api/page{i}", "GET", "oas3") for i in range(12)]
    endpoints += [endpoint(f"/api/page{i}", "GET", "js_express") for i in range(12)]
    endpoints += [endpoint("/api/only-here", "GET", "js_express")]

    index, findings, ruleset = scan(endpoints, view_map)
    lead = missing_subtree(findings, index, ruleset, floor=10)

    assert lead is not None
    assert lead.rule_id == "PHANTOM"
    assert lead.prefix == "/api/v3"
    assert lead.absent_view == "code"
    assert (lead.findings, lead.total) == (20, 20)


def test_a_subtree_the_scope_hint_already_explains_is_not_named_twice(
    endpoint, view_map
):
    """NetBox's web UI under /dcim is a second surface, and the scope hint
    says so. Calling it a subtree the specification lacks would be the same
    observation with a worse explanation."""
    from alibi.scope import missing_subtree, suggest

    endpoints = [endpoint(f"/api/thing{i}", "GET", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/api/thing{i}", "GET", "python_flask") for i in range(20)]
    endpoints += [endpoint(f"/dcim/page{i}", "GET", "python_flask") for i in range(15)]

    index, findings, ruleset = scan(endpoints, view_map)
    assert suggest(index, findings, ruleset) is not None
    assert missing_subtree(findings, index, ruleset, floor=10) is None


def test_a_subtree_the_other_view_does_hold_is_not_missing(endpoint, view_map):
    """NetBox's 418 phantoms are bulk verbs on collections the code serves
    under the same prefix -- that is a different and smaller thing."""
    from alibi.scope import missing_subtree

    endpoints = [endpoint(f"/api/ipam/thing{i}", "PATCH", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/api/ipam/thing{i}", "GET", "oas3") for i in range(20)]
    endpoints += [endpoint(f"/api/ipam/thing{i}", "GET", "python_flask") for i in range(20)]

    index, findings, ruleset = scan(endpoints, view_map)
    assert missing_subtree(findings, index, ruleset, floor=10) is None
