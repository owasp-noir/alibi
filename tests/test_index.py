from alibi.index import GRADE_EXACT, GRADE_LONE, GRADE_TEMPLATE, build


def test_the_same_endpoint_spelled_two_ways_becomes_one_entry(endpoint, view_map):
    """The reason this tool can work at all."""
    index = build(
        [
            endpoint("/users/<int:user_id>", "GET", "python_flask"),
            endpoint("/users/{userId}", "GET", "oas3"),
        ],
        view_map,
    )

    assert len(index.entries) == 1
    entry = next(iter(index.entries.values()))
    assert entry.views == {"code", "doc"}
    assert entry.grade == GRADE_TEMPLATE


def test_identical_spellings_grade_as_exact(endpoint, view_map):
    index = build(
        [
            endpoint("/health", "GET", "python_flask"),
            endpoint("/health", "GET", "oas3"),
        ],
        view_map,
    )
    assert next(iter(index.entries.values())).grade == GRADE_EXACT


def test_an_endpoint_only_one_view_knows_about_is_lone(endpoint, view_map):
    index = build([endpoint("/internal/metrics", "GET", "python_flask")], view_map)
    entry = next(iter(index.entries.values()))
    assert entry.views == {"code"}
    assert entry.grade == GRADE_LONE


def test_a_missing_parameter_is_reported_as_a_near_miss(endpoint, view_map):
    """The failure mode that would otherwise become a false finding.

    If noir cannot see that a segment is a parameter in one view, the two rows
    never meet and both sides look like gaps. Rather than report two confident
    findings, say the two rows nearly matched.
    """
    index = build(
        [
            endpoint("/users/123", "GET", "har"),
            endpoint("/users/{userId}", "GET", "oas3"),
        ],
        view_map,
    )

    captured = index.entries[
        next(k for k in index.entries if k.path == "/users/123")
    ]
    assert captured.near_misses
    assert "parameter" in captured.near_misses[0].reason


def test_a_spanning_parameter_meeting_a_single_segment_one_is_a_near_miss(
    endpoint, view_map
):
    """The same slot read at two granularities is not two endpoints.

    A specification has no way to spell "and everything below this", so a
    framework's spanning converter always meets a plain `{param}` on the other
    side. Flask's `<path:subpath>` against OpenAPI's `{subpath}` reported a
    critical shadow API *and* a phantom contract for a route both views
    described, with nothing said about why they failed to meet.
    """
    index = build(
        [
            endpoint("/api/files/<path:subpath>", "PUT", "python_flask"),
            endpoint("/api/files/{subpath}", "PUT", "oas3"),
        ],
        view_map,
    )

    assert len(index.entries) == 2
    assert index.near_miss_count == 2
    wide = index.entries[next(k for k in index.entries if k.path.endswith("*"))]
    assert "takes the rest of the path here" in wide.near_misses[0].reason


def test_two_single_segment_parameters_in_one_place_are_the_same_endpoint(
    endpoint, view_map
):
    """The guard above must not turn agreement into doubt."""
    index = build(
        [
            endpoint("/api/files/{a}", "PUT", "python_flask"),
            endpoint("/api/files/{b}", "PUT", "oas3"),
        ],
        view_map,
    )
    assert len(index.entries) == 1
    assert index.near_miss_count == 0


def test_same_path_different_verb_is_context_not_doubt(endpoint, view_map):
    """A verb difference cannot be a matching failure.

    Normalization never touches the method, so `DELETE /x` failing to meet
    `GET /x` says nothing about whether the paths were lined up correctly.
    Filed as doubt it demoted 380 of NetBox's 746 findings for the crime of
    having a sibling; recorded as context it turns 397 phantom endpoints into
    "the bulk verbs on collections that exist".
    """
    index = build(
        [
            endpoint("/orders", "POST", "python_flask"),
            endpoint("/orders", "GET", "oas3"),
        ],
        view_map,
    )

    assert len(index.entries) == 2
    assert index.near_miss_count == 0

    post = index.entries[next(k for k in index.entries if k.method == "POST")]
    assert post.siblings == [("GET", frozenset({"doc"}))]


def test_matching_endpoints_produce_no_near_miss_noise(endpoint, view_map):
    index = build(
        [
            endpoint("/users/<int:id>", "GET", "python_flask"),
            endpoint("/users/{userId}", "GET", "oas3"),
        ],
        view_map,
    )
    assert index.near_miss_count == 0


def test_internal_only_when_every_sighting_agrees(endpoint, view_map):
    index = build(
        [
            endpoint("/admin", "GET", "python_flask", internal=True),
            endpoint("/admin", "GET", "oas3", internal=False),
        ],
        view_map,
    )
    assert next(iter(index.entries.values())).internal is False


def test_a_mount_point_is_recognised_as_one(endpoint, view_map):
    """One Go route registering `/api` is not an endpoint the spec forgot."""
    endpoints = [endpoint("/api", "POST", "go_http")]
    endpoints += [
        endpoint(f"/api/v1/resource{i}", "GET", "oas2") for i in range(6)
    ]

    index = build(endpoints, view_map)
    mount = index.entries[next(k for k in index.entries if k.path == "/api")]

    assert mount.near_misses
    assert "mount" in mount.near_misses[-1].reason
    assert "6 paths" in mount.near_misses[-1].reason


def test_a_real_endpoint_with_children_is_not_called_a_mount(endpoint, view_map):
    """`/users` can legitimately exist alongside `/users/{id}`."""
    index = build(
        [
            endpoint("/users", "GET", "python_flask"),
            endpoint("/users", "GET", "oas3"),
            endpoint("/users/{id}", "GET", "oas3"),
            endpoint("/users/{id}/avatar", "GET", "oas3"),
        ],
        view_map,
    )
    users = index.entries[next(k for k in index.entries if k.path == "/users")]
    assert not any("mount" in nm.reason for nm in users.near_misses)


def test_root_is_never_read_as_a_mount(endpoint, view_map):
    """Everything lives under `/`. True, and useless as evidence."""
    endpoints = [endpoint("/", "GET", "python_flask")]
    endpoints += [endpoint(f"/thing{i}", "GET", "oas3") for i in range(6)]

    index = build(endpoints, view_map)
    root = index.entries[next(k for k in index.entries if k.path == "/")]
    assert not any("mount" in nm.reason for nm in root.near_misses)


def test_coverage_is_not_reported_when_there_is_no_web_surface(endpoint, view_map):
    """"0 of 0" answers nothing and reads as a broken gauge."""
    from alibi.collect import RawEndpoint

    index = build(
        [
            endpoint("/api", "ANY", "nginx"),
            RawEndpoint(url="cli://tool/run", method="CLI", technology="go_cli",
                        source="t", protocol="cli"),
        ],
        view_map,
    )
    assert index.coverage_stats() == {}


def test_a_rest_collection_is_not_a_mount(endpoint, view_map):
    """`/things` has `/things/{id}` beneath it. That is what a collection is.

    Counting endpoints rather than paths made every NetBox collection look like
    a mount, because its item endpoint answers on four verbs. 377 endpoints
    were mislabelled and the findings on them demoted for it.
    """
    endpoints = [endpoint("/api/things", "DELETE", "oas3")]
    endpoints += [
        endpoint("/api/things/{id}", method, "python_flask")
        for method in ("GET", "PUT", "PATCH", "DELETE")
    ]

    index = build(endpoints, view_map)
    collection = index.entries[
        next(k for k in index.entries if k.path == "/api/things" and k.method == "DELETE")
    ]
    assert not any("mount" in nm.reason for nm in collection.near_misses)


def test_many_different_paths_beneath_one_still_reads_as_a_mount(endpoint, view_map):
    """Argo CD's `/api` has 106 distinct paths under it. That is a mount."""
    endpoints = [endpoint("/api", "POST", "go_http")]
    endpoints += [
        endpoint(f"/api/v1/resource{i}", "GET", "oas2") for i in range(6)
    ]

    index = build(endpoints, view_map)
    mount = index.entries[next(k for k in index.entries if k.path == "/api")]

    assert any("mount" in nm.reason for nm in mount.near_misses)
    assert "6 paths" in next(nm.reason for nm in mount.near_misses if "mount" in nm.reason)


def test_each_named_path_reports_what_it_contributed(endpoint, view_map):
    """Passing two paths and being told "no doc source" is not enough.

    The reader cannot tell which of the two came back empty -- whether they
    named the wrong directory, or noir does not read the format their contract
    is written in.
    """
    endpoints = [
        endpoint("/a", "GET", "python_flask", source="service"),
        endpoint("/b", "GET", "python_flask", source="service"),
        endpoint("/a", "GET", "oas3", source="contracts"),
    ]

    index = build(endpoints, view_map)
    rows = index.by_source(["service", "contracts", "captures"])

    assert rows == [
        ("service", 2, ["code"]),
        ("contracts", 1, ["doc"]),
        ("captures", 0, []),
    ]


def test_a_source_count_never_exceeds_the_total(endpoint, view_map):
    """Sightings would; distinct endpoints do not, and a row above the total
    only looks broken."""
    endpoints = [
        endpoint("/same", "GET", "python_flask", source="service"),
        endpoint("/same", "GET", "go_http", source="service"),
    ]

    index = build(endpoints, view_map)
    (_, count, _), = index.by_source(["service"])

    assert count == len(index.entries) == 1


def test_a_collection_with_actions_is_still_not_a_mount(endpoint, view_map):
    """Everything beneath it is reached through a parameter.

    NetBox's `/api/ipam/prefixes` sits above `/api/ipam/prefixes/{}` and two
    actions on it -- three distinct paths, and every one of them a sub-resource
    of the collection rather than a separate thing the path leads to. A mount
    leads somewhere named: Argo CD's `/api` to `v1`, NetBox's to `dcim` and
    thirteen more.
    """
    endpoints = [endpoint("/api/prefixes", "DELETE", "oas3")]
    endpoints += [
        endpoint(path, "GET", "python_flask") for path in (
            "/api/prefixes/{id}",
            "/api/prefixes/{id}/available-ips",
            "/api/prefixes/{id}/available-prefixes",
        )
    ]

    index = build(endpoints, view_map)
    collection = index.entries[
        next(k for k in index.entries
             if k.path == "/api/prefixes" and k.method == "DELETE")
    ]
    assert not any("mount" in nm.reason for nm in collection.near_misses)


def test_a_mount_carries_no_counterpart(endpoint, view_map):
    """Nothing was nearly matched -- the path is just not an endpoint.

    Reporting it as `X ~ X` read as though an endpoint had failed to match
    itself.
    """
    endpoints = [endpoint("/api", "POST", "go_http")]
    endpoints += [endpoint(f"/api/v1/resource{i}", "GET", "oas2") for i in range(6)]

    index = build(endpoints, view_map)
    mount = index.entries[next(k for k in index.entries if k.path == "/api")]
    label = next(nm for nm in mount.near_misses if "mount" in nm.reason)

    assert label.other is None


def test_coverage_is_measured_once_however_often_it_is_asked_for(
    endpoint, view_map, monkeypatch
):
    """A severity adjustment asks per finding, and the answer is expensive.

    Every code endpoint against every routing rule: on authentik that ran 1,596
    times for 56 million path matches, and a scan that should take a second
    took 27. The index does not change after `build`, so the answer cannot
    either.
    """
    endpoints = [endpoint("/api", "ANY", "nginx")]
    endpoints += [endpoint(f"/api/thing{i}", "GET", "python_flask") for i in range(30)]

    index = build(endpoints, view_map)

    calls = []
    original = index._compute_coverage_stats
    monkeypatch.setattr(index, "_compute_coverage_stats",
                        lambda target: calls.append(target) or original(target))

    first = index.coverage_stats()
    for _ in range(50):
        index.coverage_stats()

    assert calls == ["code"]
    assert index.coverage_stats() == first


def test_two_contracts_claiming_one_path_are_reported(endpoint, view_map):
    """A monorepo holds several surfaces; this tool compares views of one.

    Scan `services/billing` and `services/search` together and their two
    `/health` endpoints become one key -- billing's implementation corroborates
    search's contract, and search's unimplemented `/health` stops being
    reported. Scanned apart it is a PHANTOM. A finding disappearing is the
    dangerous direction, so it is worth saying even though the tool cannot fix
    it.
    """
    endpoints = [
        endpoint("/health", "GET", "python_flask",
                 code_paths=({"path": "services/billing/app/main.py", "line": 4},)),
        endpoint("/health", "GET", "oas3",
                 code_paths=({"path": "services/billing/contracts/openapi.yaml"},)),
        endpoint("/health", "GET", "oas3",
                 code_paths=({"path": "services/search/contracts/openapi.yaml"},)),
    ]

    index = build(endpoints, view_map)
    conflated = index.conflated()

    assert len(conflated) == 1
    key, directories, _root = conflated[0]
    assert str(key) == "GET /health"
    assert directories == [
        "services/billing/contracts", "services/search/contracts"]


def test_one_specification_in_two_formats_is_not_two_services(endpoint, view_map):
    """Casdoor ships its specification as both `.json` and `.yml`.

    Counting files rather than directories flagged 235 of its endpoints.
    """
    endpoints = [
        endpoint("/api/thing", "GET", "python_flask"),
        endpoint("/api/thing", "GET", "oas3",
                 code_paths=({"path": "swagger/swagger.json"},
                             {"path": "swagger/swagger.yml"})),
    ]

    index = build(endpoints, view_map)
    assert index.conflated() == []


def test_an_aggregate_document_beside_its_sources_still_reports(
    endpoint, view_map
):
    """Argo CD and flipt both land here, and neither is a monorepo.

    A generated aggregate document describing the whole API, beside the
    per-package specifications it was built from, produces exactly the same
    measurement as two services sharing a path. Two attempts to separate them
    by structure failed -- neither directory nesting nor path-set containment
    holds across both -- so this is reported with both readings rather than
    filtered on a guess. The test pins that it is *not* silently dropped.
    """
    endpoints = [
        endpoint("/api/v1/account", "GET", "python_flask"),
        endpoint("/api/v1/account", "GET", "oas3",
                 code_paths=({"path": "assets/swagger.json"},)),
        endpoint("/api/v1/account", "GET", "oas3",
                 code_paths=({"path": "server/account/account.swagger.json"},)),
    ]

    index = build(endpoints, view_map)
    conflated = index.conflated()

    assert len(conflated) == 1
    assert conflated[0][1] == ["assets", "server/account"]
