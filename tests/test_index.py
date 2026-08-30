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


def test_same_path_different_verb_is_flagged_but_not_conflated(endpoint, view_map):
    index = build(
        [
            endpoint("/orders", "POST", "python_flask"),
            endpoint("/orders", "GET", "oas3"),
        ],
        view_map,
    )

    assert len(index.entries) == 2
    for entry in index.entries.values():
        assert entry.near_misses
        assert entry.near_misses[0].reason == "same path, different method"


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
    assert "6 endpoints" in mount.near_misses[-1].reason


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
