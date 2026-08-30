from alibi.ignore import IgnoreEntry, IgnoreList
from alibi.index import build
from alibi.rules import RuleSet


def findings_for(endpoints, view_map):
    index = build(endpoints, view_map)
    views = {v for e in index.entries.values() for v in e.views}
    return RuleSet.load().evaluate(index, views)[0]


def test_a_path_pattern_silences_only_what_it_names(endpoint, view_map):
    findings = findings_for(
        [
            endpoint("/internal/admin", "GET", "python_flask"),
            endpoint("/internal/metrics", "GET", "python_flask"),
            endpoint("/public/thing", "GET", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
            endpoint("/anchor", "GET", "python_flask"),
        ],
        view_map,
    )

    ignores = IgnoreList.from_patterns([r"^/internal/"])
    kept, dropped = ignores.apply(findings)

    assert {f.key.path for f in kept} == {"/public/thing"}
    assert len(dropped) == 2


def test_suppression_can_be_scoped_to_one_rule(endpoint, view_map):
    """Silence "no gateway reaches this" without silencing "undocumented"."""
    endpoints = [endpoint("/api", "ANY", "nginx")]
    endpoints += [endpoint(f"/api/thing{i}", "GET", "python_flask") for i in range(4)]
    endpoints.append(endpoint("/debug/pprof", "GET", "python_flask"))
    endpoints += [endpoint(f"/spec{i}", "GET", "oas3") for i in range(4)]
    endpoints += [endpoint(f"/spec{i}", "GET", "python_flask") for i in range(4)]

    findings = findings_for(endpoints, view_map)
    ignores = IgnoreList(entries=[IgnoreEntry(rule="UNEXPOSED", why="not fronted here")])
    kept, dropped = ignores.apply(findings)

    assert not [f for f in kept if f.rule_id == "UNEXPOSED"]
    assert [f for f in kept if f.rule_id == "SHADOW"]
    assert all(f.rule_id == "UNEXPOSED" for f, _ in dropped)


def test_an_empty_entry_silences_nothing(endpoint, view_map):
    """A rule with no condition would silence the whole report.

    That is never what someone meant to write, and a config file typo must not
    turn the tool off without saying so.
    """
    findings = findings_for(
        [
            endpoint("/thing", "GET", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
        ],
        view_map,
    )
    kept, dropped = IgnoreList(entries=[IgnoreEntry(why="oops")]).apply(findings)

    assert len(kept) == len(findings)
    assert dropped == []


def test_a_project_carries_its_own_suppressions(tmp_path, endpoint, view_map):
    (tmp_path / ".alibi.yml").write_text(
        "ignore:\n"
        "  - path: '^/internal/'\n"
        "    why: internal-only admin surface\n"
    )

    ignores = IgnoreList.discover([str(tmp_path)])
    assert len(ignores) == 1
    assert ignores.entries[0].why == "internal-only admin surface"


def test_discovery_finds_nothing_without_complaint(tmp_path):
    assert len(IgnoreList.discover([str(tmp_path)])) == 0
