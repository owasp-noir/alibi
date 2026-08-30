from alibi.cover import Rule, matches
from alibi.normalize import Key


def test_a_prefix_reaches_everything_beneath_it():
    """`location /api/` is one rule standing for a whole subtree."""
    rule = Rule(Key("ANY", "/api"), "gateway", prefix=True)
    assert rule.reaches(Key("GET", "/api/v1/users"))
    assert rule.reaches(Key("POST", "/api/v1/users/{}/avatar"))
    assert rule.reaches(Key("GET", "/api"))
    assert not rule.reaches(Key("GET", "/internal/metrics"))


def test_a_rule_bound_to_one_verb_does_not_reach_the_others():
    rule = Rule(Key("GET", "/api"), "gateway", prefix=True)
    assert rule.reaches(Key("GET", "/api/v1/x"))
    assert not rule.reaches(Key("POST", "/api/v1/x"))


def test_any_reaches_every_verb():
    rule = Rule(Key("ANY", "/api"), "gateway", prefix=True)
    for method in ("GET", "POST", "DELETE", "QUERY"):
        assert rule.reaches(Key(method, "/api/x"))


def test_root_is_not_treated_as_coverage():
    """`location /` reaches everything, which is true and proves nothing.

    Counting it would mark every endpoint in every repository as exposed and
    silently disable the rule that depends on coverage.
    """
    rule = Rule(Key("ANY", "/"), "gateway", prefix=True)
    assert not rule.reaches(Key("GET", "/anything"))


def test_placeholders_match_concrete_segments_and_each_other():
    assert matches("/users/{}", "/users/123")
    assert matches("/users/{}", "/users/{}")
    assert not matches("/users/{}", "/users/1/2")


def test_a_spanning_wildcard_swallows_any_number_of_segments():
    assert matches("/files/*", "/files/a/b/c")
    assert matches("/files/*", "/files")
    assert not matches("/files/*", "/other/a")


def test_a_partly_literal_segment_still_matches():
    """Route templates put more than one slot in a segment: `/{z}-{x}-{y}`."""
    assert matches("/tiles/{}-{}", "/tiles/12-34")
    assert not matches("/tiles/{}-{}", "/tiles/1234")
