import io

from alibi.index import build
from alibi.report import text
from alibi.rules import RuleSet


def render(endpoints, view_map, errors=(), suppressed=()):
    ruleset = RuleSet.load()
    index = build(endpoints, view_map)
    views = {v for entry in index.entries.values() for v in entry.views}
    findings, skipped = ruleset.evaluate(index, views)
    stream = io.StringIO()
    text.render(index, findings, skipped, ruleset, ["fixture"], errors,
                suppressed, stream)
    return stream.getvalue()


def test_a_long_group_is_cut_short_and_says_by_how_much(endpoint, view_map):
    """A report nobody scrolls to the end of is a report nobody reads.

    Casdoor printed 308 lines. The group is ordered worst-first, so the tail is
    the least informative part of it, and the whole list is one flag away.
    """
    endpoints = [endpoint(f"/thing{i:03}", "GET", "python_flask") for i in range(40)]
    endpoints += [endpoint("/anchor", "GET", "oas3"),
                  endpoint("/anchor", "GET", "python_flask")]

    output = render(endpoints, view_map)

    assert output.count("/thing") == text.GROUP_LIMIT
    assert f"and {40 - text.GROUP_LIMIT} more" in output


def test_a_truncated_group_still_says_what_it_holds(endpoint, view_map):
    """The severity mix has to survive the cut, or the number means nothing."""
    endpoints = [endpoint(f"/read{i:03}", "GET", "python_flask") for i in range(20)]
    endpoints += [endpoint(f"/write{i:03}", "POST", "python_flask") for i in range(20)]
    endpoints += [endpoint("/anchor", "GET", "oas3"),
                  endpoint("/anchor", "GET", "python_flask")]

    output = render(endpoints, view_map)

    assert "20 high, 20 medium" in output


def test_a_reason_that_restates_the_row_is_not_printed(endpoint, view_map):
    """"changes state rather than reading it" beside a POST adds a line and
    nothing else. It stays in the machine format, where nothing is beside it."""
    endpoints = [endpoint("/write", "POST", "python_flask"),
                 endpoint("/anchor", "GET", "oas3"),
                 endpoint("/anchor", "GET", "python_flask")]

    output = render(endpoints, view_map)

    assert "/write" in output
    assert "changes state" not in output


def test_a_distinctive_reason_is_printed(endpoint, view_map):
    endpoints = [endpoint("/upload", "POST", "python_flask", tags=["file_upload"]),
                 endpoint("/anchor", "GET", "oas3"),
                 endpoint("/anchor", "GET", "python_flask")]

    assert "upload paths carry more consequence" in render(endpoints, view_map)


def test_rules_held_back_for_one_reason_are_explained_once(endpoint, view_map):
    """Printing the same five lines under each rule buries the explanation."""
    endpoints = [endpoint(f"/code/{i}", "GET", "python_flask") for i in range(8)]
    endpoints += [endpoint(f"/spec/{i}", "GET", "oas3") for i in range(8)]

    output = render(endpoints, view_map)

    assert "SHADOW, PHANTOM held back" in output
    assert output.count("the two views\n  never met") == 1


def test_a_skip_that_cost_nothing_does_not_raise_the_alarm(endpoint, view_map):
    from alibi.collect import ScanError

    endpoints = [endpoint("/thing", "GET", "python_flask"),
                 endpoint("/anchor", "GET", "oas3")]
    declined = [ScanError(tech="detect",
                          message="skipped 1 entry: link; first error: "
                                  "symbolic link (not followed)")]
    lost = [ScanError(tech="detect",
                      message="skipped 1 file: openapi.json; first error: "
                              "file too large (12.35MB > 10.0MB)")]

    quiet = render(endpoints, view_map, errors=declined)
    assert "NOIR COULD NOT READ EVERYTHING" not in quiet
    assert "noir skipped media, binaries or symlinks" in quiet

    loud = render(endpoints, view_map, errors=lost)
    assert "NOIR COULD NOT READ EVERYTHING" in loud
