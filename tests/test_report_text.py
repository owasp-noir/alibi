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
    endpoints = [endpoint(f"/code/{i}", "GET", "python_flask") for i in range(15)]
    endpoints += [endpoint(f"/spec/{i}", "GET", "oas3") for i in range(15)]

    output = render(endpoints, view_map)

    assert "SHADOW, PHANTOM held back" in output
    # One word from the explanation, chosen so line wrapping cannot split it.
    assert output.count("never") == 1


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


def test_a_long_path_does_not_push_the_reason_out_of_the_report(endpoint, view_map):
    """The reason is the diagnostic; the path list is the expendable half.

    Real paths are absolute and long. Trimming the message from the front spent
    the whole budget on one path and dropped `file too large`, leaving a
    warning that named a file and said nothing about it.
    """
    from alibi.collect import ScanError

    endpoints = [endpoint("/thing", "GET", "python_flask"),
                 endpoint("/anchor", "GET", "oas3")]
    deep = "/" + "/".join(f"very-long-directory-name-{i}" for i in range(12))
    lost = [ScanError(tech="detect",
                      message=f"skipped 1 file: {deep}/openapi.json; first error: "
                              f"file too large (12.35MB > 10.0MB)")]

    report = render(endpoints, view_map, errors=lost)
    assert "file too large (12.35MB > 10.0MB)" in report
    # One path is not a list, so there is nothing to shorten and no half-path.
    assert "full list in -f json" not in report

    many = [ScanError(tech="detect",
                      message=("skipped 9 files: "
                               + ", ".join(f"{deep}/spec-{i}.json" for i in range(9))
                               + "; first error: file too large (12.35MB > 10.0MB)"))]
    trimmed = render(endpoints, view_map, errors=many)
    assert "file too large (12.35MB > 10.0MB)" in trimmed
    assert "full list in -f json" in trimmed
    # Whatever survives of the list is whole paths, never half of one.
    assert "spec-8.json" not in trimmed


def test_locations_are_relative_to_the_source_the_user_named(endpoint, view_map):
    """`routers/router.go` is what the repository calls the file.

    Shortening to the last three path components instead produced a tail with
    a machine-specific segment on the front, and disagreed with the path SARIF
    emits for the same finding.
    """
    root = "/home/someone/checkouts/casdoor"
    endpoints = [
        endpoint("/api/only-in-code", "GET", "go_beego", source_root=root,
                 code_paths=({"path": f"{root}/routers/router.go", "line": 87},)),
        endpoint("/api/anchor", "GET", "go_beego", source_root=root,
                 code_paths=({"path": f"{root}/routers/router.go", "line": 4},)),
        endpoint("/api/anchor", "GET", "oas3", source_root=root,
                 code_paths=({"path": f"{root}/swagger/swagger.json"},)),
    ]

    report = render(endpoints, view_map)
    assert "routers/router.go:87" in report
    assert "casdoor/routers/router.go" not in report


def test_nested_contract_directories_print_as_one_tree(endpoint, view_map):
    """The block asks whether two contracts are separate services.

    Shortened apart, `<root>/rpc/flipt` and `<root>/rpc/flipt/auth` printed as
    `flipt/rpc/flipt` and `rpc/flipt/auth` -- two unrelated directories, which
    is the alarming reading and here the wrong one.
    """
    root = "/home/someone/checkouts/flipt"
    endpoints = [
        endpoint("/auth/v1/self", "GET", "oas3", source_root=root,
                 code_paths=({"path": f"{root}/rpc/flipt/flipt.swagger.json"},)),
        endpoint("/auth/v1/self", "GET", "oas3", source_root=root,
                 code_paths=({"path": f"{root}/rpc/flipt/auth/auth.swagger.json"},)),
    ]

    report = render(endpoints, view_map)
    assert "      rpc/flipt\n" in report
    assert "      rpc/flipt/auth\n" in report


def test_an_empty_scan_says_so_rather_than_describing_the_machinery(view_map):
    """The likeliest first run of all: the wrong directory.

    "No rule had the views it needs" is true and describes the rule engine, not
    the situation, and leaves the reader hunting for a flag they are missing.
    """
    output = render([], view_map)

    assert "Noir found no endpoints here." in output
    assert "corroborated" not in output
    assert "did not run" not in output


def test_scan_accepts_no_paths_at_all(capsys):
    """`alibi scan` in a repository root is what people type.

    Refusing it with a usage block to ask for the dot is the kind of friction
    that gets a tool closed. Reaching the noir lookup proves argument parsing
    accepted the call.
    """
    from alibi.cli import EXIT_ERROR, main

    assert main(["scan", "--noir-bin", "/nonexistent/noir"]) == EXIT_ERROR
    assert "no noir binary" in capsys.readouterr().err


def test_arguments_after_a_bare_dash_dash_go_to_noir():
    """`--noir-arg` exists to hand noir a flag, and argparse refused one.

    A value starting with a dash came back as a usage block -- so the one
    thing the option is for did not work. The joined form always did; this is
    the form people reach for first.
    """
    from alibi.cli import split_passthrough

    head, tail = split_passthrough(
        ["scan", ".", "-f", "json", "--", "--exclude-path", "**/tests/**"])

    assert head == ["scan", ".", "-f", "json"]
    assert tail == ["--exclude-path", "**/tests/**"]


def test_without_a_separator_nothing_is_passed_through():
    from alibi.cli import split_passthrough

    assert split_passthrough(["scan", "."]) == (["scan", "."], [])
