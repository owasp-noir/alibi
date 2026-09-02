import json
import stat
from pathlib import Path

import pytest

from alibi import collect


def fake_noir(tmp_path, document):
    """A stand-in for the noir binary that prints one prepared document."""
    script = tmp_path / "fake-noir"
    script.write_text(
        "#!/bin/sh\n"
        "echo 'a log line that must not reach stdout parsing' >&2\n"
        f"cat <<'JSON'\n{json.dumps(document)}\nJSON\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def test_what_noir_could_not_read_is_carried_out_of_the_scan(tmp_path):
    """The difference between an empty view and an unreadable one.

    NetBox ships a 12.35MB OpenAPI document holding 308 paths. Noir skips it
    for exceeding the file-size cap and reports the skip. Drop that report and
    alibi states there is no documentation in the project -- confidently, and
    wrongly.
    """
    binary = fake_noir(tmp_path, {
        "endpoints": [],
        "errors": [{"tech": "detect", "message": "skipped 1 file: openapi.json; "
                                                 "first error: file too large"}],
    })

    result = collect.scan(collect.Source(str(tmp_path)), binary)

    assert result.endpoints == []
    assert len(result.errors) == 1
    assert "too large" in result.errors[0].message


def test_the_same_unreadable_file_is_reported_once(tmp_path):
    """Every view's scan walks past it, so the same skip arrives five times."""
    binary = fake_noir(tmp_path, {
        "endpoints": [],
        "errors": [{"tech": "detect", "message": "skipped 1 file: big.json"}],
    })

    result = collect.scan_views(
        collect.Source(str(tmp_path)), binary,
        {"code": ["python_flask"], "doc": ["oas3"], "traffic": ["har"]},
    )

    assert len(result.errors) == 1


def test_noir_logs_on_stderr_do_not_break_json_parsing(tmp_path):
    binary = fake_noir(tmp_path, {"endpoints": [
        {"url": "/x", "method": "GET", "details": {"technology": "python_flask"}}
    ]})

    result = collect.scan(collect.Source(str(tmp_path)), binary)
    assert [e.url for e in result.endpoints] == ["/x"]


def test_a_binary_that_prints_nothing_is_an_error_not_an_empty_scan(tmp_path):
    """Silence must never be read as "this project has no endpoints"."""
    script = tmp_path / "silent-noir"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    with pytest.raises(collect.NoirFailed):
        collect.scan(collect.Source(str(tmp_path)), str(script))


def test_a_single_file_is_a_source(tmp_path):
    """One HAR or one OpenAPI document holds a whole view.

    Noir scans directories, so a file has to be staged into one. It cannot be
    scanned in place by pointing noir at its parent: a `captures/` directory
    holds every other capture, and a file at a repo root would drag in the
    repository.
    """
    other = tmp_path / "unrelated.har"
    other.write_text("{}")
    target = tmp_path / "prod.har"
    target.write_text("{}")

    with collect.scannable(collect.Source(str(target))) as ready:
        staged = Path(ready.path)
        assert staged.is_dir()
        assert [p.name for p in staged.iterdir()] == ["prod.har"]
        assert ready.name == "prod.har"

    # The staging directory does not outlive the scan.
    assert not staged.exists()


def test_a_directory_is_passed_through_untouched(tmp_path):
    source = collect.Source(str(tmp_path))
    with collect.scannable(source) as ready:
        assert ready is source


def test_a_missing_path_is_left_for_noir_to_report(tmp_path):
    """Noir's own message names the problem better than a guess would."""
    missing = collect.Source(str(tmp_path / "gone"))
    with collect.scannable(missing) as ready:
        assert ready is missing


def test_a_skip_that_cost_nothing_is_not_a_missing_view(tmp_path):
    """Noir declines files on purpose, and says which kind of skip it made.

    A symlink it did not follow, or an image, cost the scan nothing -- its
    target was already walked. Raising the same alarm for those as for a
    specification too large to read teaches the reader to skip the section
    that matters.
    """
    lost = collect.ScanError(tech="detect",
                             message="skipped 1 file: openapi.json; "
                                     "first error: file too large (12.35MB > 10.0MB)")
    declined = collect.ScanError(tech="detect",
                                 message="skipped 2 entries: CLAUDE.md; "
                                         "first error: symbolic link (not followed)")
    media = collect.ScanError(tech="detect",
                              message="skipped 1 file: logo.png; "
                                      "first error: media file (.png)")
    gone = collect.ScanError(tech="detect",
                             message="skipped 1 file: x.py; "
                                     "first error: permissions, or removed during the scan")

    assert lost.consequential is True
    assert gone.consequential is True
    assert declined.consequential is False
    assert media.consequential is False


def test_a_loss_alibi_has_not_been_taught_about_still_reads_as_a_loss():
    """Noir keeps adding kinds of loss; a watch-list cannot keep up with them.

    noir 1.3.0 began reporting a specification document it could not parse and
    an entry it could not stat -- between them a whole doc view and a whole
    subtree. Neither carries any of the phrases the old watch-list matched, so
    both were filed under "noir skipped media, binaries or symlinks": the
    quietest possible rendering of the loudest possible loss.
    """
    unparsable = collect.ScanError(
        tech="oas3",
        message="skipped 1 unparsable document: api/openapi.json; "
                "first error: unexpected token '<EOF>' at line 2, column 1")
    unstattable = collect.ScanError(
        tech="detect",
        message="skipped 3 unreadable entries: gen/a/b/c; first error: "
                "Error getting file info for 'gen/a/b/c': File name too long")
    undelivered = collect.ScanError(
        tech="deliver",
        message="webhook delivery to http://x failed: connection refused")

    assert unparsable.consequential is True
    assert unstattable.consequential is True
    assert undelivered.consequential is True


def versioned_noir(tmp_path, output, name="versioned-noir"):
    """A stand-in that answers `--version` with a prepared line."""
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def test_a_noir_below_the_floor_is_refused_before_the_scan(tmp_path):
    """`noir list techs` arrived in 1.0.0, and the catalog is the first thing
    alibi asks for. Without this check the failure surfaces as "could not read
    `noir list techs -f json`", which names the symptom and not the cause."""
    old = versioned_noir(tmp_path, "0.30.0")
    with pytest.raises(collect.NoirTooOld) as exc:
        collect.require_version(old)
    assert "0.30.0" in str(exc.value)
    assert "1.0.0" in str(exc.value)


def test_a_noir_at_or_above_the_floor_passes(tmp_path):
    assert collect.require_version(versioned_noir(tmp_path, "1.0.0")) == (1, 0, 0)
    assert collect.require_version(versioned_noir(tmp_path, "1.3.0")) == (1, 3, 0)


def test_a_binary_that_will_not_report_a_version_is_not_refused(tmp_path):
    """An unreadable version is not evidence of an old one. A wrapper script or
    a build from source can both be current, and refusing on an absence would
    block installations that work."""
    quiet = versioned_noir(tmp_path, "")
    assert collect.require_version(quiet) is None


def test_a_version_check_that_cannot_run_is_not_refused(tmp_path):
    assert collect.noir_version(str(tmp_path / "does-not-exist")) is None


def test_two_sources_with_one_basename_are_still_two_sources():
    """`services/billing` and `services/search` are both `service`.

    The per-source table exists to tell the reader which path came back
    empty. Sharing a name, the two collapsed into one bucket and printed as
    two identical rows each claiming the other's endpoints -- which answers
    the opposite of the question.
    """
    from alibi.collect import sources

    built = sources(["services/billing/service", "services/search/service"])
    assert [s.name for s in built] == ["services/billing/service",
                                       "services/search/service"]
    # The root is still what the user typed, whichever name was chosen.
    assert [s.root for s in built] == ["services/billing/service",
                                       "services/search/service"]

    # A basename of its own is still the name -- it is what fits in a column.
    plain = sources(["./app", "./contracts"])
    assert [s.name for s in plain] == ["app", "contracts"]
