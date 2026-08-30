import json
import os
import stat

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
