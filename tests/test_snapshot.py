import sqlite3

import pytest

from alibi import cli, snapshot
from alibi.index import build
from alibi.rules import RuleSet

DAY1 = "2026-01-10T09:00:00Z"
DAY2 = "2026-01-11T09:00:00Z"
DAY3 = "2026-01-12T09:00:00Z"


@pytest.fixture
def db(tmp_path):
    return tmp_path / "snapshots.db"


@pytest.fixture
def record(db, view_map):
    """Evaluate a set of endpoints and write the result as one scan."""

    def run(endpoints, when):
        index = build(endpoints, view_map)
        views = {v for entry in index.entries.values() for v in entry.views}
        findings, _ = RuleSet.load().evaluate(index, views)
        snapshot.record(db, index, findings, ["fixture"], when=when)

    return run


def identities(changes):
    return {(c.rule_id, c.method, c.path) for c in changes}


def test_only_a_finding_the_previous_scan_did_not_have_is_new(
    db, record, endpoint
):
    record(
        [
            endpoint("/kept", "GET", "python_flask"),
            endpoint("/kept", "GET", "oas3"),
            endpoint("/standing", "GET", "python_flask"),
        ],
        DAY1,
    )
    record(
        [
            endpoint("/kept", "GET", "python_flask"),
            endpoint("/kept", "GET", "oas3"),
            endpoint("/standing", "GET", "python_flask"),
            endpoint("/arrived", "GET", "python_flask"),
        ],
        DAY2,
    )

    history = snapshot.history(db)

    assert identities(history.new) == {("SHADOW", "GET", "/arrived")}
    assert history.resolved == []


def test_a_finding_gone_from_the_latest_scan_is_resolved(db, record, endpoint):
    record(
        [
            endpoint("/kept", "GET", "python_flask"),
            endpoint("/kept", "GET", "oas3"),
            endpoint("/documented-later", "GET", "python_flask"),
        ],
        DAY1,
    )
    record(
        [
            endpoint("/kept", "GET", "python_flask"),
            endpoint("/kept", "GET", "oas3"),
            endpoint("/documented-later", "GET", "python_flask"),
            endpoint("/documented-later", "GET", "oas3"),
        ],
        DAY2,
    )

    history = snapshot.history(db)

    assert history.new == []
    assert identities(history.resolved) == {("SHADOW", "GET", "/documented-later")}


def test_a_severity_that_moved_is_not_one_finding_gone_and_another_arrived(
    db, record, endpoint
):
    """Severity drifts on its own, and reporting drift as progress is worse than
    reporting nothing.

    An endpoint that picks up a `pii` tag, or a codebase where noir's auth
    taggers start firing, shifts findings up and down without anything about
    the disagreement changing. If severity were part of a finding's identity,
    every such shift would read as one problem fixed and a new one opened.
    """
    record(
        [
            endpoint("/profile", "GET", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
            endpoint("/anchor", "GET", "python_flask"),
        ],
        DAY1,
    )
    record(
        [
            endpoint("/profile", "GET", "python_flask", tags=["pii"]),
            endpoint("/anchor", "GET", "oas3"),
            endpoint("/anchor", "GET", "python_flask"),
        ],
        DAY2,
    )

    history = snapshot.history(db)

    assert history.new == []
    assert history.resolved == []


def test_the_first_scan_is_a_baseline_rather_than_a_wave_of_new_findings(
    db, record, endpoint
):
    """The same refusal the rules make when a view is missing.

    Nothing was compared, so nothing can honestly be called new. Reporting the
    whole first scan as new findings would make the one run that cannot say
    anything about change the noisiest.
    """
    record(
        [
            endpoint("/undocumented", "GET", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
        ],
        DAY1,
    )

    history = snapshot.history(db)

    assert history.scans == 1
    assert history.previous_at is None
    assert history.new == []
    assert history.resolved == []


def test_an_endpoint_records_when_each_view_first_vouched_for_it(
    db, record, endpoint
):
    """The per-view grain, which is most of the reason for keeping history.

    An endpoint that has been in the code for a year and reached the
    specification last week is a different story from one that arrived in both
    at once, and only a per-view record tells them apart.
    """
    record([endpoint("/users", "GET", "python_flask")], DAY1)
    record(
        [
            endpoint("/users", "GET", "python_flask"),
            endpoint("/users", "GET", "oas3"),
        ],
        DAY2,
    )

    timeline = snapshot.timeline(db, "GET", "/users")

    assert timeline.first_seen == {"code": DAY1, "doc": DAY2}
    assert timeline.last_seen == DAY2


def test_an_endpoint_that_disappeared_keeps_the_date_it_was_last_seen(
    db, record, endpoint
):
    record([endpoint("/retired", "GET", "python_flask")], DAY1)
    record([endpoint("/still-here", "GET", "python_flask")], DAY2)

    assert snapshot.timeline(db, "GET", "/retired").last_seen == DAY1
    assert snapshot.timeline(db, "GET", "/still-here").last_seen == DAY2


def test_a_new_finding_says_how_long_its_endpoint_has_existed(
    db, record, endpoint
):
    """A new shadow API on an old route means a view stopped covering it.

    That is a deleted specification or a scan that no longer reads one, and it
    needs a different person to look at it than a route somebody shipped
    undocumented this morning. Only the endpoint's own history separates them.
    """
    record(
        [
            endpoint("/reports", "GET", "python_flask"),
            endpoint("/reports", "GET", "oas3"),
            endpoint("/anchor", "GET", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
        ],
        DAY1,
    )
    record(
        [
            endpoint("/reports", "GET", "python_flask"),
            endpoint("/anchor", "GET", "python_flask"),
            endpoint("/anchor", "GET", "oas3"),
        ],
        DAY2,
    )

    change = next(c for c in snapshot.history(db).new if c.path == "/reports")

    assert change.first_reported == DAY2
    assert change.timeline.first_seen == {"code": DAY1, "doc": DAY1}


def test_a_resolved_finding_says_how_long_it_stood(db, record, endpoint):
    standing = [
        endpoint("/anchor", "GET", "python_flask"),
        endpoint("/anchor", "GET", "oas3"),
    ]
    record(standing + [endpoint("/shadow", "GET", "python_flask")], DAY1)
    record(standing + [endpoint("/shadow", "GET", "python_flask")], DAY2)
    record(standing, DAY3)

    change = next(iter(snapshot.history(db).resolved))

    assert change.path == "/shadow"
    assert change.first_reported == DAY1
    assert change.timeline.last_seen == DAY2


def test_only_the_two_most_recent_scans_are_compared(db, record, endpoint):
    standing = [
        endpoint("/anchor", "GET", "python_flask"),
        endpoint("/anchor", "GET", "oas3"),
    ]
    record(standing + [endpoint("/old", "GET", "python_flask")], DAY1)
    record(standing, DAY2)
    record(standing + [endpoint("/fresh", "GET", "python_flask")], DAY3)

    history = snapshot.history(db)

    assert history.scans == 3
    assert identities(history.new) == {("SHADOW", "GET", "/fresh")}
    assert history.resolved == []


def test_scans_are_ordered_by_when_they_were_recorded_not_by_the_clock(
    db, record, endpoint
):
    """A clock that steps back must not reorder history.

    Daylight saving, a corrected NTP offset or a scan run on a laptop with the
    wrong date would otherwise silently swap which scan counts as previous, and
    report every resolved finding as new.
    """
    record([endpoint("/first", "GET", "python_flask")], "2026-03-01T00:00:00Z")
    record([endpoint("/second", "GET", "python_flask")], "2026-01-01T00:00:00Z")

    history = snapshot.history(db)

    assert history.current_at == "2026-01-01T00:00:00Z"
    assert history.previous_at == "2026-03-01T00:00:00Z"


def test_a_database_from_another_schema_version_is_refused_not_reinterpreted(
    db, record, endpoint
):
    """A snapshot is a record of scans that already happened.

    Reading version 2 rows as version 1 would not fail loudly; it would answer
    "when did this first appear" with a wrong date, which is worse than
    answering nothing.
    """
    record([endpoint("/a", "GET", "python_flask")], DAY1)

    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")

    with pytest.raises(snapshot.SnapshotError, match="schema version 99"):
        snapshot.history(db)


def test_asking_for_a_history_that_was_never_recorded_says_so(db):
    with pytest.raises(snapshot.SnapshotError, match="no snapshot database"):
        snapshot.history(db)


def test_a_file_that_is_not_a_snapshot_is_named_rather_than_crashed_on(tmp_path):
    """`alibi history` pointed at a JSON report is a typo, not a stack trace."""
    stray = tmp_path / "report.json"
    stray.write_text('{"findings": []}', encoding="utf-8")

    with pytest.raises(snapshot.SnapshotError, match="not a readable alibi snapshot"):
        snapshot.history(stray)


def test_the_history_command_reports_what_changed(db, record, endpoint, capsys):
    """The CLI wiring, from a recorded database to something a reader sees."""
    standing = [
        endpoint("/anchor", "GET", "python_flask"),
        endpoint("/anchor", "GET", "oas3"),
    ]
    record(standing + [endpoint("/was-here", "DELETE", "python_flask")], DAY1)
    record(standing + [endpoint("/is-here", "DELETE", "python_flask")], DAY2)

    assert cli.main(["history", str(db)]) == cli.EXIT_OK

    out = capsys.readouterr().out
    assert "NEW" in out
    assert "DELETE  /is-here" in out
    assert "RESOLVED" in out
    assert "DELETE  /was-here" in out
    assert f"reported since {DAY1}" in out
