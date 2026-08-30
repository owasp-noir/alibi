"""Keep every scan, so the next one can say what changed.

A single scan answers "where do the views disagree today". The question that
follows it is always "and did I do that" -- whether a shadow API is new, how
long a phantom contract has stood, whether the endpoint behind a finding is
newly written or merely newly undocumented. None of that can be recovered from
one report, so each scan is written down.

**Why SQLite rather than a JSON file.** The questions above are all of the form
"the earliest scan in which X" and "the latest scan in which X". Against a
directory of JSON reports every one of them is a full read of the history;
against three small tables they are indexed lookups, and the file stays a
single artifact a developer can delete.

**One row per scan, endpoint *and view*.** Storing an endpoint's views as a
list on the endpoint row would be smaller and would make "when did this first
appear in each view" a scan-and-parse rather than a query -- and that question
is most of the reason for keeping history at all. An endpoint that was in the
code for a year and reached the specification last week is a different story
from one that arrived in both at once, and only the per-view grain tells them
apart.

**A finding is identified by rule, method and path -- not by its severity.**
Severity moves on its own: an endpoint that gains a `pii` tag, or a codebase
where noir's auth taggers start firing, shifts findings up and down without
anything about the disagreement changing. Treating a shifted severity as one
finding resolved and another raised would report churn as progress.

**Scan order comes from the row id, never from the timestamp.** Two scans a
second apart, or a machine whose clock steps back, must still order the way
they were recorded. The timestamp is for reading; the id is for sorting.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path

from .index import Index
from .rules import Finding

# Alongside the caches other tools drop in the directory they were run from --
# `.pytest_cache`, `.ruff_cache`. A scan history belongs to one project rather
# than to the user, so it does not go in a home directory, and `.alibi/` is
# already ignored by this repository's .gitignore.
DEFAULT_PATH = Path(".alibi/snapshots.db")

# Bumped whenever the tables below change shape. A database is opened only at
# exactly this version: nothing is guessed at, in either direction. When the
# first change lands, this equality check becomes a walk from the stored
# version up to this one through an ordered list of upgrade steps, applied in
# a single transaction -- there are no steps yet, so there is no list yet.
SCHEMA_VERSION = 2

# The version marker is created and read before anything else is touched, so a
# database this alibi cannot read is not written to on the way to refusing it.
_META_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan (
    id      INTEGER PRIMARY KEY,
    at      TEXT NOT NULL,
    sources TEXT NOT NULL,
    -- Whether this scan recorded which rules evaluated. An empty ran_rule set
    -- is a real answer -- a scan where nothing had the views it needed -- and
    -- has to be told apart from a scan that never recorded the question.
    rules_recorded INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sighting (
    scan_id INTEGER NOT NULL REFERENCES scan(id),
    method  TEXT NOT NULL,
    path    TEXT NOT NULL,
    view    TEXT NOT NULL,
    PRIMARY KEY (scan_id, method, path, view)
);

-- Which rules actually ran. Without this, a scan that forgot to include the
-- contracts directory has no findings from SHADOW, and the next comparison
-- reads that as every shadow API having been fixed. The rules already refuse
-- to report a comparison that did not happen; history has to refuse it too.
CREATE TABLE IF NOT EXISTS ran_rule (
    scan_id INTEGER NOT NULL REFERENCES scan(id),
    rule_id TEXT NOT NULL,
    PRIMARY KEY (scan_id, rule_id)
);

CREATE TABLE IF NOT EXISTS finding (
    scan_id  INTEGER NOT NULL REFERENCES scan(id),
    rule_id  TEXT NOT NULL,
    method   TEXT NOT NULL,
    path     TEXT NOT NULL,
    severity TEXT NOT NULL,
    PRIMARY KEY (scan_id, rule_id, method, path)
);

CREATE INDEX IF NOT EXISTS sighting_endpoint ON sighting (method, path);
CREATE INDEX IF NOT EXISTS finding_identity  ON finding (rule_id, method, path);
"""


class SnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class Timeline:
    """When one endpoint was first and last seen."""

    first_seen: dict[str, str]
    last_seen: str | None


@dataclass(frozen=True)
class Change:
    """A finding that appeared or disappeared, and what the history knows."""

    rule_id: str
    method: str
    path: str
    severity: str
    first_reported: str
    timeline: Timeline


@dataclass(frozen=True)
class History:
    """Two scans compared. `previous_at` is None for the first one recorded."""

    path: Path
    scans: int
    current_at: str
    previous_at: str | None
    new: list[Change]
    resolved: list[Change]
    # Rules that ran in the earlier scan and not in this one. Their findings
    # are neither new nor resolved -- they were not looked for.
    not_compared: list[str] = dataclass_field(default_factory=list)
    # Scan ordinals. Two scans a second apart carry the same timestamp, and a
    # header reading "07:00:55Z compared against 07:00:55Z" cannot say which is
    # which -- which is every run in CI, and every run while iterating.
    current_scan: int = 0
    previous_scan: int | None = None


def record(db_path: Path | str, index: Index, findings: list[Finding],
           sources: list[str], ran: list[str] | None = None,
           when: str | None = None) -> int:
    """Write one scan and return its id.

    `ran` names the rules that actually evaluated. It is what keeps a
    misconfigured scan from reading as progress: point alibi at the code and
    forget the contracts, and SHADOW produces nothing -- indistinguishable, to
    a later comparison, from every shadow API having been closed.

    `when` exists so a test can place two scans on separate days without
    waiting for a clock to move.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with _open(path) as conn:
        cursor = conn.execute(
            "INSERT INTO scan (at, sources, rules_recorded) VALUES (?, ?, ?)",
            (when or _now(), json.dumps(list(sources)), int(ran is not None)),
        )
        scan_id = int(cursor.lastrowid)

        conn.executemany(
            "INSERT INTO sighting (scan_id, method, path, view) VALUES (?, ?, ?, ?)",
            [
                (scan_id, entry.key.method, entry.key.path, view)
                for entry in index.entries.values()
                for view in sorted(entry.views)
            ],
        )
        conn.executemany(
            "INSERT INTO ran_rule (scan_id, rule_id) VALUES (?, ?)",
            [(scan_id, rule_id) for rule_id in sorted(set(ran or []))],
        )
        conn.executemany(
            "INSERT INTO finding (scan_id, rule_id, method, path, severity) "
            "VALUES (?, ?, ?, ?, ?)",
            [
                (scan_id, f.rule_id, f.key.method, f.key.path, f.severity)
                for f in findings
            ],
        )

    return scan_id


def history(db_path: Path | str) -> History:
    """Compare the two most recently recorded scans."""
    path = _existing(db_path)
    with _open(path) as conn:
        scans = conn.execute(
            "SELECT id, at FROM scan ORDER BY id DESC LIMIT 2"
        ).fetchall()
        if not scans:
            raise SnapshotError(f"{path} holds no scans yet.")

        total = int(conn.execute("SELECT count(*) FROM scan").fetchone()[0])
        current_id, current_at = scans[0]

        # One scan is a baseline, not a comparison. Reporting all of its
        # findings as "new" would be the same overclaim the rules refuse to
        # make when a view is missing: nothing was compared, so nothing is new.
        if len(scans) == 1:
            return History(path=path, scans=total, current_at=current_at,
                           previous_at=None, new=[], resolved=[],
                           current_scan=total)

        previous_id, previous_at = scans[1]

        # A rule that ran before and not now compared nothing this time, so
        # its findings did not disappear -- nobody looked. Reporting them as
        # resolved would turn a forgotten `--` argument into a progress report.
        now_ran = _ran(conn, current_id)
        then_ran = _ran(conn, previous_id)
        known = now_ran is not None and then_ran is not None
        comparable = (now_ran & then_ran) if known else None
        stopped = sorted(then_ran - now_ran) if known else []

        return History(
            path=path,
            scans=total,
            current_at=current_at,
            previous_at=previous_at,
            current_scan=total,
            previous_scan=total - 1,
            new=_difference(conn, current_id, previous_id, comparable),
            resolved=_difference(conn, previous_id, current_id, comparable),
            not_compared=stopped,
        )


def _ran(conn, scan_id: int) -> set[str] | None:
    """Which rules evaluated in that scan, or None when it was not recorded.

    Guessing is worse than not knowing. The rules that produced findings look
    like a reasonable substitute and are not one -- a rule that ran and found
    nothing is indistinguishable from a rule that never ran, which is the exact
    confusion this table exists to end. So an unrecorded scan disables the
    check rather than driving it from an inference.

    The flag on the scan row carries that distinction, because an empty set of
    rules is itself a real answer: a scan where nothing had the views it needed
    ran no rules at all, and must not read as one that forgot to say.
    """
    recorded = conn.execute(
        "SELECT rules_recorded FROM scan WHERE id = ?", (scan_id,)
    ).fetchone()
    if not recorded or not recorded[0]:
        return None

    rows = conn.execute(
        "SELECT rule_id FROM ran_rule WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    return {row[0] for row in rows}


def timeline(db_path: Path | str, method: str, path: str) -> Timeline:
    """When an endpoint first appeared in each view, and when it was last seen."""
    with _open(_existing(db_path)) as conn:
        return _timeline(conn, method, path)


def _difference(conn: sqlite3.Connection, present: int, absent: int,
                comparable: set[str] | None = None) -> list[Change]:
    """Findings recorded in one scan and not in the other.

    `comparable` restricts the answer to rules that evaluated in both scans.
    Everything else was not looked for, and a finding nobody looked for has
    neither appeared nor gone away.
    """
    rows = conn.execute(
        """
        SELECT f.rule_id, f.method, f.path, f.severity
          FROM finding f
         WHERE f.scan_id = ?
           AND NOT EXISTS (
               SELECT 1 FROM finding other
                WHERE other.scan_id = ?
                  AND other.rule_id = f.rule_id
                  AND other.method  = f.method
                  AND other.path    = f.path)
         ORDER BY f.path, f.method, f.rule_id
        """,
        (present, absent),
    ).fetchall()

    if comparable is not None:
        rows = [row for row in rows if row[0] in comparable]

    return [
        Change(
            rule_id=rule_id,
            method=method,
            path=path,
            severity=severity,
            first_reported=_first_reported(conn, rule_id, method, path),
            timeline=_timeline(conn, method, path),
        )
        for rule_id, method, path, severity in rows
    ]


def _first_reported(conn: sqlite3.Connection, rule_id: str, method: str,
                    path: str) -> str:
    row = conn.execute(
        """
        SELECT s.at
          FROM finding f JOIN scan s ON s.id = f.scan_id
         WHERE f.rule_id = ? AND f.method = ? AND f.path = ?
         ORDER BY f.scan_id
         LIMIT 1
        """,
        (rule_id, method, path),
    ).fetchone()
    return row[0]


def _timeline(conn: sqlite3.Connection, method: str, path: str) -> Timeline:
    first = conn.execute(
        """
        SELECT sg.view, s.at
          FROM sighting sg JOIN scan s ON s.id = sg.scan_id
         WHERE sg.method = ? AND sg.path = ?
           AND sg.scan_id = (SELECT min(earlier.scan_id)
                               FROM sighting earlier
                              WHERE earlier.method = sg.method
                                AND earlier.path   = sg.path
                                AND earlier.view   = sg.view)
         ORDER BY sg.view
        """,
        (method, path),
    ).fetchall()

    last = conn.execute(
        """
        SELECT s.at
          FROM sighting sg JOIN scan s ON s.id = sg.scan_id
         WHERE sg.method = ? AND sg.path = ?
         ORDER BY sg.scan_id DESC
         LIMIT 1
        """,
        (method, path),
    ).fetchone()

    return Timeline(first_seen=dict(first), last_seen=last[0] if last else None)


def _existing(db_path: Path | str) -> Path:
    path = Path(db_path)
    if not path.exists():
        raise SnapshotError(
            f"no snapshot database at {path}. Record one with "
            f"`alibi scan <source> --snapshot {path}`."
        )
    return path


@contextmanager
def _open(path: Path) -> Iterator[sqlite3.Connection]:
    """A connection that commits on the way out and closes either way.

    `sqlite3.Connection` is its own context manager, but that one only ends the
    transaction -- it leaves the connection open.
    """
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(_META_SCHEMA)
        _check_version(conn, path)
        conn.executescript(_SCHEMA)
        with conn:
            yield conn
    except sqlite3.DatabaseError as exc:
        # Almost always the wrong path: `alibi history` aimed at a report, a
        # config file, or a directory. A stack trace would not say that.
        raise SnapshotError(f"{path} is not a readable alibi snapshot: {exc}") from exc
    finally:
        conn.close()


def _check_version(conn: sqlite3.Connection, path: Path) -> None:
    row = conn.execute(
        "SELECT value FROM meta WHERE key = 'schema_version'"
    ).fetchone()

    if row is None:
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()
        return

    found = int(row[0])
    if found != SCHEMA_VERSION:
        raise SnapshotError(
            f"{path} was written at schema version {found}, and this alibi "
            f"speaks version {SCHEMA_VERSION}. A snapshot is a record of past "
            f"scans, so it is refused rather than reinterpreted -- delete it "
            f"to start a new history, or use the alibi that wrote it."
        )


def _now() -> str:
    return (
        datetime.now(UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
