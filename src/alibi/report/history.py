"""Terminal report for what changed between the last two scans."""

from __future__ import annotations

import sys

from ..snapshot import Change, History
from .text import Painter, _use_color


def render(history: History, severities: list[str], stream=None) -> None:
    stream = stream or sys.stdout
    paint = Painter(_use_color(stream))
    def out(line=""):
        print(line, file=stream)

    out()
    out(paint("alibi history", "bold") + paint(
        f"  ·  {history.path}  ·  "
        f"{history.scans} scan{'s' if history.scans != 1 else ''}", "dim"))
    out()

    if history.previous_at is None:
        # The same refusal the rules make when a view is missing: nothing was
        # compared, so nothing is reported as new.
        out("  " + paint(f"scan {history.current_scan}", "bold")
            + paint(f"  {history.current_at}", "dim"))
        out("  " + paint("The first recorded scan. Nothing to compare it "
                         "against yet.", "dim"))
        out()
        return

    out(f"  {paint(f'scan {history.current_scan}', 'bold')}"
        + paint(f"  {history.current_at}", "dim")
        + paint(f"   compared against   scan {history.previous_scan}", "dim")
        + paint(f"  {history.previous_at}", "dim"))

    _render_different_sources(history, paint, out)
    _render_not_compared(history, paint, out)

    if not history.new and not history.resolved:
        out()
        out("  " + paint("No finding appeared or disappeared since the "
                         "previous scan.", "info"))
        out()
        return

    _section("NEW", "the previous scan did not have these", history.new,
             severities, paint, out, _why_new)
    _section("RESOLVED", "the previous scan had these and this one does not",
             history.resolved, severities, paint, out, _why_resolved)
    out()


def _section(title: str, summary: str, changes: list[Change],
             severities: list[str], paint, out, explain) -> None:
    if not changes:
        return
    out()
    out(paint(title, "bold") + paint(f"  {summary}", "dim"))
    out(paint(f"  {len(changes)} finding{'s' if len(changes) != 1 else ''}", "dim"))
    out()
    for change in _by_severity(changes, severities):
        out(f"  {paint(f'{change.severity:<8}', change.severity)} "
            f"{change.rule_id:<8} {change.method:<7} {change.path}")
        out(paint(f"           {explain(change)}", "dim"))


def _why_new(change: Change) -> str:
    """Say whether the endpoint is new, or only its disagreement is.

    A shadow API that appeared with the route is a documentation step someone
    skipped. One on a route that has been in the code for months means a view
    stopped covering it -- a specification that was deleted, or a scan that no
    longer reads it. The two need different people to look at them.
    """
    return "endpoint first seen in " + ", ".join(
        f"{view} {at}"
        for view, at in sorted(change.timeline.first_seen.items())
    )


def _why_resolved(change: Change) -> str:
    parts = [f"reported since {change.first_reported}"]
    if change.timeline.last_seen:
        parts.append(f"endpoint last seen {change.timeline.last_seen}")
    return " · ".join(parts)


def _by_severity(changes: list[Change], severities: list[str]) -> list[Change]:
    """Worst first. A severity the ruleset does not name sorts last."""
    def rank(change: Change) -> tuple:
        try:
            position = -severities.index(change.severity)
        except ValueError:
            position = 1
        return (position, change.path, change.method, change.rule_id)

    return sorted(changes, key=rank)


def _render_different_sources(history: History, paint, out) -> None:
    """The two scans were not of the same thing.

    `not_compared` catches a rule that stopped running. It does not catch the
    case where every rule ran in both scans and the scans were of different
    projects -- one snapshot database used for two, or a CI job whose paths
    changed. Then each project's findings are reported as the other's
    progress, which is the same overclaim in a form the rule check cannot see.

    Both lists below are still printed. Sources changing is not always a
    mistake -- adding a contracts directory to a scan is exactly how a
    comparison is meant to grow -- so this says what changed and leaves the
    reading to whoever knows why.
    """
    if not history.sources_differ:
        return
    out()
    out(paint("DIFFERENT SOURCES", "high"))
    out(paint("  These two scans were not given the same paths, so what "
              "follows is not\n  one project changing over time.", "dim"))
    out(paint(f"  scan {history.previous_scan}: "
              f"{', '.join(history.sources_then) or '(none recorded)'}", "dim"))
    out(paint(f"  scan {history.current_scan}: "
              f"{', '.join(history.sources_now) or '(none recorded)'}", "dim"))


def _render_not_compared(history: History, paint, out) -> None:
    """Rules the earlier scan ran and this one did not.

    This is the trap the whole comparison had to be built around. Point alibi
    at the code and forget the contracts, and SHADOW evaluates nothing -- which
    looks, to a naive difference, exactly like every shadow API having been
    closed. Those findings are held out of both lists and named here instead.
    """
    if not history.not_compared:
        return
    out()
    out(paint("NOT COMPARED", "high"))
    out(paint("  These ran in the previous scan and not in this one, so their "
              "findings are\n  neither new nor resolved -- nobody looked. "
              "Check the sources you passed.", "dim"))
    out(paint(f"  {', '.join(history.not_compared)}", "dim"))
