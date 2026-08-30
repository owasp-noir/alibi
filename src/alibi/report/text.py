"""Terminal report."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from ..index import GRADE_LONE, Index
from ..rules import Finding, RuleSet, Skipped

_COLORS = {
    "critical": "\x1b[1;31m",
    "high": "\x1b[31m",
    "medium": "\x1b[33m",
    "low": "\x1b[36m",
    "info": "\x1b[90m",
    "dim": "\x1b[90m",
    "bold": "\x1b[1m",
    "reset": "\x1b[0m",
}


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


class Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, style: str) -> str:
        if not self.enabled:
            return text
        return f"{_COLORS.get(style, '')}{text}{_COLORS['reset']}"


def render(
    index: Index,
    findings: list[Finding],
    skipped: list[Skipped],
    rules: RuleSet,
    sources: list[str],
    stream=sys.stdout,
) -> None:
    paint = Painter(_use_color(stream))
    out = lambda line="": print(line, file=stream)

    view_counts: dict[str, int] = {}
    for entry in index.entries.values():
        for view in entry.views:
            view_counts[view] = view_counts.get(view, 0) + 1

    out()
    out(paint("alibi", "bold") + paint(
        f"  ·  {len(sources)} source{'s' if len(sources) != 1 else ''}"
        f"  ·  {len(index.entries)} endpoints", "dim"))
    out()
    out("  " + "   ".join(
        f"{view} {paint(str(count), 'bold')}"
        for view, count in sorted(view_counts.items(), key=lambda kv: -kv[1])
    ))

    # The near-miss count is the tool's own error bar. It belongs next to the
    # totals, not buried under the findings, because every finding below is
    # only as trustworthy as this number is small.
    misses = index.near_miss_count
    if misses:
        out()
        out("  " + paint(
            f"{misses} endpoint{'s' if misses != 1 else ''} nearly matched another view "
            f"-- these may be matching failures, not real gaps", "medium"))

    if not findings:
        out()
        out("  " + paint("No disagreement between the views in this scan.", "info"))
        _render_skipped(skipped, paint, out)
        out()
        return

    for rule_id in _rule_order(findings):
        group = [f for f in findings if f.rule_id == rule_id]
        head = group[0]
        out()
        out(f"{paint(rule_id, 'bold')}  {head.name} "
            + paint(f"-- {head.summary}", "dim"))
        out(paint(f"  {len(group)} finding{'s' if len(group) != 1 else ''}", "dim"))
        out()
        for finding in group:
            _render_finding(finding, paint, out)

    _render_near_misses(index, paint, out)
    _render_skipped(skipped, paint, out)
    out()


def _rule_order(findings: list[Finding]) -> list[str]:
    seen: list[str] = []
    for finding in findings:
        if finding.rule_id not in seen:
            seen.append(finding.rule_id)
    return seen


def _render_finding(finding: Finding, paint: Painter, out) -> None:
    severity = paint(f"{finding.severity:<8}", finding.severity)
    method = f"{finding.key.method:<7}"
    line = f"  {severity} {method} {finding.key.path}"

    where = _first_location(finding)
    if where:
        line += paint(f"   {where}", "dim")
    out(line)

    if finding.adjustments:
        reasons = " · ".join(a.why for a in finding.adjustments if a.why)
        if reasons:
            out(paint(f"           {reasons}", "dim"))

    if finding.uncertain:
        near = finding.entry.near_misses[0]
        out(paint(f"           near miss: {near.other} "
                  f"in {', '.join(sorted(near.other_views))} -- {near.reason}", "medium"))


def _first_location(finding: Finding) -> str:
    for path_info in finding.entry.code_paths():
        path = path_info.get("path")
        if not path:
            continue
        line = path_info.get("line")
        shortened = _shorten(str(path))
        return f"{shortened}:{line}" if line else shortened
    return ", ".join(sorted(finding.entry.techs))


def _shorten(path: str) -> str:
    """Show a location the reader can act on.

    Noir echoes back whatever base path it was given, so scanning an absolute
    directory yields absolute code paths that push the useful part of the line
    off the terminal. Relative to the working directory is what a reader can
    paste into an editor.
    """
    try:
        return str(Path(path).relative_to(Path.cwd()))
    except ValueError:
        return Path(path).name


def _render_near_misses(index: Index, paint: Painter, out) -> None:
    flagged = [e for e in index.entries.values() if e.near_misses and e.grade == GRADE_LONE]
    if not flagged:
        return
    out()
    out(paint("REVIEW", "bold") + paint(
        "  endpoints that nearly matched another view", "dim"))
    out(paint("  Check these before trusting the findings above -- a bad match "
              "here becomes a false finding.", "dim"))
    out()
    for entry in flagged[:20]:
        near = entry.near_misses[0]
        out(f"  {entry.key}")
        out(paint(f"     ~ {near.other} in {', '.join(sorted(near.other_views))} "
                  f"-- {near.reason}", "dim"))
    if len(flagged) > 20:
        out(paint(f"  ... and {len(flagged) - 20} more", "dim"))


def _render_skipped(skipped: list[Skipped], paint: Painter, out) -> None:
    if not skipped:
        return
    out()
    out(paint("Rules that did not run", "dim"))
    for item in skipped:
        views = ", ".join(item.missing)
        out(paint(f"  {item.rule_id:<12} no {views} source in this scan", "dim"))
