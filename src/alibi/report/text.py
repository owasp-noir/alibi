"""Terminal report."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from ..index import GRADE_LONE, Index
from ..scope import Hint, suggest
from ..rules import Finding, RuleSet, Skipped

# How many findings of one kind to print before saying how many are left.
GROUP_LIMIT = 12

_COLORS = {
    "critical": "\x1b[1;31m",
    "high": "\x1b[31m",
    "medium": "\x1b[33m",
    "low": "\x1b[36m",
    "info": "\x1b[90m",
    "ok": "\x1b[32m",
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
    errors: list = (),
    suppressed: list = (),
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
    if not index.entries:
        # By far the likeliest first run: the wrong directory. Saying "no rule
        # had the views it needs" here describes the machinery rather than the
        # situation, and leaves the reader looking for a flag they are missing.
        out()
        out("  " + paint("Noir found no endpoints here.", "medium"))
        out(paint("  It reads code in 33 languages, OpenAPI and other API "
                  "contracts, captured\n  traffic, gateway config and "
                  "infrastructure declarations. Point alibi at\n  a directory "
                  "holding some of those, or run `noir -b <path>` to see what "
                  "it finds.", "dim"))
        out()
        return

    out()
    out("  " + "   ".join(
        f"{view} {paint(str(count), 'bold')}"
        for view, count in sorted(view_counts.items(), key=lambda kv: -kv[1])
    ))

    if len(sources) > 1:
        _render_sources(index, sources, paint, out)
    out()
    out("  " + paint(f"{index.corroborated} corroborated", "ok")
        + paint(" -- vouched for by more than one view", "dim"))

    for view, (rules_count, reached, total) in index.coverage_stats().items():
        share = f"{reached / total * 100:.0f}%" if total else "n/a"
        out("  " + paint(
            f"{view}: {rules_count} rule{'s' if rules_count != 1 else ''} "
            f"reaching {reached} of {total} code endpoints ({share})", "dim"))

    # Anything noir could not read goes above the findings, because it changes
    # what the findings mean. A specification skipped for being too large reads
    # downstream as "this project documents nothing".
    lost = [e for e in errors if e.consequential]
    declined = [e for e in errors if not e.consequential]

    if lost:
        out()
        out(paint("NOIR COULD NOT READ EVERYTHING", "high"))
        out(paint("  Views below may be incomplete, and a missing view is not "
                  "the same as an empty one.", "dim"))
        for error in lost:
            out(paint(f"  [{error.tech}] {_wrap(_trim(error.message), indent='    ')}", "dim"))

    if declined:
        # Images, binaries and symlinks noir passed over on purpose. Worth
        # recording, not worth alarming about -- an alarm for these teaches the
        # reader to skip the one above.
        out()
        out(paint(f"  {len(declined)} note{'s' if len(declined) != 1 else ''}: "
                  f"noir skipped media, binaries or symlinks (details in -f json)",
                  "dim"))

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
        # "Nothing to report" and "the comparison never ran" look identical from
        # the outside and mean opposite things, so only claim agreement when a
        # rule actually compared something.
        if suppressed:
            out("  " + paint(
                f"Nothing left to report -- {len(suppressed)} finding"
                f"{'s' if len(suppressed) != 1 else ''} suppressed. See below.", "dim"))
        elif any(s.reason == "no-overlap" for s in skipped):
            out("  " + paint("No findings -- but nothing was compared. See below.", "medium"))
        elif skipped and len(skipped) == len(rules.rules):
            out("  " + paint("No rule had the views it needs. See below.", "dim"))
        else:
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
        out(paint(f"  {len(group)} finding{'s' if len(group) != 1 else ''}"
                  f"{_breakdown(group, paint)}", "dim"))
        out()

        # A report nobody scrolls to the end of is a report nobody reads. The
        # group is already ordered worst-first, so the tail is the least
        # informative part of it -- and the full list is one flag away.
        for finding in group[:GROUP_LIMIT]:
            _render_finding(finding, paint, out)
        if len(group) > GROUP_LIMIT:
            out(paint(f"  ... and {len(group) - GROUP_LIMIT} more "
                      f"({rule_id} in full: -f json)", "dim"))

    _render_scope_hint(suggest(index, findings, rules), paint, out)
    _render_near_misses(index, paint, out)
    _render_suppressed(suppressed, paint, out)
    _render_skipped(skipped, paint, out)
    out()


def _render_sources(index: Index, sources: list[str], paint: Painter, out) -> None:
    """Which named path produced which view, and which produced nothing."""
    rows = index.by_source(sources)
    width = max(len(name) for name, _, _ in rows)
    silent = [name for name, count, _ in rows if count == 0]

    out()
    for name, count, views in rows:
        described = ", ".join(views) if views else paint("nothing noir recognised", "medium")
        out(paint(f"  {name:<{width}}  {count:>5}  ", "dim") + described)

    if silent:
        out(paint(f"  Check {'that path' if len(silent) == 1 else 'those paths'} "
                  f"-- either it is not where you meant, or noir does not read "
                  f"the format there.", "dim"))


def _breakdown(group: list[Finding], paint: Painter) -> str:
    """The severity mix of a group, so a truncated list still says what it holds."""
    counts: dict[str, int] = {}
    for finding in group:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    if len(counts) < 2:
        return ""
    order = ["critical", "high", "medium", "low", "info"]
    parts = [f"{counts[s]} {s}" for s in order if s in counts]
    return "  ·  " + ", ".join(parts)


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

    # A reason that only restates a column already on this row costs a line
    # per finding and tells the reader nothing they cannot see.
    distinctive = [a.why for a in finding.adjustments if a.why and not a.restates]
    if distinctive:
        out(paint(f"           {' · '.join(distinctive)}", "dim"))

    if finding.entry.siblings:
        verbs = ", ".join(sorted({m for m, _ in finding.entry.siblings}))
        views = sorted({v for _, vs in finding.entry.siblings for v in vs})
        out(paint(f"           same path answers {verbs} in {', '.join(views)}", "dim"))

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


def _render_scope_hint(hint: Hint | None, paint: Painter, out) -> None:
    """Say where the contract's remit ends, without saying what to do about it.

    Whether the findings outside it are a different surface or an undocumented
    part of the same one is not something paths can answer -- so this reports
    the measurement and the command, and leaves the judgement where it belongs.
    """
    if hint is None:
        return
    out()
    out(paint("TWO SURFACES?", "bold"))
    out(paint(f"  The {hint.view} view is {hint.share}% under {hint.prefix}, "
              f"and {hint.outside} of these findings are outside it.", "dim"))
    out(paint("  If that is a separate surface the contract never covered, "
              "narrow the scan:", "dim"))
    out(paint(f"    alibi scan <paths> --ignore '{hint.ignore_pattern}'", "dim"))
    out(paint(f"  If it is the same surface left undocumented, they are the "
              f"findings that matter most.", "dim"))


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


def _render_suppressed(suppressed: list, paint: Painter, out) -> None:
    """Say how much was silenced. Never silence silently."""
    if not suppressed:
        return
    out()
    reasons: dict[str, int] = {}
    for _, entry in suppressed:
        reasons[entry.why or "no reason given"] = reasons.get(entry.why or "no reason given", 0) + 1
    out(paint(f"{len(suppressed)} finding"
              f"{'s' if len(suppressed) != 1 else ''} suppressed", "dim"))
    for why, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
        out(paint(f"  {count:>4}  {why}", "dim"))


def _render_skipped(skipped: list[Skipped], paint: Painter, out) -> None:
    if not skipped:
        return

    blocked = [s for s in skipped if s.reason == "no-overlap"]
    quiet = [s for s in skipped if s.reason != "no-overlap"]

    # A rule held back because the views did not connect is the most important
    # thing on the page: it is the difference between "nothing to report" and
    # "the comparison did not work", and the two look identical otherwise.
    if blocked:
        out()
        out(paint("THE VIEWS DID NOT CONNECT", "high"))
        # Rules blocked for the same reason share one explanation. Printing the
        # same five lines under each of them buries it by repeating it.
        for detail, rules in _by_detail(blocked):
            out(paint(f"  {', '.join(rules)} held back", "bold"))
            out(paint(f"  {_wrap(detail)}", "dim"))

    if quiet:
        out()
        for detail, rules in _by_detail(quiet):
            out(paint(f"  {', '.join(rules)} did not run -- {detail}", "dim"))


def _by_detail(items: list[Skipped]) -> list[tuple[str, list[str]]]:
    """Group skipped rules by the reason they share, keeping first-seen order."""
    grouped: dict[str, list[str]] = {}
    for item in items:
        grouped.setdefault(item.detail, []).append(item.rule_id)
    return list(grouped.items())


def _trim(message: str, limit: int = 160) -> str:
    """Keep a skip report readable.

    Noir lists every path it skipped, which for a repository full of test
    symlinks is a paragraph of absolute paths. The count and the first example
    carry the meaning; the full list is in `-f json`.
    """
    if len(message) <= limit:
        return message
    head, _, _ = message[:limit].rpartition(", ")
    return f"{head or message[:limit]} ... (full list in -f json)"


def _wrap(text: str, width: int = 74, indent: str = "  ") -> str:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return f"\n{indent}".join(lines)
