"""Machine-readable report."""

from __future__ import annotations

import json

from ..index import Index
from ..rules import MAX_UNCORROBORATED_FINDINGS, Finding, Skipped
from ..scope import from_tests, missing_subtree, suggest


def _by_view(index: Index) -> dict[str, list[dict]]:
    """Every endpoint each view held, with the evidence behind it.

    What the report says is that two views disagree. What it never says is
    what either view actually contained -- so the first move in debugging any
    finding is to re-run noir by hand, once per view, with the same
    `--only-techs` lists alibi used, and join the results. That is the whole
    tool, reimplemented at a shell prompt, before the question can even be
    asked. Both prefix diagnoses in this release were found that way.

    Behind a flag because it is large: on NetBox it is 1,627 endpoints and
    roughly nine times the default payload. The default answer to "what do
    the views hold" stays the summary counts.
    """
    listing: dict[str, list[dict]] = {}
    for entry in index.entries.values():
        for view in sorted(entry.views):
            here = [o for o in entry.observations if o.view == view]
            listing.setdefault(view, []).append({
                "method": entry.key.method,
                "path": entry.key.path,
                "protocol": entry.key.protocol,
                # Which other views vouched for this one. Reading down a
                # single view's list, this is the column that says whether
                # the endpoint corroborated, and against what.
                "views": sorted(entry.views),
                "technologies": sorted({o.raw.technology for o in here}),
                # The spelling before normalization. When two views hold what
                # should be one endpoint and did not match, the difference is
                # always here and never in the key.
                "originals": sorted({o.normalized.original_url for o in here}),
                "code_paths": [dict(cp, source_root=o.raw.source_root)
                               for o in here for cp in o.raw.code_paths],
            })
    for rows in listing.values():
        rows.sort(key=lambda row: (row["path"], row["method"]))
    return listing


def build(index: Index, findings: list[Finding], skipped: list[Skipped],
          sources: list[str], errors: list = (), suppressed: list = (),
          ruleset=None, endpoints: bool = False) -> dict:
    view_counts: dict[str, int] = {}
    for entry in index.entries.values():
        for view in entry.views:
            view_counts[view] = view_counts.get(view, 0) + 1

    document = {
        "sources": [
            {"name": name, "endpoints": count, "views": views}
            for name, count, views in index.by_source(sources)
        ],
        "scan_errors": [
            {"tech": e.tech, "message": e.message, "source": e.source}
            for e in errors
        ],
        "summary": {
            "endpoints": len(index.entries),
            "corroborated": index.corroborated,
            "findings": len(findings),
            "near_misses": index.near_miss_count,
            "degraded": bool(errors),
            "suppressed": len(suppressed),
            "views": view_counts,
            "coverage": {
                view: {"rules": rules, "reaches": reached, "of": total}
                for view, (rules, reached, total) in index.coverage_stats().items()
            },
        },
        "scope_hint": _hint(suggest(index, findings, ruleset)),
        "missing_subtree": (
            {"rule": ms.rule_id, "prefix": ms.prefix, "findings": ms.findings,
             "of": ms.total, "absent_view": ms.absent_view}
            if (ms := missing_subtree(findings, index, ruleset,
                                      MAX_UNCORROBORATED_FINDINGS)) else None
        ),
        "test_hint": (
            {"findings": th.findings, "total": th.total,
             "directories": th.directories, "exclude": th.exclude_globs}
            if (th := from_tests(findings, index)) else None
        ),
        "conflated": [
            {"endpoint": str(key), "contract_directories": directories}
            for key, directories, _ in index.conflated()
        ],
        "findings": [_finding(f) for f in findings],
        "skipped_rules": [
            {"rule": s.rule_id, "reason": s.reason, "detail": s.detail}
            for s in skipped
        ],
        "suppressed": [
            {"rule": f.rule_id, "method": f.key.method, "path": f.key.path,
             "why": entry.why}
            for f, entry in suppressed
        ],
        "review": [
            {
                "endpoint": str(entry.key),
                "views": sorted(entry.views),
                "near_misses": [
                    {
                        "other": str(nm.other) if nm.other else None,
                        "other_views": sorted(nm.other_views),
                        "reason": nm.reason,
                    }
                    for nm in entry.near_misses
                ],
            }
            for entry in index.entries.values()
            if entry.near_misses
        ],
    }
    if endpoints:
        document["endpoints"] = _by_view(index)
    return document


def _hint(hint) -> dict | None:
    if hint is None:
        return None
    return {
        "view": hint.view,
        "prefix": hint.prefix,
        "concentration": round(hint.concentration, 3),
        "findings_inside": hint.inside,
        "findings_outside": hint.outside,
        "ignore_pattern": hint.ignore_pattern,
    }


def _finding(finding: Finding) -> dict:
    entry = finding.entry
    return {
        "rule": finding.rule_id,
        "name": finding.name,
        "summary": finding.summary,
        "severity": finding.severity,
        "base_severity": finding.base_severity,
        "method": finding.key.method,
        "path": finding.key.path,
        "match_grade": finding.grade,
        "views": sorted(entry.views),
        "technologies": sorted(entry.techs),
        "tags": sorted(entry.tags),
        "originals": sorted({o.normalized.original_url for o in entry.observations}),
        "code_paths": entry.code_paths(),
        "adjustments": [
            {"shift": a.shift, "why": a.why} for a in finding.adjustments
        ],
        "uncertain": finding.uncertain,
        "siblings": [
            {"method": method, "views": sorted(views)}
            for method, views in entry.siblings
        ],
    }


def dump(index: Index, findings: list[Finding], skipped: list[Skipped],
         sources: list[str], errors: list = (), suppressed: list = (),
         ruleset=None, endpoints: bool = False) -> str:
    return json.dumps(
        build(index, findings, skipped, sources, errors, suppressed, ruleset,
              endpoints),
        indent=2)
