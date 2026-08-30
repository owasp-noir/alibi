"""Machine-readable report."""

from __future__ import annotations

import json

from ..index import Index
from ..scope import suggest
from ..rules import Finding, Skipped


def build(index: Index, findings: list[Finding], skipped: list[Skipped],
          sources: list[str], errors: list = (), suppressed: list = (),
          ruleset=None) -> dict:
    view_counts: dict[str, int] = {}
    for entry in index.entries.values():
        for view in entry.views:
            view_counts[view] = view_counts.get(view, 0) + 1

    return {
        "sources": sources,
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
                        "other": str(nm.other),
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
         ruleset=None) -> str:
    return json.dumps(
        build(index, findings, skipped, sources, errors, suppressed, ruleset),
        indent=2)
