"""Machine-readable report."""

from __future__ import annotations

import json

from ..index import Index
from ..rules import Finding, Skipped


def build(index: Index, findings: list[Finding], skipped: list[Skipped],
          sources: list[str]) -> dict:
    view_counts: dict[str, int] = {}
    for entry in index.entries.values():
        for view in entry.views:
            view_counts[view] = view_counts.get(view, 0) + 1

    return {
        "sources": sources,
        "summary": {
            "endpoints": len(index.entries),
            "findings": len(findings),
            "near_misses": index.near_miss_count,
            "views": view_counts,
        },
        "findings": [_finding(f) for f in findings],
        "skipped_rules": [
            {"rule": s.rule_id, "reason": s.reason, "detail": s.detail}
            for s in skipped
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
    }


def dump(index: Index, findings: list[Finding], skipped: list[Skipped],
         sources: list[str]) -> str:
    return json.dumps(build(index, findings, skipped, sources), indent=2)
