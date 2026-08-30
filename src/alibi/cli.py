"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from . import collect, snapshot
from .ignore import IgnoreList
from .index import build as build_index
from .report import history as history_report
from .report import json_report, sarif, text
from .rules import RuleSet
from .views import ViewMap

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="alibi",
        description="Cross-check the views of your attack surface and find the "
                    "endpoints that cannot corroborate each other.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan sources and report where the views disagree")
    scan.add_argument("paths", nargs="+", metavar="PATH",
                      help="anything noir can read: a codebase, a spec directory, a capture file")
    scan.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--noir-bin", help="path to the noir binary (default: found on PATH)")
    scan.add_argument("--views", help="alternative views.yml")
    scan.add_argument("--rules", help="alternative rules.yml")
    scan.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"],
                      help="exit non-zero when a finding reaches this severity")
    scan.add_argument("--noir-arg", action="append", default=[], metavar="ARG",
                      help="extra argument passed through to noir (repeatable)")
    scan.add_argument("--ignore", action="append", default=[], metavar="REGEX",
                      help="suppress findings whose path matches (repeatable)")
    scan.add_argument("--ignore-file", metavar="FILE",
                      help="suppression list (default: .alibi.yml beside the source)")
    scan.add_argument("--snapshot", nargs="?", metavar="PATH",
                      const=str(snapshot.DEFAULT_PATH),
                      help="record this scan so `alibi history` can report what "
                           f"changed (default: {snapshot.DEFAULT_PATH})")

    doctor = sub.add_parser(
        "doctor", help="check the view map against this noir build's catalog")
    doctor.add_argument("--noir-bin")
    doctor.add_argument("--views")

    history = sub.add_parser(
        "history", help="report what changed since the previous recorded scan")
    history.add_argument("path", nargs="?", default=str(snapshot.DEFAULT_PATH),
                         metavar="PATH", help="a snapshot database")

    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "doctor":
            return _doctor(args)
        if args.command == "history":
            return _history(args)
    except (collect.NoirNotFound, collect.NoirFailed,
            snapshot.SnapshotError) as exc:
        print(f"alibi: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


def _scan(args) -> int:
    view_map = ViewMap.load(args.views)
    rules = RuleSet.load(args.rules)
    noir_bin = collect.find_noir(args.noir_bin)

    # Noir's own catalog decides which technologies exist; views.yml decides
    # what each one speaks for. One `--only-techs` list per view falls out.
    catalog = collect.list_techs(noir_bin)
    techs_by_view = view_map.techs_by_view(catalog)

    endpoints = []
    errors = []
    names = []
    for path in args.paths:
        source = collect.Source(path=path)
        names.append(source.name)
        result = collect.scan_views(source, noir_bin, techs_by_view,
                                    extra_args=args.noir_arg)
        endpoints.extend(result.endpoints)
        errors.extend(result.errors)

    index = build_index(endpoints, view_map)
    present_views = {view for entry in index.entries.values() for view in entry.views}
    findings, skipped = rules.evaluate(index, present_views)

    ignores = (IgnoreList.load(args.ignore_file) if args.ignore_file
               else IgnoreList.discover(args.paths))
    ignores = ignores.extend(IgnoreList.from_patterns(args.ignore))
    findings, suppressed = ignores.apply(findings)

    if args.format == "json":
        print(json_report.dump(index, findings, skipped, names, errors, suppressed))
    elif args.format == "sarif":
        print(sarif.dump(index, findings, skipped, names, rules, errors,
                         suppressed))
    else:
        text.render(index, findings, skipped, rules, names, errors, suppressed)

    # After the report: a snapshot that cannot be written should not cost the
    # user the scan they just paid for.
    if args.snapshot:
        snapshot.record(args.snapshot, index, findings, names)

    if args.fail_on:
        threshold = rules.severities.index(args.fail_on)
        if any(rules.severities.index(f.severity) >= threshold for f in findings):
            return EXIT_FINDINGS
    return EXIT_OK


def _history(args) -> int:
    # The ruleset is loaded for its severity ladder alone: a snapshot records
    # the severity a finding was reported at, not where that rung sits.
    severities = RuleSet.load().severities
    history_report.render(snapshot.history(args.path), severities)
    return EXIT_OK


def _doctor(args) -> int:
    """Report technologies this noir build knows that the view map does not.

    The view map defaults anything unlisted to `code`, which is right for the
    200-plus language analyzers and wrong for a specification analyzer added
    after this file was last touched. Noir reports a `language` for the former
    and not the latter, so the drift is exactly detectable.
    """
    view_map = ViewMap.load(args.views)
    noir_bin = collect.find_noir(args.noir_bin)
    catalog = collect.list_techs(noir_bin)

    spec_techs = {name for name, spec in catalog.items() if "language" not in spec}
    unmapped = sorted(spec_techs - view_map.mapped_techs)
    stale = sorted(view_map.mapped_techs - set(catalog))

    print(f"noir catalog: {len(catalog)} technologies "
          f"({len(spec_techs)} non-language)")
    print(f"view map:     {len(view_map.mapped_techs)} mapped")

    if unmapped:
        print()
        print("Unmapped, and would be read as code:")
        for tech in unmapped:
            print(f"  {tech}")
        print()
        print("Add each to views.yml under the view it speaks for.")

    if stale:
        print()
        print("Mapped but no longer in this noir build:")
        for tech in stale:
            print(f"  {tech}")

    if not unmapped and not stale:
        print()
        print("View map matches this noir build.")

    return EXIT_FINDINGS if unmapped else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
