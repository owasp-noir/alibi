"""SARIF 2.1.0, for CI systems that already know how to read findings.

The text and JSON reports are alibi's own shape. This one is somebody else's --
GitHub code scanning, a viewer, an aggregator -- and that settles four
decisions which would otherwise be free.

**The rule catalog is read out of the ruleset, not written down here.** SARIF
requires every result's `ruleId` to be backed by a descriptor in the run's tool
driver. rules.yml is data on purpose -- adding the traffic, gateway and infra
rules is meant to be a matter of editing YAML -- so a list kept in this file
would go stale the first time that happened, and emit results whose rule
nothing describes.

**SARIF has four levels where alibi has five severities.** `note`, `warning`
and `error` are the entire vocabulary, so the adjustment machinery -- personal
data, uploads, no sign of auth, a method that changes state -- arrives
flattened. The unflattened severity is kept in `properties`, which is where
SARIF puts what it has no field for, and so is the near-miss demotion: a
consumer reading only the level would never learn that alibi doubts a finding.

**A finding with no file is ordinary here.** PHANTOM is a finding *about*
nothing implementing the endpoint. Noir does name the specification that
promises it, so most phantoms do get a file, but a traffic or gateway sighting
carries no code path at all. Pointing those at an invented file would be the
one thing this tool refuses to do everywhere else, so they get a *logical*
location instead -- the endpoint identity, which is the only location they
have. `locations` stays non-empty for consumers that insist on it, and no
reader is sent to open a file that has nothing to say.

**A rule that was held back is a notification, not silence.** The text report
treats "the comparison did not work" as the most important thing on the page.
Dropping it here would leave a SARIF consumer reading zero findings as
agreement between the views, which is the exact confusion the rest of the tool
is built to prevent, so held-back rules travel as tool execution notifications.
"""

from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _installed_version
from pathlib import Path
from urllib.parse import quote

from ..index import Index
from ..rules import Finding, RuleSet, Skipped

SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/owasp-noir/alibi"

# SARIF's four levels against alibi's five severities. `none` is reserved for
# results that are not problems, and nothing here produces one.
_LEVELS = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

# The severity ladder lives in rules.yml, so a custom ruleset can name a rung
# this table has never heard of. Reporting it as a warning keeps the finding;
# guessing at its place in the ladder would not.
_UNKNOWN_LEVEL = "warning"


def _level(severity: str) -> str:
    return _LEVELS.get(severity, _UNKNOWN_LEVEL)


def build(index: Index, findings: list[Finding], skipped: list[Skipped],
          sources: list[str], ruleset: RuleSet, errors: list = (),
          suppressed: list = ()) -> dict:
    rules = [_rule(rule) for rule in ruleset.rules]
    position = {rule["id"]: i for i, rule in enumerate(rules)}

    driver = {
        "name": "alibi",
        "informationUri": INFORMATION_URI,
        "rules": rules,
    }
    release = _release()
    if release:
        driver["version"] = release

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": driver},
                "invocations": [
                    {
                        # A rule held back is a conclusion, not a failure to
                        # reach one, so skipped rules leave this true. A file
                        # noir could not read is different: the scan did not
                        # see everything it was pointed at, and a consumer that
                        # treats the result as complete is being misled.
                        "executionSuccessful": not errors,
                        "toolExecutionNotifications": [
                            _notification(item) for item in skipped
                        ] + [_error_notification(item) for item in errors],
                    }
                ],
                # Suppressed findings travel as results carrying a SARIF
                # suppression rather than being dropped. Code scanning shows
                # them as dismissed with the project's own reason attached,
                # which is the same promise the terminal report makes: say what
                # was withheld, never withhold it silently.
                "results": [_result(f, position) for f in findings]
                + [_result(f, position, entry) for f, entry in suppressed],
                # A findings list with no denominator is what this tool exists
                # to avoid: 147 findings mean something different beside 230
                # corroborated endpoints than beside none. A SARIF file is
                # often the only artifact a CI run keeps, so the totals travel
                # with it.
                "properties": {
                    "sources": sources,
                    "endpoints": len(index.entries),
                    "corroborated": index.corroborated,
                    "nearMisses": index.near_miss_count,
                    "suppressed": len(suppressed),
                    "degraded": bool(errors),
                },
            }
        ],
    }


def _error_notification(error) -> dict:
    """Something noir could not read, as a tool notification."""
    return {
        "level": "warning",
        "message": {"text": f"noir could not read everything: {error.message}"},
        "properties": {"tech": error.tech, "source": error.source},
    }


def dump(index: Index, findings: list[Finding], skipped: list[Skipped],
         sources: list[str], ruleset: RuleSet, errors: list = (),
         suppressed: list = ()) -> str:
    return json.dumps(
        build(index, findings, skipped, sources, ruleset, errors, suppressed),
        indent=2,
    )


def _release() -> str | None:
    """The installed version, when alibi was installed rather than run from src."""
    try:
        return _installed_version("noir-alibi")
    except PackageNotFoundError:
        return None


def _rule(rule: dict) -> dict:
    severity = rule.get("severity", "medium")
    descriptor = {
        "id": rule["id"],
        "name": rule.get("name", rule["id"]),
        "shortDescription": {"text": rule.get("summary") or rule["id"]},
        "defaultConfiguration": {"level": _level(severity)},
        "properties": {
            "severity": severity,
            "views": list(rule.get("needs", [])),
        },
    }
    detail = (rule.get("detail") or "").strip()
    if detail:
        descriptor["fullDescription"] = {"text": detail}
    return descriptor


def _notification(item: Skipped) -> dict:
    return {
        # A rule with no view to run against is housekeeping. Two populated
        # views that share nothing means the comparison did not work, and that
        # has to read louder than the findings it suppressed.
        "level": "warning" if item.reason == "no-overlap" else "note",
        "associatedRule": {"id": item.rule_id},
        "message": {"text": f"{item.rule_id} did not run: {item.detail}"},
        "properties": {"reason": item.reason},
    }


def _result(finding: Finding, position: dict[str, int],
            suppression=None) -> dict:
    entry = finding.entry
    locations = _locations(finding)

    result = {
        "ruleId": finding.rule_id,
        "level": _level(finding.severity),
        "message": {"text": _message(finding)},
        "locations": locations[:1],
        # Line numbers move with every edit above them; the endpoint identity
        # does not. Handing code scanning a fingerprint of alibi's own keeps
        # one shadow API as one alert, rather than a new alert every time the
        # file it sits in shifts.
        "partialFingerprints": {
            "alibiEndpoint/v1": f"{finding.rule_id} {finding.key}",
        },
        "properties": {
            "severity": finding.severity,
            "baseSeverity": finding.base_severity,
            "views": sorted(entry.views),
            "technologies": sorted(entry.techs),
            "matchGrade": finding.grade,
            "uncertain": finding.uncertain,
            # SARIF reserves `tags` in a property bag for exactly this: a set
            # of distinct strings that categorize the result.
            "tags": sorted(entry.tags),
        },
    }

    rule_index = position.get(finding.rule_id)
    if rule_index is not None:
        result["ruleIndex"] = rule_index

    # SARIF reads a second entry in `locations` as "and this one has to be
    # changed too". Several files registering one route are corroboration, not
    # a list of edits, so they belong in `relatedLocations`.
    if len(locations) > 1:
        result["relatedLocations"] = locations[1:]

    if suppression is not None:
        # `external` is the accurate kind: the decision lives in .alibi.yml or
        # on the command line, not in an annotation in the source file.
        entry_note = {"kind": "external"}
        if suppression.why:
            entry_note["justification"] = suppression.why
        result["suppressions"] = [entry_note]

    return result


def _locations(finding: Finding) -> list[dict]:
    physical: list[dict] = []
    seen: set[tuple[str, int | None]] = set()

    for code_path in finding.entry.code_paths():
        path = code_path.get("path")
        if not path:
            continue
        line = code_path.get("line")
        # SARIF counts lines from one, and noir omits the line for
        # specification analyzers -- they point at a document rather than at a
        # statement in it. A region with no line would be a claim about where.
        start = line if isinstance(line, int) and line > 0 else None
        uri = _uri(str(path))
        if (uri, start) in seen:
            continue
        seen.add((uri, start))

        location = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        if start is not None:
            location["physicalLocation"]["region"] = {"startLine": start}
        physical.append(location)

    if physical:
        return physical

    return [{"logicalLocations": [{"name": str(finding.key), "kind": "resource"}]}]


def _uri(path: str) -> str:
    """Turn a noir code path into a URI reference a consumer can resolve.

    Noir echoes back whatever base path it was given, so an absolute scan
    yields absolute code paths. Relative to the working directory is what code
    scanning can line up against the repository; anything outside it can only
    be named absolutely. Either way a file path is not a URI -- a space or a
    `#` in a name has to be escaped, or the reference is not one.
    """
    location = Path(path)
    if not location.is_absolute():
        return quote(location.as_posix(), safe="/")
    try:
        return quote(location.relative_to(Path.cwd()).as_posix(), safe="/")
    except ValueError:
        return location.as_uri()


def _message(finding: Finding) -> str:
    entry = finding.entry
    vouched = ", ".join(sorted(entry.views))
    lines = [
        f"{finding.key} -- {finding.summary}.",
        f"Vouched for by {vouched}; match grade {finding.grade}.",
    ]

    reasons = [a.why for a in finding.adjustments if a.why]
    if reasons:
        why = "; ".join(reasons)
        lines.append(
            f"Severity {finding.base_severity} -> {finding.severity}: {why}."
        )

    if finding.uncertain:
        near = entry.near_misses[0]
        lines.append(
            f"Uncertain: {near.other} in {', '.join(sorted(near.other_views))} "
            f"-- {near.reason}. This may be a matching failure inside alibi "
            f"rather than a real gap."
        )

    return "\n".join(lines)
