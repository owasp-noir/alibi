# Changelog

Notable changes to alibi. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-30

First release. Runs [noir](https://github.com/owasp-noir/noir) once per view,
joins the results, and reports the endpoints that no second view can account
for.

### Added

- `alibi scan` compares all five of noir's views -- code, doc, traffic,
  gateway and infrastructure -- by scanning each source once per view with
  `--only-techs`, so that endpoints two views agree on are not deduplicated
  into one before they can be counted as corroboration.
- Eight rules over those views: `ORPHAN`, `LIVE_UNDOC`, `SHADOW`, `DANGLING`,
  `DRIFT`, `PHANTOM`, `UNEXPOSED` and `COLD`. Severity then shifts on noir's
  taggers -- personal data, file uploads, no sign of authentication, a method
  that changes state.
- Path normalization across framework route syntaxes, on the rule that a path
  parameter's name is not part of its identity. Findings carry a match grade:
  `G1` the spellings already agreed, `G2` they agree once normalized, `G0`
  only one view has it.
- Near-miss detection. An endpoint found in one view is checked against the
  others for a same-path-different-verb or one-segment-apart match; findings
  carrying one are demoted and flagged, and the count is printed beside the
  totals.
- Held-back rules. A rule only runs when every view it reasons about was in
  the scan, and two populated views sharing no endpoint at all suppress the
  comparison rather than reporting it as hundreds of findings. Both are named
  in the report.
- Reachability coverage for the gateway and infrastructure views, which answer
  *does this reach that endpoint* rather than *does this contain it*.
- `-f json` and `-f sarif` output. A scan noir could not read in full reports
  `executionSuccessful: false`, so a degraded run does not pass as a clean one.
- `--fail-on SEVERITY` for gating in CI.
- `--snapshot` and `alibi history`, which record which rules evaluated so that
  a rule that stopped running is not read as a pile of resolved findings.
- Suppression through `.alibi.yml` or `--ignore REGEX`. Suppressed findings
  are counted and the count is printed.
- `alibi doctor`, which reports technologies this noir build knows that the
  view map does not.
- `--noir-arg` and a bare `--` for passing flags through to noir.
- `alibi --version`.
- A minimum noir version of 1.0.0, checked before a scan is spent.

[Unreleased]: https://github.com/owasp-noir/alibi/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/owasp-noir/alibi/releases/tag/v0.1.0
