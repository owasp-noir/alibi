# Changelog

Notable changes to alibi. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `.well-known` is a literal path segment, not a parameter. The regex-meta
  heuristic required a leading word character to recognise a filename, so
  every path under `/.well-known/` keyed as `/{}/...` -- colliding with any
  real `/{tenant}/...` and merging two endpoints into one.
- A format suffix keeps the resource name in front of it. `reports.{format}`
  leaves the literal `reports.`, which failed the same heuristic from the
  other end, so `/v2/reports.{format}`, `/v2/exports.{format}` and `/v2/{id}`
  were one endpoint.
- A spanning parameter meeting a single-segment one is a near miss. A
  specification cannot spell "and everything below this", so Flask's
  `<path:subpath>` and OpenAPI's `{subpath}` never met -- and one documented
  upload route was reported as a critical shadow API and a phantom contract at
  once.
- Code and contract paths are shown relative to the source that was scanned,
  matching what SARIF already emits. In the conflated-contracts block this was
  more than cosmetic: two directories of one tree printed as two unrelated
  ones, which is the reading that block exists to let you rule out.
- `REVIEW` lists doubt about the findings that were printed. It was built from
  the index, so it named entries that produced no finding, and printed in full
  the path of a finding the project had suppressed.
- The scope hint's `--ignore` suppresses exactly what its count named. The old
  pattern also removed the endpoint at the prefix itself, which the count
  treats as inside -- and which in the gRPC-gateway shape this hint appears in
  is the mount point.
- `alibi history` says when the two scans it compared were not given the same
  paths. Every rule can run in both and the comparison still be meaningless:
  two projects in one snapshot database reported each other's findings as
  progress.
- Two sources sharing a basename are two sources. `services/billing` and
  `services/search` merged into one bucket, and the per-source table printed
  two identical rows each claiming the other's endpoints.
- A suppression list that cannot be read is reported rather than raised: a
  malformed `--ignore` regex, invalid YAML, an `.alibi.yml` that is not a
  mapping, and a missing `--ignore-file` all reached the user as tracebacks.
  The list is now also read before noir runs, so a mistyped pattern does not
  cost a scan.
- The reason noir skipped a file survives into the report. The message was
  trimmed from the front, which on real absolute paths spent the whole budget
  on one path and dropped `file too large (12.35MB > 10.0MB)` -- the one fact
  explaining why a view is missing.

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
