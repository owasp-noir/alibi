# Contributing

## Setting up

```console
$ uv sync --group dev
$ uv run pytest -q
$ uv run ruff check .
```

[noir](https://github.com/owasp-noir/noir) 1.0.0 or newer on `PATH` is
optional for development but not for judging a change. Six end-to-end tests
skip themselves when it is absent, and those are the only ones that exercise
the contract this tool is built on -- noir's JSON, its `list techs` catalog,
its tagger output. `pytest -rs` names what skipped; if the noir tests are in
that list, the suite has not tested the integration.

`uv run alibi doctor` reports technologies the installed noir knows that
`views.yml` does not place.

## What a change has to carry

- **A test that fails without it.** The commit history is a record of specific
  wrong answers on real repositories; `tests/` is where each one is pinned so
  it does not come back.
- **The reason, in the code.** Comments here explain why a rule exists, not
  what the line does -- usually by naming the repository and the number that
  made it necessary. A threshold with no such note is a threshold nobody can
  safely change later.

## Rules and views are data

`src/alibi/rules.yml` and `src/alibi/views.yml` are read, not compiled. A new
rule or a newly-mapped technology is usually a change to those files and a
test, not to Python.

## Releasing

1. Update `version` in `pyproject.toml` and move the `Unreleased` section of
   `CHANGELOG.md` under the new number.
2. Merge that to `main`.
3. Tag it: `git tag v0.2.0 && git push origin v0.2.0`.

`.github/workflows/release.yml` takes it from there -- it refuses a tag that
disagrees with `pyproject.toml`, runs the suite, checks that the wheel carries
`views.yml` and `rules.yml`, publishes to PyPI through Trusted Publishing, and
opens the GitHub release. There is no API token to hold.
