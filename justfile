alias b := build
alias t := test
alias c := check
alias f := fix
alias vc := version-check
alias vu := version-update
alias s := scan

# List available tasks.
default:
    @just --list

# Install the project and its dev dependencies into .venv.
[group('build')]
setup:
    uv sync --group dev

# Build the wheel and sdist into dist/.
[group('build')]
build: clean
    uv build

# views.yml and rules.yml reach the wheel only because hatchling includes
# non-Python files in the package directory by default. That is a default, not
# a declaration -- a wheel without them installs cleanly and fails on first
# use. release.yml runs this same check before publishing.
#
# Build, then assert the wheel is one people can actually use.
[group('build')]
build-check: build
    @python3 -m zipfile -l dist/*.whl | grep -q 'alibi/views.yml' && echo "ok  views.yml"
    @python3 -m zipfile -l dist/*.whl | grep -q 'alibi/rules.yml' && echo "ok  rules.yml"
    @rm -rf .build-check && python3 -m venv .build-check
    @.build-check/bin/pip install --quiet dist/*.whl
    @echo "ok  installs as $(.build-check/bin/alibi --version)"
    @rm -rf .build-check

# Remove build artifacts and caches.
[group('build')]
clean:
    rm -rf dist/ build/ .build-check/
    rm -rf .pytest_cache/ .ruff_cache/
    find . -name __pycache__ -type d -prune -exec rm -rf {} +

# Run the whole suite.
[group('development')]
test:
    uv run pytest -q

# Run one test file or node: `just test-one tests/test_rules.py`.
[group('development')]
test-one TARGET:
    uv run pytest -q {{TARGET}}

# The six end-to-end tests skip themselves when noir is absent, and those are
# the only ones exercising the contract this tool is built on. A green run
# without them has not tested the integration.
#
# Run the end-to-end tests, naming any that skipped.
[group('development')]
test-noir:
    uv run pytest -q -rs tests/test_end_to_end.py

# Check lint without changing anything.
[group('development')]
check:
    uv run ruff check .

# Auto-fix what ruff can fix.
[group('development')]
fix:
    uv run ruff check --fix .

# Lint, test and version-check -- what CI will say, before pushing.
[group('development')]
ci: check test version-check

# Scan a path with the working tree's alibi: `just scan ./some/repo`.
[group('development')]
scan +PATHS=".":
    uv run alibi scan {{PATHS}}

# Report technologies the installed noir knows that views.yml does not place.
[group('development')]
doctor:
    uv run alibi doctor

# Check that every file carrying a version agrees with pyproject.toml.
[group('release')]
version-check:
    @python3 scripts/version.py check

# Set the version everywhere and roll the changelog: `just version-update 0.2.0`.
[group('release')]
version-update VERSION:
    @python3 scripts/version.py update {{VERSION}}

# Stops short of tagging. Pushing the tag is the irreversible step -- PyPI does
# not allow a file to be replaced once it is uploaded -- so it stays a thing a
# person types.
#
# Everything the tag will be judged on, in the order release.yml runs it.
[group('release')]
release-check: version-check check test build-check
    @echo
    @echo "Ready. To publish:"
    @echo "  git tag v$(python3 scripts/version.py check | head -1 | cut -d' ' -f2)"
    @echo "  git push origin --tags"
