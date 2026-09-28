"""Passthrough flags that would make a scan look clean must be refused."""

import pytest

from alibi import collect
from alibi.cli import EXIT_ERROR, main


@pytest.mark.parametrize(
    "extra",
    [
        ["--diff-ref", "HEAD"],
        ["--diff-ref=main"],
        ["--diff-path", "/tmp/old"],
        ["--diff-path=/tmp/old"],
        ["-f", "yaml"],
        ["-fyaml"],
        ["-f=json"],
        ["--format", "yaml"],
        ["--format=sarif"],
        ["--no-log"],
        ["--nolog"],
        ["--only-techs", "python_flask"],
        ["--only-techs=python_flask,oas3"],
        ["--exclude-techs", "har"],
        ["--exclude-techs=oas3"],
    ],
)
def test_each_dangerous_class_is_refused(extra):
    with pytest.raises(collect.DangerousNoirArg, match="refusing"):
        collect.refuse_dangerous_noir_args(extra)


@pytest.mark.parametrize(
    "extra",
    [
        [],
        None,
        ["--exclude-path", "**/tests/**"],
        ["--exclude-path=**/vendor/**"],
        ["--concurrency", "2"],
        ["--tls-skip-verify"],
        ["--verbose"],
        ["-t", "python_flask"],
        ["--techs", "python_flask"],
        ["--fail-on", "added"],
    ],
)
def test_harmless_passthrough_is_allowed(extra):
    collect.refuse_dangerous_noir_args(extra)


def test_refusal_names_the_flag_and_why():
    with pytest.raises(collect.DangerousNoirArg, match="--only-techs") as caught:
        collect.refuse_dangerous_noir_args(["--only-techs", "flask"])
    assert "per-view" in str(caught.value)


def test_cli_refuses_via_noir_arg(capsys):
    code = main(["scan", ".", "--noir-arg=--format=yaml",
                 "--noir-bin", "/nonexistent/noir"])
    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "refusing --format" in err
    # Must not have reached the binary lookup -- the denylist is earlier.
    assert "no noir binary" not in err


def test_cli_refuses_via_bare_dash_dash(capsys):
    code = main(["scan", ".", "--", "--diff-ref", "HEAD",
                 "--noir-bin", "/nonexistent/noir"])
    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "refusing --diff-ref" in err
    assert "no noir binary" not in err


def test_cli_still_forwards_harmless_args_to_lookup(capsys):
    """Allowed passthrough must not trip the denylist before noir is found."""
    code = main(["scan", ".", "--noir-arg=--exclude-path=**/tests/**",
                 "--noir-bin", "/nonexistent/noir"])
    assert code == EXIT_ERROR
    assert "no noir binary" in capsys.readouterr().err


def test_short_format_flag_names_the_long_form_too():
    with pytest.raises(collect.DangerousNoirArg, match=r"-f / --format"):
        collect.refuse_dangerous_noir_args(["-f", "plain"])
