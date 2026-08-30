# Security policy

## Reporting a vulnerability

Report privately through
[GitHub security advisories](https://github.com/owasp-noir/alibi/security/advisories/new).
Please do not open a public issue for a vulnerability.

## Scope

alibi runs `noir` as a subprocess and parses its JSON. It makes no network
requests of its own and sends nothing anywhere. What it reads is whatever the
user pointed it at.

Two things are worth knowing when judging a report:

- **Scanned content reaches a report, not a shell.** Paths, parameter names and
  tags come out of the sources under scan, which for this tool are frequently
  untrusted. They are passed to noir as arguments to `subprocess.run` with an
  argument list -- never a shell string -- and rendered into text, JSON or
  SARIF output. A path in a scanned file that escapes into command execution or
  into a SARIF consumer as markup is in scope.
- **A wrong finding is a bug, not a vulnerability.** A missed shadow API or a
  false positive belongs in the issue tracker.

Also in scope: a crafted source tree that makes alibi write outside the paths
it was given, and anything in the `--snapshot` SQLite database that a scanned
repository can control in a way that affects a later run.

## Supported versions

The most recent release.
