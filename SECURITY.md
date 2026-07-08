# Security Policy

RCEKit is an offensive **RCE testing toolkit for authorised security
testing**. This policy covers vulnerabilities **in the tool itself** — please
read the scope section, because generating attack payloads is the tool's
intended function, not a vulnerability.

## Supported versions

Only the latest released version is supported. Fixes ship in a new version
(see `--version`); please upgrade before reporting.

| Version | Supported |
|---------|-----------|
| latest `2.x` | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security reports.** Instead, report
privately:

- Preferred: GitHub **Private Vulnerability Reporting** —
  *Security → Report a vulnerability* on this repository.
  (Maintainers: enable it under *Settings → Code security and analysis*.)
- Alternatively, contact the maintainer privately at
  `certification.kabiri@gmail.com`.

Please include:

- the version (`python rcekit.py --version`),
- a clear description and minimal steps to reproduce,
- the impact and any suggested fix.

You can expect an acknowledgement within **5 business days**. We aim to
validate and fix confirmed issues promptly and will credit reporters who wish
to be named. Please allow **coordinated disclosure** (a reasonable window to
fix before public details are shared).

## In scope

Genuine flaws in this project's own code, for example:

- the tool doing something the operator did not request (e.g. writing outside
  the intended output path, executing a payload on the operator's own host, or
  making network requests without an explicit flag);
- an unintended **bypass of the safety controls** (the `--acknowledge-consent`
  gate, safety tiers, the destructive-payload guard, or audit logging);
- crashes, path traversal, or injection triggered by untrusted **template**,
  **profile**, or manifest input;
- unsafe handling of files or subprocesses within the tool.

## Out of scope

- **The intended behaviour of the tool** — generating RCE/injection payloads,
  reverse shells, OOB callbacks, etc., is by design and is not a vulnerability.
- **Payloads succeeding against a target you point the tool at** — that is the
  purpose of authorised testing.
- **Misuse by third parties.** The maintainers are not responsible for use of
  this tool against systems without authorisation; such use is illegal and
  unethical.
- Findings that require running the tool against systems you are not
  authorised to test.

## A note on responsible use

This toolkit is provided for authorised penetration testing, security
research, education, and defensive training only. **Never use it against
systems without explicit permission.**
