# Security Policy

NDIF is public-alpha instrumentation tooling. It is expected to have rough edges, but security-sensitive issues are still worth reporting responsibly.

## Supported Versions

Only the current `main` branch public alpha is supported.

## Reporting

Please do not open a public issue for a vulnerability that enables unauthorized access, privilege escalation, or unsafe execution behavior.

Report privately to the repository owner with:

- affected commit or release
- build configuration and Windows version
- concise reproduction steps
- expected behavior and observed behavior
- any crash dumps or logs that are safe to share

## Scope

In scope:

- memory corruption in NDIF code
- unsafe default behavior in public-alpha tooling
- vulnerabilities in the plugin ABI or loader behavior
- issues that make the documented defensive/research scope materially unsafe

Out of scope:

- reports requiring unauthorized access to third-party systems
- issues in private/local projects not shipped in the public alpha
- generic malware or evasion requests

## Use Policy

Use NDIF only on software and systems you own or have explicit permission to analyze.
