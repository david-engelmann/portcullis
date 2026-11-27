# Security Policy

## Supported Versions

Security fixes land on the `0.2.x` release line. Versions prior to `0.2.0` do not receive security patches.

## Security Model

Portcullis evaluates structured tool-call records against a policy in the fixed evaluation order of `CONTRACT.md` and appends decisions to a local audit log under an exclusive file lock. The library executes zero tool calls, performs zero network access, and holds zero credentials. Malformed calls and policy errors fail closed before any rule or decision model referral is reached.

## Reporting a Vulnerability

Do not open a public issue for a suspected security vulnerability. Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/david-engelmann/portcullis/security/advisories/new) with a minimal synthetic policy and call record, the affected version, and the contract obligation involved. Every report receives an initial review within seven days, and confirmed fixes ship with a regression pin in the test suite before public disclosure.
