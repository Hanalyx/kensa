# Kensa guide for administrators and engineers

_Applies to: Kensa v0.7.6 — last updated 2026-07-10._

The operator-facing manual for Kensa. Read in order if you are new to
Kensa; jump in by topic otherwise.

## Audience

You are an SRE, sysadmin, or platform engineer running Kensa against
real Linux fleets. You know SSH, sudo, systemd, SELinux, and YAML.
You want to know what Kensa does, how to run it, what guarantees it
makes, and what to do when something goes wrong.

## Contents

| # | Chapter | What you'll learn |
|---|---|---|
| 01 | [Install](01-install.md) | RPM and tarball install, key generation, the `kensa-rules` package |
| 02 | [Quickstart](02-quickstart.md) | First scan, first remediation, first rollback |
| 03 | [Concepts](03-concepts.md) | Atomicity, capturable handlers, capability gating, evidence envelopes |
| 04 | [Scan and remediate](04-scan-and-remediate.md) | `kensa check`, `kensa remediate`, output formats, inventory mode |
| 05 | [Rollback and history](05-rollback-and-history.md) | `kensa rollback`, `kensa history`, sessions, `kensa verify` |
| 06 | [Rule authoring](06-rule-authoring.md) | Rule YAML, capability gating, framework refs, validation |
| 07 | [Integration](07-integration.md) | OpenWatch, CI/CD, SSH configuration, agent mode |
| 08 | [Troubleshooting](08-troubleshooting.md) | Common errors, debug flags, support bundles |
| 09 | [Reference](09-reference.md) | Every flag, exit code, env var, schema |
| 10 | [Mechanisms](10-mechanisms.md) | Every remediation mechanism and the reversal you get |

## Status

All ten chapters are written and validated against the `kensa` binary at
v0.7.6. Each chapter carries an _"Applies to"_ line.

## How to read this guide

- Every command shown is runnable against a current `kensa` binary.
- Flag names are exact; backticks indicate verbatim CLI tokens.
- Exit codes follow GNU/POSIX: `0` success, `1` runtime error, `2`
  usage error. Subcommand-specific exit codes are called out in each
  chapter.
- Atomicity claims (capture, rollback, deadman) describe tested,
  released behavior.

## Versioning

This guide is published with the binary it documents. The version on the
cover matches the release it ships with. Breaking changes between versions
are listed in the release notes.
