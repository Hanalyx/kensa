# Security policy

Kensa is a transactional configuration-management engine that makes privileged
changes to production Linux hosts. Security reports matter to us, and we want
them. This policy tells you how to report a vulnerability in Kensa, what happens
after you do, and what protections you have when you research in good faith.

## Report a vulnerability

Report a vulnerability through either channel:

- **Email** `security@hanalyx.com`. For a sensitive report, encrypt it with the
  Hanalyx GNU Privacy Guard (GPG) public key in [`KEYS`](KEYS) (master
  fingerprint `4CB7 0E1C 0942 6E43 CBBA D280 4AA0 538F E239 E50C`).
- **GitHub**, through [private vulnerability reporting](https://github.com/Hanalyx/kensa/security/advisories/new)
  on this repository.

Don't open a public issue, pull request, or discussion for a security report.
Public disclosure before a fix puts operators at risk.

## What to include

A report we can act on quickly has:

- The Kensa version (`kensa --version`) and how you installed it: package,
  tarball, or source.
- The affected component or command, with the exact file path or code reference
  if you have one.
- Steps to reproduce, including a minimal rule or configuration where it helps.
- The impact you observed, and the access or preconditions an attacker needs.

## What happens next

- We acknowledge your report within 3 business days.
- We investigate, confirm the issue, and send you our assessment and a target
  fix timeline.
- We keep you updated as we work, and we tell you when a fix ships.
- We assign a Common Vulnerabilities and Exposures (CVE) identifier, with a
  Common Weakness Enumeration (CWE) classification, for every confirmed
  vulnerability in Kensa.
- We credit you in the advisory and the changelog, unless you ask us not to.

## Coordinated disclosure

We follow coordinated disclosure. After we acknowledge your report, give us up
to 90 days to ship a fix before you disclose publicly. If a fix needs longer,
we tell you why and agree on a date with you. We aim to publish the advisory and
credit you at the same time the fix ships.

## Safe harbor

We consider security research that follows this policy to be authorized, and we
won't pursue or support legal action against you for it. To stay in scope:

- Act in good faith, and only to the extent needed to find and report a
  vulnerability.
- Don't access, change, or keep data that isn't yours.
- Don't degrade or disrupt any system, and don't run a denial-of-service test.
- Don't research against a third party's hosts without their permission. Kensa
  changes the Linux hosts an operator points it at, so test only against systems
  you own or are authorized to use.
- Give us a reasonable time to fix the issue before you disclose it.

If you're unsure whether an action is authorized, ask us first at
`security@hanalyx.com`.

## Scope

In scope:

| Component | Examples |
|---|---|
| The Kensa binaries | `kensa`, `kensa-validate`, `kensa-keygen`, `kensa-systemd-helper` |
| The public Go packages | `github.com/Hanalyx/kensa/api`, `github.com/Hanalyx/kensa/pkg/kensa` |
| The rule corpus | The content of the `kensa-rules` package |
| The release supply chain | Package signing, the checksums file and its cosign signature, and the trust material in `KEYS` |

Out of scope:

- The Linux hosts an operator manages with Kensa. Those are the operator's
  systems, and a setting an operator chooses to apply isn't a Kensa
  vulnerability.
- Findings that need an already-compromised host, or the root-equivalent access
  the trust model already assumes.
- Deliberate design decisions, including the passwordless-`sudo`-only model and
  the air-gap, no-network-fetch posture. If you think one of these has an
  exploit path we didn't intend, report it and explain the path.
- Denial of service, social engineering, and physical attacks.
- A vulnerability in a dependency with no Kensa-specific exploit path. Report
  those to the dependency's maintainers, and tell us if Kensa's use of it makes
  the impact worse.

## Supported versions

Kensa is pre-1.0. Security fixes land in a new patch release on the current
minor line, and we support only the most recent tagged release (see
[the releases page](https://github.com/Hanalyx/kensa/releases/latest)).

| Version | Security fixes |
|---|---|
| Latest release | Yes |
| Any earlier release | No. Upgrade to the latest release. |

Verify a release before you run it. Every release ships GPG-signed packages and
a cosign-signed checksums file, both anchored to the keys in [`KEYS`](KEYS). The
[install guide](docs/guide/01-install.md) has the verification steps.

---

**Last reviewed:** 2026-06-15.
