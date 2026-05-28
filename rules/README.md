# rules/ — the Kensa rules corpus

The 539 YAML rules in this tree are the inputs to `kensa check` and
`kensa remediate`. The binary carries **no embedded corpus**; this
directory is the source of truth.

## Layout

Rules are grouped into 8 topic directories — purely organizational, the
loader walks recursively so the layout is for humans, not the engine:

| Topic            | Scope                                                   |
|------------------|---------------------------------------------------------|
| `access-control` | PAM, authselect, faillock, sudo, login banners          |
| `audit`          | auditd rules, audispd, augenrules                       |
| `filesystem`     | mount options, file permissions, owner/group, paths     |
| `kernel`         | sysctl, modules, boot params (the `grub_parameter_*` family) |
| `logging`        | rsyslog/journald config, log rotation, audit forwarding |
| `network`        | sshd, firewalld/iptables, network sysctls, MTA          |
| `services`       | systemd unit enable/disable/mask, package presence/absence |
| `system`         | SELinux, DNF/APT, repo trust, vendor support            |

## Consumed by

- `kensa check --rules-dir <here>` — read-only compliance scan.
- `kensa remediate --rules-dir <here>` — transactional apply.
- The `kensa-rules` package (rpm/deb, noarch) installs this directory to
  `/usr/share/kensa/rules`. With the `kensa-rules` package present the
  `--rules-dir` flag is optional; `cmd/kensa.loadRulesFromDirOrFiles` falls
  back to the default path per `specs/rule/default-path-resolution.spec.yaml`.

## Schema

Every rule conforms to the contract in `docs/CANONICAL_RULE_SCHEMA_V1.md`
(`docs/` is local-only; the schema is enforced by the loader at
`internal/rule/`). Validate the whole corpus with:

```bash
make build
./bin/kensa-validate --rules-dir rules
```

A green run reports `539 file(s): 0 error(s)`. Stylistic warnings
(`W005` and friends) are advisory — not gates.

## Provenance

These rules originated in the archived Python kensa repo at
`/home/rracine/hanalyx/kensa.archive/rules` and were vendored into this
Go codebase on 2026-05-28 to give the `kensa-rules` package something to
ship. Subsequent edits land here directly; the archive is frozen.
