# rules/: the Kensa rules corpus

The YAML rules in this tree are the inputs to `kensa check` and
`kensa remediate`, and this directory is their source of truth. The
`kensa` binaries carry **no embedded corpus**. They read it at run time,
so the corpus can be updated without a binary release.

This directory is also the Go package `github.com/Hanalyx/kensa/rules`
(`embed.go`). It embeds the corpus for programs that link the Kensa
module, so they get the engine and the corpus of one module version.

## Layout

Every rule lives exactly one level down, in a topic directory:
`rules/<topic>/<rule-id>.yml`. The embedded package and the release
tarball select rules at that depth, and a test fails if a rule file is
placed anywhere else, is a symlink, or sits under a `testdata`
directory. Keep test fixtures out of this tree. Rules are grouped into 8
topic directories:

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

- `kensa check --rules-dir <here>`: read-only compliance scan.
- `kensa remediate --rules-dir <here>`: transactional apply.
- The `kensa-rules` package (rpm/deb, noarch) installs the rule files and
  this README to `/usr/share/kensa/rules`, staged by
  `scripts/stage-corpus.sh` so the Go source here is not installed. With the `kensa-rules` package present the
  `--rules-dir` flag is optional; `cmd/kensa.loadRulesFromDirOrFiles` falls
  back to the default path per `specs/rule/default-path-resolution.spec.yaml`.
- The Go package in this directory: `rules.FS()` returns the embedded
  corpus, loaded with `pkg/kensa.LoadRulesFS` and its siblings.

## Schema

Every rule conforms to the V1 rule schema, which the loader at
`internal/rule/` enforces. Validate the whole corpus with:

```bash
make build
./bin/kensa-validate --rules-dir rules
```

A green run reports `0 error(s)` for every file. Stylistic warnings
(`W005` and friends) are advisory, not gates.

## Provenance

These rules originated in the archived Python kensa repo at
`/home/rracine/hanalyx/kensa.archive/rules` and were vendored into this
Go codebase on 2026-05-28 to give the `kensa-rules` package something to
ship. Subsequent edits land here directly; the archive is frozen.
