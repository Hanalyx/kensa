# Phase 4 close — systemd D-Bus migration

**Closed: 2026-05-13.** Six deliverables shipped, ~1.5 days of execution against a ~1 week sketch budget. Phase 4 delivers the **D-Bus primitive layer** that future v1.x service-handler dual-paths consume; the handler ports themselves are an explicit v1.x backlog item by founder ratification.

## What shipped

| Deliverable | Merge | Summary |
|---|---|---|
| D-007 | `4e3185e` (PR #2) | `cmd/kensa-systemd-helper/` scaffolding + `internal/agent/systemd/` wrapper + `specs/agent/systemd-helper.spec.yaml`. D-Bus stubbed; argv + NDJSON contract locked. |
| D-008 | `7d2ca4b` (PR #3) | Real D-Bus `EnableUnitFilesContext` + `is-enabled` + `unit-state`. New `systemd_dbus` capability probe. Scope correction split the original D-008 (which conflated helper + handler port) into D-008 (helper) and a now-deferred handler-port deliverable. |
| D-009 | `f731a20` (PR #4) | Helper `disable` subcommand (`DisableUnitFilesContext`). |
| D-010 | `f731a20` (PR #4) | Helper `mask` subcommand (`MaskUnitFilesContext`). Co-landed with D-009. |
| D-011 | `8dbb966` (PR #5) | Helper `start` + `stop` with channel-based JobRemoved synchronization. First job-producing operations in the helper. Un-defers spec C-03 + AC-05 (subscribe-before-invoke ordering). |
| D-012 | this commit | Phase 4 close: atomicity contract refresh + CLAUDE.md cleanup + this document. |

## Architectural decisions

### Privilege model: Option C (founder-ratified 2026-05-13)

The kensa agent runs **unprivileged** (as the SSH user). For each systemd operation, the agent invokes `sudo /usr/libexec/kensa-systemd-helper <op> <unit>` as a subprocess. The helper opens the system D-Bus as root, performs the operation, prints structured NDJSON on stdout, and exits.

Two alternatives were considered and rejected:
- **A. Agent runs as root.** Simplest, but the wire-protocol parser, framing layer, and every handler would run with full privilege; a parser bug → root code execution. The existing four-agent peer review of fsatomic caught 3 P0s, demonstrating that this code surface can have vulns.
- **B. Agent unprivileged + polkit rules.** Textbook least-privilege, but polkit rule format diverges across distros (.pkla vs JavaScript syntax across RHEL 7/8/9/10), packaging adds an install-time intrusion into `/etc/polkit-1/`, AND the dominant privilege path (file ops via sudo) is unaffected. Decorative least-privilege.

Option C preserves the security model kensa already uses (`sudo systemctl enable foo`); the helper substitutes for that shell command. The wire-protocol parser stays unprivileged. The helper is small enough (~700 LoC including tests) to peer-review thoroughly.

### Scope correction: handler ports deferred to v1.x (Option 3)

The mid-flight D-008b deliverable (`service_enabled` handler dual-path Apply + Capture + Rollback) surfaced a scope problem: `service_enabled`'s rollback requires both `DisableUnitFiles` (D-009) AND `StopUnit` (the StartUnit-class operation that lands in D-011). A handler port without working rollback breaks the atomicity contract. After three rescoping options were surfaced, the founder ratified **Option 3**: Phase 4 ships the D-Bus primitive layer only; handler ports become a single v1.x backlog deliverable that has all the helper subcommands available from the start.

The atomicity contract is unchanged. The existing shell-out `service_enabled` / `service_disabled` / `service_masked` handlers continue to satisfy the documented `daemon-atomic (systemd)` basis per `TRANSACTION_CONTRACT_V1.md §2.6`. Dual-path handler consumption of the D-Bus primitive layer is a code-quality + observability upgrade with no contract change.

### NDJSON-on-stdout output discipline

Helper output is **NDJSON only on stdout**, with diagnostic messages on stderr. This is spec C-02 and the AC-04 envelope-shape contract. The agent's parser reads the last non-empty NDJSON line from stdout; anything else on stdout would be an output-confusion attack surface. Locked by:
- The helper code structure: every emit path goes through `writeNDJSON(stdout, &resp)` — no `fmt.Print*(os.Stdout, ...)` anywhere.
- `TestStdoutIsExactlyOneNDJSONLine` asserts exactly one newline per stdout payload.

### Schema version envelope (fail-closed)

Every NDJSON line carries `schema_version: 1`. The agent rejects helpers reporting a `schema_version` it doesn't understand with `ErrSchemaUnsupported` — fail-closed. The corollary AC-10 binary-version envelope (`helper_version`) is **informational-only**: agent emits a stderr warning on mismatch but does not fail the operation. Schema is the contract; binary version is diagnostic.

### JobRemoved synchronization (D-011)

`StartUnit` and `StopUnit` are the only job-producing operations in Phase 4. The helper uses coreos/go-systemd's channel-based pattern: pass a non-nil buffered `chan<- string` to the method; the library registers it against the resulting job path atomically (`jobListener` mutex held across method call + map insert). The signal handler that dispatches JobRemoved acquires the same mutex; this means the channel cannot miss the signal. Spec C-03 mandates the channel must be non-nil at the invocation site — passing nil would leave the signal nowhere to land, surfacing as a false timeout failure on instantaneous jobs.

`runJobUnit()` is the shared implementation; both `runStart` and `runStop` delegate to it. AC-05's three-part assertion (non-nil channel, buffered channel, select-with-timeout) is locked in fakeConn-based unit tests.

## Capability probe

`detect.systemd_dbus` returns true when all three conditions hold:
1. `/run/dbus/system_bus_socket` exists (system D-Bus reachable).
2. `/usr/libexec/kensa-systemd-helper` is executable (kensa-rpm installed the helper).
3. `systemctl --version` succeeds (systemd is the init system).

The probe runs in the unprivileged agent process. The helper's privileged D-Bus call is what exercises actual root D-Bus access; the agent-side probe just checks "can we even attempt the helper."

## Packaging requirement (post-Phase 4)

The kensa-rpm spec file must install:
- `/usr/libexec/kensa-systemd-helper` — the binary, mode 0755, root:root.
- `/etc/sudoers.d/kensa-systemd-helper` — sudoers fragment, mode 0440:

```
%kensa ALL=(root) NOPASSWD: /usr/libexec/kensa-systemd-helper
```

Operators add their service account to the `kensa` group at install time. The exact-path grant (no wildcards, no path prefixes) is mandated by spec C-06 — a permissive sudoers entry would erase the Option C privilege story.

The packaging deliverable itself is post-v1.0 and tracked separately. Spec AC-09 stays deferred until the .spec file lands. Today's developer setup invokes the helper from `bin/kensa-systemd-helper` with manually-configured sudoers; production deployment is gated on the RPM.

## v1.x backlog

- **Handler ports** (`service_enabled` / `service_disabled` / `service_masked` dual-path Apply + Capture + Rollback consuming the helper). Estimated ~2 days; primary risk is the Enable-then-Start composite Apply (`service_enabled` does both; rollback must handle partial-success cleanly).
- **Phase 5 (AUDIT_NETLINK)** uses `elastic/go-libaudit` for the `audit_rule_set` handler; ~2 weeks per the sketch in DELIVERABLES.md.
- **Phase 7 (SELinux runtime + dconf D-Bus)** reuses the `godbus/dbus/v5` dep Phase 4 added; ~1 week per the sketch.

## Verification

- `go test ./...` — 56/56 packages green on every merge.
- `specter check --strict` — 86/86 specs structurally clean.
- `make spec-coverage-strict` — 86/86 passing, including all 9 in-scope `agent-systemd-helper` ACs (AC-01..AC-08 + AC-10 + AC-11; AC-09 sudoers deferred).
- L-004 (RHEL 8 glibc 2.28) + L-005 (Alpine musl) portability gates — green on every Phase 4 PR. `coreos/go-systemd v22.7.0` + transitive `godbus/dbus/v5 v5.1.0` pass `CGO_ENABLED=0 -tags netgo` static-link discipline.
