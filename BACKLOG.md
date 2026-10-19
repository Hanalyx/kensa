# Kensa Backlog

Actionable defects and residual work. Each item carries a stable ID made of a
feature ID and a number, for example `PT-04.1`. The feature IDs group work into
three queues:

- **PT, protect the promise:** truthful verdicts, restoration and trustworthy
  evidence;
- **CV, expand useful coverage:** having a rule, selecting it correctly,
  observing it run, and proving its assertion matches the control;
- **AD, improve adoption:** interfaces, packaging, integration and maintenance.

Items are ordered by priority within each feature. Nothing here is a
scheduling commitment.

**Baseline.** Source references are to tag `v0.12.0` (commit `97fcd7b`), as
`path:line`. "First tag" is the earliest release tag that contains a change.
Where an item says "not re-verified", its text comes from the earlier backlog
and was not checked against v0.12.0 in the 2026-10-19 reconciliation.

**Earlier text.** The backlog as tagged in v0.12.0 is the historical record of
every earlier entry: `git show v0.12.0:BACKLOG.md`. Entries closed in the
reconciliation are listed in "Closed on 2026-10-19", with the change that
closed each one.

---

## PT: Protect the promise

### PT-03 Deadman guard

Most of the scheduler redesign shipped in #368 (first tag v0.9.0): an absolute
systemd deadline, pinned timer accuracy, a script directory outside `/tmp`, a
fired marker checked before shell cancellation, a lock between the two legs,
and a cancel that tries every armed timer. Cancellation remains partial.

- **PT-03.1 [Red, FOUNDER-GATED] The engine reports `armed = true` for
  control-channel `command_exec` transactions that schedule no timer.**
  `shouldArmDeadman` keys on mechanism only (`internal/engine/preflight.go:24-31`;
  `command_exec` is `true` at `:55`). With nothing to roll back, `armViaShell`
  and `armViaAgent` return `recordInert(...)` with a nil error
  (`internal/engine/deadman/deadman.go:272`, `:310`, `:387-392`), and
  `internal/engine/engine.go:375-378` sets `armed = true`. No `api/` field
  separates "guarded" from "inert". The affected rule count must be taken with
  `kensa plan` per rule, not by grep.
- **PT-03.2 [Red, FOUNDER-GATED] Shell cancellation can report success without
  establishing that rollback was prevented.** `ssh.Transport.Run` returns ssh
  exit 255 with a nil error (`internal/transport/ssh/ssh.go:384-397`). With
  only the systemd leg armed, `cancelOne` checks only the error
  (`internal/engine/deadman/deadman.go:920-923`), `verifySystemdUnitGone` accepts
  empty output (`:992-1024`), and `deadmanAlreadyFired` reads it as not fired
  (`:649-653`). The engine can commit while a timer remains armed
  (`internal/engine/engine.go:418-428`). The marker is checked only before
  cancellation (`deadman.go:449-471`): a timer can fire afterward, with no
  subsequent marker check before success. The `at` path checks `atrm`'s
  result (`:902-909`), but `verifyAtJobGone` accepts empty stdout without
  checking `ExitCode` (`:964-972`). A failed observation is not proof of
  absence. `TestUnverifiableCancelIsNotSuccess`
  (`internal/engine/deadman/at_timespec_test.go:774-795`) injects a Go transport
  error; it does not establish nonzero-exit handling with nil error or these
  concurrent orderings. Source-supported unresolved behavior; no new live
  reproduction.
- **PT-03.3 [Red, FOUNDER-GATED] Agent-mode cancel can interrupt rollback and
  cannot classify an already-fired arm.** `CancelDeadman` cancels a matching
  arm's watcher context, waits, and returns true
  (`internal/agent/deadman/armer.go:294-306`).
  That context also runs rollback commands (`:277-280`); cancellation can
  interrupt an active command and skip the remaining commands (`:282-285`).
  `cancelViaAgent` discards `wasActive`
  (`internal/engine/deadman/deadman.go:479-485`), and the agent removes the arm
  on watcher exit (`armer.go:246-249`). A cancel after firing, including after
  interrupted restoration, can return success and let the engine commit.
  Rollback command errors are discarded (`armer.go:277-285`), and without
  `pidfd` the fallback cannot run rollback when its parent is killed
  (`:113-117`, `:176-195`). The expanded cancellation paths are source-supported;
  no new live reproduction is claimed.
- **PT-03.4 Deadman keep-alive (spec deadman AC-07).** `Armer.Extend` re-arms
  the job during long applies; a failed keep-alive aborts the transaction. No
  `Extend` method exists.
- **PT-03.5 Clock-skew detection (spec deadman AC-10).** Compare the host's
  date before and after the script upload, and widen the window if skew
  exceeds 30s.
- **PT-03.6 Deadman wiring in engine tests (spec engine AC-06).** Use a
  recording armer and a control-channel-sensitive fake transport to verify that
  `Arm` runs before apply and `Cancel` after commit.
- **PT-03.7 Control-channel risk is classified by mechanism, not by what a rule
  touches.** Measured 2026-08-07: 105 rules use a mechanism classified as unable
  to cut the channel while their parameters point at SSH, PAM, firewall or
  network state (`sysctl_set` 39, `config_set_dropin` 33, `config_set` 30,
  `file_permissions` 3). The first half, mechanisms missing from the map, was
  closed in #391 (first tag v0.10.0) with a test. A per-handler or per-rule risk
  query closes this half. Whether `command_exec` should stay
  control-channel-sensitive is part of the same decision.
- **PT-03.8 An at-job armed by the deadman is not canceled on crash recovery.**
  From the v0.6.0 release review. Not re-verified.

### PT-04 Evidence signing integrity

The signing-order and payload-ownership fix shipped in #428 (first tag
v0.11.0). Its acceptance record is kept below, under "Evidence signing
integrity (2026-09-18)".

- **PT-04.1 [SECURITY, HIGH, Red-class, FOUNDER-GATED] `rollback_results` is
  serialized but not authenticated.** `envelopeCanonical` and `canonicalize`
  (`internal/evidence/signer.go:341-356`, `:372-392`) carry 14 of the 17
  `api.EvidenceEnvelope` fields. `Signature` and `SigningKeyID` are excluded by
  design; `RollbackResults` is excluded by nothing, so editing the record of
  whether restoration succeeded leaves `kensa verify` reporting a valid
  signature. Spec AC-03 promises that a tamper of any field invalidates the
  signature, and AC-01 omits the field. The fix needs a `schema_version` bump
  and a verifier that reports "valid v1 signature" separately from "rollback
  results authenticated". Verifying v1 must not imply the protection applied
  retroactively.
- **PT-04.2 [PENDING SEPARATE AUTHORIZATION] Historical exposure of retained
  records.** The signing-order defect is in every tagged release through
  v0.10.0. Checking retained field records needs its own authorization.
- **PT-04.3 Envelope JSON Schema (spec evidence-envelope AC-07 and AC-10).**
  Generate `internal/evidence/envelope-v1.json` from `api.EvidenceEnvelope`
  with a round-trip validator test, and add a CI comparison of the spec against
  the struct. Both tests are skipped today
  (`internal/evidence/signer_test.go:261`, `:272`). Native scan evidence is
  already validated against its schema.

### PT-05 Terminal persistence and truthful reporting

Errored transactions are persisted (`internal/engine/commit.go:249-265`). On a
terminal persistence failure, `committed`, `rolled_back` and `staged` are
demoted to `errored` and re-signed (`commit.go:157-168`, #428). The journal
entry is kept so recovery still sees the transaction (`commit.go:179-185`).

- **PT-05.1 [Red, FOUNDER-GATED] Some terminal statuses carry no persistence
  failure.** `partially_applied`, `rollback_failed` and `recovered` keep their
  status with a nil `Error` when persistence fails (`commit.go:174-177`).
  `Error` is set only for `errored`, so the failure has nowhere to go. Adding a
  carrier is a frozen `api/` question.
- **PT-05.2 Add a `recovered` case to the demotion matrix test**
  (`internal/engine/error_path_matrix_test.go:42-111`).
- **PT-05.3 Establish whether a later `kensa recover` re-runs a rollback that
  already happened** after a persistence failure on `partially_applied` or
  `rollback_failed`.

### PT-06 Post-apply validation

The mandatory post-apply recheck shipped in #122 (first tag v0.6.0).

- **PT-06.1 [Red] A recheck execution error commits as "unverified".**
  `recheck` sets `Passed=true` and puts "unverified" in the detail text
  (`internal/engine/validate.go:101-103`). No typed field carries it.
- **PT-06.2 [Red] The recheck runs with the pre-check's privilege, not the
  agent's** (`validate.go:34-44`). A root-only file can produce a clean FAIL and
  roll back a correct change.
- **PT-06.3 Validator injection has no production caller.** `WithValidators`
  (`internal/engine/validators.go:37`) and `WithInMemoryEvents`
  (`internal/engine/eventbus.go:143`) are never constructed outside tests, and
  the built-in `ServiceHealthValidator` and `ConfigSyntaxValidator` are unused.
  Expose them through a rule or CLI surface, or remove them. The test hook
  `engine.WithFakeValidator` (spec engine AC-03) belongs to the same decision.

### PT-07 Post-rollback state capture

Post-state recapture shipped in #125 (first tag v0.6.0).

- **PT-07.1 [Red, FOUNDER-GATED] A diverging post-state does not change the
  rollback verdict.** `commit.go:46-58` appends "DIVERGES from pre-state" to the
  step detail, and the status still derives from the handler's report. No test
  asserts that behavior. Making it demote `rolled_back` is a contract change.

### PT-08 `audit_rule_set` staging on immutable-audit hosts

Staging shipped in #325 (first tag v0.8.0), with `persist_only` in #400 (first
tag v0.10.0).

- **PT-08.1 Live gates have not run.** Immutable host to `staged`, mutable host
  to normal load, and the mid-run flip, each on a disposable host.
- **PT-08.2 [FOUNDER-GATED] The failure-mode analysis needs ratification.** The
  #325 commit labels it a draft pending founder ratification.
- **PT-08.3 Stale comment.** `api/kensa.go:244-245` says a status is always one
  of four values; there are eight.
- **PT-08.4 Confirm the consumer mapping for `staged`.** Not verified.
- **PT-08.5 [DISPUTED] Persist-file ordering.** The earlier finding: the default
  `99-kensa.rules` sorts after a `99-finalize.rules` holding `-e 2`, so its
  rules follow `-e 2` and never load, even at reboot. Upstream `augenrules`
  moves the last `-e` directive to the end of the generated file
  (`linux-audit/audit-userspace`: `init.d/augenrules.in` and `docs/augenrules.8`;
  the same logic exists at tag `v3.0`), so filename order alone does not
  establish the failure. Every corpus `audit_rule_set` rule also sets its own
  `persist_file`, so the default (`internal/handlers/auditruleset/auditruleset.go:47`)
  is unused. To settle it, on a disposable host with mutable audit on each OS
  family: write `-e 2` into `99-finalize.rules` and a watch into
  `99-kensa.rules`; run `augenrules` without `--load`; confirm the last line
  of `audit.rules` is `-e 2` with the watch before it; reboot; confirm
  `auditctl -s` shows `enabled 2` and `auditctl -l` lists the watch. A host
  that loads `audit.rules` without `augenrules` does not read `rules.d` at all,
  which is a different issue.
- **PT-08.6 A mixed staged and non-staged transaction skips the sibling's
  validation** (`internal/engine/engine.go:441-447`). No corpus rule does this
  today; refuse or validate before one does.

### PT-09 Handler rollback robustness

Whole-file capture is used for new `pam_module_arg` records (#143, first tag
v0.6.0) and by `pam_module_configure`. Byte-perfect shell capture shipped in
#264 (first tag v0.7.4). The mutable `audit_rule_set` rollback reads live
rules back and reports a partial restore if one is still loaded
(`auditruleset.go:723-747`).

- **PT-09.1 Legacy `pam_module_arg` restore.** Records written before #143 are
  restored by line-number `sed` plus a `.bak` fallback ending in `|| true`,
  which reports success when no `.bak` exists
  (`internal/handlers/pammodulearg/pammodulearg.go:477-545`, `:491`).
- **PT-09.2 Legacy `config_append` rollback.** Records without `prior_content`
  use `rollbackLegacySed` (`internal/handlers/configappend/configappend.go:295`,
  `:348-373`). Its quoting was fixed in #313; the path is not byte-perfect.
- **PT-09.3 Package removal takes dependents, and rollback does not restore
  them.** `package_absent` applies `dnf remove -y`, which removes dependents;
  capture records only the named package; rollback runs `dnf install -y <name>`
  without the dependents or the prior version
  (`internal/handlers/packageabsent/packageabsent.go:67`, `:92`, `:160`).
  `apt_absent` is the same (`internal/handlers/aptabsent/aptabsent.go:58`,
  `:142`). New in the reconciliation.
- **PT-09.4 `apt_present` and `package_present` rollback blast radius.**
  Rollback removes the package, and the package manager can remove dependents
  acquired in the meantime. A leaf-only guard would bound it.
- **PT-09.5 `audit_rule_set` netlink error handling.** The real
  `go-libaudit` `DeleteRule` never decodes the netlink errno, so the
  `unix.ENOENT` guard (`auditruleset.go:713`) is unreachable against the real
  client. The staged rollback reports success when reading live rules fails
  (`:679`, `:692-696`), and `BuildRule` errors in rollback are skipped (`:684`,
  `:708-710`, `:738-740`).
- **PT-09.6 Ownership and mode changes in the agent's kernel-IO path are not
  atomic.** No production code uses `fchownat` or `fchmodat`.

### PT-10 Input and injection hardening

Shell quoting of owner, group and mode shipped for `file_permissions` (#184,
first tag v0.7.0) and for `file_content`, `file_absent` and the legacy
`config_append` sed program (#313, first tag v0.7.6). Root-write input
hardening shipped in #241 (first tag v0.7.2).

- **PT-10.1 Data-flow injection sweep.** Trace every rule and `--var` value to
  each shell sink, and add a CI test that fails on an unquoted handler
  argument. Not re-verified.
- **PT-10.2 Lower-severity hardening SEC3 to SEC5:** username quoting,
  module-name path traversal, and `QuoteMeta` on regex input. Not re-verified.
- **PT-10.3 [LOW, security] The systemd helper honors
  `KENSA_HELPER_EUID_OVERRIDE` without a build-tag guard**
  (`cmd/kensa-systemd-helper/main.go:115`). Sudo's default `env_reset` strips
  it on the shipped path today. Put the override behind a test build tag.
- **PT-10.4 `--var` trust.** Keep the operator-trust note for variable values
  current in the documentation.

### PT-11 Service restart and reload

`restart`, `reload` and `notify` are parsed (`internal/rule/parse.go:91-93`,
`:255-269`) and exposed in the rule read model
(`pkg/kensa/catalog.go:256`). No code path restarts or reloads a unit, and the
systemd helper has no restart operation
(`cmd/kensa-systemd-helper/dbusops.go:94-108`). 68 rule files declare
`restart:` or `reload:`.

- **PT-11.1 Surface pending restarts in `remediate` output.**
- **PT-11.2 [FOUNDER-GATED] Decide what `restart:` means:** an instruction
  Kensa carries out, or metadata it reports.
- **PT-11.3 Add the missing `restart:` declarations.** The count needs
  re-deriving.
- **PT-11.4 Document the difference between "compliant" and "currently
  enforcing".**

### PT-12 Host-side pending-state query

- **PT-12.1 [FOUNDER-GATED] Decide the scope and release of a query that asks
  a host what is pending:** a staged audit rule, an armed bootguard trial, or
  an unapplied restart. Nothing answers this today.

### PT-13 Grouped atomicity

Remediation runs one transaction per rule (`internal/scan/scan.go:275`,
`:348`).

- **PT-13.1 [FOUNDER-GATED] Two blocking decisions:** the grouping key, and
  what failure aborts a group.
- **PT-13.2 The increments:** fix any documentation that promises run-wide
  atomicity; partition reversible from best-effort steps; coupling-based
  grouping; grouped by default; package-transaction capture.

### PT-14 Bootguard follow-ups

- **PT-14.1 [Red] A second arm silently discards the first trial.**
  `ArmOneshot` does not check for an existing trial
  (`internal/bootguard/oneshot.go:54-74`) and `recordTrial` overwrites it
  (`:244`).
- **PT-14.2 Check the trial-removal cleanup path.** Removing a trial by kernel
  path may delete the real default entry. Unverified.
- **PT-14.3 [Red] A trial that boots into rescue strands the host.** The
  confirm unit is ordered after `multi-user.target`
  (`internal/bootguard/confirm.go:66`, `:88`).
- **PT-14.4 [Red, v1.0 ship gate] RHEL 8 `$kernelopts` capture and restore.**
  No `kernelopts` handling exists, and `CheckArmable` does not refuse RHEL 8
  (`internal/bootguard/gate.go:68-80`).
- **PT-14.5 Verify bootloader flavor detection** rather than assume it.

### PT-15 Mechanical enforcement of the design rules

- **PT-15.1 Recorded transport transcripts and a strict fake.** Work exists on
  branch `test/recorded-transport-transcripts` only. `FakeTransport.Run` still
  returns exit 0 for any unprogrammed command
  (`internal/engine/testing.go:31-39`).
- **PT-15.2 Round-trip matrices for every capturable handler.** Matrices exist
  for the three `service_*` handlers only. The live round-trip harness is not
  in CI.
- **PT-15.3 [FOUNDER-GATED] Reversibility as a declared property.** Blocked on
  the repair-versus-refuse decision.
- **PT-15.4 Specs may not embed command syntax that no test executes.**
- **PT-15.5 Assert which `api` fields the engine populates for `ScanResult`.**
  `api.Plan` is covered (`internal/engine/plan_fields_test.go`).

### PT-16 Recovery and rollback operations

- **PT-16.1 `rollback --list` says "none have committed transactions"** when
  the store has no rollback-able session (`cmd/kensa/rollback_session.go:102`).
  The message does not match every reason a session is excluded.
- **PT-16.2 Crash-recovery integration test (spec engine AC-04).** Kill the
  engine after capture is persisted and before apply; verify that
  `kensa rollback` restores the host from the persisted pre-states.

### PT-17 Verdict and result surfaces

- **PT-17.1 [api, FOUNDER-GATED] A `manual` or `not_applicable` compliance
  verdict.** An additive frozen-`api/` change.
- **PT-17.2 [api] `RemediationResult` compliance-verdict surface.** `Remediate`
  reports transaction statuses only; already-compliant entries reuse
  `StatusCommitted` with a synthetic check step. Needs an `Outcomes`-style
  additive field.
- **PT-17.3 Remediation evidence host ID.** The `pkg/kensa` remediate path
  stamps it (`pkg/kensa/kensa.go:65`). A `scan.Runner` built without
  `WithHostID` still leaves it empty (`internal/scan/scan.go:57-60`).

---

## CV: Expand useful coverage

### CV-01 Cross-rule citation gates

The duplicate-citation gate and the check-versus-citation linter shipped in
#249 and #250 (first tag v0.7.2).

- **CV-01.1 Triage the 25 check-versus-citation allowlist entries still marked
  "pending triage"** (`internal/catalog/check_vs_cite_test.go:26-59`).

### CV-02 Fail-observed verification

A live round-trip harness shipped in #400 (`scripts/roundtrip.py`). Its
baselines cover `audit_rule_set` and `mount_option_set` and do not feed the
verification ledger.

- **CV-02.1 Add an observed-verdict field to the verification ledger**
  (`catalog/sources/verifications.json`): pass on a compliant host, fail on a
  violating host, or a full cycle.
- **CV-02.2 Define and document the two verification tiers.**
- **CV-02.3 Backfill audit of existing ledger entries.** The ledger was last
  changed in #360 (first tag v0.8.0).
- **CV-02.4 Negative-test harness beyond two mechanisms, run in CI or on a
  schedule.**
- **CV-02.5 Show the tier in any published corpus view.**

### CV-03 Benchmark coverage campaign

- **CV-03.1 Refresh the wave ledger from a fresh engine-produced
  measurement.** Do not publish a coverage percentage before that.
- **CV-03.2 `scripts/status.sh:29` reads the wrong column.** It prints awk
  field `$6`, which is DRIFT in `kensa-catalog coverage` output
  (`cmd/kensa-catalog/main.go:471-479`), as `cov_pct`. The correct field is
  `$7`. Every `cov_pct` it has written reads 0.
- **CV-03.3 GUI and smart-card controls need a graphical test host.** 12 STIG
  RHEL 10 controls (V-281225/226, V-281275, V-281278/280/282, V-281283,
  V-281285, V-281287, V-281291/292, V-281297) and 2 STIG RHEL 9 controls
  (V-258013, V-258032). All are dconf or gsettings lock-state controls that a
  headless host cannot fail-observe.
- **CV-03.4 RHEL 10 audit-syntax modernization:** a `dir=` matcher and the `-w`
  to syscall rewrite for the remaining CIS RHEL 10 controls.
- **CV-03.5 The RHEL 8 follow-up lists.** CIS: partial cite-adds, mis-cite
  reconciliations, net-new rules and manual dispositions. STIG: a suspected
  mis-cite of V-257258 in `shell-timeout.yml`. Not re-verified.
- **CV-03.6 [FOUNDER-GATED] Three STIG RHEL 8 control interpretations:**
  privileged `execve` auditing, the session-lock mechanism, and faillock
  pairing.
- **CV-03.7 [FOUNDER-GATED] The Ubuntu coverage target for v1.0.**
- **CV-03.8 Re-check the STIG RHEL 9 candidate list** (about 20 controls)
  against what #281 covered.

### CV-05 Capability refresh after dependency installation

- **CV-05.1 Re-detect capabilities after a dependency changes the host.**
  Detection runs once (`internal/scan/scan.go:256`) and every rule's selection
  reuses it (`:290`). `service-enable-firewalld` followed by
  `nftables-service-disabled` is a concrete case.

### CV-06 Runtime capturability versus declared metadata

- **CV-06.1 Share handler capability metadata with validation.** The
  validator's static list (`internal/rule/validate.go:217-222`) omits
  `crypto_policy_subpolicy`, whose handler is not capturable
  (`internal/handlers/cryptopolicysubpolicy/cryptopolicysubpolicy.go:59`).
  `crypto-policy-no-sha1`, `crypto-policy-strong-macs` and
  `crypto-policy-no-cbc-ssh` declare no `transactional:` key, so they default to
  true, pass validation, and are refused at engine preflight
  (`internal/engine/preflight.go:28-29`). `RuleSummary` reports them as
  transactional (`pkg/kensa/catalog.go:166-168`). Correct the three rule
  declarations too.
- **CV-06.2 Correct the preflight comment** that calls `crypto_policy_set`
  non-capturable (`internal/engine/preflight.go:85-88`); its handler returns
  true.

### CV-07 Capability gates and permissive fallbacks

#138 (first tag v0.6.0) removed the package-removal default from 20 GDM
configure rules; later changes in v0.10.0 gated or dropped eight more
permissive defaults.

- **CV-07.1 Two GDM rules still fall back to removing the `gdm` package**
  when the `gdm` capability is false: `gdm-dconf-database-current.yml` and
  `gdm-xdmcp-disabled.yml`. A missing capability must skip, not select a
  destructive default.
- **CV-07.2 Gate false-pass sweep classes B and D.** Absence-means-pass on a
  requirement, and passes where a peer fails, are review tools only
  (`scripts/false_pass_sweep.py:9-24`).
- **CV-07.3 Enforce or resolve rule conflicts before remediation.**
  `conflicts_with` produces an advisory warning only. Contradictory controls
  such as the GDM configure rules and `gdm-removed` both stay executable.

### CV-08 Distribution-specific service names

- **CV-08.1 [DEFERRED] Extend service rules whose Debian or Ubuntu unit name
  differs.** No alternative-name mechanism exists; rules use a per-distribution
  implementation gated `when: apt`, as in `kdump-disabled.yml`. About 11 to 17
  rules in `rules/services/` are RHEL-only today, including `chrony-enabled.yml`
  and `crond-service-enabled.yml`. Families: chrony, `crond`→`cron`,
  `httpd`→`apache2`, `named`→`bind9`, `nfs-server`→`nfs-kernel-server`, and
  `kdump`→`kdump-tools`. Verify each unit name on a host.

### CV-09 Rule faithfulness and structured checks

- **CV-09.1 Sweep for CIS-versus-STIG threshold conflicts:** rules that cite
  both with a single value assertion. The fix pattern is a STIG-strict
  companion rule, as in `password-encrypt-method-sha512.yml` and
  `ssh-host-key-permissions.yml`.
- **CV-09.2 Compare each `method: command` rule's assertion to its control's
  finding condition.**
- **CV-09.3 Reduce and test arbitrary command checks.** Prefer structured
  methods, and add fixtures for expected exit and output behavior and for
  check and remediation convergence.
- **CV-09.4 Resolve the W005 warning on `system/selinux-policy-targeted.yml`:**
  state that it is a next-boot control, or add a runtime check.
- **CV-09.5 Review which find-based `file_permissions` rules are safe to
  remediate automatically.**

### CV-10 Coverage-gap-aware output

`kensa coverage` reports NIST 800-171 against a measured denominator (#401,
#417). Other frameworks have no denominator.

- **CV-10.1 [FOUNDER-GATED] Decide how the control manifest is packaged.**
- **CV-10.2 Compute and print unassessed controls at scan level.**
- **CV-10.3 [api] `ScanResult.Unassessed`.** An additive frozen-`api/` field.

### CV-11 First-class CCI references

- **CV-11.1 [FOUNDER-GATED] Decide whether CCI becomes a top-level reference.**
  CCI appears today only as a STIG sub-field, in 71 rule files. A CMMC Level 2
  lens derived from the 800-171 mapping already shipped (#401).

### CV-12 Live verification of mechanisms

A historical run is evidence for its host and date only.

- **CV-12.1 [v1.0 ship gate] systemd D-Bus service handlers.** Blocked on an
  undiagnosed `EPERM` on `execve` from the sudo-spawned agent.
- **CV-12.2 `audit_rule_set` netlink rule load on a mutable-audit host.**
- **CV-12.3 PAM handlers:** `pam_module_arg`, `pam_module_configure` and
  `authselect_feature_enable` have no recorded live cycle. Run the
  `kensa-fuzz` matrix for `pam_module_configure` and `mount_option_set`.
- **CV-12.4 Reconcile `mount-var-log-options`:** #400 names a residue on it,
  and the round-trip baseline records it as "ok".
- **CV-12.5 A test host that needs a sudo password.**

---

## AD: Improve adoption

### AD-01 `kensa explain`

- **AD-01.1 [FOUNDER-GATED] Decide on an engine-sourced `kensa explain <rule>`**
  that prints each check's command and pass condition and the remediation, with
  a drift guard. No such command exists.

### AD-02 Corpus viewer

- **AD-02.1 Move the viewer generator into tracked source, with tests.** The
  `viewer` Makefile target (`Makefile:337-347`) does nothing in a fresh clone.
- **AD-02.2 Regenerate it in CI on every corpus change.**
- **AD-02.3 [FOUNDER-GATED] Choose the publish target.**
- **AD-02.4 Stamp each published view with its corpus revision.**

### AD-03 Framework-independent desired-state surface

- **AD-03.1 [DEMAND-GATED] A desired-state read model on `pkg/kensa`** with the
  check method, capability gates and framework projection functions.
  `RuleSummary` (`pkg/kensa/catalog.go:156-216`) has none of these. Build it
  when a consumer asks.

### AD-04 Inventory support across commands

- **AD-04.1 Inventory for `detect` and `remediate`.** Only `check` accepts
  `-i/--inventory` (`cmd/kensa/main.go:693-694`). For `remediate` this is a
  design question: per-host sessions and stores.
- **AD-04.2 Lift the `check` inventory limits:** file outputs, `--store`,
  `--password` and `--sudo-password` are rejected in inventory mode
  (`cmd/kensa/main.go:715-731`, `:876`, `:884`, `:895`).

### AD-05 JSON Lines output

- **AD-05.1 `remediate` does not accept `--format jsonl`.** `check`, `history`,
  `list sessions` and `info` do (`internal/output/json.go:46-75`).

### AD-06 OpenWatch integration

- **AD-06.1 OpenWatch moves to v0.12.0 and the embedded corpus.** Its `go.mod`
  pins v0.10.0.
- **AD-06.2 Import `api.ComplianceStatus`, or keep a drift test.** OpenWatch
  maps an unknown status to error today.
- **AD-06.3 Ratify "skipped versus absent"** before OpenWatch persists
  `skipped` rows.

### AD-07 Embedded corpus and file-tree loaders

Shipped in #433, #434 and #435 (first tag v0.12.0).

- **AD-07.1 The published-module check is manual**
  (`scripts/check-module-consumer.sh --public VERSION`).
- **AD-07.2 Two run-to-run ordering differences:** step summaries iterate a
  map (`internal/engine/plan.go:338`), and so do framework references
  (`internal/mappings/mappings.go:43`).

### AD-08 Binary and corpus compatibility

- **AD-08.1 Stop a binary and a corpus from being paired wrongly.** Packaging
  declares only `recommends: kensa-rules`, with no version constraint
  (`.goreleaser.yaml:158-167`). The v0.12.0 changelog lists this under known
  limits. A corpus-identity contract exists on an unmerged branch.

### AD-09 FIPS

- **AD-09.1 [DEMAND-GATED] FIPS build and release chain:** build against Go's
  validated module, enforce it at runtime, add a spec and CI matrix, ship a
  release variant, and write an attestation. No FIPS setting exists in the
  build today (`Makefile:77-81`).
- **AD-09.2 FIPS-mode enforcement option for the SSH transport:** refuse a
  connection when the target's `fips_mode` is false.

### AD-10 Strict host-key default

- **AD-10.1 [FOUNDER-GATED] Decide whether `--strict-host-keys` becomes the
  default.** Today the default is `accept-new`
  (`internal/transport/ssh/ssh.go:304-314`).

### AD-11 Signing-key revocation

- **AD-11.1 A verify-time revocation list** distinct from rotation history.
  `kensa verify` trusts any `<keyid>.pub` in the trust directory
  (`cmd/kensa/verify.go:136-137`), and `WithRotationHistory` has no production
  caller.
- **AD-11.2 A documented compromise and revocation procedure for the release
  keys.**

### AD-12 Security reporting process

#414 (first tag v0.11.0) routes sensitive reports to GitHub private
vulnerability reporting.

- **AD-12.1 [SECURITY-PROCESS, FOUNDER-GATED] A separate encryption key for
  vulnerability intake,** with a `security@hanalyx.com` uid, published beside
  `KEYS` rather than replacing it. The release key cannot encrypt.
- **AD-12.2 [MINOR] A revoked `y (release signing)` uid** appears on the
  published key. Cosmetic, but visible in every `gpg --show-keys`.

### AD-13 Retention, schemas and maintenance tooling

- **AD-13.1 Background retention (spec store AC-07).** `kensa history --prune`
  exists; `RunRetention` does not (`internal/store/sqlite_test.go:360`).
- **AD-13.2 Store index accessor (spec store AC-09).**
- **AD-13.3 `scripts/bench_aggregate.go` is described wrongly.** It is a
  build-ignored benchmark of store aggregate queries over synthetic data, not a
  benchmark across the rule corpus, and no target runs it. Correct the
  description and decide whether to gate on it.
- **AD-13.4 Dead code.** `internal/bootguard` `Capture` and `Restore` have no
  production caller. The earlier list also named unreferenced helpers
  (`redact.Value`, `varsub.Names`, `shellcapture.ContentReadCmd`, the
  streaming-CSV writers, `text_scan.RenderScanResult`); not re-verified.
- **AD-13.5 Stale comments.** `cmd/kensa/flags.go:118-125` and some `t.Skip`
  reasons describe hooks that now exist, and `internal/agent/systemd/helper.go:320` carries a
  planning label. Not re-verified.
- **AD-13.6 The CI secret-scan comment overstates CI and pre-commit parity.**
  Not re-verified.

### AD-14 fapolicyd

Four rules cover fapolicyd with generic mechanisms.

- **AD-14.1 [DEFERRED, DEMAND-GATED] A first-class fapolicyd transaction
  primitive.** Deferred, not declined. Triggers: a control needing
  operator-defined allowlists enforced atomically, or a broader transactional
  scope.
- **AD-14.2 The deny-all remediation may be ineffective on the `rules.d`
  layout.** `fapolicyd-deny-all.yml` appends to `fapolicyd.rules`, which RHEL 9
  generates from `rules.d`. Not verified on a host. Make the write
  placement-aware and validate that the host can still `execve`.

---
## Closed on 2026-10-19

Each row is an entry from the v0.12.0 backlog. "Line" is its line in
`git show v0.12.0:BACKLOG.md`. Where part of an entry remains, the remainder
moved to the item named in the last column.

| line | earlier entry | closed by | remainder |
|---|---|---|---|
| 12 | `file_content` and `file_absent` interpolate owner, group and mode unquoted | #313, first tag v0.7.6 | PT-10.1 |
| 27 | `config_append` legacy-sed rollback breakout | #313, first tag v0.7.6 | PT-09.2 |
| 33 | dead code: bootguard capture path, engine validators, unreferenced helpers | not closed | AD-13.4, PT-06.3 |
| 39 | unused engine validator injection | not closed | PT-06.3 |
| 44 | stale comments and test-skip reasons | not closed | AD-13.5 |
| 52 | evidence signing integrity: six acceptance gates | #428, first tag v0.11.0; the record is kept below | PT-04.2 |
| 204 | `rollback_results` serialized but not authenticated | not closed | PT-04.1 |
| 222 | `SECURITY.md` directs reporters to a key that cannot encrypt | part 1 (doc-only routing) by #414, first tag v0.11.0 | AD-12.1 |
| 246 | revoked `y (release signing)` uid | not closed | AD-12.2 |
| 256 | 12 GDM and graphical STIG RHEL 10 controls | not closed | CV-03.3 |
| 265 | CIS-versus-STIG threshold conflicts | not closed | CV-09.1 |
| 273 | rule-faithfulness sweep | not closed | CV-09.2 |
| 284 | Ubuntu and Debian probe support | complete 2026-04-15 | none |
| 299 | `pam_tally2` probe | shipped in v0.2.2 | none |
| 304 | service rules whose Ubuntu unit name differs | deferred, not closed | CV-08.1 |
| 325 | `audit_rule_set` handler | shipped | CV-12.2 (netlink rule load on a mutable host) |
| 329 | `grub_parameter_set` | shipped via #15 and #21 | PT-14.4 |
| 333 | `command_exec` | shipped | none |
| 335 | `manual` | shipped | none |
| 338 | five handlers shipped but untested | resolved | none |
| 347 | real-host atomicity validation for `pam_module_configure` and `mount_option_set` | not closed | CV-12.3 |
| 353 | `RemediationResult` compliance-verdict surface | not closed | PT-17.2 |
| 358 | fapolicyd transaction primitive | deferred, not closed | AD-14.1 |
| 370 | fapolicyd follow-up 1: a RHEL 9 deny-all rule | `fapolicyd-deny-all.yml` already cites STIG RHEL 9 (V-270180), applies to RHEL 8 and later, and checks `rules.d/` | none |
| 371 | fapolicyd follow-up 2: placement-aware deny-all write | not closed | AD-14.2 |
| 386 | `pam_module_arg` fragile edit-reversal | new records use whole-file capture since #143, first tag v0.6.0 | PT-09.1 (legacy records) |
| 394 | `audit_rule_set` `ENOENT` delete guard is dead code | not closed; a live-rule read-back now reports a partial restore | PT-09.5 |
| 405 | `apt_present` and `package_present` rollback blast radius | not closed | PT-09.4 |
| 419 | `kensa recover` missing from top-level help | present since tag v0.7.6 (`cmd/kensa/main.go:440`) | none |
| 423 | `--inventory` for `check`, `detect` and `remediate` | `check` has it (`cmd/kensa/main.go:693-694`) | AD-04.1, AD-04.2 |
| 424 | JSON Lines scan output for OpenWatch | `internal/output/json.go:46-75`, present since tag v0.1.0 | AD-05.1 |
| 430 | OpenWatch should import `api.ComplianceStatus` | not closed | AD-06.2 |
| 435 | confirm "skipped versus absent" with OpenWatch | not closed | AD-06.3 |
| 446 | `scripts/bench_aggregate.go` | present since tag v0.1.0 | AD-13.3 |
| 447 | FIPS-mode enforcement option for the SSH transport | not closed | AD-09.2 |
| 457 | Dependabot triage, 2026-06-08 | resolved 2026-06-10 and 2026-06-11; the record is kept below | none |
| 486 | systemd helper EUID override not build-tag guarded | not closed | PT-10.3 |
| 495 | CI secret-scan comment overstates parity | not closed | AD-13.6 |
| 508 | post-apply rule validation | mandatory recheck in #122, first tag v0.6.0 | PT-06.1, PT-06.2 |
| 513 | terminal persistence errors are ignored | #118 (first tag v0.6.0) and #428 (first tag v0.11.0) surface them for `committed`, `rolled_back`, `staged` and `errored` | PT-05.1 |
| 517 | errored transactions are not durably recorded | #118, first tag v0.6.0 (`internal/engine/commit.go:249-265`) | none |
| 522 | remediation evidence host ID can be empty | #127, first tag v0.6.0, on the `pkg/kensa` path | PT-17.3 |
| 527 | control-channel risk classification is too coarse | first half by #391, first tag v0.10.0 | PT-03.7 |
| 548 | post-state evidence is not captured | #125, first tag v0.6.0 (`internal/engine/commit.go:347`) | PT-07.1 |
| 562 | unify capability vocabulary | #381, first tag v0.10.0 (`internal/rule/validate.go:288`) | none |
| 567 | implement or remove unprobed capability gates | `gdm` probe in #138 (v0.6.0); `nftables_active` and `rsyslog_active` in #382 (v0.10.0) | none |
| 572 | make capability fallbacks non-destructive | #138 for 20 rules, later changes for more | CV-07.1 |
| 578 | re-detect capabilities across dependency boundaries | not closed | CV-05.1 |
| 585 | use runtime handler metadata for atomicity validation | not closed | CV-06.1 |
| 592 | enforce or resolve rule conflicts before remediation | not closed | CV-07.3 |
| 597 | enforce platform applicability | done 2026-06-11 (v0.3.0, #64) | none |
| 605 | reduce and test arbitrary command checks | not closed | CV-09.3 |
| 610 | strict lint warning for the SELinux policy rule | not closed | CV-09.4 |
| 622 | deadman AC-07 keep-alive | not closed | PT-03.4 |
| 623 | deadman AC-10 clock skew | not closed | PT-03.5 |
| 624 | engine AC-03 fake validator hook | not closed | PT-06.3 |
| 625 | engine AC-04 crash-recovery test | not closed | PT-16.2 |
| 626 | engine AC-06 deadman wiring | not closed | PT-03.6 |
| 627 | store AC-07 retention | not closed | AD-13.1 |
| 628 | store AC-09 index accessor | not closed | AD-13.2 |
| 629 | evidence-envelope AC-07 schema generation | not closed | PT-04.3 |
| 630 | evidence-envelope AC-10 spec comparison | not closed | PT-04.3 |

---

The two sections below are kept exactly as they appear in `git show v0.12.0:BACKLOG.md`. They are records, not open work. The one open item from the signing section is PT-04.1.

## Evidence signing integrity (2026-09-18)

Required evidence for the signing-order and payload-ownership change on
`internal/engine/finalize`. These are acceptance gates on that change, not
follow-up work. Attach an evidence reference to each as it is satisfied. A
gate is not satisfied by a proposed test or by a green suite.

- **[GATE] Signing order.** Demonstrate the pre-fix regression failure, then
  verify real Ed25519 signatures on the returned envelope and on the envelope
  persisted and reloaded through `SQLite.Get`.
  Evidence: `TestFinalize_ReturnedEnvelopeVerifies`,
  `TestFinalize_PersistedEnvelopeVerifies`, `TestFinalize_StrandedSurvivesSigning`
  (`internal/engine/signing_order_test.go`), branch `fix/evidence-signing-order`.
  Both verification tests fail at the parent commit and pass after it;
  reintroducing the post-`Sign` write fails them again.
- **[GATE] Payload ownership.** Independent review of the `PreState.Data` type
  inventory and of the copy implementation. Test nested alias isolation,
  every supported type, numeric precision, and unsupported-value handling.
  Evidence in `internal/engine/payload_test.go`:
  `TestEvidenceEnvelope_OwnsEverySourceField` (all six mutable fields mutated
  independently, `RollbackResults` checked directly because it is outside the
  v1 signature), `TestPayloadCopy_SupportedTypes`, `_NumericPrecision`,
  `_NilnessPreserved`, `_NestedIsolation`, `_UnsupportedFailsClosed`,
  `_ElementTypes`. Independent review raised two defects in the first cut
  (unredacted re-sign fallback, typed-nil slices widened to empty); both are
  fixed and locked by tests.
- **[GATE] Persistence and re-signing.** Inject persistence and signing
  failures. Prove evidence retention, joined error reporting where the frozen
  `TransactionResult.Error` rule permits it, a valid replacement signature,
  and an explicitly unsigned fallback that carries no stale signature.
  Evidence in `internal/engine/error_path_matrix_test.go`:
  `TestPersistFailure_DemotionMatrix` (committed, rolled_back with
  `HostUnchanged` preserved, staged; partially_applied and rollback_failed
  retained with nil `Error` and a valid signature),
  `TestPersistFailure_TerminalEventIsFailure`,
  `TestCopyFailure_PersistsUnsignedDiagnostic`; plus
  `TestFinalize_PersistFailureSignsReplacementEvidence` and
  `TestFinalize_ResignFailureIsExplicitlyUnsigned`.
- **[GATE] Operational pre-state.** Prove signing and redaction leave both the
  caller's captured state and the persisted restoration source (the
  `pre_states` table) unchanged.
  Evidence: `TestFinalize_RedactionBoundaries` subtests
  `store-redaction/AC-04` and `store-redaction/AC-06`,
  `TestEvidenceEnvelope_RedactsOwnedBundles`, and
  `TestResignFailure_EvidenceIsRedacted`, which covers evidence returned when
  no signer ever redacted it.
- **[GATE] Rollback behavior.** Review the diff and run the rollback, recovery,
  deadman and apply regressions to establish that rollback eligibility,
  rollback execution, recovery and deadman behavior are unchanged.
  Evidence: `go test ./... -count=1` clean; the rollback, recovery, deadman and
  apply regressions across `internal/engine`, `internal/store` and
  `internal/evidence` pass unchanged. `make spec-sync` and
  `make spec-coverage-strict` report 153 of 153 specs passing. The strict gate
  needs `make build` first: without `bin/kensa`, `TestOpenAgent_LocalStub`
  skips and `agent-cli-env-var` reports 5 of 7. That is a missing local build
  artifact, not a defect, and it reproduces at the parent commit.
- **[GATE] Historical exposure.** Determine affected versions from repository
  history. Retained-record verification is PENDING SEPARATE AUTHORIZATION; do
  not access field records.
  Evidence, from repository history only: the signing-order defect enters at
  `c58d527` (2026-04-14) with real signing wired at `b97283c` (2026-05-10);
  both are contained in `v0.1.0`, so every tagged release through `v0.10.0` carries it, reaching transactions that end
  `partially_applied` with a successful non-capturable step. The in-place
  `Decision` edit enters at `e86dc6b` and first ships in `v0.6.0`, reaching
  transactions whose terminal result fails to persist after signing. No field
  records were accessed.

### Reproducing the evidence

All results below are the author's. No second party has rerun them. Each
command is exact; a reviewer who reruns one should get the stated outcome.

Baseline, meaning the state before the fix. It runs in a throwaway worktree
at a path unique to the run, and every setup step must succeed before the
next one runs, so a failed worktree creation or a failed `cd` cannot leave
the commands editing a real checkout. `448ff8c` is the parent commit this
branch starts from:

```
set -eu
wt=$(mktemp -d -t kensa-baseline.XXXXXX)
git worktree add --detach "$wt" fix/evidence-signing-order
cd "$wt"
git checkout 448ff8c -- internal/engine/commit.go
rm internal/engine/payload.go internal/engine/payload_test.go
set +e   # the test run below is EXPECTED to fail
go test ./internal/engine/ -run 'TestFinalize_' -count=1
```

Clean up by removing only the worktree this run created, named by the `$wt`
set above:

```
cd - >/dev/null && git worktree remove --force "$wt"
```

`payload_test.go` is removed with `payload.go` because it is an in-package
test of the copy helpers, which do not exist at the parent commit. The other
three new test files compile against the parent commit unchanged.

Seven tests fail: `ReturnedEnvelopeVerifies`, `PersistedEnvelopeVerifies`,
`ResultWritesDoNotReachEnvelope`, `PersistFailureSignsReplacementEvidence`,
`ResignFailureIsExplicitlyUnsigned`, `UnsupportedCapturedStateFailsClosed`,
and `RedactionBoundaries/store-redaction/AC-06`. Two pass:
`StrandedSurvivesSigning` and `RedactionBoundaries/store-redaction/AC-04`.
Those two are companion assertions, not detectors.

The recorded baseline covers the `TestFinalize_` set only. The error-path
matrix tests were written after it and have no recorded baseline; they cover
behavior the fix introduces.

Use `-count=1` on every run so Go executes the tests instead of reporting a
cached result from an earlier identical run.

Mutations. Each row is one edit to the fixed tree, followed by the named
test, which must fail. Run these in a throwaway worktree as above, so
restoring means deleting the worktree rather than reverting files in place.

| Edit | File | Test that must fail |
|---|---|---|
| Move the stranded marking below `result.Envelope = envelope`, writing through `result.Steps`, AND make `copySteps` return its input | `commit.go`, `payload.go` | `ReturnedEnvelopeVerifies`, `PersistedEnvelopeVerifies` |
| Move the stranded marking only, keeping the copies | `commit.go` | `StrandedSurvivesSigning` |
| `func copySteps(in []api.StepResult) []api.StepResult { return in }` | `payload.go` | `ResultWritesDoNotReachEnvelope` |
| Make `copyStringKeyedMap` return `in, nil` | `payload.go` | `RedactionBoundaries/store-redaction/AC-06` |
| Replace the `resignAsErrored` call with `result.Envelope.Decision = api.StatusErrored` | `commit.go` | `PersistFailureSignsReplacementEvidence` |
| Discard the `resignAsErrored` error instead of joining it | `commit.go` | `ResignFailureIsExplicitlyUnsigned` |
| Make the `copyDataValue` default branch `return v, nil` | `payload.go` | `UnsupportedCapturedStateFailsClosed`, `PayloadCopy_UnsupportedFailsClosed` |
| Delete the two `redactBundles` calls | `commit.go` | `ResignFailure_EvidenceIsRedacted` |
| Delete the `t == nil` guards in the `[]string` and `[]any` cases | `payload.go` | `PayloadCopy_NilnessPreserved` |
| Make `copyValidators`, `copyRollbacks` and `copyFrameworkRefs` return their input | `payload.go` | `EvidenceEnvelope_OwnsEverySourceField` |
| Make `post` alias `postStates` instead of copying | `commit.go` | `EvidenceEnvelope_OwnsEverySourceField` |

A mutation must leave the package compiling, or it tests nothing about the
assertion it targets. Removing the `fmt` error in the `copyDataValue` row
leaves that import unused, so keep it referenced when making that edit.

Full gates, which need the binary built first because
`TestOpenAgent_LocalStub` skips without it and a skipped test does not count
toward coverage:

```
make build && make spec-coverage-strict     # expect 153 of 153 passing
go test ./... -count=1
golangci-lint run --config=.golangci.yml ./...
make comment-lint docs-check docs-style
```

CI already orders this correctly: `.github/workflows/ci.yml` runs
`make build` immediately before `make spec-coverage-strict`.

---

## Dependabot PRs. RESOLVED 2026-06-10/11 (kept for the triage record)

All four PRs from the 2026-06-08 triage are closed. The per-PR rule stands
for future Dependabot PRs: review individually, do NOT blind-merge; they
are **not** covered by the auto-merge-on-green rule.

- **#31, `actions/checkout` 5 → 6.** MERGED (as triaged: low risk, green).
- **#33, gomod minor-and-patch group.** Closed by dependabot, recreated as
  **#58** (4 updates: godbus v5.2.2, x/sys v0.46, x/term v0.44, modernc
  sqlite v1.52). MERGED after review; pure-Go SQLite preserved
  (portability CI green).
- **#28, `actions/upload-artifact` 4 → 7.** MERGED after the CAUTION
  review (behavior + node runtime checked against `action.yml`).
- **#29, `golangci-lint-action` 6 → 9.** CLOSED as triaged ("DO NOT MERGE
  as-is" was correct), then **superseded by #60**, which did the deliberate
  golangci-lint **v2.12.2** migration (config schema `version: "2"`,
  staticcheck SA*-parity then S*/ST*/QF* tiers via #61) together with the
  action v9 bump. The Lint job also gained `GOTOOLCHAIN: local` (#59) after
  the v1-era linter was found being auto-built with go1.25, the root cause
  of a repo-wide SA5011 false-positive storm (poisoned action caches were
  purged).

Residual note: the Node-20 deprecation churn concern from the v0.2.2 A2
work (#35) did not materialize, #28/#31/#60 all landed green on node24
majors.
