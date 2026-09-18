# Kensa Backlog

Items are ordered roughly by priority within each section. No commitment to scheduling until promoted to a milestone.

---

## Code-quality & security review (2026-07-10)

From a full stale/dead/unused/security audit at v0.7.4 (`go vet` + `staticcheck`
incl. U1000 both 0 findings; `govulncheck` 0 reachable vulns).

- **[SECURITY, HIGH, Red-class, FOUNDER-GATED] `file_content` and `file_absent`
  interpolate owner/group/mode UNQUOTED into `chown`/`chmod`, same RCE class as
  the #184 file_permissions fix.** `internal/handlers/filecontent/filecontent.go`
  (Apply chown/chmod ~184/215/222; Rollback ~450/506/513) and
  `internal/handlers/fileabsent/fileabsent.go` (~317/346/353) splice `spec`
  (owner:group) and `mode` raw while only Path/SELinux go through `shellEscape`;
  `decodeParams` applies no `valueguard`/quote. The sibling `filepermissions.go`
  quotes them (`shellQuote(spec)`/`shellQuote(p.Mode)`) after #184, these two
  were missed by that sweep. On the default agent remediate path; reachable via a
  rule or `--var` value in owner/group/mode. Shipped-corpus reachability is low
  (only `issue-net-configured.yml`, static values). **Fix = mirror
  filepermissions' shellQuote at every site in both handlers + a regression test
  like `TestApply_OwnerModeInjectionQuoted`.** Touches handler Apply+Rollback and
  is security-classified → founder FMA + two-human rollback review + real-host
  atomicity test before merge. Corrects [[file-permissions-owner-injection]].
- **[SECURITY, MED, gated] `config_append` legacy-sed rollback breakout.**
  `configappend.go:330` wraps the sed program in literal single quotes and
  `line` passes only `sedEscape` (does not escape `'`); a `'`-bearing line →
  root exec. Gated: `rollbackLegacySed` only fires on a pre-state written by an
  older binary (current Capture always writes prior_content). Fix: `shellEscape`
  the whole program like every sibling handler.
- **[DEAD code] `internal/bootguard` Snapshot/Capture/Restore path** is
  production-dead (grub handlers restore via `ArmOneshot`/`ArmOneshotRemove`,
  never Capture/Restore), delete or wire. Plus the engine
  `ServiceHealthValidator`/`ConfigSyntaxValidator` (`internal/engine/validators.go`)
  and a cluster of unreferenced internal helpers (`redact.Value`, `varsub.Names`,
  `shellcapture.ContentReadCmd`, the streaming-CSV writers, `text_scan.RenderScanResult`).
- **[UNUSED feature] engine validator injection (`WithValidators`)** is wired
  into `e.validate` but no production path constructs it, a post-apply
  independent-validator capability that does nothing in shipped use. Decide:
  expose (CLI/rule surface, this is the "post-apply rule validation" architecture
  item already in the backlog) or remove.
- **[STALE] `cmd/kensa/flags.go:118-125`** comment claims `ShortRule` "has no
  active binding" but it IS bound (`main.go:1915`, history `--rule` filter).
  Several `t.Skip` reasons reference hooks that now exist (`engine.WithValidators`,
  the output `Writer` interface), restate or enable. `helper.go:320` "phase-4"
  label trips the no-planning-labels comment-lint rule.

---

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

Baseline, meaning the state before the fix. `448ff8c` is the parent commit
this branch starts from:

```
git checkout 448ff8c -- internal/engine/commit.go
rm internal/engine/payload.go internal/engine/payload_test.go
go test ./internal/engine/ -run 'TestFinalize_' -count=1
git checkout HEAD -- internal/engine/commit.go internal/engine/payload.go \
    internal/engine/payload_test.go
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

`-count=1` is required. Go caches test results, and an edit to a file the
package does not compile leaves a stale pass in place.

Mutations. Each row is one edit to the fixed tree, followed by the named
test, which must fail. Restore the file afterward.

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

A mutation that stops the package compiling proves nothing. Removing the
`fmt` error in the `copyDataValue` row leaves that import unused, so keep it
referenced when making that edit.

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

Kept open alongside it, as separate Red work:

- **[SECURITY, HIGH, Red-class, FOUNDER-GATED] `rollback_results` is serialized
  but not authenticated.** `envelopeCanonical` (`internal/evidence/signer.go`)
  carries 14 of the 17 `api.EvidenceEnvelope` fields. `Signature` and
  `SigningKeyID` are excluded by design; `RollbackResults` is excluded by
  nothing, so editing the record of whether restoration succeeded leaves
  `kensa verify` reporting a valid signature. Spec AC-03 promises that a tamper
  of any field invalidates the signature, and AC-01 omits the field, so the
  spec disagrees with itself and the struct follows neither. Same class as the
  `Severity` omission that `TestVerify_TamperedSeverity` locks. Adding the
  field changes the canonical bytes and breaks existing signatures, so the fix
  needs a `schema_version` bump with a verifier that distinguishes "valid v1
  signature" from "rollback results authenticated". Continuing to verify v1
  must not imply the protection was supplied retroactively.

---

## Security process (2026-07-25)

- **[SECURITY-PROCESS, MED, FOUNDER-GATED] `SECURITY.md` directs vulnerability
  reporters to a key that cannot encrypt.** `SECURITY.md:12-14` tells reporters
  to encrypt sensitive reports with the GPG public key in `KEYS`. That key has
  no encryption capability: `gpg --show-keys --with-fingerprint KEYS` shows
  `[CA]` on the primary and `[S]` on the sole subkey, and capability inspection
  confirms no `e` anywhere (`pub caps=caSCA`, `sub caps=s`). Encrypting to it
  fails, verified against a scratch keyring: `gpg: ops@hanalyx.com: skipped:
  No data`. A reporter following the documented process gets an error, and the
  likely outcomes are abandoning the report or sending it in plaintext; both are
  worse than not offering encryption. **Second defect, same instruction:** the
  address given is `security@hanalyx.com`, but the key's only uid is
  `ops@hanalyx.com`, that address is not on the key at all, so even adding an
  encryption subkey would not make the documented path work as written.
  **Root cause:** a release-signing key doing security-intake duty. The two have
  opposite trust directions, signing is Hanalyx→operator with the private half
  in CI, intake is reporter→Hanalyx with the private half held by whoever
  triages the mailbox. **Fix (two parts):** (1) *immediate, doc-only*, restate
  the sentence to route sensitive reports to GitHub private vulnerability
  reporting, which `SECURITY.md` already offers and which works; do not simply
  delete the option, since silence invites plaintext email. (2) *needs the
  founder*, generate a **separate** encryption key carrying a
  `security@hanalyx.com` uid rather than adding an `[E]` subkey to the release
  key, and publish it alongside, not in place of, the root `KEYS` file that
  anchors release verification. Security-classified → founder gate.
- **[MINOR, same file] Revoked `y (release signing) <ops@hanalyx.com>` uid on
  the published key** looks like a mistyped identity revoked rather than
  removed. Cosmetic, but it surfaces in any `gpg --show-keys` an operator runs
  while verifying a release.

---

## Compliance coverage (W6 RHEL 10 STIG campaign, 2026-07-10)

stig-rhel10 reached **97.2% (422/434)**. The residue is scoped, not arbitrary:
- **12 GDM/graphical controls uncovered, need a graphical test host.**
  V-281225/226 (login banner + banner-override), V-281275 (autologin),
  V-281278/280/282 (session lock / idle / conceal), V-281283 (dconf-policy),
  V-281285 (Ctrl-Alt-Del override), V-281287 (user list), V-281291/292
  (automount/autorun), V-281297 (default display manager). All are
  dconf/gsettings lock-state controls; the fleet is headless so `when:gdm`
  rules SKIP there and can't be fail-observed. Blocked on a GUI test box.
  (Compounds the pre-existing `gdm`-probe + destructive-fallback items under
  "Rule corpus review findings" below, worth fixing together.)
- **Shared-rule CIS-vs-STIG threshold conflicts, audit for more.** The
  campaign found rules serving both a lenient CIS cite and a strict STIG cite
  on one check (password-hashing yescrypt-vs-SHA512; ssh host-key 0640-vs-0600).
  The fix pattern is a STIG-strict companion rule beside the CIS rule (see
  `password-encrypt-method-sha512.yml`, `ssh-host-key-permissions.yml`). Other
  hashing/permission/audit rules likely carry the same latent mis-serve; a
  sweep for "rule cites both CIS and STIG with a single value assertion" would
  surface them.
- **Rule-faithfulness sweep.** The founder-gated batch (#311) fixed four checks
  that were unfaithful to their cited control (exact-match vs `>=`, `num_logs`
  proxy vs `df`, OR-mask vs both-stacks). These were found reactively; a
  proactive pass comparing each `method: command` rule's assertion to its
  XCCDF finding-condition would catch the rest. (Overlaps the existing
  "Reduce and test arbitrary command checks" item.)

---

## Capability Detection

### Ubuntu/Debian probe support: COMPLETE (2026-04-15)

**Shipped:** 6 new Ubuntu probes (`dpkg`, `apt`, `apparmor`, `ufw`,
`apt_unattended_upgrades`, `ubuntu_advantage`) + `fips_mode` universal
fallback + distro-aware `package_installed`/`package_absent` (rpm-or-dpkg)
+ new `dpkg_installed`, `dpkg_absent`, `apparmor_state` check methods.

`apt_present` / `apt_absent` Go handlers + Python runner handlers added.
77 corpus rules patched with `when: apt` implementation blocks via
`scripts/add_ubuntu_pkg_impls.py`.  `rule.schema.json`, `REMEDIATION_HANDLERS`,
and `CAPABILITY_PROBES` all updated and committed.

Live result on `.217`: 13/31 caps detected (was 7/25).

**Remaining (lower priority):**
- ~~`pam_tally2` probe for older Ubuntu (pam_faillock may not be present).~~
 , **SHIPPED 2026-06-04** (v0.2.2). `internal/detect/detect.go` probes for
  the pam_tally2 CLI or module `.so`; added to `rule.KnownCapabilities`.
  Rules don't yet gate on it, that's part of the deferred service-name
  work below.
- **Service rules where the Ubuntu service name differs from RHEL** (e.g.
  `chronyd` → `chrony`). **DEFERRED out of v0.2.2** to a dedicated effort
  (2026-06-04). This is not a mechanical rename: the ~11–17 affected rules
  in `rules/services/` are `family: rhel`-only today, so the work is
  *extending* them to Debian/Ubuntu with the correct per-distro service
  name (via `when: apt` gates, the pattern already in
  `chrony-installed.yml`). It can't be CI-verified, `kensa-validate` is
  schema-only, so it needs real-host validation on the Ubuntu test-fleet
  box. A first-pass mapping survey also turned up at least one wrong entry
  (`kdump` → `crash`; the real Ubuntu unit is `kdump-tools`) and an
  uncertain one (`rngd` → `rng-tools`), so each rule needs its actual unit
  name verified rather than table-applied. Affected families: chrony,
  `crond`→`cron`, `httpd`→`apache2`, `named`→`bind9`,
  `nfs-server`→`nfs-kernel-server`, plus the two uncertain ones above.

---

## Handlers

All four mechanisms originally listed here have **shipped** (29 handlers
total now):
- ~~`audit_rule_set`, implementation pending.~~ **SHIPPED**, capturable,
  `cli-best-effort` shell-out version. The `AUDIT_NETLINK` "Phase 5"
  variant (transaction-phase events via `elastic/go-libaudit`) remains the
  v1.0 quality bar.
- ~~`grub_parameter_set`, non-capturable, needs a deadman guard.~~
  **SHIPPED** via #15 / #21, bootguard-staged, Option-B one-shot trial +
  saved-default auto-fallback. RHEL 8 `$kernelopts` capture (S-009) is the
  remaining gated piece.
- ~~`command_exec`, generic escape hatch.~~ **SHIPPED** (non-capturable;
  `transactional: false` enforced by engine AC-07).
- ~~`manual`, marks a rule as requiring human intervention.~~ **SHIPPED**
  (non-capturable; engine records `StatusSkipped` with a note).

~~**Remaining:** `commandexec`, `manual`, `grubparameterset`,
`grubparameterremove`, and `cryptopolicysubpolicy` are shipped but
**untested**.~~ **RESOLVED**, all five carry spec-driven Apply +
interface-compliance tests (since PR #13; grub set/remove extended by
#15/#21) and pass the strict coverage gate at their tier. All 29 handler
packages have passing tests.

**Open (post-v0.3.0):**

- **Founder real-host atomicity validation for `pam_module_configure`
  (#54) and `mount_option_set` (#56)**, the F1 param-alignment PRs merged
  with unit/spec coverage but without per-handler live-host tests (the
  2026-06-10 live validation covered kmod/config_set/audit/sysctl/cron).
  Run the kensa-fuzz matrix on a dedicated host for these two before
  claiming them at the same confidence tier.
- **`RemediationResult` compliance-verdict surface**, `Remediate` still
  reports only transaction statuses; its already-compliant entries reuse
  `StatusCommitted` with a synthetic "check" step (the overload #62/#63
  removed from `Scan`). Flagged on the `RemediationResult` doc comment;
  needs an `Outcomes`-style additive surface in a future `api/` minor.
- **fapolicyd transaction primitive, LOW priority; deliberately deferred,
  not declined.** A first-class atomic fapolicyd transaction (capture
  compiled `rules.d` → apply → validate-host-can-still-`execve` →
  commit/rollback). The "no today" is a *priority/demand* call, not an
  architectural one: fapolicyd is a Linux subsystem with a real ABI, and the
  long-term *fully transactional layer for Linux* vision wants it, but its
  compliance need is already met by generic primitives, the allowlist content
  is operator policy (the mechanism is Kensa's, the policy isn't, they
  compose), and nothing names it yet. Flips to a yes on either trigger:
  a customer/control needing operator-defined fapolicyd allowlists enforced
  atomically, **or** Kensa's roadmap broadening from compliance-config to the
  general transactional layer. Two smaller, demand-gated follow-ups sit under
  it: (1) add the RHEL 9 deny-all corpus rule (rules.d/ layout; today
  rhel8-only), (2) harden the `config_append` deny-all into a placement-aware
  atomic write + exec-validate (the deny-all is a lock-out foot-gun).
  The general test for whether Kensa should talk to a subsystem at all: it
  must be able to read the subsystem's live state back, or a remediation
  cannot be verified or reversed.

### Rollback-robustness follow-ups, LOW priority (per-handler idempotency audit)

From the 2026-06-21 per-handler recovery-idempotency audit of all 24 capturable
handlers (crash recovery drives every captured step's `Rollback`, including
un-applied ones). The audit's headline held, **no handler corrupts a host on a
never-applied rollback, so cursor-bounded recovery is not needed**. The three
actionable, non-corrupting findings (dconf lock-orphan, mount unconditional
remount, file_absent spurious-failure) shipped as the rollback-robustness trio.
These three remain, all LOW priority (none corrupt, none block recovery):
- **`pam_module_arg`, fragile edit-reversal; move to full-content restore.**
  Rollback replaces line N via `sed '<N>s/.*/.../'` keyed on the line *number*
  captured at grep time, plus a `.bak` fallback that references Apply-side state
  (`cp <file>.bak <file>`), not pure pre-state. Non-idempotent under any
  line-count change, and a double-run overwrites the `.bak` safety copy. Switch
  to the verbatim full-content restore the sibling `pam_module_configure`
  already uses (`internal/handlers/pammoduleconfigure`). Tolerant of the
  never-applied case today, just fragile.
- **`audit_rule_set`, the `unix.ENOENT` delete guard is dead code.** The real
  `go-libaudit` `DeleteRule` (`internal/agent/auditnl/audit.go`) never decodes
  the netlink errno, `getReply` returns the kernel's `NLMSG_ERROR` as a
  *successful* message, so `DeleteRule` returns nil even when the kernel
  rejected the delete. The handler's `errors.Is(derr, unix.ENOENT)` guard
  (`auditruleset.go`) is therefore unreachable against the real client and is
  only "tested" against a fake that cannot return `ENOENT`/`EPERM`. Net effect
  is tolerant (the swallow makes never-loaded deletes succeed), but a *genuine*
  delete failure is silently reported as a successful rollback. Decode the errno
  in `DeleteRule` (mirror `AddRule`'s `ParseNetlinkError`), then make the guard
  real. Immutable-audit hosts are correctly diverted to the shell fallback.
- **`apt_present` / `package_present`, remove-direction rollback blast radius.**
  Their rollback removes the package, and `dnf remove -y` removes its
  *dependents recursively* (RPM default); `apt-get remove` drops a now-depended-on
  package. This is the intended inverse of an install and the never-applied case
  is a no-op (remove of an absent package exits 0), so it is **not** a
  recovery-specific defect, but a leaf-only / `--noautoremove`-style guard
  would bound the blast radius for a rollback of a genuinely-applied install
  that acquired dependents in the interim. Pre-existing rollback property, not
  introduced by recovery.

---

## CLI / UX

- **`kensa recover` is missing from the top-level `kensa --help` command list.**
  (Found 2026-07-10 during the guide-verification pass.) `recover --help` works
  and every flag is correct, but a user reading `kensa --help` can't discover
  the command. Add it to the top-level command listing in `cmd/kensa`.
- `--inventory` flag for `check`, `detect`, `remediate`, parse Ansible-style `inventory.ini` and fan out across hosts.
- Machine-readable scan output suitable for OpenWatch ingestion (JSON Lines per host).

---

## OpenWatch integration follow-ups (v0.3.0)

- **OpenWatch should import `api.ComplianceStatus` directly** instead of
  declaring its own `ResultStatus` with matching string values, turns the
  pass/fail/skipped/error parity from convention into a compile-time
  guarantee (or at minimum add a drift test on the OpenWatch side when the
  live `Scan` binding replaces `unwiredScanFunc`).
- **Confirm the "skipped vs absent" not-applicable contract with
  OpenWatch.** Kensa's `ComplianceSkipped` fires for platform-gated and
  no-default rules; OpenWatch's kensa-executor spec expects rules whose
  capability gate didn't match to be *absent*. Both currently hold, but
  the boundary should be ratified before OpenWatch persists `skipped`
  rows into `host_rule_state`.

---

## Infrastructure

- `scripts/bench_aggregate.go`, aggregate benchmark across a rule corpus.
- FIPS-mode enforcement option for the SSH transport (reject connections when `fips_mode` is false on target).

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

---

## Review follow-ups, v0.2.2 multi-agent review (2026-06-04)

Lower-severity items from the adversarial review of the v0.2.2 PRs. The
two MEDIUM findings (postinst `getent`→`/etc/group`; built-artifact
mode+owner CI assertion) were fixed directly; these are the LOW/NIT
residue, deferred by the founder.

- **LOW (security, defense-in-depth):** `cmd/kensa-systemd-helper/main.go`
  `euidCheck` honors `KENSA_HELPER_EUID_OVERRIDE` unconditionally (no
  build-tag guard; the code comment already flags the lock as deferred).
  Now that the package ships this binary as the *sanctioned* sudo
  escalation target, lock the override behind a `//go:build test` tag so
  the released helper ignores the env var entirely. Currently mitigated:
  the shipped sudoers fragment sets no `env_keep`/`setenv`, so sudo's
  default `env_reset` strips the var on the sanctioned path, residual
  risk is a future `env_keep` regression or a non-sudo root caller only.
- **NIT (docs):** `.github/workflows/ci.yml` secret-scan step comment
  says CI and pre-commit "agree byte-for-byte", overstated. They share
  one exclude policy, but CI scans the full tracked tree each run while
  pre-commit scans staged files incrementally. Reword when next touching
  the file.

---

## Architecture review findings

These items came from a code review of whether Kensa's implementation
fully supports the atomic remediation, auditability, and evidence claims.

- **Post-apply rule validation**, `internal/engine/validate.go` does not
  re-run the selected rule check after remediation. A successful handler
  `Apply` can currently commit when no injected or built-in validator runs.
  Wire `api.Rule.Implementations[selected].Check` through the transaction
  path and make the VALIDATE phase independently confirm desired state.
- **Terminal persistence errors are ignored**, `internal/engine/commit.go`
  discards `e.store.PersistResult(...)` errors. Return or surface terminal
  store failures so callers cannot observe `committed`/`rolled_back` results
  that are missing from durable history.
- **Errored transactions are not durably recorded by SQLite**:
  `engine.errored()` builds a `TransactionResult` without an evidence
  envelope, while `store.SQLite.PersistResult` rejects nil envelopes. Add an
  errored-envelope path or relax the store contract so preflight/capture/store
  failures appear in history.
- **Remediation evidence host ID can be empty**, scanner-built remediation
  transactions do not populate `Transaction.HostID`, and the evidence
  envelope copies `HostID` from the transaction. Thread host identity into
  `internal/scan.Runner.Remediate` / transaction construction so every signed
  remediation envelope identifies the target host.
- **Control-channel risk classification is too coarse**, deadman arming uses
  a static mechanism-level map. Generic mechanisms such as `config_set`,
  `config_set_dropin`, `file_content`, and `sysctl_set` can affect SSH,
  networking, PAM, or firewall state depending on params/path. Add per-rule
  or per-handler risk metadata so risky parameterized changes arm the
  deadman reliably.

  Measured 2026-08-07: **105 rules** have a mechanism classified as unable to
  cut the channel while their own parameters point at SSH, PAM, firewall or
  network state. `sysctl_set` 39, `config_set_dropin` 33 (for example
  `ssh-max-startups`, which edits the SSH daemon's own config),
  `config_set` 30 (for example `firewalld-nftables-backend`),
  `file_permissions` 3 (for example `ssh-public-key-permissions`).

  This is the SECOND half of the problem. The first half, mechanisms missing
  from the map entirely, was closed separately along with a test that fails
  when a corpus mechanism is unclassified. That test cannot see this half: every
  one of these 105 rules uses a mechanism that IS classified, just classified by
  mechanism rather than by what the rule actually touches. A per-handler or
  per-rule risk query is what closes it, and until then the deadman's coverage
  is bounded by mechanism granularity rather than by risk.
- **Post-state evidence is not captured**, committed evidence envelopes set
  `PostStateBundle` to nil. Add post-apply/post-rollback recapture where
  feasible so evidence can prove both pre-state and resulting state, not only
  the attempted apply steps.

---

## Rule corpus review findings

These items came from reviewing how the `rules/` corpus is validated,
selected, ordered, and applied. On 2026-06-05,
`kensa-validate --rules-dir rules --cap-check --strict` reported 539 files,
96 capability-reference errors, and 1 lint warning.

- **Unify capability vocabulary**, `internal/detect` and
  `internal/rule.KnownCapabilities` maintain separate capability sets.
  Detection includes `apt`, while strict validation rejects it. Derive
  validation and CLI override vocabularies from one canonical registry so
  the checked corpus and runtime selector cannot drift.
- **Implement or remove unprobed capability gates**, rules reference `gdm`,
  `nftables_active`, and `rsyslog_active`, but runtime detection does not
  produce those capabilities. Add probes with tests or replace the gates
  with existing capabilities. Until fixed, those implementations are
  unreachable without manual overrides.
- **Make capability fallbacks non-destructive**, several GDM configuration
  rules select package-removal defaults when the unprobed `gdm` gate is
  false. For example, `gdm-login-banner` can choose `apt_absent` or
  `package_absent` instead of configuring an installed GDM. A missing or
  unknown capability must skip/not-applicable rather than select a
  destructive fallback.
- **Re-detect capabilities across dependency boundaries**, remediation
  detects capabilities once before processing the ordered rule set.
  Dependencies can install packages or enable services that change later
  selection decisions. Re-evaluate affected capabilities after successful
  dependency remediation, or select each rule immediately before execution.
  `service-enable-firewalld` followed by `nftables-service-disabled` is a
  concrete failure case.
- **Use runtime handler metadata for atomicity validation**, the validator's
  static non-capturable mechanism list omits `crypto_policy_subpolicy`, even
  though the registered handler reports non-capturable. As a result,
  `crypto-policy-no-cbc-ssh`, `crypto-policy-strong-macs`, and
  `crypto-policy-no-sha1` validate but are rejected by engine preflight.
  Share handler capability metadata with validation and correct those rule
  declarations.
- **Enforce or resolve rule conflicts before remediation**:
  `conflicts_with` currently produces an advisory warning while both rules
  remain executable. Add a deterministic exclusion, policy choice, or hard
  remediation error for contradictory controls such as GDM configuration
  rules loaded alongside `gdm-removed`.
- ~~**Enforce platform applicability**~~, **DONE 2026-06-11** (v0.3.0,
  PR #64). `detect.AppliesTo` gates both `check` and `remediate` on
  family/min/max-version (rhel/redhat aliased; EL derivatives honored)
  before capability selection; out-of-platform rules render `SKIP`
  (`ComplianceSkipped` on `ScanResult.Outcomes`) and never reach
  `engine.Run`. Lenient rails: no-`platforms` rules run everywhere;
  an undetectable host OS gates nothing. Spec `scan-compliance-outcome`
  C-07/AC-07/AC-08.
- **Reduce and test arbitrary command checks**, many findings rely on
  `method: command`, whose shell semantics cannot be validated by the rule
  schema. Prefer structured check methods where possible and add corpus
  tests or real-host fixtures for remaining command checks, including
  expected exit/output behavior and check/remediation convergence.
- **Resolve strict lint warning for SELinux policy**:
  `system/selinux-policy-targeted.yml` checks only
  `/etc/selinux/config`. Clarify that this is a next-boot configuration
  control or add an effective/runtime policy check so the finding does not
  overstate the host's current SELinux state.

---

## Spec coverage gaps (surfaced by Specter)

These are kensa implementation items required to remove `t.Skip` from existing spec tests.

- **deadman AC-07**, `Armer.Extend(ctx, transport, txnID)` keep-alive that re-schedules the job +60s every 30s during long-running applies. Failed keep-alive must abort the transaction.
- **deadman AC-10**. Clock skew detection in `Armer.Arm()`: compare host `date` before and after script upload; extend timer window if skew >30s.
- **engine AC-03**. Add `engine.WithFakeValidator(fn)` test hook so a failing post-apply validator can be injected; verifies `Status=RolledBack` on validator failure.
- **engine AC-04**. Crash-recovery integration test: kill the engine process after CAPTURE persistence but before APPLY; verify `kensa rollback` restores host state from the persisted pre-states.
- **engine AC-06**. Wire `engine.WithDeadman(recordingArmer)` and a `ControlChannelSensitive=true` FakeTransport into engine tests; verify `Arm` is called before apply and `Cancel` after commit.
- **store AC-07**. Implement `store.SQLite.Prune(preStateMaxAge, txnMaxAge)` and `RunRetention(interval)` background task.
- **store AC-09**. Add `store.SQLite.DB() *sql.DB` (or `InspectIndexes() []string`) accessor to allow schema index inspection in tests.
- **evidence-envelope AC-07**. Add `go:generate` that emits `internal/evidence/envelope-v1.json` from `api.EvidenceEnvelope` via a JSON Schema generator; add roundtrip validator test.
- **evidence-envelope AC-10**, CI step that compares `kensa-spec/specs/evidence/envelope-v1.yaml` against the Go struct to fail the build on mismatch.
