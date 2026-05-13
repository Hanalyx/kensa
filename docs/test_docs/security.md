# Security — Known Limits Founders Must Sign Off On

This is the founder-facing list of deliberate security exclusions in the current build. **Each entry is shipped on purpose** and represents a trade-off between scope, risk, and current development capacity. The founder's job before each release is to confirm these exclusions are still acceptable for the deployment context.

## Critical limits (release-blocking for some deployments)

### 1.5 Atomicity basis splits by transport (Phase 2, agent-mode default)

- **What.** As of the fix/phase-2-rework drop plus P-011 (agent-mode default ratified 2026-05-12), the four file-touching capturable handlers (`file_content`, `file_absent`, `config_set`, `config_set_dropin`) deliver literal kernel-primitive atomicity (`O_TMPFILE` + `linkat`, `renameat2(RENAME_EXCHANGE)` with `renameat` fallback, parent-dir `fsync` barriers) when running under agent mode — **the default**. Direct-SSH mode (opt-out via `KENSA_NO_AGENT=1`) retains shell-pipeline best-effort atomicity (`printf > file && mv`, `sed -i`, `rm -f`).
- **Risk.** An operator who sets `KENSA_NO_AGENT=1` (e.g., for a host with noexec /tmp where agent bootstrap is not viable) gets the shell-pipeline path. The mental model mismatch is the risk: an audit may claim atomicity that wasn't delivered for the run that produced the evidence.
- **Mitigation.** `kensa remediate` prints a one-line stderr disclosure on every run stating which atomicity basis is active. The basis is also listed per-mechanism-family in `TRANSACTION_CONTRACT_V1.md §2.6`. Operators who opt out of agent-mode see "direct-SSH mode (KENSA_NO_AGENT=1)" in the disclosure.
- **Sign-off question.** ~~Should the v1.0 release default to agent-mode?~~ **RATIFIED 2026-05-12 (Q1.c) — agent-mode default; direct-SSH retained as explicit opt-out.**

### 1.6 Symlink-traversal refusal (Phase 2 hardening)

- **What.** The fsatomic primitives walk target paths component-by-component with `O_NOFOLLOW` and refuse to operate if any component (including the base) is a symlink. Rules that legitimately target a symlinked path must pass the resolved path explicitly.
- **Risk.** A future rule that targets a symlink would fail with `fsatomic: refuses to follow symlink in path`. Today's corpus has none.
- **Mitigation.** Typed `ErrSymlinkInPath` error gives operators a clear diagnostic; rule authors can use a stat-based check at rule design time.

### 1.7 Agent-SIGKILL → no rollback fires (Phase 3 known limit)

- **What.** Phase 3's in-process kernel-primitive deadman (`timerfd` + `pidfd` + `signalfd` + `epoll`) runs in the agent process. If the agent process is SIGKILLed mid-transaction (operator `kill -9`, oomkiller, kernel panic), the watcher goroutine dies and the rollback does NOT fire. The shell-based `at(1)`/`systemd-run` deadman (direct-SSH mode, opt-in via `KENSA_NO_AGENT=1`) DOES survive agent SIGKILL because the scheduled job is independent of the agent process.
- **Risk.** Operators who SIGKILL the agent during a control-channel-sensitive Apply leave the host in an indeterminate state. Common triggers: oomkiller during memory pressure, deliberate `kill -9` to force a stuck process to exit, kernel panic.
- **Mitigation.** Q3.a ratification (2026-05-12) accepts this trade-off: the in-process deadman's wins (suspend-resistance, clock-jump-immunity, no scheduler dependency, sub-200ms parent-death detection) outweigh the SIGKILL-survival regression. Operators preferring SIGKILL-survival can opt out via `KENSA_NO_AGENT=1`. Operationally: if a Phase 3 customer hits agent-SIGKILL mid-transaction, the engine logs "agent connection lost mid-Apply" and the operator must inspect the host manually + invoke `kensa rollback --info <txn>` for recovery.
- **Sign-off question.** None — Q3.a is closed.

### 1.8 Deadman fan-out on SIGTERM (Phase 3 intentional behavior)

- **What.** Each in-flight ArmDeadman registers its own SIGTERM watcher (via `signal.Notify` + self-pipe). Go's runtime fans out a single process-level SIGTERM to every registered channel, so N concurrent armed transactions all wake and all N rollback scripts execute. This is fail-safe-closed behavior: SIGTERM means "the agent is being asked to die," so any in-flight transaction must roll back before the agent exits.
- **Risk.** A successful Apply whose Cancel hasn't yet arrived from the controller (Cancel-in-flight window) will be rolled back if SIGTERM fires during that window. False-positive rollback.
- **Mitigation.** Operationally recoverable: re-apply the rule. Evidence envelopes record the rollback source as "deadman-fired-on-signal" so audit reviewers can distinguish false-positive (race) from true-positive (controller died mid-Apply). The alternative (silent exit, no rollback) would leave hosts in indeterminate state with no recovery path — strictly worse.
- **Sign-off question.** None — design decision documented in `internal/agent/deadman/armer.go` package doc-comment.

### ~~1. Evidence envelopes are unsigned~~ — RESOLVED 2026-05-10 (M-012 + C-060)

- **Status.** Closed. M-012 shipped the Ed25519 signer primitive (`internal/evidence/Ed25519Signer` + `cmd/kensa-keygen/`). C-060 wired it through the engine, deleted `noopSigner`, and added `kensa verify <evidence-file>` for auditor validation.
- **Operator workflow today**: `kensa-keygen --key-id production` produces a `.priv` + `.pub` keypair. Set `KENSA_SIGNING_KEY=/path/to/production.priv` before running `kensa check --store` or `kensa remediate`; envelopes carry real Ed25519 signatures. Auditors run `kensa verify <evidence.json>` against a trust directory of `.pub` files. Default trust dir matches kensa-keygen's output dir, so no configuration needed in the canonical workflow.
- **What v1.0 ships without**: cryptographic *revocation* distinct from rotation history. A compromised key can be rotated out (its public stays in the rotation history so old envelopes still verify with a `signed_by_rotated_key` warning), but there's no way to mark "this key is poisoned, reject anything signed by it." Tracked as a v1.1 follow-up.

### 2. Default SSH host-key policy is TOFU (`accept-new`)

- **What.** Without `--strict-host-keys`, kensa connects with `StrictHostKeyChecking=accept-new`. The first connection to a host auto-trusts whatever key the host presents.
- **Risk.** A first-connection MITM can be undetectable. An attacker who controls the network path on day 1 can substitute their own host key, kensa trusts it, and every subsequent kensa run authenticates against the attacker's key.
- **Mitigation.** Operators wanting strict-from-day-one must populate `~/.ssh/known_hosts` via `ssh-keyscan` (after out-of-band fingerprint verification) and use `--strict-host-keys`. Under strict mode, kensa-go also sets `UpdateHostKeys=no` to prevent OpenSSH 8.5+ from silently learning rotated keys.
- **Sign-off question.** Is the target deployment OK with TOFU as the default? Should the CI matrix include an integration test that runs ALL scans with `--strict-host-keys`?

## High-confidence limits (acceptable for most deployments)

### 3. `--var` values flow into shell commands (and so do `defaults.yml` / `hosts/<host>.yml` / `groups/<g>.yml` / `conf.d/*.yml` values)

- **What.** Variable values substituted via `--var KEY=VALUE` OR any of the four file-based tiers under `--config-dir` (Phase 3.5/3.6) are spliced literally into rule YAML, which then drives handlers like `config_set` (writes to /etc/security/faillock.conf) and `command_exec` (runs commands literally).
- **Risk.** An operator passing `-x banner='$(rm -rf /)'`, OR a hosts/web-01.yml with `banner: "$(rm -rf /)"`, would have that command run on the target host as root (since remediate runs under sudo). This is not kensa-go-specific — Python kensa has the same path. The 5-tier surface (Phase 3.6) widens the surface: any operator with write access to the config dir can inject into kensa runs initiated by other operators.
- **Mitigation.** The `--var` help text now includes: "VALUE is spliced literally into rule YAML and may flow into shell commands run by handlers — pass only trusted input." All tier sources apply the same vocabulary check at load time (KEY must match `[A-Za-z][A-Za-z0-9_]*`), but **VALUE is unrestricted** by design.
- **Sign-off question.** Is the target deployment's operator population trusted to handle un-escaped variable values, AND is write access to `--config-dir` properly restricted (file permissions)? If not, defer to a single deployment-managed `defaults.yml` and disable `--var` + custom `--config-dir` via shell-wrapper.

### 4. `--capability` override is a debugging knob, not a security boundary

- **What.** Operators can override the host's detected capability set per key (`-C selinux=false -C apparmor=true`). This drives rule selection — different impls run.
- **Risk.** Forced capabilities don't change what the host actually has. A rule selected via "force selinux=true" on a host without SELinux will fail at the transport layer when its impl invokes `getsebool` (binary not found). Engine atomicity preserves host state regardless, so no corruption — but the operator's mental model of "what kensa did" is incorrect.
- **Mitigation.** Documented in `specs/cli/capability-override.spec.yaml` risk-model stanza.
- **Sign-off question.** None — this is a debug-mode flag and doesn't expand the attack surface.

### 5. `command_exec` requires runtime opt-in

- **What.** The `command_exec` mechanism runs arbitrary shell commands. Per AC-07 of `engine-transaction.spec.yaml`, a rule using `command_exec` MUST have `transactional: false` set explicitly — atomicity is not guaranteed for these rules, so the operator must opt out of the contract.
- **Risk.** A rule with `command_exec` and `transactional: true` would slip past the engine's safety net. AC-07 enforces the rejection at engine-level.
- **Mitigation.** Engine validation enforces. Tests cover the rejection path.

### 6. Specter coverage strict mode not enabled

- **What.** Per CLAUDE.md, `specter coverage --strict` is not yet wired. Every `@spec`/`@ac` annotation in code is a source comment, not a runner-visible test surface. Turning strict on today would demote every annotated AC to "uncovered."
- **Risk.** A spec AC can ship with no actual test backing it; the coverage gate only checks that *some* file mentions the AC. False-confidence in test coverage.
- **Mitigation.** The gate is structural-only today (`specter check --strict` confirms specs parse and constraints have AC references). Migration to Convention A (`t.Run("spec-id/AC-NN ...", ...)`) or Convention B (`t.Log("// @spec ...")` + `t.Log("// @ac ...")`) is queued.

## Medium-confidence limits (informational)

### 7. `grub_parameter_set` lacks a deadman guard

- **What.** A misconfigured GRUB parameter can brick the host's next boot. The deadman timer (`internal/deadman/`) protects against operator-disconnect mid-Apply for most handlers, but GRUB doesn't recover via deadman because the host doesn't boot.
- **Mitigation.** Handler ships as `transactional: false` non-capturable. Operators using grub_parameter_set rules accept manual verification before reboot.

### 8. Conflict resolution warns but does not block

- **What.** C-021's conflict resolver detects rules that conflict (e.g., `ssh-ciphers-fips` vs `ssh-crypto-policy`). Both currently emit warnings to stderr and run anyway — no exit-code change.
- **Mitigation.** Future `--allow-conflicts` strict mode is queued; until then, operators must manually review stderr warnings.

### 9. `audit_rule_set` capture is incomplete

- **What.** The handler implements Apply but doesn't capture audit-rule pre-state correctly. Rolling back a remediation that touched audit rules is incomplete.
- **Mitigation.** Documented in CLAUDE.md "Open items before M7 ships." Operators using auditruleset rules accept the rollback gap.

### 10. 10 handlers have no integration tests

Per CLAUDE.md: `authselectfeatureenable`, `commandexec`, `configappend`, `cryptopolicyset`, `cryptopolicysubpolicy`, `dconfset`, `grubparameterremove`, `grubparameterset`, `manual`, `pammodulearg`. Shipped as `transactional: false` non-capturable stubs. Atomicity is not promised; operators relying on automatic rollback for these handlers will be disappointed.

## Verification protocol for security limits

```bash
# 1. Confirm noopSigner is GONE (M-012 + C-060 landed 2026-05-10).
grep -n "noopSigner\|noop_signer" /home/rracine/hanalyx/kensa-go/internal/engine/stubs.go
# Expected output: (no matches — engine.New() now defaults to evidence.Generate()).

# 1b. Confirm engine produces real signatures end-to-end.
./bin/kensa-keygen --out /tmp/k --key-id smoke && \
  KENSA_SIGNING_KEY=/tmp/k/smoke.priv ./bin/kensa --help >/dev/null && \
  echo "signer wired"
# Expected: "signer wired".

# 2. Confirm default host-key policy.
./bin/kensa detect -H test-host --help | grep -A1 "strict-host-keys"
# Expected: "no-strict-host-keys (default today; ...)"

# 3. Confirm command_exec opt-in is enforced.
go test ./internal/engine/... -run TestCommandExecRequiresTransactionalFalse

# 4. Confirm --var help text includes the trusted-input warning.
./bin/kensa check --help | grep -A1 'var stringArray'
# Expected: "...VALUE is spliced literally into rule YAML and may flow into shell commands..."

# 5. Confirm specter coverage strict NOT enabled in CI.
grep -n "coverage --strict" .github/workflows/*.yml
# Expected: no matches (gate not wired).

# 6. Confirm 10 untested handlers still flagged.
ls /home/rracine/hanalyx/kensa-go/internal/handlers/{authselectfeatureenable,commandexec,configappend,cryptopolicyset,cryptopolicysubpolicy,dconfset,grubparameterremove,grubparameterset,manual,pammodulearg}/*_test.go 2>&1 | grep -c "No such file"
# Expected: 10 (all 10 handlers have no _test.go).
```

## Founder sign-off checklist

Before each release, confirm:

- [x] **noopSigner placeholder** — RESOLVED 2026-05-10 (M-012 shipped the Ed25519 signer; C-060 wired it through the engine and added `kensa verify`). Auditor verification path: `kensa verify <evidence-file>` against a trust dir of `.pub` files.
- [ ] **Default TOFU host-key policy** — acceptable for this deployment, OR documentation directs operators to use `--strict-host-keys`.
- [ ] **--var trust model** — operators trusted, OR --var is disabled at the deployment layer.
- [ ] **--config-dir write access** — restricted to deployment owner. Phase 3.6 widens the variable injection surface to four file-based tiers; any operator with write access to `<config-dir>/hosts/`, `groups/`, `conf.d/`, or `defaults.yml` can inject values that other operators' kensa runs will splice into shell commands.
- [ ] **Conflict-resolution warnings** — operators trained to read stderr, OR conflicts in the corpus have been manually resolved.
- [ ] **Untested handler list** — operators avoid those handlers, OR accept manual rollback.
- [ ] **grub_parameter_set** — not in use, OR operators have manual-verification protocol.
- [ ] **audit_rule_set** — capture-incompleteness understood, OR not in use.
