# Security — Known Limits Founders Must Sign Off On

This is the founder-facing list of deliberate security exclusions in the current build. **Each entry is shipped on purpose** and represents a trade-off between scope, risk, and current development capacity. The founder's job before each release is to confirm these exclusions are still acceptable for the deployment context.

## Critical limits (release-blocking for some deployments)

### 1. Evidence envelopes are unsigned

- **What.** `internal/engine/stubs.go` ships a `noopSigner` placeholder. Every evidence envelope kensa-go produces (via `-o evidence:PATH`, the `--info` flow on `rollback`, the engine's per-transaction record in the SQLite store) carries an empty signature.
- **Risk.** Compliance auditors who require cryptographic proof that an evidence record originated from kensa cannot validate kensa-go's output. An attacker with write access to the evidence file or the SQLite store could modify records undetected.
- **Mitigation.** M7 task #12 (Ed25519 signer) is the ship-blocker for v1.0.0. Until it lands, operators relying on signed evidence must use Python kensa (which has its own signing path) or accept the auditability gap.
- **Sign-off question.** Is the target deployment OK with unsigned evidence for now?

### 2. Default SSH host-key policy is TOFU (`accept-new`)

- **What.** Without `--strict-host-keys`, kensa connects with `StrictHostKeyChecking=accept-new`. The first connection to a host auto-trusts whatever key the host presents.
- **Risk.** A first-connection MITM can be undetectable. An attacker who controls the network path on day 1 can substitute their own host key, kensa trusts it, and every subsequent kensa run authenticates against the attacker's key.
- **Mitigation.** Operators wanting strict-from-day-one must populate `~/.ssh/known_hosts` via `ssh-keyscan` (after out-of-band fingerprint verification) and use `--strict-host-keys`. Under strict mode, kensa-go also sets `UpdateHostKeys=no` to prevent OpenSSH 8.5+ from silently learning rotated keys.
- **Sign-off question.** Is the target deployment OK with TOFU as the default? Should the CI matrix include an integration test that runs ALL scans with `--strict-host-keys`?

## High-confidence limits (acceptable for most deployments)

### 3. `--var` values flow into shell commands

- **What.** Variable values substituted via `--var KEY=VALUE` or `defaults.yml` are spliced literally into rule YAML, which then drives handlers like `config_set` (writes to /etc/security/faillock.conf) and `command_exec` (runs commands literally).
- **Risk.** An operator passing `-x banner='$(rm -rf /)'` would have that command run on the target host as root (since remediate runs under sudo). This is not kensa-go-specific — Python kensa has the same path. But the `--var` flag introduces a more direct injection surface than a config file.
- **Mitigation.** The `--var` help text now includes: "VALUE is spliced literally into rule YAML and may flow into shell commands run by handlers — pass only trusted input." Operators must already be authorized to remediate the host, so the threat model is internal-misuse, not external compromise.
- **Sign-off question.** Is the target deployment's operator population trusted to handle un-escaped variable values? If not, defer to defaults.yml only and disable --var via shell-wrapper.

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
# 1. Confirm noopSigner is still in place (M7 task #12 not yet landed).
grep -n "noopSigner\|noop_signer" /home/rracine/hanalyx/kensa-go/internal/engine/stubs.go
# Expected output: noopSigner is the active signer.

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

- [ ] **noopSigner placeholder** — acceptable for this deployment, OR M7 task #12 has landed.
- [ ] **Default TOFU host-key policy** — acceptable for this deployment, OR documentation directs operators to use `--strict-host-keys`.
- [ ] **--var trust model** — operators trusted, OR --var is disabled at the deployment layer.
- [ ] **Conflict-resolution warnings** — operators trained to read stderr, OR conflicts in the corpus have been manually resolved.
- [ ] **Untested handler list** — operators avoid those handlers, OR accept manual rollback.
- [ ] **grub_parameter_set** — not in use, OR operators have manual-verification protocol.
- [ ] **audit_rule_set** — capture-incompleteness understood, OR not in use.
