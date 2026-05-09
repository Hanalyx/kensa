# `kensa remediate`

## Purpose

Apply failing rules to a host. Each rule runs as a four-phase **atomic** transaction: Capture → Apply → Validate → Commit/Rollback. On validation failure, the engine rolls back to captured pre-state. This is the load-bearing safety guarantee of the entire kensa product — see [`../engine.md`](../engine.md) for the contract.

## Current state

DONE through Phase 3.5. Single-host only — multi-host remediation is **not** in this build (no `--inventory` flag). Operators wanting fleet remediation should script it via shell loops or wait for Phase 4's session model.

29 handlers ship with full Apply / Capture / Rollback (capturable). 10 handlers are non-capturable stubs (`transactional: false` in their rules) — see [`../engine.md`](../engine.md) for the per-handler matrix.

## Flags

### Target options

| Flag | Status | Note |
|---|---|---|
| `-H, --host` | DONE | Required |
| `-u, --user` | DONE | |
| `-k, --key` | DONE | |
| `-p, --password` | DONE (C-026) | |
| `-P, --port` | DONE | |
| `--sudo` | DONE | |
| `--strict-host-keys` / `--no-strict-host-keys` | DONE (C-027) | |
| `-C, --capability` | DONE (C-028) | |

### Rule options

(Identical to check.)

| Flag | Status |
|---|---|
| `-r, --rules-dir` | DONE |
| `--rule` | DONE (C-037) |
| `-s, --severity` | DONE (C-030) |
| `-t, --tag` | DONE (C-031) |
| `-c, --category` | DONE (C-032) |
| `-f, --framework` | DONE (C-033) |
| `--control` | DONE (C-035) |
| `-x, --var` | DONE (Phase 3.5) |
| `--config-dir` | DONE (Phase 3.5) |

### Output options

| Flag | Status | Note |
|---|---|---|
| `--format` | DEPRECATED | Use `-o` |
| `-o, --output` | DONE | Same FORMAT[:PATH] surface as check |
| `--oscal` | DEPRECATED | Use `-o oscal:PATH` |
| `-q, --quiet` | DONE | |

## Verification protocol

```bash
# 1. Help text grouped (C-038).
./bin/kensa remediate --help

# 2. Negative-path validation (no network).
./bin/kensa remediate --host x -s bogus --rules-dir /tmp                   # exit 2
./bin/kensa remediate --host x --strict-host-keys --no-strict-host-keys --rules-dir /tmp  # exit 2

# 3. Atomicity smoke against a throwaway host.
# This is the load-bearing test. Pick a rule whose check fails, run remediate,
# verify host state changed, then run rollback (kensa rollback --txn UUID),
# verify host state reverted to pre-state.
KENSA_TEST_SSH_HOST=<throwaway> KENSA_TEST_SSH_USER=root \
    go test ./cmd/kensa-fuzz/... -v -timeout 10m

# 4. Variable substitution end-to-end on a templated rule.
./bin/kensa remediate -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml \
    -x pam_faillock_deny=5
# Expected: rule applied if check failed pre-remediate; rollback path tested in step 3.

# 5. Filter combinations as for check.
./bin/kensa remediate -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -s critical -t pci

# 6. Output: full corpus run with evidence + OSCAL.
./bin/kensa remediate -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -o evidence:/tmp/evidence.json -o oscal:/tmp/oscal.json
```

## Known limits

- **Single-host only.** No `--inventory` / `--limit` / `--workers`. A 100-host fleet remediation requires shell loop. Phase 4's session model is the planned path.
- **Evidence envelopes are unsigned.** The `noopSigner` placeholder in `internal/engine/stubs.go` ships empty signatures until M7 task #12 (Ed25519 signer) lands. See [`../security.md`](../security.md).
- **`command_exec` mechanism requires runtime opt-in.** AC-07 of `engine-transaction.spec.yaml` enforces this — non-capturable command execution requires the rule's transactional field to be explicitly false. Bypass attempts surface as engine-level errors.
- **`grub_parameter_set` lacks deadman guard.** A misconfigured GRUB parameter could brick the host's next boot. Documented in CLAUDE.md "Open items before M7 ships." Operators must verify GRUB output before reboot — kensa-fuzz can't catch this since it's only testable on a throwaway physical host.
- **10 handlers have no integration tests** (per CLAUDE.md): authselectfeatureenable, commandexec, configappend, cryptopolicyset, cryptopolicysubpolicy, dconfset, grubparameterremove, grubparameterset, manual, pammodulearg. They're shipped as `transactional: false` non-capturable stubs; rolling back from one of these is out of contract.
- **Conflict resolution warns but does not block.** C-021 detects (e.g.) `ssh-ciphers-fips` conflicting with `ssh-crypto-policy`; both run. A future `--allow-conflicts` strict mode is queued.
- **No `--dry-run` flag.** kensa-go has no preview-without-mutate yet on remediate; use `kensa plan` instead (kensa-go addition; capability-gating deferred).
