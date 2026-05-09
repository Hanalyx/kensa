# Live-Host Verification Protocol

## Purpose

Verifying kensa-go on a real host is the only way to know it actually works. Unit tests cover the engine logic in isolation; smoke tests cover the CLI surface; specter covers the spec / test relationship. None of those answer "does kensa actually scan and remediate this host atomically."

This document is the founder-facing protocol for that verification. Run it before every release.

## Required fixtures

| Fixture | Purpose |
|---|---|
| `inventory.ini` (in repo root) | Multi-host inventory for inventory-mode smoke. |
| 192.168.1.211 (or equivalent) | Read-only smoke target. RHEL 9.6 expected. |
| Throwaway VM (one-shot) | kensa-fuzz target. State will be mutated; do not use a host with content. |
| `~/.ssh/known_hosts` populated | For `--strict-host-keys` testing. |
| `sshpass` installed | For `--password` testing. |

## Protocol

### Stage 1 — Read-only smoke (no mutations, ~5 minutes)

```bash
# 1.1 Detect.
./bin/kensa detect -H 192.168.1.211 -u owadmin --no-strict-host-keys
# Expected: 31 capabilities, sorted, with ✓/✗ per probe.

# 1.2 Detect with capability override.
./bin/kensa detect -H 192.168.1.211 -u owadmin --no-strict-host-keys \
    -C selinux=false -C apparmor=true
# Expected: same 31 caps, with selinux ✗ and apparmor ✓ regardless of host.

# 1.3 Single-host check, full corpus.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules
# Expected: ~539 rules processed; pass/fail/warning counts; exit 0.
# NOTE: ~30 rules will skip with the Phase 3.5 "undefined variables" warning.

# 1.4 Filter chain.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -s critical -s high -t pci -f cis-rhel9
# Expected: filtered subset; exit 0 OR exit 2 with disambiguating empty-after-filter
# message naming the upstream count.

# 1.5 Variable substitution.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml \
    -x pam_faillock_deny=3
# Expected: 1 passed if host's faillock deny == 3, else 1 failed.

# 1.6 Inventory mode.
./bin/kensa check --inventory inventory.ini --no-strict-host-keys -w 4 \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -s critical
# Expected: parallel scan across all reachable hosts; per-host result; exit 0.

# 1.7 Multi-format fan-out.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -s critical \
    -o json -o csv:/tmp/results.csv -o evidence:/tmp/evidence.json \
    -o pdf:/tmp/results.pdf -o oscal:/tmp/oscal.json
ls -la /tmp/results.csv /tmp/evidence.json /tmp/results.pdf /tmp/oscal.json
# Expected: all files written; PDF is a valid PDF; JSON / OSCAL parse with jq.
```

### Stage 2 — Atomicity verification (mutates host, ~30 minutes)

```bash
# 2.1 Setup.
# Pick a throwaway VM. Do NOT use a host with content.
SACRIFICE=test-vm-throwaway

# 2.2 Run kensa-fuzz against the sacrificial VM.
KENSA_TEST_SSH_HOST=${SACRIFICE} \
KENSA_TEST_SSH_USER=root \
go test ./cmd/kensa-fuzz/... -v -timeout 10m
# Expected: every capturable handler passes; PreState restored after every
# failure injection.

# 2.3 Manual round-trip on a single rule.
# Pick a rule whose check fails on the host.
./bin/kensa check -H ${SACRIFICE} -u root --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/services/sshd-config-permissions.yml
# Note the FAIL.

# Apply.
./bin/kensa remediate -H ${SACRIFICE} -u root --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/services/sshd-config-permissions.yml \
    -o json | jq -r '.transactions[0].transaction_id' > /tmp/txn.uuid
TXN=$(cat /tmp/txn.uuid)

# Re-check — should now pass.
./bin/kensa check -H ${SACRIFICE} -u root --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/services/sshd-config-permissions.yml
# Expected: PASS.

# Roll back.
./bin/kensa rollback -H ${SACRIFICE} -u root --no-strict-host-keys --sudo \
    --txn ${TXN}

# Re-check — should be back to pre-remediate state.
./bin/kensa check -H ${SACRIFICE} -u root --no-strict-host-keys --sudo \
    --rule /home/rracine/hanalyx/kensa/rules/services/sshd-config-permissions.yml
# Expected: FAIL (matches the original pre-remediate state).
```

### Stage 3 — Strict-mode SSH (~5 minutes)

```bash
# 3.1 Confirm host-key in known_hosts.
ssh-keyscan -H 192.168.1.211 >> ~/.ssh/known_hosts.test
# Out-of-band: verify the fingerprint matches the host's actual key
# (e.g., via console access).
mv ~/.ssh/known_hosts.test ~/.ssh/known_hosts

# 3.2 Strict scan.
./bin/kensa check -H 192.168.1.211 -u owadmin --strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -s critical
# Expected: succeeds (host key already known).

# 3.3 Strict against unknown host.
./bin/kensa detect -H 192.168.99.99 -u owadmin --strict-host-keys
# Expected: fails with the kensa-side hint about ssh-keyscan / --no-strict-host-keys
# fallback (per the C-027 connect-failure stderr augmentation).
```

### Stage 4 — Password auth (~5 minutes)

```bash
# 4.1 Confirm sshpass installed.
which sshpass || sudo apt-get install -y sshpass

# 4.2 Inline password (not for production scripts).
./bin/kensa detect -H 192.168.1.211 -u owadmin --no-strict-host-keys \
    --password=hunter2

# 4.3 TTY prompt.
./bin/kensa detect -H 192.168.1.211 -u owadmin --no-strict-host-keys --password
# Expected: "SSH password: " prompt on the controlling TTY; password not echoed.

# 4.4 Non-TTY guard.
echo | ./bin/kensa detect -H 192.168.1.211 -u owadmin --password
# Expected: usage error mentioning TTY; no hang.

# 4.5 Verify password not in argv.
( ./bin/kensa detect -H 192.168.1.211 -u owadmin --password=hunter2 \
    --no-strict-host-keys & sleep 1; pgrep -af sshpass; wait )
# Expected: pgrep output shows sshpass invocation WITHOUT the password.
```

### Stage 5 — Edge cases (~10 minutes)

```bash
# 5.1 Inventory with one unreachable host.
# Add an unreachable IP to inventory.ini.
./bin/kensa check --inventory inventory.ini --no-strict-host-keys -w 4 \
    --rules-dir /home/rracine/hanalyx/kensa/rules -s critical
# Expected: reachable hosts complete; unreachable host gets a connect-error row.
# Exit code 0 (per-host failures are not test failures of kensa itself).

# 5.2 Inventory + --password rejected.
./bin/kensa check --inventory inventory.ini --password=test \
    --rules-dir /home/rracine/hanalyx/kensa/rules
# Expected: exit 2; "--password is not allowed with --inventory".

# 5.3 Inventory + file output rejected.
./bin/kensa check --inventory inventory.ini --no-strict-host-keys \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -o csv:/tmp/x.csv
# Expected: exit 2; data-loss guard.

# 5.4 Filter chain disambiguation.
./bin/kensa check -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --rules-dir /home/rracine/hanalyx/kensa/rules \
    -s critical -t fake-tag
# Expected: exit 2; "after --severity filter, N rule(s) remained; none had matching tags".
```

## Pass/fail criteria

A live-verification run passes when:

1. Stage 1 completes without unexpected errors. ~30 corpus rules legitimately skip due to undefined variables (Phase 3.5 expected behavior); these are listed in stderr's aggregated warning. Other rules' pass/fail counts are host-dependent.
2. Stage 2 atomicity round-trip restores PreState exactly. PostRollback host state must match PreRemediate host state byte-for-byte for the affected files.
3. Stage 3 strict-mode succeeds against known hosts and fails clean against unknown.
4. Stage 4 password auth works without leaking the password to argv.
5. Stage 5 edge cases produce the expected exit-2 usage errors with disambiguating messages.

If any stage fails unexpectedly, the build is **not releasable**. Open a bug, link to the verification log, and gate the release on a fix.

## Reporting

After a verification run, capture:
- Date.
- Build SHA (`./bin/kensa version`).
- Host fingerprints (192.168.1.211, sacrificial VM).
- Stage 1 rule pass/fail counts (sanity check against last run — large drifts indicate regressions).
- Stage 2 kensa-fuzz output (every handler PASS).
- Any stderr warnings beyond the expected Phase 3.5 substitution warnings.

Save this in `docs/release_notes/<version>.md` for audit.
