# Bug-fix log — 2026-05-13

Post-Phase-4 bug sweep. Surfaced by the founder-requested "full live test of all kensa functionalities" against `192.168.1.211` (RHEL 9.6, SSH user `owadmin`, sudo enabled). Eight items reported; five were real bugs, three were false positives.

## Summary

| # | Item | Resolution | PR / commit |
|---|---|---|---|
| B1 | Agent-mode bootstrap fails with non-root SSH user | **FIXED** | PR #7, `c28e3d6` |
| B2 | Rollback reports success but doesn't restore state | **FIXED** | PR #7, `c28e3d6` |
| B3 | Remediate exits 0 on failure | **False positive** — test measured `tail`'s exit | — |
| B4 | Default `.kensa/results.db` doesn't auto-create parent dir | **FIXED** | PR #8, `2c5c5e7` |
| B5 | `kensa list sessions` empty but history populated | **By-design** — sessions opt-in via `--store` on `check` | — |
| B6 | "Committed" count conflates applied + already-compliant (433 vs 36 stored) | **FIXED** | PR #8, `2c5c5e7` |
| B7 | `--version` inconsistent across binaries | **FIXED** | PR #8, `2c5c5e7` |
| B8 | Agent emits "unexpected EOF" on stdin close | **False positive** — test sent garbage byte, not clean EOF | — |

## Atomicity-critical bugs (B1 + B2)

Both broke the documented v1.0 security model ("unprivileged SSH user + sudo for privileged ops"). Each individually was a silent failure: unit tests passed, the bug only surfaced in the end-to-end live path.

### B2 — rollback silently no-op'd

**Symptom.** `kensa remediate --rule var-log-messages-permissions.yml` committed a chmod (mode 600 → 640) on `/var/log/messages`. `kensa rollback -T <txn>` returned exit 0 with `"Success: true, Detail: 'all rollback steps succeeded', StepIndex: -1, Mechanism: \"\""`. File mode stayed at 640.

**Root cause.** `internal/store/log_query.go::Get` loaded the envelope (which contains the `apply_steps` array) and the pre-states (via the dedicated `LoadPreStates`), but never populated `rec.Steps` on the returned `TransactionRecord`. `engine.RollbackTransaction(record)` iterates `record.Steps` to find capturable apply results to reverse — with a nil slice, the loop iterated zero times, the result slice was empty, and the aggregator returned a synthetic `"all rollback steps succeeded"` response.

**Fix.** One-line addition in `Get`:
```go
if includeEnv {
    var env api.EvidenceEnvelope
    json.Unmarshal([]byte(envJSON), &env)
    rec.Envelope = &env
    rec.Steps = env.ApplySteps  // ← the fix
}
```

**Why the unit tests missed it.** Every existing test that exercised rollback constructed the `TransactionRecord` in-memory with Steps populated — no test went through the `Get` round-trip. Regression test `TestStore_GetPopulatesSteps_B2Regression` locks the fix.

### B1 — agent-mode bootstrap path failed under sudo

**Symptom.** `kensa remediate --sudo` (agent mode default) failed at handshake: `bootstrap: put bin/kensa → /root/.cache/kensa/agent-<sha>: ssh: scp upload bin/kensa -> /root/.cache/kensa/agent-<sha>: exit status 1 (stderr: scp: dest open ".../...": Permission denied)`.

**Root cause.** Two architectural mismatches:
1. `bootstrap.EnsureAgent` resolved the target cache directory via `printf '%s' "$HOME"` through the sudo-wrapped transport — `$HOME` returned `/root`. The subsequent `transport.Put` was implemented via scp/sftp which does **not** honor sudo (it runs as the SSH user). The non-root SSH user `owadmin` had no write access to `/root/.cache/`.
2. Even after the binary landed somewhere accessible, the dispatcher's `defaultSSHCommand` invoked the agent without `sudo`: `ssh user@host <cachePath> agent --stdio`. The agent needs root privileges to perform compliance remediation.

**Fix.**
1. Switch the cache to `/var/cache/kensa/agent-<sha>` (FHS-correct system path, root-owned). Use a stage-then-install dance: scp to `/var/tmp/kensa-stage-<sha>` (universally user-writable + sticky), then `sudo install -m 0755 <stage> <cache>` (atomic mv with chmod), then cleanup the stage. The install command IS sudo-wrapped because it goes through `transport.Run`.
2. Add `dispatcher.Options.Sudo bool`, threaded through from `api.HostConfig.Sudo`. When set, prefix the agent invocation with `sudo -n` so sudo elevates BEFORE the remote shell resolves the binary path.

**Cache layout post-fix.**
- `/var/cache/kensa/` — root:root, mode 0755 (per `mkdir -p` umask)
- `/var/cache/kensa/agent-<sha>` — root:root, mode 0755 (per `install -m 0755`)
- `/var/tmp/kensa-stage-<sha>` — created and removed within one EnsureAgent call

**Sudoers convention.** The kensa-rpm packaging deliverable (post-v1.0) will install `/etc/sudoers.d/kensa` granting:
```
%kensa ALL=(root) NOPASSWD: /var/cache/kensa/agent-*
```
Operators add their service account to the `kensa` group at install time. Until packaging lands, deployment-managed sudoers is the workaround.

## UX / correctness bugs (B4, B6, B7)

### B4 — default db path required pre-existing parent dir

**Symptom.** Fresh `kensa history` (no `--db` flag) failed with `kensa: open store: store: PRAGMA journal_mode = WAL: unable to open database file: out of memory (14)`. SQLite's `out of memory (14)` is its unhelpful name for SQLITE_CANTOPEN; the underlying cause was `.kensa/results.db` requires the `.kensa/` directory to exist first.

**Fix.** `store.OpenSQLite` now runs `os.MkdirAll(filepath.Dir(path), 0o755)` before `sql.Open`. Skipped for `:memory:` and `mode=memory` paths (SQLite handles those internally).

### B6 — "committed" count conflated applied + already-compliant

**Symptom.** `kensa remediate` reported `433 committed, 6 rolled_back, 100 errors, 0 skipped`. `kensa history --stats` showed only 36 stored transactions (30 committed + 6 rolled_back). A 397-transaction gap.

**Root cause.** `internal/scan/scan.go:138-152` — when the scanner's pre-check determines a rule is already in desired state, it builds a synthetic `TransactionResult{Status: StatusCommitted, Steps: [{Mechanism: "check", Detail: "already in desired state — skipped"}]}` and appends it to `result.Transactions` WITHOUT calling `engine.Run`. The engine is the only path that persists transactions (via `finalize → store.PersistResult`), so these synthetic records exist only in-memory. The text writer tallied them under "committed" alongside real applies, creating a misleading conflation.

**Fix.** `internal/output/text.go::WriteRemediationResult` now splits `committed` into `applied` (real engine work; persisted) and `already-compliant` (synthetic skip; not persisted). The per-row STATUS column also distinguishes. Detection heuristic: a transaction with exactly one `StepResult` whose `Mechanism == "check"` and `Detail` contains `"already in desired state"` matches the scanner's synthetic-record pattern.

Post-fix summary format:
```
N applied, M already-compliant, K rolled_back, L errors, P skipped
```

The underlying `api.TransactionResult` shape is unchanged — programmatic consumers (JSON / CSV / OSCAL) can replicate the split by checking the same marker.

### B7 — `--version` inconsistent across binaries

**Symptom.** `kensa --version` works. `kensa-fuzz --version`, `kensa-validate --version`, `kensa-keygen --version`, `kensa-systemd-helper --version` all rejected as unknown flag.

**Fix.** Each utility binary now exposes `--version` / `-V`. The systemd-helper's `--version` is checked BEFORE the EUID-must-be-root check (the version string is not privileged information; requiring sudo to read it would be wrong UX).

## False positives (B3, B5, B8)

### B3 — remediate exit code 0 on failure

**Original report.** I ran `bin/kensa remediate ... 2>&1 | tail -15` and observed exit 0 despite a bootstrap failure that should have been exit 1.

**Re-verification.** `bin/kensa remediate ... ; echo "exit=$?"` (without the pipe) reported exit 1 correctly. The `tail` in my test pipeline absorbed the exit code; the dispatcher's `err != nil → return 1` was always correct.

### B5 — list sessions empty but history has rows

**Original report.** After `kensa remediate` populated 36 transactions in history, `kensa list sessions` reported "no sessions in the store" — apparent model inconsistency.

**Re-verification.** Per `cmd/kensa/main.go:918`'s explicit code comment, sessions are OPT-IN via the `--store` flag on `kensa check` (the C-041 session-and-transaction persistence deliverable). `kensa remediate` writes transactions directly through the engine without creating session records. The two surfaces are intentionally different: transactions are the audit truth-of-record; sessions are a higher-level grouping the operator opts into.

### B8 — agent emits "unexpected EOF" on stdin close

**Original report.** `echo "" | timeout 2 bin/kensa agent --stdio` produced `kensa agent: decode: read frame: unexpected EOF` on stderr.

**Re-verification.** `echo ""` writes a newline byte (0x0a) THEN closes stdin. The framing reader read the newline as the first byte of a frame type, then attempted to read the 4-byte length, got EOF, correctly returned `ErrUnexpectedEOF`. The diagnostic is accurate — the bytes ARE truncated mid-frame.

A genuinely clean shutdown (`< /dev/null`, zero bytes then immediate EOF) produces zero stderr output and exit 0:
```
$ timeout 2 bin/kensa agent --stdio < /dev/null ; echo exit=$?
exit=0
```

## Live-test recap (post-fix)

192.168.1.211, RHEL 9.6, owadmin SSH user, --sudo enabled:

1. Pre-state `/var/log/messages`: `mode=600 user=root group=root`
2. `kensa remediate --sudo --rule var-log-messages-permissions.yml` (agent mode default):
   - Bootstrap: scp to `/var/tmp/kensa-stage-<sha>` → `sudo install -m 0755` to `/var/cache/kensa/agent-<sha>` ✓
   - Handshake: completed ✓
   - Apply: `var-log-messages-permissions: applied` (post-B6 wording) ✓
   - Summary: `1 applied, 0 already-compliant, 0 rolled_back, 0 errors, 0 skipped` ✓
3. Post-remediate `/var/log/messages`: `mode=640`
4. `kensa rollback -T <txn> --sudo`: `Success: true` ✓
5. Post-rollback `/var/log/messages`: `mode=600` (restored) ✓

The atomicity contract holds end-to-end in the production code path.

## What the live-test discipline caught that unit tests missed

This sweep is a useful data point for the kensa-go testing philosophy. Two atomicity-critical bugs (B1, B2) shipped through:
- 56 unit-test packages, all green
- 86/86 specter strict-coverage gates
- 225/225 CLI smoke tests
- L-004 (RHEL 8 glibc 2.28) + L-005 (Alpine musl) portability gates
- 4 founder-facing test docs (engine.md, live.md, transport.md, security.md)

What caught them: a single founder-requested end-to-end live test against a non-root SSH user.

The lesson is not "unit tests are useless" — they prevent dozens of bugs per release. The lesson is **the atomicity contract has a per-host-config matrix that unit tests cannot exercise**:
- agent-mode × sudo × non-root SSH user → broken (B1)
- store-round-trip × manual rollback → broken (B2)

The post-fix `live.md` Stage 2.5 protocol locks both as part of the release-sign-off checklist. CI cannot run this stage (no SSH-able host in CI environment); it's a founder-step before tagging a release.
