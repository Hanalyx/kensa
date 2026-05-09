# `kensa-fuzz`

## Purpose

**Failure-injection harness for atomicity verification.** Drives a real host through deliberate failures during the four-phase transaction (Capture → Apply → Validate → Commit/Rollback) and asserts the host is in pre-state at the end. This is the load-bearing test that proves kensa's atomicity claim.

Per CLAUDE.md authorship contract: *"Rollback handlers additionally require two-human review and a real-host atomicity test via `cmd/kensa-fuzz`."* No rollback handler ships without passing kensa-fuzz against a real host.

## Current state

DONE for the capturable handler set (19 handlers). Skipped without `KENSA_TEST_SSH_HOST` env var. **Cannot run on the same host that's running the test binary** — needs a separate target so kensa-fuzz can mutate it.

Tests are under `cmd/kensa-fuzz/` and run via `go test`, not as a regular binary. The compiled `bin/kensa-fuzz` is the test runner.

## Flags

| Flag | Status |
|---|---|
| `-h, --help` | DONE |

`kensa-fuzz` is primarily a Go test entry point. Most invocation is via `go test`; the binary form is for ad-hoc reproduction of a specific failure scenario.

## Verification protocol

```bash
# 1. The full atomicity matrix.
KENSA_TEST_SSH_HOST=192.168.1.211 \
KENSA_TEST_SSH_USER=root \
go test ./cmd/kensa-fuzz/... -v -timeout 10m

# 2. A single handler's atomicity.
KENSA_TEST_SSH_HOST=192.168.1.211 \
KENSA_TEST_SSH_USER=root \
go test ./cmd/kensa-fuzz/... -v -run TestFuzz_FilePermissions -timeout 5m

# 3. Inspect the captured-vs-restored state diff for a specific run (if the test
# logs PreState / PostState for diff). Useful when adding a new handler.
KENSA_TEST_SSH_HOST=192.168.1.211 \
KENSA_TEST_SSH_USER=root \
go test ./cmd/kensa-fuzz/... -v -run TestFuzz_<Handler> -timeout 5m | grep -E "PreState|PostState|Restored"
```

## Failure modes verified

| Phase | Failure injection | Expected result |
|---|---|---|
| Capture | Capture errors (e.g., file unreadable) | Transaction fails fast; no Apply runs |
| Apply | Mid-apply failure (e.g., command non-zero exit) | Engine triggers rollback; PreState restored |
| Validate | Validator fails after successful Apply | Engine triggers rollback; PreState restored |
| Commit | Commit fails (e.g., evidence write fails) | Engine triggers rollback; PreState restored |

Each capturable handler has dedicated fuzz tests covering all four phases. The 10 non-capturable handlers (`commandexec`, `manual`, etc.) are NOT atomicity-tested because they're shipped as `transactional: false` — atomicity is not in their contract.

## Known limits

- **Requires a sacrificial host.** Operators cannot kensa-fuzz against production. The Hanalyx test fleet has dedicated VMs for this; operators outside that environment must spin up their own.
- **No CI integration.** kensa-fuzz tests are gated behind `KENSA_TEST_SSH_HOST`; CI runs only the non-network tests. A real-host CI target with a throwaway VM is queued for M7.
- **No deadman-timer scenario.** kensa-fuzz doesn't currently exercise the deadman-rollback path (where the operator's connection drops mid-Apply and the host self-rolls-back via the deadman timer). The deadman timer subsystem (`internal/deadman/`) has its own unit tests, but the integrated end-to-end test is queued.
- **`grub_parameter_set` cannot be fuzz-tested.** A misconfigured GRUB parameter could brick the host's next boot; the throwaway VM model doesn't survive that. This handler ships as `transactional: false` non-capturable for safety; operators must verify GRUB output before reboot.
