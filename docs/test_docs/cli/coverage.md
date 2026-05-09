# `kensa coverage`

## Purpose

Lists the registered handler mechanisms and notes which are capturable (Apply/Capture/Rollback) vs. non-capturable stubs. Gives operators / auditors the "what can kensa do" view.

## Current state

DONE. Static list — no host probe. Reads from `internal/handler.Default()` registry which is populated at init() time via blank imports in `cmd/kensa/main.go`.

## Naming note: `kensa coverage` will be renamed to `kensa mechanisms`

The Python kensa CLI uses `kensa coverage` for a *different* concept (framework-control coverage report — "what fraction of CIS RHEL9 controls does my rule corpus address"). To match Python semantics, kensa-go will:
- Rename the current `kensa coverage` → `kensa mechanisms` (Phase 4 cleanup).
- Add a new `kensa coverage` that does the framework-control breakdown.

This rename is documented in `docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md` and is one of the Phase 4 deliverables.

## Flags

| Flag | Status | Note |
|---|---|---|
| `-h, --help` | DONE | |
| `-o, --output` | DONE | text, json |

NOT advertised: `--quiet` (operator explicitly asked for output by running this subcommand; suppressing it makes no sense).

## Verification protocol

```bash
# 1. Help text.
./bin/kensa coverage --help

# 2. Default text output.
./bin/kensa coverage

# 3. JSON for programmatic consumers.
./bin/kensa coverage -o json | jq '.[] | {name, capturable}'
```

## Known limits

- **Will be renamed.** Operators scripting `kensa coverage` today will need to update to `kensa mechanisms` post-Phase-4. The migration doc commits to a deprecation cycle (warning emitted by old name for one release before removal).
- **No filter flags.** All 29 handlers shown; output is sorted alphabetically. To get only capturable handlers, pipe through `jq`.
- **No per-handler test status.** A founder reviewing this list cannot tell which handlers have integration tests vs. which are still in the "no tests" subset. That information is in `CLAUDE.md` and `engine.md`; pick it up there.
