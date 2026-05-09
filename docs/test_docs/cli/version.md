# `kensa version`

## Purpose

Prints the kensa-go version (build-time-injected via -ldflags), Go version, OS/arch, and build commit SHA.

## Current state

DONE. Static; no host probe, no store access. Useful for operator diagnostics ("which kensa is on this host?") and CI matrix verification.

## Flags

| Flag | Status |
|---|---|
| `-h, --help` | DONE |
| `-o, --output` | DONE — text, json |

NOT advertised: `--quiet` — same rationale as coverage.

## Verification protocol

```bash
# 1. Default text output.
./bin/kensa version

# 2. JSON for CI / automation.
./bin/kensa version -o json | jq '.version, .go_version, .commit'
```

Expected text output shape:
```
kensa version <X.Y.Z or "dev">
  go: go1.26.1
  commit: <SHA>
  built: <ISO timestamp>
  os/arch: linux/amd64
```

## Known limits

- **Version embedding requires `-ldflags`.** A `go build ./cmd/kensa` without ldflags injection prints "dev" as the version. The Makefile's `make build` target wires ldflags from git correctly. CI / packaging must do the same.
- **No --short or --long.** Single output shape today.
