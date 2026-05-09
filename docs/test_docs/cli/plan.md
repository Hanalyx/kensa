# `kensa plan`

## Purpose

kensa-go addition (no Python equivalent). Returns a structured `api.Plan` describing what `remediate` would do for a single rule against a single host: the selected implementation, captured pre-states, apply step previews, rollback step previews, validators, estimated duration, warnings.

Used by:
- OpenWatch (the planned UI consumer) to show operators the change preview.
- AI-agent surfaces (mediated through OpenWatch, not directly) to validate planned remediation before issuing it.
- Operators wanting a structured `--dry-run` substitute.

## Current state

DONE for the basic flow. Capability-gated implementation selection is **NOT** wired here yet — `engine.PlanTransaction` calls `selectDefaultImpl` (picks the first / `default: true` impl) rather than running the rule selector. This is the documented limitation.

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

### Output options

| Flag | Status | Note |
|---|---|---|
| `--format` | DONE | text, markdown, json, plain |
| `-q, --quiet` | DONE | |

### Positional

| Arg | Status | Note |
|---|---|---|
| `<rule.yml>` | DONE | Required; single file |

## Verification protocol

```bash
# 1. Help text.
./bin/kensa plan --help

# 2. Negative-path validation (no network).
./bin/kensa plan -H foo                              # exit 2 (rule required)
./bin/kensa plan                                       # exit 2 (host required)
./bin/kensa plan --strict-host-keys --no-strict-host-keys -H foo /tmp/r.yml  # exit 2 (mutex)

# 3. Live plan against fixture.
./bin/kensa plan -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml

# 4. JSON output for OpenWatch shape verification.
./bin/kensa plan -H 192.168.1.211 -u owadmin --no-strict-host-keys --sudo \
    --format json \
    /home/rracine/hanalyx/kensa/rules/access-control/pam-faillock-deny.yml | \
    jq '.transactional, .control_channel_sensitive, (.apply_steps | length)'
```

## Known limits

- **Capability gating not honored.** Plan picks the default implementation regardless of host capabilities. A rule whose `default: true` impl uses `authselect` will plan that path even on a host without authselect; remediate would have picked the right impl. This makes plan a less faithful preview than it should be. Tracked for future work; the migration plan exclude in C-028 spec calls this out.
- **No `--rule` plural form.** Plan takes a single rule file as a positional arg. Bulk preview requires shell scripting.
- **No `--var` / `--config-dir` flags on plan.** A templated rule (e.g., `pam-faillock-deny.yml`) will plan with literal `{{ var }}` text in the apply-step previews. Fix: add the same Phase 3.5 wiring (small followup).
- **No filter flags on plan** (--severity, --tag, etc.). Single-rule subcommand by design.
- **Plan output is not signed.** Same `noopSigner` limit as remediate's evidence envelopes.
