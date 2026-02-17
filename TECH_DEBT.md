# Tech Debt Tracker

Items discovered during development sessions. Checked items are resolved.
Priority: **P0** = security risk, **P1** = correctness/audit, **P2** = consistency/hygiene.

---

## P0 — Security

All P0 items resolved. See Resolved section below.

---

## P1 — Correctness / Audit

- [ ] STIG RHEL 9 coverage at 76% (338/446) — needs 18 more implementations to
  reach the 80% target from the implementation plan.

---

## P2 — Consistency / Hygiene

All P2 items resolved. See Resolved section below.

---

## Resolved

- [x] CIS RHEL 9 mapping dangling references — created all 102 missing rule YAMLs
  across 8 categories (sysctl, services, file permissions, cron, audit, SSH,
  PAM/password, system). Added CIS baseline references, validation script, and
  `/cis` slash command. Coverage: 93.9% (229/244), 0 missing rules (2026-02-17)
- [x] Unquoted values in sed/grep commands — added `shell_util.escape_sed()` and
  `shell_util.escape_grep_bre()` helpers; applied across remediation, rollback, and
  capture handlers; updated `sed_replace_line`, `sed_delete_line`, `sed_delete_block`,
  and `grep_config_key` in shell_util.py (2025-02-15)
- [x] Unquoted `rule` arg in `auditctl` command — wrapped with `shell_util.quote()`
  in `handlers/remediation/_security.py` (2025-02-15)
- [x] Weak SSH host key verification — added `strict_host_keys` param to `SSHSession`,
  `--strict-host-keys/--no-strict-host-keys` CLI flag; uses `RejectPolicy` + `known_hosts`
  when enabled (2025-02-15)
- [x] Missing evidence on check handler edge cases — propagated sub-check evidence in
  multi-check failure/success paths; added synthetic `Evidence(method="error")` for unknown
  check method, unknown package state, and unknown module state (2026-02-15)
- [x] Stale handler count in CLAUDE.md — updated stats line to 20 check handlers and
  23 remediation handlers (2026-02-15)
- [x] Stale architecture.md module descriptions — updated `_checks.py`, `_remediation.py`,
  `_capture.py`, `_rollback.py` descriptions to reflect re-export facade pattern with
  domain module listings (2026-02-15)
- [x] Missing `from __future__ import annotations` — added to `runner/_checks.py`,
  `runner/_remediation.py`, `runner/_capture.py`, `runner/_rollback.py`, and
  `runner/handlers/__init__.py` (2026-02-15)
- [x] CIS RHEL 9 mapping file used incompatible format — `framework:` was a nested
  dict and sections were under `mappings:` instead of `sections:`, causing the loader
  to register it with an empty ID and zero sections. Converted to standard format
  with `id:`, `framework:`, `sections:`, `unimplemented:`, and `control_ids:` manifest.
  Also removed dead `order_by_framework()` from `runner/mappings.py` (2026-02-16)
- [x] Stale `prd/IMPLEMENTATION_PLAN.md` — rewrote with current stats (390 rules,
  94% CIS, 76% STIG), marked phases 1/3/4/5 complete, documented remaining Phase 2
  gap (102 missing rule YAMLs, STIG needs 18 more) (2026-02-16)
- [x] Stale `prd/p3-2-rule-scaling.md` — updated status from "Not Started" to
  "Largely Complete (superseded)" with current stats note (2026-02-16)
