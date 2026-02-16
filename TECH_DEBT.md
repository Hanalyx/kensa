# Tech Debt Tracker

Items discovered during development sessions. Checked items are resolved.
Priority: **P0** = security risk, **P1** = correctness/audit, **P2** = consistency/hygiene.

---

## P0 — Security

All P0 items resolved. See Resolved section below.

---

## P1 — Correctness / Audit

All P1 items resolved. See Resolved section below.

---

## P2 — Consistency / Hygiene

All P2 items resolved. See Resolved section below.

---

## Resolved

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
