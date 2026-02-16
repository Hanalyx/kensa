# Tech Debt Tracker

Items discovered during development sessions. Checked items are resolved.
Priority: **P0** = security risk, **P1** = correctness/audit, **P2** = consistency/hygiene.

---

## P0 — Security

All P0 items resolved. See Resolved section below.

---

## P1 — Correctness / Audit

### Missing evidence on check handler edge cases

CLAUDE.md invariant: "All check handlers MUST return CheckResult with Evidence object."
These code paths return `CheckResult` without evidence:

- [ ] `runner/handlers/checks/__init__.py` ~L119 — multi-check failure propagation
- [ ] `runner/handlers/checks/__init__.py` ~L121 — multi-check success aggregation
- [ ] `runner/handlers/checks/__init__.py` ~L140 — unknown method fallback
- [ ] `runner/handlers/checks/_package.py` ~L104 — unknown package state
- [ ] `runner/handlers/checks/_system.py` ~L192 — unknown module state

**Fix approach:** Add synthetic Evidence with `method="error"`, the attempted command
(or None), and the error detail as `actual`. This preserves the audit trail for edge cases.

### Stale handler count in CLAUDE.md

- [ ] `CLAUDE.md` line 7 — says "19 check handlers" but there are ~23
- [ ] `CLAUDE.md` line 7 — verify remediation handler count (says nothing, but should match)

**Fix approach:** Count handlers from `CHECK_HANDLERS` and `REMEDIATION_HANDLERS` dicts and
update the stats line.

---

## P2 — Consistency / Hygiene

### Stale architecture.md module descriptions

- [ ] `context/architecture.md` lines 72-75 — describes `_checks.py`, `_remediation.py`,
  `_capture.py`, `_rollback.py` as containing handler logic. They are now thin re-export
  facades; implementations are in `runner/handlers/{checks,remediation,capture,rollback}/`.

**Fix approach:** Update the bullet points to say "Re-export facade; implementations in
`handlers/<package>/`" and add a sub-bullet listing the domain modules.

### Missing `from __future__ import annotations`

Project convention (CLAUDE.md) requires this at the top of every file. These are missing it:

- [ ] `runner/_checks.py`
- [ ] `runner/_remediation.py`
- [ ] `runner/_capture.py`
- [ ] `runner/_rollback.py`
- [ ] `runner/handlers/__init__.py`

**Fix approach:** Add `from __future__ import annotations` after the module docstring in each.

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
