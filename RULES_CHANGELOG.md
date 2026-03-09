# Rules Changelog

Tracks individual rule additions, removals, rewrites, and reference updates.
Organized by date. Most recent first.

---

## 2026-03-09

### Rewritten

- **audisp-remote-server** → **rsyslog-remote-server** (V-230479)
  STIG check text requires `grep @@ /etc/rsyslog.conf`, not audisp-remote.conf.
  Old rule checked the wrong subsystem (audisp-remote plugin instead of rsyslog).

- **audisp-encrypt-connection** → **rsyslog-encrypt-connection** (V-230481)
  STIG check text requires `$DefaultNetstreamDriver gtls` and
  `$ActionSendStreamDriverMode 1` in rsyslog.conf.
  Old rule checked `enable_krb5` in audisp-remote.conf.

- **audisp-verify-remote-server** → **rsyslog-verify-remote-server** (V-230482)
  STIG check text requires `$ActionSendStreamDriverAuthMode x509/name` in rsyslog.conf.
  Old rule checked `verify_cert` in audisp-remote.conf.

### Updated

- **aslr-enabled** — Added missing `rhel8_v2r6` STIG reference (V-230280).
  Sysctl check was already correct; only the cross-reference was missing.

### Mapping Fixes

- **V-230471** remapped from `audit-binary-permissions` → `audit-config-permissions`.
  STIG checks `/etc/audit/rules.d/` and `/etc/audit/auditd.conf` permissions (0640),
  not `/sbin/audit*` binary permissions. The existing `audit-config-permissions` rule
  already checks the correct paths and permissions.

- **audit-binary-permissions** — Removed stale `rhel8_v2r6` reference (V-230471).
  Rule remains valid for RHEL 9 STIG (V-257924/V-257925).

- **audit-config-permissions** — Added `rhel8_v2r6` STIG reference (V-230471).

- **mappings/stig/rhel8_v2r6.yaml** — Updated V-230479, V-230481, V-230482
  to reference the new `rsyslog-*` rule IDs.
