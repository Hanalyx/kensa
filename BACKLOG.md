# Kensa-go Backlog

Items are ordered roughly by priority within each section. No commitment to scheduling until promoted to a milestone.

---

## Capability Detection

### Ubuntu/Debian probe support
**Context:** `internal/detect` currently probes 25 capabilities, all RHEL/EL-family specific. Running `detect` against `.217` (Ubuntu `owas-ub5s2`) yields only 7/25 because probes like `authselect`, `crypto_policies`, `fapolicyd`, `selinux`, `subscription_manager`, `grub_bls`, and `dnf_automatic` do not exist on Debian-family systems.

**Work required:**
- Add Ubuntu/Debian equivalent probes alongside RHEL probes, keyed by the same capability name where a functional equivalent exists:

| Capability (RHEL probe) | Ubuntu/Debian equivalent |
|---|---|
| `authselect` | `pam-auth-update` — `command -v pam-auth-update` |
| `crypto_policies` | No direct equivalent; detect via `dpkg -l libssl-dev` or `openssl version` |
| `fips_mode` | `fips-mode-setup` exists on Ubuntu Pro; otherwise `/proc/sys/crypto/fips_enabled` = 1 |
| `dnf_automatic` | `unattended-upgrades` — `dpkg -l unattended-upgrades` |
| `subscription_manager` | `ua status` (Ubuntu Advantage / Pro) |
| `selinux` | `apparmor_status` — detect AppArmor as a separate cap `apparmor` |
| `fapolicyd` | No equivalent; mark false on Debian |
| `grub_bls` | `[ -d /boot/loader/entries ]` works if systemd-boot; else `/etc/default/grub` |
| `sshd_config_d` | Same probe works (directory check + Include grep) |
| `pam_faillock` | `pam_tally2` or `pam_faillock` depending on Ubuntu version |
| `usbguard` | Same `systemctl` probe works |
| `sssd` | Same `systemctl` probe works |
| `chronyd` | `chrony` package: same `systemctl` probe works |
| `at` | Same `command -v at` works |
| `auditd` | Same `systemctl` probe works |
| `aide` | Same `command -v aide` works |
| `cron` | Ubuntu uses `cron.service`, not `crond.service` — probe already handles both |
| `rsyslog` | Same `systemctl` probe works |
| `journald` | Same `systemctl` probe works |
| `nftables` | Same `command -v nft` works |
| `firewalld` | Ubuntu may use `ufw` instead — add `ufw` as a separate capability |
| `coredump_systemd` | Same `systemctl` probe works |

**New Ubuntu-specific capabilities to add:**
- `apparmor` — `aa-status 2>/dev/null | grep -q 'apparmor module is loaded'`
- `ufw` — `systemctl list-unit-files ufw.service 2>/dev/null | grep -q ufw`
- `apt_unattended_upgrades` — `dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'`
- `ubuntu_advantage` — `command -v ua >/dev/null 2>&1 || command -v pro >/dev/null 2>&1`
- `dpkg` — `command -v dpkg >/dev/null 2>&1` (distro discriminator for implementation selection)
- `apt` — `command -v apt-get >/dev/null 2>&1` (gates `package_present`/`package_absent` Ubuntu impls)

**Implementation approach:**
- Add the new probes to `internal/detect/detect.go` alongside existing ones; the probe runner is already distro-agnostic.
- Add `package_installed` / `package_absent` check methods for `dpkg -l` in `internal/check/check.go`.
- Add `package_present` / `package_absent` handler impls gated on the `apt` capability.
- Rules that have both RHEL and Ubuntu implementations should list them as separate `implementations` entries with `requires` capability constraints.

**Test host:** `192.168.1.217` (`owas-ub5s2.hanalyx.local`) — Ubuntu, reachable as `owadmin`.

---

## Handlers

- `audit_rule_set` — handler stub exists; implementation pending (Week 6 partial).
- `grub_parameter_set` — non-capturable; requires deadman-guarded write to `/etc/default/grub` + `grub2-mkconfig`.
- `command_exec` — generic escape hatch for one-off remediation commands not covered by a structured handler.
- `manual` — mechanism that marks a rule as requiring human intervention; engine records it as `StatusSkipped` with a note.

---

## CLI / UX

- `--inventory` flag for `check`, `detect`, `remediate` — parse Ansible-style `inventory.ini` and fan out across hosts.
- Machine-readable scan output suitable for OpenWatch ingestion (JSON Lines per host).

---

## Infrastructure

- `scripts/bench_aggregate.go` — aggregate benchmark across a rule corpus.
- FIPS-mode enforcement option for the SSH transport (reject connections when `fips_mode` is false on target).
