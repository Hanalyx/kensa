# Benchmark Disagreement Resolution Plan

**Date:** 2026-02-19
**Source:** `results/report/benchmark-report-00.md` — single-host CIS RHEL 9 v2.0.0 comparison (rhel9-211)
**Baseline:** 392 controls, 206 common, 40 disagreements (80.6% agreement rate)

---

## Executive Summary

The 40 disagreements between Aegis and OpenSCAP fall into four root-cause categories. This plan proposes targeted fixes for each category, ordered by impact and effort.

| Category | Count | Effort | Impact |
|----------|-------|--------|--------|
| A. Aegis check bugs | 5 | Low | Eliminates false failures |
| B. OpenSCAP mapping errors | 9 | Medium | Filters false disagreements |
| C. Aegis scope/criteria tuning | 18 | Medium | Aligns with CIS intent |
| D. Audit rule detection gap | 8 | Low–Medium | Clarifies real vs apparent failures |

**Target:** Reduce disagreements from 40 to <10 genuine differences.

---

## Category A: Aegis Check Bugs (5 controls)

These are broken checks that produce incorrect results regardless of host state. Highest priority — straightforward fixes.

### A1. `nftables-installed` (CIS 4.1.1)

**File:** `rules/network/nftables-installed.yml`
**Bug:** `state: "installed"` — the `package_state` handler only accepts `"present"` or `"absent"`.
**Error:** `Unknown package state: installed`

**Fix:** Change `state: "installed"` to `state: "present"`.

### A2. `package-libpwquality-installed` (CIS 5.3.1.3)

**File:** `rules/access-control/package-libpwquality-installed.yml`
**Bug:** Same as A1 — `state: "installed"` not recognized.
**Error:** `Unknown package state: installed`

**Fix:** Change `state: "installed"` to `state: "present"`.

### A3. `ctrl-alt-del-disabled` (CIS 1.4.5)

**File:** `rules/system/ctrl-alt-del-disabled.yml`
**Bug:** Uses `method: command` with `systemctl is-masked ctrl-alt-del.target`. The `is-masked` verb is not available on all systemd versions.
**Error:** `Unknown command verb is-masked.`

**Fix:** Switch to `method: service_state` with `name: ctrl-alt-del.target` and `enabled: false`. The `service_state` handler already recognizes "masked" as a valid disabled state (see `_service.py` `DISABLED_STATES`).

### A4. `pam-unix-no-nullok` (CIS 5.3.3.4.1)

**File:** `rules/access-control/pam-unix-no-nullok.yml`
**Bug:** Grep pattern `pam_unix\.so.*nullok` scans ALL files under `/etc/pam.d/`, including `sssd-shadowutils` which contains `nullok` in a context unrelated to `pam_unix`. This is a false positive.
**Error:** Finds nullok in `/etc/pam.d/sssd-shadowutils`

**Fix:** Restrict grep to the canonical PAM stack files only:
```bash
grep -E 'pam_unix\.so.*\bnullok\b' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null | grep -v '^\s*#'
```

### A5. `password-inactive` (CIS 5.4.1.5)

**File:** `rules/access-control/password-inactive.yml`
**Bug:** Check runs `useradd -D | grep -q 'INACTIVE=30'` — fails silently (exit 1, empty output) when the default INACTIVE is not exactly 30. No diagnostic output.
**Error:** `exit 1 (expected 0):`

**Fix:** Two options:
- **Option 1 (flexible):** Accept any INACTIVE value between 1 and 45 (CIS allows a range).
- **Option 2 (diagnostic):** Keep exact check but add diagnostic output showing actual vs expected value.

Recommended: Option 1, accept `INACTIVE` in range 1–45 per CIS guidance, with diagnostic output on failure.

---

## Category B: OpenSCAP Mapping Errors (9 controls)

These disagreements are caused by **incorrect CIS section references in the OpenSCAP SCAP Security Guide (SSG) XCCDF content**. The wrong OpenSCAP rules are mapped to the wrong CIS sections, creating false disagreements. Aegis cannot fix SSG data, but can **detect and flag** these in the report.

### Affected Controls

| Control | CIS Topic | OpenSCAP Maps (Wrong Rules) |
|---------|----------|-----------------------------|
| **1.2.1** | GPG signature checking | `package_firewalld_installed`, `service_firewalld_enabled`, `package_nftables_installed`, `service_nftables_disabled` |
| **1.4.2** | GRUB config permissions | 13 rules including unrelated owner/perm checks |
| **1.4.3** | GRUB user config permissions | `sysctl_net_ipv6_conf_default_accept_source_route`, `sysctl_net_ipv4_conf_all_rp_filter`, and 9 more sysctl rules |
| **1.4.5** | Ctrl-Alt-Delete (also A3) | `sysctl_net_ipv4_conf_all_send_redirects`, `sysctl_net_ipv4_conf_default_send_redirects` |
| **1.5.1** | Restrict core dumps | `sysctl_kernel_randomize_va_space` (ASLR, not core dumps) |
| **1.5.2** | SUID core dumps | `sysctl_kernel_yama_ptrace_scope` (ptrace, not core dumps) |
| **2.2.4** | Telnet removed | 19 unrelated rules: `package_dhcp_removed`, `package_ftp_removed`, `service_rpcbind_disabled`, etc. |
| **3.3.1** | IP forwarding disabled | `coredump_disable_backtraces`, `coredump_disable_storage`, `sysctl_kernel_randomize_va_space` mixed in |
| **4.1.2** | Single firewall utility | `package_firewalld_installed`, `service_firewalld_enabled`, `service_nftables_disabled` (overlapping, not utility-count check) |

### Proposed Solution

Add a **mapping-mismatch detection heuristic** to the benchmark report. When OpenSCAP maps rules whose names have zero keyword overlap with the CIS control title, flag the disagreement as "suspected mapping error" rather than a genuine disagreement.

**Implementation options (pick one):**

1. **Allowlist approach (recommended):** Maintain a small YAML file (`scripts/benchmark/known_mapping_errors.yaml`) listing known bad OpenSCAP-to-CIS mappings. The report generator excludes these from the disagreement count and lists them in a separate "Mapping Errors" section.

2. **Heuristic approach:** Compare OpenSCAP rule names against CIS control title keywords. Flag when overlap score is below a threshold. More automated but less precise.

3. **Do nothing:** Document these 9 as known issues. Simple but clutters the report.

---

## Category C: Aegis Scope/Criteria Differences (18 controls)

These are genuine evaluation differences where both tools work correctly but apply different interpretations. Ordered by sub-category.

### C1. SSH Configuration Checks (6 controls)

| Control | Aegis Rule | Aegis Approach | OpenSCAP Approach | Difference |
|---------|-----------|---------------|-------------------|------------|
| **5.1.5** | `ssh-approved-kex` | Checks KexAlgorithms is *defined* (`grep -qi '^kexalgorithms\s'`) | `sshd_use_strong_kex` — validates specific algorithm list | Aegis only checks presence, not values |
| **5.1.6** | `ssh-approved-macs` | Checks MACs is *defined* (`grep -qi '^macs\s'`) | `sshd_use_strong_macs` — validates specific algorithm list | Same: presence-only check |
| **5.1.8** | `ssh-banner` | `sshd_effective_config` key=banner, expected=/etc/issue | `sshd_enable_warning_banner_net` — checks `/etc/issue.net` | Different file: `/etc/issue` vs `/etc/issue.net` |
| **5.1.9** | `ssh-client-alive-interval` | ClientAliveInterval <= 600 (STIG) / 900 (CIS) | `sshd_set_keepalive` + `sshd_set_idle_timeout` | Different thresholds or keepalive vs interval |
| **5.1.18** | `ssh-max-sessions` | `sshd_effective_config` expects exactly `10` | `sshd_set_max_sessions` | May have different expected value |
| **1.6.2** | `ssh-crypto-policy` | Greps for manual crypto overrides in sshd_config (expects none) | `configure_ssh_crypto_policy` | Aegis checks for override presence; OpenSCAP checks policy is applied |

**Proposed fixes:**
- **5.1.5 / 5.1.6:** Validate configured algorithms against a **configurable allowlist** of secure algorithms (defaulted in `defaults.yml`). Do NOT hardcode a CIS-specific list into the rule — per Principle 4, frameworks are metadata. The allowlist default should be the intersection of algorithms considered secure across CIS, STIG, and NIST guidance. Organizations can override via `rules.d/` to match their specific framework or policy. This preserves the framework-agnostic rule while closing the presence-only gap.
- **5.1.8:** Add `/etc/issue.net` as an accepted banner path (CIS mentions both).
- **5.1.9:** The rule already carries dual thresholds (600 STIG / 900 CIS) because frameworks disagree. Per Principle 4, do NOT tune to match one framework — instead, parameterize the threshold via `defaults.yml` (default: 900, the least restrictive compliant value). Organizations targeting STIG can override to 600 in `rules.d/`. The rule expresses the security property "idle timeout is configured within a reasonable bound."
- **5.1.18:** Verify expected value matches CIS. If CIS says "10 or less", change to range check.
- **1.6.2:** Verify this is the correct interpretation. If Aegis finds MACs override lines, that's a real config issue — may be a genuine host config problem, not a check bug.

### C2. Banner/Policy Checks (2 controls)

| Control | Aegis Rule | Issue |
|---------|-----------|-------|
| **1.7.2** | `banner-dod-consent` | Expects DoD consent text ("Authorized uses only..."). CIS only requires *a* warning banner, not DoD-specific text. |
| **1.6.1** | `crypto-policy-no-weak` | Checks `update-crypto-policies --show | grep -qvE 'LEGACY\|DEFAULT:.*weak'`. OpenSCAP's `configure_crypto_policy` may check differently. |

**Proposed fixes:**
- **1.7.2:** The rule's desired state is "a meaningful warning banner is displayed" — this is the framework-agnostic security property. The canonical check should verify the banner file is non-empty and differs from the OS default (e.g., not `\S` or `Kernel \r`). Organization-specific or DoD-specific banner text belongs in `defaults.yml` or `rules.d/` overrides, not in the rule itself. The existing `{{ banner_text }}` parameter is the right mechanism — but the default value should be framework-agnostic (check for non-empty, non-default), not DoD-flavored.
- **1.6.1:** Investigate what `configure_crypto_policy` actually checks. If it's a stricter check (e.g., requires FIPS), the disagreement may be genuine.

### C3. Account/PAM Checks (4 controls)

| Control | Aegis Rule | Issue |
|---------|-----------|-------|
| **5.2.7** | `pam-wheel-su` | Only checks `pam_wheel.so use_uid` in `/etc/pam.d/su`. OpenSCAP also checks wheel group is empty (`ensure_pam_wheel_group_empty`). |
| **5.4.2.2** | `root-only-gid0` | Flags `sync`, `shutdown`, `halt`, `operator` as non-root GID 0 accounts. OpenSCAP's `accounts_root_gid_zero` only checks root's GID. |
| **5.4.2.7** | `nologin-system-accounts` | Checks UID < 1000 has nologin/false shell. OpenSCAP checks both shell and password auth. |
| **5.4.3.2** | `shell-timeout` | Checks TMOUT in `/etc/profile` and `/etc/profile.d/*.sh`. OpenSCAP's `accounts_tmout` may check different locations. |

**Proposed fixes:**
- **5.2.7:** Consider adding wheel group membership check as a second condition.
- **5.4.2.2:** CIS 5.4.2.2 says "Ensure root is the only GID 0 account." Aegis is actually correct and stricter — `sync`, `shutdown`, `halt`, `operator` with GID 0 are flagged correctly. OpenSCAP's check is too lenient. **No change needed.**
- **5.4.2.7:** Investigate exit 1 with empty output — may be an awk quoting issue in the check command.
- **5.4.3.2:** Check if TMOUT is set via `/etc/bashrc` or systemd environment. May need to expand search paths.

### C4. Filesystem/Logging Checks (3 controls)

| Control | Aegis Rule | Issue |
|---------|-----------|-------|
| **5.4.1.6** | `password-change-past` | Custom script checking `/etc/shadow`. OpenSCAP's `accounts_password_last_change_is_in_past` fails — likely a different algorithm or edge case. |
| **6.1.2** | `aide-scheduled` | Checks `aidecheck.timer` or root crontab. OpenSCAP's `aide_periodic_cron_checking` may check different scheduling methods. |
| **6.2.4.1** | `logfiles-access-configured` | Checks ALL `/var/log` files for world-readable perms. OpenSCAP only checks rsyslog-managed files. |

**Proposed fixes:**
- **5.4.1.6:** Aegis passes, OpenSCAP fails. Investigate OpenSCAP's logic — this may be an OpenSCAP false failure.
- **6.1.2:** Expand to also check `aide.timer` (alternative timer name) and `/etc/cron.daily/aide`.
- **6.2.4.1:** Aegis is stricter (checks all log files). This is arguably more correct per CIS. **No change needed**, but document as a known scope difference.

### C5. Other (3 controls)

| Control | Aegis Rule | Issue |
|---------|-----------|-------|
| **3.1.3** | `kmod-disable-bluetooth` | Checks kernel module blacklist. OpenSCAP checks `service_bluetooth_disabled`. Both valid approaches. |
| **6.3.3.12** | `audit-logins` | Aegis checks `-k logins` audit key (passes). OpenSCAP checks `faillock` + `lastlog` rules (fails). Different audit rule scope. |
| **4.1.2** | `firewall-single-utility` | Aegis counts active firewall services. OpenSCAP maps firewalld install/enable rules (mapping error overlap with Category B). |

**Proposed fixes:**
- **3.1.3:** **No change needed.** The kernel module blacklist is the more fundamental control — if the module cannot load, the service cannot run. Adding a service state check is redundant and adds complexity without security benefit. Aegis targets the root mechanism (Principle 2: capabilities, not surface symptoms).
- **6.3.3.12:** No change — Aegis check is correct. OpenSCAP is checking different/additional rules.
- **4.1.2:** Partially a Category B issue. Aegis check logic is correct.

---

## Category D: Audit Rule Detection Gap (8 controls)

Aegis uses `audit_rule_exists` (checks **loaded rules** via `auditctl -l`) while OpenSCAP likely checks **config files** in `/etc/audit/rules.d/`. This creates a detection gap when rules are configured but not loaded.

### Affected Controls

| Control | Aegis Rule | Audit Key/Rule Checked |
|---------|-----------|----------------------|
| **6.3.3.7** | `audit-file-access-failed` | `-k access` |
| **6.3.3.8** | `audit-identity-change` | `-k identity` |
| **6.3.3.9** | `audit-perm-mod` | `-k perm_mod` |
| **6.3.3.13** | `audit-delete` | `-k delete` |
| **6.3.3.15** | `audit-cmd-chcon` | Full rule with `-F path=/usr/bin/chcon` |
| **6.3.3.16** | `audit-cmd-setfacl` | Full rule with `-F path=/usr/bin/setfacl` |
| **6.3.3.17** | `audit-cmd-chacl` | Full rule with `-F path=/usr/bin/chacl` |
| **6.3.3.18** | `audit-cmd-usermod` | Full rule with `-F path=/usr/sbin/usermod` |

### Analysis

The `audit_rule_exists` handler (`runner/handlers/checks/_security.py:155-207`) runs `auditctl -l` and performs **substring matching** against the output. This approach:

- **Correctly checks runtime state** — rules must be loaded to be effective
- **May miss configured-but-not-loaded rules** — if auditd hasn't restarted since config changes
- **Is stricter than OpenSCAP** — which may check config files only

### Proposed Approach

These are likely **genuine failures** on the host (audit rules not loaded). The benchmark detail messages confirm: "Audit rule not found: -k access" etc.

**Investigation needed:**
1. SSH into rhel9-211 and run `auditctl -l` to verify if rules are actually loaded
2. Check `/etc/audit/rules.d/` to see if config files exist
3. If config exists but rules aren't loaded: host config issue (needs `augenrules --load`)
4. If config doesn't exist: genuine missing configuration

**No Aegis code changes needed** — the check is correct in checking loaded rules. Document this as a methodology difference: Aegis checks runtime state, OpenSCAP checks config files.

---

## Implementation Plan

### Phase 1: Quick Wins (Category A — 5 fixes)

**Effort:** 1–2 hours | **Impact:** -5 disagreements

| # | Rule | Fix | Files |
|---|------|-----|-------|
| 1 | `nftables-installed` | `state: "present"` | `rules/network/nftables-installed.yml` |
| 2 | `package-libpwquality-installed` | `state: "present"` | `rules/access-control/package-libpwquality-installed.yml` |
| 3 | `ctrl-alt-del-disabled` | Switch to `service_state` handler | `rules/system/ctrl-alt-del-disabled.yml` |
| 4 | `pam-unix-no-nullok` | Restrict grep to system-auth/password-auth | `rules/access-control/pam-unix-no-nullok.yml` |
| 5 | `password-inactive` | Accept INACTIVE range 1–45, add diagnostics | `rules/access-control/password-inactive.yml` |

### Phase 2: Mapping Error Handling (Category B — 9 controls)

**Effort:** 3–4 hours | **Impact:** -9 false disagreements in report

| # | Task | Files |
|---|------|-------|
| 1 | Create `scripts/benchmark/known_mapping_errors.yaml` with 9 known bad OpenSCAP mappings | New file |
| 2 | Update `scripts/benchmark/report.py` to load allowlist and separate "Mapping Errors" section | `scripts/benchmark/report.py` |
| 3 | Add `--known-errors` CLI flag to point to allowlist | `scripts/benchmark/benchmark_cli.py` |
| 4 | Add tests for mapping error filtering | `tests/test_benchmark.py` |

### Phase 3: SSH/Crypto Check Improvements (Category C1 — 6 controls)

**Effort:** 4–6 hours | **Impact:** -4 to -6 disagreements

| # | Rule | Fix | Files |
|---|------|-----|-------|
| 1 | `ssh-approved-kex` | Validate against configurable secure-algorithm allowlist in `defaults.yml` (framework-agnostic intersection of CIS/STIG/NIST guidance) | `rules/access-control/ssh-approved-kex.yml`, `rules/defaults.yml` |
| 2 | `ssh-approved-macs` | Same approach: configurable allowlist, not framework-specific list | `rules/access-control/ssh-approved-macs.yml`, `rules/defaults.yml` |
| 3 | `ssh-banner` | Accept both `/etc/issue` and `/etc/issue.net` | `rules/access-control/ssh-banner.yml` |
| 4 | `ssh-client-alive-interval` | Parameterize threshold in `defaults.yml` (default: 900). Organizations targeting STIG override to 600 via `rules.d/` | `rules/access-control/ssh-client-alive-interval.yml`, `rules/defaults.yml` |
| 5 | `ssh-max-sessions` | Change to range check (<=10) if CIS allows | `rules/access-control/ssh-max-sessions.yml` |
| 6 | `ssh-crypto-policy` | Investigate host config — may be genuine failure | Investigation only |

### Phase 4: Remaining Scope Tuning (Category C2–C5 — 11 controls)

**Effort:** 3–5 hours | **Impact:** -3 to -5 disagreements

| # | Rule | Fix |
|---|------|-----|
| 1 | `banner-dod-consent` | Change default check to framework-agnostic: verify banner file is non-empty and differs from OS default. Move DoD/org-specific text to `defaults.yml` override |
| 2 | `pam-wheel-su` | Add wheel group empty check as second condition |
| 3 | `nologin-system-accounts` | Debug awk quoting issue causing empty output |
| 4 | `shell-timeout` | Expand TMOUT search to `/etc/bashrc` and systemd environment |
| 5 | `aide-scheduled` | Add `aide.timer` and `/etc/cron.daily/aide` checks |

### Phase 5: Audit Rule Investigation (Category D — 8 controls)

**Effort:** 1–2 hours (investigation) | **Impact:** Documentation / host remediation

| # | Task |
|---|------|
| 1 | SSH into rhel9-211, run `auditctl -l`, verify loaded rules |
| 2 | Check `/etc/audit/rules.d/` for configured rules |
| 3 | If rules configured but not loaded: document as host config issue |
| 4 | Run `augenrules --load` if needed, re-run benchmark to verify |

---

## Expected Outcome

| Phase | Disagreements Resolved | Remaining |
|-------|----------------------|-----------|
| Before | — | 40 |
| After Phase 1 | 5 | 35 |
| After Phase 2 | 9 (flagged separately) | 26 |
| After Phase 3 | 4–6 | 20–22 |
| After Phase 4 | 2–5 | 15–20 |
| After Phase 5 | 0–8 (investigation) | 7–20 |

Conservative target: **<15 genuine disagreements** after all phases.
Optimistic target: **<10 genuine disagreements** if audit rules are a host config issue.

**Note on remaining disagreements:** Some residual disagreements are expected and acceptable — they represent cases where Aegis intentionally applies a stricter or more fundamental check than OpenSCAP (e.g., 5.4.2.2 root-only-gid0, 6.2.4.1 logfile permissions, 3.1.3 kernel module blacklist). These are not defects; they reflect Aegis's evidence-first, capability-targeted philosophy.

---

## Verification

After each phase:
1. Re-run benchmark: `python3 -m scripts.benchmark.benchmark_cli --aegis results/aegis-211.json --openscap results/openscap/rhel9-211.xml --framework cis-rhel9-v2.0.0 --output results/report/benchmark-report-XX.md`
2. Compare disagreement count against previous run
3. Run full test suite: `pytest tests/test_benchmark.py -v`
4. Lint: `ruff check && ruff format --check`
