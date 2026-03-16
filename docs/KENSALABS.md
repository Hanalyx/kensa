# Kensa Labs: From Validator to Source of Truth

**Status:** Strategic vision document
**Last updated:** 2026-03-15

---

## 1. The Problem We're Solving

The compliance industry has a trust chain problem. Organizations secure their Linux systems based on benchmarks written by committees (DISA STIG, CIS Benchmarks) and validated by tools (OpenSCAP, Nessus, Qualys). But neither the benchmarks nor the tools are as reliable as they appear:

- **Stale check methods.** CIS and STIG checks frequently read static config files (`/etc/ssh/sshd_config`) instead of verifying effective state (`sshd -T`). Drop-in overrides, runtime changes, and package defaults are invisible to these checks.
- **Copy-paste errors.** Multi-hundred-page benchmarks contain version-specific assumptions, wrong file paths, and contradictory remediation guidance propagated across releases.
- **Opaque tooling.** OpenSCAP returns pass/fail through OVAL XML assertions. When a check fails, there's no human-readable evidence — the auditor must trust the tool or re-run the check manually.
- **Fragile remediation.** Benchmark fix scripts edit main config files directly, breaking on package updates. No rollback. No pre-state capture. No idempotency guarantees.

Organizations pass audits while remaining vulnerable, and fail audits on false positives. Neither outcome serves the actual goal: secure systems with verifiable evidence.

Kensa exists to fix this. But today, Kensa validates against external sources of truth (CIS, STIG). The long-term goal of Kensa Labs is to make Kensa itself the trusted source of truth for Linux operating system compliance and security.

---

## 2. The Two-Layer Model

The transition from validator to authority requires two layers operating simultaneously. One earns trust by being correct about what others define. The other earns trust by being right about what others miss.

### Layer 1: Compliance (Current Priority)

The compliance layer matches external SOT — CIS, STIG, NIST 800-53, FedRAMP, PCI-DSS — exactly. Every check, every key name, every expected value must align with what the benchmark document specifies. This is non-negotiable and must be airtight before Layer 2 has any credibility.

**Why this comes first:** A single false positive erodes trust faster than a hundred correct findings build it. When an auditor runs a Kensa STIG scan and gets a finding on a correctly-configured host (as happened with the `-k privileged` vs `-k privileged-chage` audit key mismatch — PR #167), the tool loses credibility. The auditor switches back to OpenSCAP.

**What "airtight" means:**
- Every rule's check criteria is verified against the benchmark source document (STIG XML datastream, CIS PDF, NIST OSCAL baseline)
- Every rule's remediation produces a state that the corresponding check will pass
- Evidence output is human-readable and auditor-verifiable without re-running the scan
- Zero false positives on correctly-configured hosts. Zero.

**Current state (v1.3.0):**
- CIS RHEL 8: 91.0% coverage (293/322 controls mapped)
- CIS RHEL 9: 92.9% (276/297)
- STIG RHEL 8: 95.1% (348/366)
- STIG RHEL 9: 94.2% (420/446)
- Live scan validation against OpenSCAP on RHEL 8.10 and RHEL 9.6 hosts completed

### Layer 2: Kensa Labs Advisories

The Labs layer documents where Kensa has a researched, evidence-backed position that differs from or extends the benchmark. Each advisory is:

- **Identified** — references the specific benchmark control (e.g., "STIG V-258191, CIS 4.1.3.7")
- **Researched** — explains the benchmark's approach, its limitations, and the underlying OS behavior
- **Tested** — validated on real systems across supported OS versions
- **Recommended** — provides Kensa's position with clear rationale
- **Non-blocking** — the compliance layer still passes based on the SOT; the advisory is supplementary

**Example advisory (from the audit key incident):**

> **KL-0001: Per-command audit keys for privileged command forensics**
>
> *Benchmark:* STIG RHEL 9 V2R7 (V-258191 and 24 related controls)
> *SOT position:* Use shared key `-k privileged` for all privileged command audit rules
> *Kensa Labs position:* Per-command keys (`-k privileged-chage`, `-k privileged-sudo`, etc.) enable targeted forensic searches with `ausearch -k privileged-chage` instead of searching the entire privileged command log
> *Trade-off:* Shared key is simpler to deploy and audit; per-command keys provide better incident response granularity
> *Recommendation:* Organizations with mature SOC operations should consider per-command keys. Compliance scans should use the shared key to match the SOT.

---

## 3. Core Competencies for Kensa Labs

Becoming a trusted source of truth for Linux compliance requires deep expertise across multiple domains. These are the core competencies the Kensa team must develop and demonstrate.

### 3.1 Linux Kernel and Subsystem Internals

**Why:** Compliance controls ultimately gate kernel behavior — syscall auditing, network stack parameters, filesystem permissions, security modules. Without understanding the kernel, you're pattern-matching config files without knowing what they control.

**What to master:**
- **Audit subsystem** (`auditd`, `auditctl`, `aureport`, `ausearch`): How rules are loaded (augenrules vs auditctl), how `-S all` is implicit for path rules, how key names work, the difference between `-k` and `-F key=`, how `auid!=unset` maps to `-1` and `4294967295`
- **SELinux**: Policy compilation, boolean effects, context inheritance, targeted vs MLS policy, `semanage`, `restorecon`, how `permissive` domains differ from `enforcing`
- **Sysctl**: Namespace hierarchy (`net.ipv4` vs `net.ipv6`), `conf.all` vs `conf.default` vs per-interface semantics, runtime vs persistent state, how sysctl.d drop-ins layer
- **PAM**: Stack evaluation order, module behavior (required vs requisite vs sufficient), how `authselect` manages PAM on RHEL 8+, `faillock` vs `pam_tally2`, `pwquality` integration
- **Systemd**: Unit file precedence (vendor → admin → runtime), drop-in directories, dependency ordering, socket activation, `systemctl show` vs config files, timer units
- **Filesystem**: Mount options and propagation, `fstab` vs `systemd.mount`, `findmnt` as the source of truth for mount state, `xattr` and ACL interaction
- **Cryptographic policy**: `crypto-policies` on RHEL 8+, how `update-crypto-policies` affects OpenSSH/GnuTLS/NSS/OpenSSL simultaneously, FIPS mode implications

### 3.2 Distribution-Specific Knowledge

**Why:** The same kernel runs differently across distributions. Package defaults, file locations, init systems, and security tooling vary. A check that works on RHEL 9 may silently give wrong results on SUSE or Ubuntu.

**What to master:**
- **RHEL/CentOS/Rocky/Alma** (current): RPM packaging, `dnf` module streams, RHEL-specific security tooling (`aide`, `fapolicyd`, `usbguard`), Red Hat's backporting policy (kernel version != feature set), RHEL minor release security differences
- **SUSE/SLES** (v2 target): `zypper`, YaST security modules, `apparmor` vs SELinux default, `/etc/sysconfig` patterns, SUSE-specific PAM stack
- **Ubuntu/Debian** (v3 target): `apt`, `dpkg-reconfigure`, `ufw` vs direct `iptables`/`nftables`, `unattended-upgrades`, Debian's filesystem hierarchy divergences, AppArmor default policy
- **Fedora** (experimental): Bleeding-edge packages, Fedora-to-RHEL pipeline (what lands in Fedora today ships in RHEL tomorrow), testing ground for capability detection

**Distribution research impact:** A Kensa Labs advisory might say "CIS RHEL 9 control 5.2.4 checks `/etc/ssh/sshd_config` for `PermitRootLogin`, but RHEL 9.2+ ships with `PermitRootLogin` set to `prohibit-password` in the compiled default — the file may not contain the directive at all, and the system is compliant." This kind of knowledge comes from understanding distribution packaging decisions, not from reading the benchmark.

### 3.3 Security Research and Threat Modeling

**Why:** Benchmarks check controls. Controls are proxies for security outcomes. Understanding the actual threat — not just the control — lets you evaluate whether a benchmark check is effective, redundant, or misguided.

**What to master:**
- **Linux privilege escalation paths**: SUID/SGID abuse, capability escalation, cgroup escapes, namespace breakouts, kernel exploits — understanding what controls actually prevent
- **Audit log analysis**: What audit events matter for detection, what's noise, how attackers clear logs, how immutable audit logging works
- **Network attack surfaces**: Which sysctl parameters matter for real-world attacks (IP forwarding, ICMP redirects, source routing) vs which are cargo-cult hardening
- **Credential security**: PAM attack surface, password storage (`/etc/shadow` algorithms), SSO/MFA integration points, SSH key management lifecycle
- **Supply chain**: Package integrity verification, `gpgcheck`, repository signing, SBOM for compliance tooling itself
- **Container and VM boundary**: How host-level compliance applies (or doesn't) to containerized workloads, what controls are meaningless in ephemeral container environments

### 3.4 Benchmark Forensics

**Why:** To surpass the benchmarks, you have to understand how they're built, where they fail, and why. This is the most directly applicable competency for Kensa Labs advisories.

**What to master:**
- **STIG development process**: How DISA produces STIGs, the XCCDF/OVAL format, how the SCAP datastream is constructed, the relationship between SRG (generic) and STIG (product-specific), how to read OVAL definitions to understand what OpenSCAP actually checks
- **CIS benchmark process**: How CIS Workbenches produce benchmarks, the Level 1/Level 2 distinction, the "Scored/Not Scored" (now "Automated/Manual") classification, how CIS benchmarks differ from STIGs on the same control
- **NIST 800-53 control decomposition**: How abstract controls (AC-2 "Account Management") decompose into technical checks, the relationship between control families and implementation, why different frameworks disagree on what satisfies a control
- **Benchmark version diffing**: Tracking what changed between benchmark versions (CIS RHEL 8 v3.0 → v4.0, STIG V2R6 → V2R7), identifying controls that were added, removed, or silently modified
- **Cross-benchmark gap analysis**: Where CIS and STIG disagree on the same underlying security control, which is right, and why

### 3.5 Evidence Engineering

**Why:** The shift from "trust the tool" to "trust the evidence" is Kensa's core differentiator. The quality and verifiability of evidence determines whether Kensa can stand as a source of truth.

**What to master:**
- **Evidence capture design**: What command output constitutes proof for each check type, how to make evidence self-contained (an auditor can verify the finding from the evidence alone, without access to the host)
- **Evidence chain integrity**: Timestamps, command provenance, host identity — enough metadata for forensic chain of custody
- **Remediation evidence**: Pre-state snapshots, post-state verification, rollback proof — demonstrating that remediation was safe and reversible
- **Evidence presentation**: Making raw command output meaningful to non-Linux audiences (auditors, GRC analysts, executives) without losing technical precision

---

## 4. The Advisory Process: How to Build the Body of Work

Building trust as a SOT requires a disciplined, repeatable process for producing advisories. Each advisory adds to a body of work that, in aggregate, demonstrates expertise.

### 4.1 Discovery

Advisories originate from five sources:

1. **Live scan discrepancies**: Running Kensa and OpenSCAP (or Nessus, Qualys) against the same host and investigating disagreements. The audit key mismatch (PR #167) was discovered this way.

2. **Benchmark review**: Systematically reading benchmark controls and cross-referencing with actual OS behavior. "Does this CIS check actually verify what it claims to verify?"

3. **Distribution change tracking**: Monitoring RHEL/SUSE/Ubuntu release notes, package changelogs, and errata for changes that affect compliance controls. "RHEL 9.4 changed the default crypto policy — does CIS control X still make sense?"

4. **Security incident analysis**: When a real-world vulnerability or breach involves a misconfigured Linux system, analyzing whether existing benchmark controls would have detected or prevented it.

5. **Community and customer feedback**: Reports from users running Kensa in production who encounter unexpected results, false positives, or benchmark gaps.

### 4.2 Research

Once a candidate advisory is identified, the research phase determines whether it warrants formal publication.

**Research checklist:**
- [ ] Identify the specific benchmark control(s) affected (STIG V-ID, CIS section, NIST control)
- [ ] Read the benchmark's exact check description and remediation guidance
- [ ] Reproduce the benchmark's check on a real system — verify it behaves as documented
- [ ] Identify the discrepancy: Is the benchmark wrong, incomplete, or suboptimal?
- [ ] Test across supported OS versions (RHEL 8, RHEL 9, and applicable derivatives)
- [ ] Document the OS-level mechanism involved (kernel subsystem, config precedence, service behavior)
- [ ] Assess the security impact: Does the discrepancy create a real vulnerability, a false positive, or a missed detection?
- [ ] Check if other tools (OpenSCAP, Nessus, Qualys) handle this case correctly or exhibit the same issue

### 4.3 Classification

Each advisory is classified by type and severity:

**Advisory types:**
- **SOT Deviation**: The benchmark says X, but the technically correct answer is Y. Kensa's compliance layer follows X; the advisory recommends Y.
- **SOT Gap**: The benchmark doesn't check something it should. No existing control covers this risk.
- **SOT Error**: The benchmark's check or remediation is factually wrong — it will pass a misconfigured system or break a correctly-configured one.
- **SOT Staleness**: The benchmark hasn't been updated for a distribution change. The check worked on RHEL 8 but is meaningless on RHEL 9.
- **Enhancement**: The benchmark's approach works but a better method exists (more reliable, more evidence, fewer false positives).

**Severity levels:**
- **Critical**: The benchmark error creates a security vulnerability (e.g., remediation weakens security, check passes a vulnerable state)
- **High**: The benchmark produces false positives/negatives that undermine compliance accuracy
- **Medium**: The benchmark's approach is suboptimal but not wrong — better methods exist
- **Low**: Cosmetic or informational — naming conventions, evidence clarity, documentation gaps

### 4.4 Publication Format

Each advisory follows a standardized format:

```
Advisory ID:     KL-NNNN
Title:           Short descriptive title
Published:       YYYY-MM-DD
Updated:         YYYY-MM-DD
Type:            SOT Deviation | SOT Gap | SOT Error | SOT Staleness | Enhancement
Severity:        Critical | High | Medium | Low
Affects:         Benchmark control IDs (STIG V-XXXXX, CIS X.Y.Z)
OS Versions:     RHEL 8, RHEL 9 (etc.)

BENCHMARK POSITION
  What the benchmark specifies — exact check and remediation text.

OBSERVED BEHAVIOR
  What actually happens on a real system. Command output, version-specific
  differences, edge cases.

KENSA LABS POSITION
  Our researched recommendation. What we believe is the correct approach
  and why.

EVIDENCE
  Test results from real systems demonstrating the discrepancy.
  Reproducible commands and expected output.

IMPACT
  What happens if you follow the benchmark vs. the Kensa Labs recommendation.
  Security implications, operational risk, false positive/negative rates.

RECOMMENDATION
  Concrete guidance for operators. May include multiple tiers
  (minimum compliance, recommended hardening, maximum security).
```

### 4.5 Review and Quality Gate

No advisory publishes without:
- **Technical review**: Verified on at least two OS versions by someone other than the author
- **Benchmark verification**: The SOT text is quoted exactly, not paraphrased
- **Reproducibility**: Any reader can reproduce the finding using the provided commands
- **Neutrality**: The advisory documents the trade-off, not just our preference. If the benchmark's approach has advantages, we say so

---

## 5. The Trust Shift: From Validator to Authority

Trust doesn't shift because you declare yourself an authority. It shifts because practitioners — security engineers, auditors, compliance officers — consistently find your work more reliable than the alternative.

### Phase 1: Prove Accuracy (Current — 2026)

**Goal:** Kensa's compliance layer is demonstrably as accurate as or more accurate than OpenSCAP for CIS and STIG on RHEL 8/9.

**Milestones:**
- 100% SOT alignment on all mapped controls (zero false positives on correctly-configured hosts)
- Head-to-head scan comparisons published with evidence
- Every Kensa finding includes auditor-verifiable evidence that OpenSCAP does not provide
- Community adoption: security engineers choose Kensa for compliance scans based on evidence quality

**Trust signal:** "Kensa gives the same results as OpenSCAP, but with better evidence."

### Phase 2: Demonstrate Expertise (2026-2027)

**Goal:** Kensa Labs publishes 50+ advisories documenting benchmark issues, with a track record of being correct.

**Milestones:**
- Systematic benchmark review completed for STIG RHEL 9, CIS RHEL 9
- Advisories published covering all major subsystems (audit, PAM, SSH, sysctl, SELinux, filesystem, services)
- At least 5 advisories where the benchmark is subsequently updated to match Kensa Labs' recommendation
- Cross-platform coverage: advisories applicable to SUSE and Ubuntu as those platforms are added
- Engagement with DISA and CIS benchmark development processes (submitting corrections, participating in reviews)

**Trust signal:** "When Kensa Labs says the benchmark is wrong, they're usually right."

### Phase 3: Become the Reference (2027+)

**Goal:** Practitioners consult Kensa Labs advisories as a primary reference alongside (not instead of) CIS and STIG.

**Milestones:**
- Kensa Labs advisory database is publicly searchable and indexed
- Advisories are cited in third-party security documentation, training materials, and audit reports
- Organizations reference Kensa Labs recommendations in their compliance programs ("We follow STIG with Kensa Labs supplemental guidance")
- Benchmark authors reference Kensa Labs research when updating their controls

**Trust signal:** "What does Kensa say about this control?"

### Phase 4: Define the Standard (Long-term)

**Goal:** Kensa's body of work is comprehensive and reliable enough that organizations use it as their primary compliance framework, with CIS/STIG as secondary references.

**This is not a near-term goal.** It requires years of accumulated research, broad platform coverage, a public track record, and community trust. It cannot be declared — it must be earned.

**Trust signal:** "We use Kensa for compliance. It covers STIG and CIS plus the gaps they miss."

---

## 6. Getting Started: First 10 Advisories

The body of work starts with the first advisory. Here are 10 candidates identified from existing Kensa development work, ordered by research readiness.

### Ready Now (evidence already gathered)

**KL-0001: Per-command vs shared audit keys for privileged commands**
- Type: Enhancement
- Affects: STIG V-258191 and 24 related V-IDs (RHEL 8 and 9)
- Source: PR #167 audit key correction work
- Research needed: Performance comparison of `ausearch -k privileged` vs `ausearch -k privileged-chage` on high-volume audit logs

**KL-0002: Effective sshd configuration vs static file checks**
- Type: SOT Error
- Affects: CIS 5.2.x (SSH controls), STIG V-25xxxx (SSH controls)
- Source: Kensa's `sshd_effective_config` handler exists because `grep sshd_config` is unreliable
- Research needed: Document specific scenarios where static file check passes but effective config differs (drop-in overrides, compiled defaults, Match blocks)

**KL-0003: Sysctl conf.all vs conf.default vs per-interface semantics**
- Type: SOT Error
- Affects: STIG V-230548 (ip_forward), CIS 3.3.x (network parameters)
- Source: PR #149 found STIG mapping errors from conf.all/conf.default confusion
- Research needed: Document kernel behavior when conf.all=0 but conf.eth0=1, and which sysctl check method catches this

### Near-term Research Needed

**KL-0004: PAM authselect management vs direct file editing**
- Type: SOT Staleness
- Affects: STIG and CIS PAM controls on RHEL 8+
- Source: Benchmarks still reference direct editing of `/etc/pam.d/` files, which `authselect` will overwrite
- Research needed: Document the authselect lifecycle and when direct edits are safe vs dangerous

**KL-0005: Crypto-policies vs per-application crypto configuration**
- Type: SOT Deviation
- Affects: CIS/STIG SSH cipher and MAC controls
- Source: RHEL 8+ crypto-policies set crypto defaults globally; per-application overrides may conflict
- Research needed: Document interaction between `update-crypto-policies` and sshd_config Ciphers/MACs settings

**KL-0006: Drop-in configuration file precedence and package update survival**
- Type: Enhancement
- Affects: All controls that remediate by editing main config files
- Source: Kensa's `config_set_dropin` handler exists because main-file edits are fragile
- Research needed: Systematic test of which config systems support drop-ins (sshd, sysctl, chrony, systemd, sudoers, audit, rsyslog, logrotate) and their precedence rules

**KL-0007: Mount option verification via findmnt vs fstab parsing**
- Type: SOT Error
- Affects: CIS 1.1.x (filesystem controls), STIG V-230xxx (mount options)
- Source: Kensa checks `findmnt` for effective mount state; benchmarks check `/etc/fstab`
- Research needed: Document scenarios where fstab and mount state diverge (systemd .mount units, autofs, bind mounts, propagation)

### Medium-term Research

**KL-0008: AIDE vs other file integrity monitoring approaches**
- Type: SOT Gap
- Affects: CIS 1.3.x, STIG V-230551
- Source: Benchmarks mandate AIDE specifically; alternative FIM tools (OSSEC, Tripwire, Wazuh) satisfy the same security objective
- Research needed: Compare FIM approaches on detection capability, performance, and operational overhead

**KL-0009: Audit rule completeness vs audit log volume trade-offs**
- Type: Enhancement
- Affects: All audit controls (STIG, CIS Chapter 4)
- Source: STIG mandates 100+ individual audit rules; high-volume systems may face log saturation
- Research needed: Measure audit log volume impact, identify rules that generate noise vs actionable findings, propose tiered audit profiles

**KL-0010: GDM/GUI controls on headless servers**
- Type: SOT Gap
- Affects: STIG V-230349 through V-230359 (GDM controls)
- Source: Kensa uses `conflicts_with: [gdm-removed]` pattern; benchmarks check GDM settings without verifying GDM is installed
- Research needed: Document the security rationale for removing GDM entirely vs configuring it, and when each approach is appropriate

---

## 7. Infrastructure for Kensa Labs

### 7.1 Advisory Storage

Advisories live in `context/labs/` as structured YAML files (machine-parseable, renderable to markdown or HTML):

```
context/labs/
  KL-0001.yaml
  KL-0002.yaml
  ...
  index.yaml        # Advisory index with metadata for filtering/search
```

### 7.2 Test Hosts

Research requires real systems at multiple OS versions. The current lab inventory (RHEL 8.10 and 9.6 hosts) supports initial research. As platform coverage expands:

- RHEL 8 (latest minor), RHEL 9 (latest minor), RHEL 10 (when available)
- Rocky/Alma equivalents for derivative testing
- SUSE/SLES 15 (v2 timeline)
- Ubuntu 22.04/24.04 (v3 timeline)
- Minimal and full installations of each (to test package-dependent controls)

### 7.3 Comparison Tooling

The Kensa-vs-OpenSCAP scan comparison infrastructure (`/tmp/kensa-vs-oscap/`) should be formalized into a repeatable tool:

- Parse OpenSCAP XCCDF results XML
- Parse Kensa JSON results
- Produce rule-by-rule comparison with disagreement analysis
- Track comparison results over time (new disagreements after benchmark or Kensa updates)

### 7.4 Benchmark Source Documents

Maintain authoritative copies of benchmark source documents for reference:

```
SOT/
  CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v4.0.0.pdf
  CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0.pdf
  STIG RHEL 8 V2R6 (extracted from datastream)
  STIG RHEL 9 V2R7 (extracted from datastream)
```

---

## 8. Organizational Principles

### Research Integrity

- **Never claim the benchmark is wrong without evidence.** Every advisory must be reproducible.
- **Acknowledge when the benchmark is right.** If research confirms the SOT is correct, document that too — it builds credibility.
- **Separate opinion from finding.** The advisory documents the discrepancy and evidence. The recommendation is clearly labeled as Kensa's position.
- **Update advisories when wrong.** If subsequent research or benchmark updates invalidate an advisory, retract or update it publicly. Being wrong and correcting it builds more trust than never being wrong.

### Independence

- Kensa Labs research is independent of any benchmark vendor. We don't coordinate findings with CIS or DISA before publication (though we may submit corrections through their processes after publication).
- Advisories are not influenced by customer requests to weaken or strengthen specific controls. The research says what the research says.

### Scope Discipline

- Kensa Labs covers **operating system compliance and security**. Not application security, not cloud infrastructure, not governance processes.
- Every advisory must be testable on a real Linux system with reproducible commands.
- Organizational and procedural controls (policy documents, training, access reviews) are out of scope. Kensa measures technical state.

---

## 9. Success Metrics

How we know Kensa Labs is working:

| Metric | Phase 1 | Phase 2 | Phase 3 |
|--------|---------|---------|---------|
| False positive rate on live scans | < 1% | 0% | 0% |
| Published advisories | 5 | 50+ | 200+ |
| Advisories confirmed by benchmark updates | — | 5+ | 20+ |
| OS versions covered per advisory | 2 (RHEL 8, 9) | 4+ | 6+ |
| External citations of Kensa Labs advisories | — | — | 10+ |
| Head-to-head comparisons published | 2 | 10+ | Continuous |

---

## 10. Closing Thought

The compliance industry is built on trust in documents written by committees that meet twice a year. Kensa Labs is built on trust in evidence gathered from real systems every day. The question isn't whether a committee-authored benchmark or a continuously-tested tool is more reliable — it's how long it takes for the industry to recognize the answer.

The body of work starts with KL-0001. Each advisory after that adds weight. There's no shortcut and no declaration — just accumulated, verified, public expertise that practitioners learn to rely on.
