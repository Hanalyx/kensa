# P4-1: OpenWatch Integration - Evidence & Framework Expansion

## Overview

Enable AEGIS to serve as the canonical evidence source for OpenWatch, supporting claims 7-11 of the OpenWatch positioning framework.

## Goals

| Claim | Goal | Success Criteria |
|-------|------|------------------|
| 7 | Posture queryable at any point in time | Evidence captured with raw output, queryable by time range |
| 8 | Exceptions are explicit state | Exception model designed, AEGIS emits data OpenWatch needs |
| 10 | Frameworks are views, not authorities | 3+ framework families mapped to same canonical rules |
| 11 | Audits are queries over canonical evidence | Structured evidence output contract for OpenWatch API |

## Non-Goals (Deferred)

- Application STIGs (Apache, nginx, PostgreSQL, Docker)
- Cloud benchmarks (AWS, Azure, GCP CIS)
- OpenWatch storage/query implementation (OpenWatch team owns)

---

## Phase 1: Evidence Capture Infrastructure

**Objective:** Capture machine-verifiable evidence with every check.

### 1.1 Extend CheckResult with Evidence

**File:** `runner/_types.py`

```python
@dataclass
class Evidence:
    """Raw evidence captured during a check."""

    method: str                      # Handler name (e.g., "config_value", "command")
    command: str | None              # Actual command executed
    stdout: str                      # Raw stdout
    stderr: str                      # Raw stderr
    exit_code: int                   # Exit code
    expected: str | None             # Expected value (if applicable)
    actual: str | None               # Actual value found
    timestamp: datetime              # When check was executed


@dataclass
class CheckResult:
    """Outcome of a single check."""

    passed: bool
    detail: str = ""
    evidence: Evidence | None = None  # NEW
```

### 1.2 Update Check Handlers to Capture Evidence

Each handler in `runner/handlers/checks/` must populate the `Evidence` dataclass.

**Example - `_config.py`:**

```python
def _check_config_value(ssh: SSHSession, c: dict) -> CheckResult:
    path = c["path"]
    key = c["key"]
    expected = c["expected"]

    cmd = f"grep -E '^{key}' {quote(path)}"
    result = ssh.run(cmd)

    # Parse actual value from output
    actual = parse_config_line(result.stdout, key)
    passed = (actual == expected)

    return CheckResult(
        passed=passed,
        detail=f"{key}={actual}" if actual else f"{key} not found",
        evidence=Evidence(
            method="config_value",
            command=cmd,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            expected=expected,
            actual=actual,
            timestamp=datetime.now(timezone.utc),
        ),
    )
```

### 1.3 Handlers to Update

| Handler | File | Evidence Fields |
|---------|------|-----------------|
| `config_value` | `_config.py` | expected, actual, config line |
| `config_absent` | `_config.py` | key checked, file path |
| `sysctl_value` | `_system.py` | sysctl key, expected, actual |
| `kernel_module_state` | `_system.py` | module name, lsmod output, modprobe output |
| `grub_parameter` | `_system.py` | parameter, grubby output |
| `service_state` | `_service.py` | service name, systemctl output |
| `package_state` | `_package.py` | package name, rpm query output |
| `file_permission` | `_file.py` | path, stat output, expected mode |
| `command` | `_command.py` | full command, stdout, stderr, exit |
| `audit_rule_exists` | `_security.py` | rule pattern, auditctl output |
| `selinux_state` | `_security.py` | getenforce output, config file |
| `pam_module` | `_security.py` | module name, pam config content |

### 1.4 Add Framework References to RuleResult

**File:** `runner/_types.py`

```python
@dataclass
class RuleResult:
    """Outcome of evaluating one rule on one host."""

    rule_id: str
    title: str
    severity: str
    passed: bool
    skipped: bool = False
    skip_reason: str = ""
    detail: str = ""
    evidence: Evidence | None = None           # NEW - from CheckResult
    framework_refs: dict[str, str] = field(default_factory=dict)  # NEW
    # ... existing fields ...
```

**Populate from rule YAML:**

```python
def build_framework_refs(rule: dict) -> dict[str, str]:
    """Extract all framework references from a rule."""
    refs = {}
    if "references" in rule:
        if "cis" in rule["references"]:
            for framework, data in rule["references"]["cis"].items():
                refs[f"cis_{framework}"] = data.get("section", "")
        if "stig" in rule["references"]:
            for framework, data in rule["references"]["stig"].items():
                refs[f"stig_{framework}"] = data.get("vuln_id", "")
        if "nist_800_53" in rule["references"]:
            refs["nist_800_53"] = ",".join(rule["references"]["nist_800_53"])
    return refs
```

---

## Phase 2: Storage Schema Extension

**Objective:** Persist evidence for historical queries.

### 2.1 Extend Database Schema

**File:** `runner/storage.py`

```sql
-- New table for evidence (linked to results)
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id INTEGER NOT NULL,
    method TEXT NOT NULL,
    command TEXT,
    stdout TEXT,
    stderr TEXT,
    exit_code INTEGER,
    expected TEXT,
    actual TEXT,
    check_timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
);

-- New table for framework references
CREATE TABLE IF NOT EXISTS framework_refs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id INTEGER NOT NULL,
    framework TEXT NOT NULL,
    reference TEXT NOT NULL,
    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidence_result ON evidence(result_id);
CREATE INDEX IF NOT EXISTS idx_framework_refs_result ON framework_refs(result_id);
CREATE INDEX IF NOT EXISTS idx_framework_refs_framework ON framework_refs(framework);
```

### 2.2 Update ResultStore Methods

```python
def record_result(
    self,
    session_id: int,
    host: str,
    rule_id: str,
    passed: bool,
    detail: str,
    remediated: bool = False,
    evidence: Evidence | None = None,
    framework_refs: dict[str, str] | None = None,
) -> int:
    """Record a rule result with evidence."""
    # Insert result, get result_id
    # Insert evidence if provided
    # Insert framework_refs if provided
```

### 2.3 Query Methods for OpenWatch

```python
def get_results_by_timerange(
    self,
    start: datetime,
    end: datetime,
    host: str | None = None,
    rule_id: str | None = None,
    framework: str | None = None,
) -> list[ResultRecord]:
    """Query results within a time range with optional filters."""

def get_evidence(self, result_id: int) -> Evidence | None:
    """Retrieve evidence for a specific result."""

def get_framework_refs(self, result_id: int) -> dict[str, str]:
    """Retrieve all framework references for a result."""
```

---

## Phase 3: Structured Output Contract

**Objective:** Define JSON schema for OpenWatch consumption.

### 3.1 Evidence Export Schema

**File:** `runner/output/evidence_schema.json`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AEGIS Evidence Export",
  "type": "object",
  "required": ["version", "session", "host", "results"],
  "properties": {
    "version": {"const": "1.0.0"},
    "session": {
      "type": "object",
      "required": ["id", "timestamp", "rules_path"],
      "properties": {
        "id": {"type": "string"},
        "timestamp": {"type": "string", "format": "date-time"},
        "rules_path": {"type": "string"}
      }
    },
    "host": {
      "type": "object",
      "required": ["hostname", "platform"],
      "properties": {
        "hostname": {"type": "string"},
        "ip": {"type": "string"},
        "platform": {
          "type": "object",
          "properties": {
            "family": {"type": "string"},
            "version": {"type": "string"}
          }
        },
        "capabilities": {"type": "object"},
        "tags": {"type": "array", "items": {"type": "string"}}
      }
    },
    "results": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["rule_id", "passed", "timestamp"],
        "properties": {
          "rule_id": {"type": "string"},
          "title": {"type": "string"},
          "severity": {"enum": ["low", "medium", "high", "critical"]},
          "passed": {"type": "boolean"},
          "skipped": {"type": "boolean"},
          "skip_reason": {"type": "string"},
          "detail": {"type": "string"},
          "timestamp": {"type": "string", "format": "date-time"},
          "evidence": {
            "type": "object",
            "properties": {
              "method": {"type": "string"},
              "command": {"type": "string"},
              "stdout": {"type": "string"},
              "stderr": {"type": "string"},
              "exit_code": {"type": "integer"},
              "expected": {"type": "string"},
              "actual": {"type": "string"}
            }
          },
          "frameworks": {
            "type": "object",
            "additionalProperties": {"type": "string"}
          },
          "remediated": {"type": "boolean"},
          "remediation_evidence": {"type": "object"}
        }
      }
    }
  }
}
```

### 3.2 New Output Format: `evidence`

**Usage:**
```bash
./aegis check -i inventory.ini --sudo -r rules/ -o evidence:results.json
```

**File:** `runner/output/evidence_fmt.py`

```python
def format_evidence(run_result: RunResult) -> str:
    """Format results with full evidence for OpenWatch."""
    output = {
        "version": "1.0.0",
        "session": {
            "id": run_result.session_id,
            "timestamp": run_result.timestamp.isoformat(),
            "rules_path": run_result.rules_path,
        },
        "hosts": []
    }

    for host in run_result.hosts:
        host_data = {
            "hostname": host.hostname,
            "platform": host.platform.__dict__ if host.platform else None,
            "capabilities": host.capabilities,
            "results": []
        }

        for result in host.results:
            result_data = {
                "rule_id": result.rule_id,
                "title": result.title,
                "severity": result.severity,
                "passed": result.passed,
                "timestamp": result.evidence.timestamp.isoformat() if result.evidence else None,
                "evidence": asdict(result.evidence) if result.evidence else None,
                "frameworks": result.framework_refs,
                "remediated": result.remediated,
            }
            host_data["results"].append(result_data)

        output["hosts"].append(host_data)

    return json.dumps(output, indent=2, default=str)
```

---

## Phase 4: Framework Expansion

**Objective:** Prove "frameworks are views" by mapping multiple frameworks to canonical rules.

### 4.1 Add PCI-DSS v4.0 Mapping

**File:** `mappings/pci-dss/v4.0.yaml`

PCI-DSS requirements map heavily to existing controls:

| PCI-DSS Req | Maps To | Existing Rules |
|-------------|---------|----------------|
| 2.2.1 | System hardening | ssh-*, sysctl-*, service-disable-* |
| 2.2.2 | Unnecessary services | service-disable-*, pkg-*-absent |
| 2.2.4 | Security parameters | ssh-*, pam-*, login-defs-* |
| 5.2.1 | Malware protection | aide-installed, aide-cron-check |
| 8.2.1 | Unique user IDs | no-duplicate-usernames |
| 8.2.3 | Password complexity | pam-pwquality-* |
| 8.3.4 | Account lockout | pam-faillock-* |
| 10.2.1 | Audit logging | auditd-*, audit-* |
| 10.3.1 | Audit log integrity | audit-log-permissions |

**Estimated rules mapped:** ~80-100 (60%+ of AEGIS rules)

### 4.2 Add FedRAMP Mapping (via NIST 800-53)

**File:** `mappings/fedramp/moderate.yaml`

FedRAMP Moderate baseline inherits NIST 800-53 controls. AEGIS rules already reference NIST 800-53.

| Control Family | AEGIS Coverage |
|---------------|----------------|
| AC (Access Control) | ssh-*, pam-*, sudo-* |
| AU (Audit) | audit-*, auditd-* |
| CM (Config Mgmt) | All hardening rules |
| IA (Identification) | pam-*, login-defs-* |
| SC (System Protection) | sysctl-*, crypto-* |
| SI (System Integrity) | aide-*, audit-* |

**Approach:** Generate FedRAMP mapping from existing NIST 800-53 references in rules.

```python
def generate_fedramp_mapping(rules_dir: Path) -> dict:
    """Generate FedRAMP mapping from NIST 800-53 refs in rules."""
    mapping = {}
    for rule_file in rules_dir.rglob("*.yml"):
        rule = yaml.safe_load(rule_file.read_text())
        if nist := rule.get("references", {}).get("nist_800_53"):
            for control in nist:
                mapping.setdefault(control, []).append(rule["id"])
    return mapping
```

### 4.3 Add Additional OS Mappings

**Priority order:**

1. **CIS Rocky Linux 9** - Near-identical to RHEL 9, copy mapping
2. **CIS AlmaLinux 9** - Near-identical to RHEL 9, copy mapping
3. **STIG RHEL 8** - Many rules apply, add platform gates
4. **CIS Ubuntu 22.04** - Different commands, new rules needed

**File structure:**
```
mappings/
├── cis/
│   ├── rhel9_v2.0.0.yaml      # Existing
│   ├── rocky9_v1.0.0.yaml     # NEW - derived from rhel9
│   ├── almalinux9_v1.0.0.yaml # NEW - derived from rhel9
│   └── ubuntu2204_v1.0.0.yaml # NEW - requires new rules
├── stig/
│   ├── rhel9_v2r7.yaml        # Existing
│   └── rhel8_v1r14.yaml       # NEW - many rules apply
├── pci-dss/
│   └── v4.0.yaml              # NEW
└── fedramp/
    └── moderate.yaml          # NEW
```

---

## Phase 5: Exception Model Design

**Objective:** Define how exceptions integrate with OpenWatch.

### 5.1 Recommendation: OpenWatch Owns Exception State

AEGIS remains a pure measurement engine. It reports:
- Pass/fail based on technical check
- Host metadata for exception matching
- All framework references

OpenWatch manages:
- Exception definitions (which hosts/rules are excepted)
- Approval workflow
- Expiration tracking
- POA&M linkage

### 5.2 AEGIS Requirements for Exception Support

**Host metadata emission:**

```yaml
# Host tags in inventory
[webservers]
web-01 ansible_host=192.168.1.10 tags=production,web-tier,pci-scope
web-02 ansible_host=192.168.1.11 tags=production,web-tier,pci-scope

[bastions]
bastion-01 ansible_host=192.168.1.5 tags=production,bastion,emergency-access
```

**Evidence output includes tags:**

```json
{
  "host": {
    "hostname": "bastion-01",
    "tags": ["production", "bastion", "emergency-access"]
  },
  "results": [
    {
      "rule_id": "ssh-disable-root-login",
      "passed": false,
      "detail": "PermitRootLogin=yes",
      "frameworks": {"stig_rhel9_v2r7": "V-257960"}
    }
  ]
}
```

**OpenWatch exception rule (example):**

```yaml
# In OpenWatch, not AEGIS
exceptions:
  - id: EXC-2024-0142
    rule_id: ssh-disable-root-login
    host_filter:
      tags_include: [bastion]
    status: accepted_risk
    justification: "Emergency access requirement per IR-4(1)"
    approved_by: "ISSO"
    approved_date: 2024-06-15
    expires: 2025-06-15
    poam_ref: "POA&M-2024-0142"
```

### 5.3 Future: AEGIS-Side Exception Hints (Optional)

If needed later, AEGIS could support exception hints in rules:

```yaml
# In rule YAML
exception_hints:
  - condition: "bastion in host.tags"
    suggested_status: accepted_risk
    rationale: "Bastion hosts may require root access for emergency response"
```

This is informational only - OpenWatch still controls exception state.

---

## Implementation Phases

### Phase 1: Evidence Capture (Week 1-2)

- [ ] Add `Evidence` dataclass to `_types.py`
- [ ] Update `CheckResult` with evidence field
- [ ] Update 12 check handlers to capture evidence
- [ ] Unit tests for evidence capture

### Phase 2: Storage Extension (Week 2)

- [ ] Extend database schema (evidence, framework_refs tables)
- [ ] Update `ResultStore` methods
- [ ] Add migration for existing databases
- [ ] Query methods for time-range and framework filtering

### Phase 3: Output Contract (Week 2-3)

- [ ] Create evidence JSON schema
- [ ] Implement `evidence` output format
- [ ] Add `RuleResult.framework_refs` population
- [ ] Validate output against schema

### Phase 4: Framework Expansion (Week 3-4)

- [ ] Create PCI-DSS v4.0 mapping (~100 rules)
- [ ] Generate FedRAMP Moderate mapping from NIST refs
- [ ] Create Rocky Linux 9 / AlmaLinux 9 mappings (copy + adjust)
- [ ] Update `aegis coverage` to report all frameworks

### Phase 5: Exception Design (Week 4)

- [ ] Document exception model (OpenWatch-owned)
- [ ] Add host tags to inventory parsing
- [ ] Include tags in evidence output
- [ ] Write integration spec for OpenWatch team

---

## Success Metrics

| Claim | Metric | Target |
|-------|--------|--------|
| 7 | Evidence captured for all check types | 100% of handlers |
| 7 | Historical queries functional | Query by time, host, rule, framework |
| 8 | Exception model documented | Design approved by OpenWatch team |
| 10 | Framework families mapped | 4+ (CIS, STIG, PCI-DSS, FedRAMP) |
| 10 | Same rule mapped to multiple frameworks | 80%+ of rules |
| 11 | Evidence schema defined | JSON Schema published |
| 11 | OpenWatch can consume output | Integration test passes |

---

## Dependencies

- OpenWatch team for exception workflow requirements
- OpenWatch API spec for evidence ingestion
- Security review of evidence output (no credential leakage)

---

## Risks

| Risk | Mitigation |
|------|------------|
| Evidence size (stdout can be large) | Truncate at 64KB, compress in storage |
| Credential leakage in evidence | Scrub known patterns (password=, key=) |
| Framework mapping accuracy | Peer review, reference official benchmark docs |
| Schema breaking changes | Version field, backwards compatibility policy |
