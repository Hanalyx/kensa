You are helping a developer systematically verify that framework-to-rule mappings are correct and that Kensa rules accurately implement what each framework control requires.

## Core Principle

**Kensa rules are framework-independent.** A rule describes desired system state. Frameworks (STIG, CIS, NIST, PCI-DSS) map *to* rules. When a mismatch is found, the most common fix is correcting the mapping or adding a new rule — not changing an existing rule to fit a framework. Always determine: is the rule wrong, or is the mapping wrong?

## Sources of Truth

| Framework | SOT | How to Access | URL Pattern |
|-----------|-----|---------------|-------------|
| STIG RHEL 8 V2R6 | DISA STIG Check Text + Fix Text | stigviewer.com | `https://www.stigviewer.com/stigs/red_hat_enterprise_linux_8/2025-05-14/finding/V-XXXXXX` |
| STIG RHEL 9 V2R7 | DISA STIG Check Text + Fix Text | stigviewer.com | `https://www.stigviewer.com/stigs/red_hat_enterprise_linux_9/2025-05-14/finding/V-XXXXXX` |
| CIS RHEL 8 v4.0.0 | CIS Benchmark PDF | `context/cis/rhel8-v4.0.0-baseline.yaml` for structure | N/A |
| CIS RHEL 9 v2.0.0 | CIS Benchmark PDF | `context/cis/rhel9-v2.0.0-baseline.yaml` for structure | N/A |
| NIST 800-53 Rev 5 | NIST SP 800-53 catalog | `context/fedramp/moderate-rev5-baseline.yaml` | N/A |
| PCI-DSS v4.0 | PCI SSC standard | Offline reference | N/A |

For STIG reviews, the **Check Text** is the primary SOT — it defines exactly what an auditor runs. The **Fix Text** defines the expected remediation.

### SOT URL in Review Notes

Every review note **must** include the SOT URL when one is available. This gives the human reviewer a direct link to verify the finding.

**STIG URL format:**
```
SOT: https://www.stigviewer.com/stigs/red_hat_enterprise_linux_8/2025-05-14/finding/V-XXXXXX
```

Include the URL after the control ID and framework version, before the finding details:
```
V-230481. Reviewed against STIG RHEL 8 V2R6. SOT: https://www.stigviewer.com/stigs/red_hat_enterprise_linux_8/2025-05-14/finding/V-230481. WRONG SCOPE. [details...]
```

## Context Files

Read these before starting a review session:

1. **Rule schema**: `docs/CANONICAL_RULE_SCHEMA_V0.md` — how rules are structured
2. **Mapping file** for the target framework (e.g., `mappings/stig/rhel8_v2r6.yaml`)
3. **Review database**: accessed via the review server API at `http://127.0.0.1:5050`

## Review Checklist (4 Steps per Control-to-Rule Mapping)

For each framework control mapped to a Kensa rule, evaluate these in order:

### Step 1: Mapping Correctness
> Does this framework control's title/description actually correspond to what this Kensa rule enforces?

- Read the framework control's description from the SOT
- Read the Kensa rule's `title`, `description`, and `rationale`
- If they describe fundamentally different things → flag `wrong-mapping`
- A rule can be broader than the control (acceptable), but not unrelated

### Step 2: Check Alignment
> Does the rule's `check:` block test what the framework's check text says to test?

- Read the SOT's check text (STIG Check Text, CIS Audit procedure)
- Read the rule's `check:` block in each `implementations:` entry
- Compare: same files? same parameters? same command logic?
- Watch for: wrong file path, wrong parameter name, wrong check method (e.g., `config_value` on static file vs `sshd_effective_config`)
- If the check tests the wrong thing → flag `incorrect-check`

### Step 3: Remediation Alignment
> Does the rule's `remediation:` block fix what the framework's fix text says?

- Read the SOT's fix text
- Read the rule's `remediation:` block
- Compare: same mechanism? same target file? same value?
- If the remediation fixes the wrong thing → flag `incorrect-remediation`

### Step 4: Completeness
> Does the rule cover the full scope of the control?

- Does the SOT check multiple files but the rule only checks one?
- Does the SOT check multiple conditions but the rule only checks some?
- If partial coverage → flag `missing-coverage`

## Flag Types

| Flag | Meaning | Severity |
|------|---------|----------|
| `wrong-mapping` | Control should not map to this rule | High — mapping file needs fixing |
| `incorrect-check` | Mapping is right, but check logic doesn't match SOT | High — rule needs fixing |
| `incorrect-remediation` | Check is fine, but remediation doesn't match SOT fix | Medium — remediation needs fixing |
| `missing-coverage` | Rule only partially covers what the control requires | Medium — rule may need extension |
| `verify` | Looks plausible but cannot confirm without live testing | Low — needs human/live verification |
| `stale-reference` | Metadata is wrong (vuln_id, section number, severity) | Low — human handles this |
| `cleared` | Previously flagged issue has been resolved | Resolution |

## What You Can Do

### Start a Review Batch

When the user invokes `/review` with a framework and optional batch size:

1. **Identify the framework mapping** from the argument (e.g., `stig-rhel8-v2r6` → `mappings/stig/rhel8_v2r6.yaml`)
2. **Load existing reviews** by querying the review server: `curl http://127.0.0.1:5050/api/summary`
3. **Select the next batch** of unreviewed controls from the mapping file (skip controls whose rules already have a review entry dated today or later)
4. **For each control in the batch:**
   a. Look up the SOT check text (web search for STIG, baseline file for CIS/NIST)
   b. Read the mapped Kensa rule YAML from `rules/`
   c. Run through the 4-step checklist above
   d. Record the finding by POSTing to the review server:
      ```bash
      curl -X POST http://127.0.0.1:5050/api/reviews \
        -H 'Content-Type: application/json' \
        -d '{"rule_id":"<rule-id>","flag":"<flag>","reviewer":"ai","note":"<detailed note>"}'
      ```
      For rules that pass all 4 checks, POST with flag `cleared` and note describing what was verified.
5. **Print a batch summary** showing: reviewed count, flagged count, flags by type

### Review a Specific Control

When the user asks about a specific control (e.g., "review V-230481"):

1. Find which rule it maps to in the mapping file
2. Look up the SOT check text
3. Read the rule YAML
4. Run the 4-step checklist
5. Report findings and POST to the review server

### Review a Specific Rule

When the user asks about a specific rule (e.g., "review ssh-disable-root-login"):

1. Read the rule YAML
2. Find all framework controls that map to this rule (search all mapping files)
3. For each mapped control, run the 4-step checklist against the SOT
4. Report findings and POST to the review server

### Show Review Progress

When the user asks for status:

1. Query `curl http://127.0.0.1:5050/api/summary`
2. Count total controls in the mapping vs. reviewed controls
3. Show breakdown by flag type
4. List controls not yet reviewed

## Important Notes

- **Batch size**: Default 10 controls per batch. User can override.
- **Prioritization**: Within a batch, review `command` method rules first (highest risk), then `manual` remediation, then grep-based, then structured handlers.
- **One review per control-mapping**: Each review note should reference the specific framework control being verified (e.g., "STIG V-230481: ...").
- **The review server must be running** at `http://127.0.0.1:5050` before starting. If not running, tell the user to start it with `python3 scripts/review_server.py`.
- **AI limitations**: The AI reviewer can evaluate steps 1-4 of the checklist by reading documentation and code. It cannot execute commands on live systems. Flag `verify` for cases that need live testing.
- **Never auto-clear a flag** set by a human reviewer. Only humans clear human-set flags.
- **Date tracking**: The review server auto-timestamps each entry. The note should include the framework version reviewed against (e.g., "Reviewed against STIG RHEL 8 V2R6").
