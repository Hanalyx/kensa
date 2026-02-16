You are helping a developer work with the Aegis FedRAMP Moderate baseline mapping.

## Context Files

Read these files first to understand the current state:

1. **Baseline reference**: `context/fedramp/moderate-rev5-baseline.yaml` — authoritative list of all 323 FedRAMP Moderate Rev 5 controls with applicability tags
2. **Current mapping**: `mappings/fedramp/moderate.yaml` — Aegis mapping file linking controls to rules
3. **Reference doc**: `context/fedramp/FEDRAMP_MODERATE_REFERENCE.md` — human-readable reference with FedRAMP parameters

Then run the validation script to get the current gap analysis:

```bash
python scripts/fedramp_validate.py --json
```

## What You Can Do

Based on the user's request, perform one of these workflows:

### Gap Analysis
Show the current state of FedRAMP coverage:
- Run `python scripts/fedramp_validate.py` for a text report
- Run `python scripts/fedramp_validate.py --family <FAMILY>` to focus on one family
- Highlight any unaccounted controls, missing rules, or technical gaps

### Add a Rule for a Control
When the user wants to add coverage for a specific control (e.g., "add a rule for AC-X"):
1. Look up the control in the baseline reference to understand what it requires
2. Check if any existing rules could satisfy it (search `rules/` directory)
3. If a new rule is needed, create it following the canonical rule schema in `context/prd/CANONICAL_RULE_SCHEMA_V0.md`
4. Add the control-to-rule mapping in `mappings/fedramp/moderate.yaml` under `controls:`
5. If the control was previously in `unimplemented:`, remove it from there
6. Run validation to confirm the mapping is still complete

### Update Mapping After Adding Rules
After new rules have been added to the `rules/` directory:
1. Run validation to check for technical gaps that could now be filled
2. Update `mappings/fedramp/moderate.yaml` to add new control entries
3. Verify with `python scripts/fedramp_validate.py`

### Show What's Missing for a Family
For a specific control family:
1. Run `python scripts/fedramp_validate.py --family <FAMILY>`
2. List technical controls that don't have rules yet
3. Suggest which existing rules could be mapped
4. Identify what new rules would be needed

### Validate Current Mapping
Run a full validation check:
1. All controls in `control_ids` are in either `controls` or `unimplemented`
2. All referenced rules exist in the `rules/` directory
3. No duplicate entries
4. Report any issues found

## Important Notes

- The mapping uses NIST-style many-to-many format: each control in `controls:` has a `rules:` list
- Control IDs use conventional format: AC-2(1), not OSCAL format ac-2.1
- When in doubt about applicability, check the baseline reference for the control's `applicability` tag
- Technical controls should have rules; procedural controls go in `unimplemented:`
- Semi-technical controls may go in either section depending on what's automatable
- The `control_ids` manifest must list exactly 323 controls
- After any changes, the mapping's `is_complete` property must remain True
