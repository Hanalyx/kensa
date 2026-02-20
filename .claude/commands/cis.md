You are helping a developer work with the Kensa CIS benchmark mappings.

## Context Files

Read these files first to understand the current state:

1. **RHEL 9 baseline reference**: `context/cis/rhel9-v2.0.0-baseline.yaml` — authoritative list of all 244 CIS RHEL 9 v2.0.0 controls
2. **RHEL 8 baseline reference**: `context/cis/rhel8-v4.0.0-baseline.yaml` — authoritative list of all 311 CIS RHEL 8 v4.0.0 controls
3. **RHEL 9 mapping**: `mappings/cis/rhel9_v2.0.0.yaml` — Kensa mapping file linking CIS sections to rules
4. **RHEL 8 mapping**: `mappings/cis/rhel8_v4.0.0.yaml` — Kensa mapping file linking CIS sections to rules

Then run the validation script to get the current gap analysis:

```bash
python3 scripts/cis_validate.py --json
```

## What You Can Do

Based on the user's request, perform one of these workflows:

### Gap Analysis
Show the current state of CIS coverage:
- Run `python3 scripts/cis_validate.py` for a text report across all benchmarks
- Run `python3 scripts/cis_validate.py --mapping cis-rhel9-v2.0.0` to focus on RHEL 9
- Run `python3 scripts/cis_validate.py --mapping cis-rhel8-v4.0.0` to focus on RHEL 8
- Run `python3 scripts/cis_validate.py --chapter 5` to focus on a specific chapter
- Highlight missing rules, unimplemented sections, and coverage gaps

### Add a Rule for a CIS Section
When the user wants to add coverage for a specific CIS section (e.g., "add a rule for 5.1.4"):
1. Look up the section in the baseline reference to understand what it requires
2. Check if any existing rules could satisfy it (search `rules/` directory)
3. If a new rule is needed, create it following the canonical rule schema in `context/prd/CANONICAL_RULE_SCHEMA_V0.md`
4. Add the section-to-rule mapping in the appropriate `mappings/cis/*.yaml` under `sections:`
5. If the section was previously in `unimplemented:`, remove it from there
6. Run validation to confirm the mapping is still complete

### Update Mapping After Adding Rules
After new rules have been added to the `rules/` directory:
1. Run validation to check for sections that could now be mapped
2. Update the appropriate `mappings/cis/*.yaml` to add new section entries
3. Verify with `python3 scripts/cis_validate.py`

### Show What's Missing for a Chapter
For a specific CIS chapter:
1. Run `python3 scripts/cis_validate.py --chapter <N>`
2. List sections that don't have rules yet
3. Suggest which existing rules could be mapped
4. Identify what new rules would be needed

### Validate Current Mapping
Run a full validation check:
1. All controls in `control_ids` are in either `sections` or `unimplemented`
2. All referenced rules exist in the `rules/` directory
3. No duplicate entries
4. Report any issues found

## Important Notes

- CIS mappings use 1:1 format: each section has a single `rule:` field
- Section IDs use dotted notation: "5.1.4", not "5.1.4.1" (though sub-sections exist)
- When in doubt about what a CIS section requires, check the baseline reference
- Technical sections (Automated) should have rules; Manual sections go in `unimplemented:`
- The `control_ids` manifest must list the exact number of controls for the benchmark
- After any changes, the mapping's completeness must be maintained (all control_ids accounted for)
- Rules are canonical and framework-agnostic — one rule can map to multiple CIS sections across benchmarks
