#!/usr/bin/env python3
"""Apply crosswalk extend candidates as STIG reference additions.

The kensa-catalog crosswalk classifies each benchmark control as covered /
extend / net-new. An "extend" is a control whose check target (package, sysctl,
path, service, module, config key) matches an existing rule's check — i.e. the
rule already implements the control on another OS and only needs the new
framework/OS reference cited.

This tool turns those extend candidates into reference additions, but ONLY when
the matched rule's `platforms:` already covers the target OS (so the rule
genuinely runs there). Cross-OS false matches — where a rule matches a target
but does not run on the target OS — are skipped and reported for manual review;
those are exactly the cases that need a per-control value check (the FIPS-cipher
/ yescrypt / group-ownership divergences seen during the campaign).

Usage:
    apply_crosswalk_extends.py --db bin/kensa-catalog.db --framework stig \
        --os rhel10 [--apply]

Default is a dry run (prints the plan). --apply edits the rule YAML in place,
preserving file formatting by inserting only the new reference block.
"""
import argparse
import os
import re
import sqlite3
import sys

SEVERITY_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}

# Low-specificity config keys: when several controls match one rule via a generic
# key, the match is likely coincidental for all but one. These are reported for
# manual review instead of auto-applied.
GENERIC_CONFIG_KEYS = {"port", "dir", "name", "mode", "type", "value", "enabled",
                       "action", "key", "path", "level", "size", "count", "limit"}

# RHEL-family aliases the engine's platform gate treats as rhel (detect.familyMatches).
RHEL_ALIASES = {"rhel", "redhat", "centos", "almalinux", "rocky", "ol", "oracle"}


def os_family_major(os_id):
    m = re.match(r"([a-z]+)(\d+)$", os_id)
    if not m:
        raise SystemExit(f"unsupported os id: {os_id!r} (want e.g. rhel10, ubuntu24)")
    return m.group(1), int(m.group(2))


def load_yaml(path):
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


def platform_covers(rule_doc, family, major):
    """True if the rule's platforms cover (family, major)."""
    plats = rule_doc.get("platforms") or []
    fam_set = RHEL_ALIASES if family == "rhel" else {family}
    for p in plats:
        if not isinstance(p, dict):
            continue
        pf = str(p.get("family", "")).lower()
        if pf not in fam_set:
            continue
        mv = p.get("min_version")
        try:
            if mv is None or int(str(mv).split(".")[0]) <= major:
                return True
        except ValueError:
            return True
    return False


def rule_id_to_path(rules_dir):
    out = {}
    for root, _, files in os.walk(rules_dir):
        for fn in files:
            if not fn.endswith(".yml"):
                continue
            p = os.path.join(root, fn)
            with open(p) as f:
                for line in f:
                    m = re.match(r"id:\s*(\S+)", line)
                    if m:
                        out[m.group(1)] = p
                        break
    return out


def extend_candidates(db, framework, os_id):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        """
        SELECT c.id AS pk, c.control_id, c.secondary_id, c.severity
        FROM control c JOIN benchmark b ON c.benchmark_id = b.id
        WHERE b.framework = ? AND b.os = ?
          AND NOT EXISTS (SELECT 1 FROM coverage cov
                          WHERE cov.framework = ? AND cov.os = ? AND cov.control_id = c.control_id)
        ORDER BY c.control_id
        """,
        (framework, os_id, framework, os_id),
    ).fetchall()
    out = []
    for r in rows:
        match = con.execute(
            """
            SELECT rt.rule_id, ct.kind, ct.value
            FROM control_target ct
            JOIN rule_target rt ON rt.kind = ct.kind AND rt.value = ct.value
            WHERE ct.control_pk = ?
            ORDER BY ct.kind, ct.value, rt.rule_id LIMIT 1
            """,
            (r["pk"],),
        ).fetchone()
        if match:
            out.append({
                "control_id": r["control_id"], "stig_id": r["secondary_id"],
                "severity": r["severity"], "rule_id": match["rule_id"],
                "kind": match["kind"], "value": match["value"],
            })
    con.close()
    return out


def insert_ref(path, framework, os_id, control_id, stig_id, severity):
    """Insert references.<framework>.<os> block; return (changed, reason)."""
    with open(path) as f:
        lines = f.readlines()
    text = "".join(lines)
    # Idempotent: if the os key already appears (under any framework), skip.
    if re.search(rf"^\s+{re.escape(os_id)}:\s*$", text, re.M):
        return False, "already cites %s" % os_id
    # Find the framework block (e.g. "  stig:") under references.
    fw_idx = None
    fw_indent = None
    for i, ln in enumerate(lines):
        m = re.match(rf"^(\s+){re.escape(framework)}:\s*$", ln)
        if m:
            fw_idx, fw_indent = i, len(m.group(1))
            break
    if fw_idx is None:
        return False, "no references.%s block" % framework
    entry_indent = fw_indent + 2
    # Find end of the framework block: next non-blank line indented <= fw_indent.
    end = len(lines)
    for j in range(fw_idx + 1, len(lines)):
        if lines[j].strip() == "":
            continue
        cur = len(lines[j]) - len(lines[j].lstrip())
        if cur <= fw_indent:
            end = j
            break
    pad = " " * entry_indent
    fpad = " " * (entry_indent + 2)
    block = [f'{pad}{os_id}:\n', f'{fpad}vuln_id: "{control_id}"\n']
    if stig_id:
        block.append(f'{fpad}stig_id: "{stig_id}"\n')
    block.append(f'{fpad}severity: "{SEVERITY_CAT.get((severity or "").lower(), "CAT II")}"\n')
    lines[end:end] = block
    with open(path, "w") as f:
        f.writelines(lines)
    return True, "added"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="bin/kensa-catalog.db")
    ap.add_argument("--framework", required=True)
    ap.add_argument("--os", required=True, dest="os_id")
    ap.add_argument("--rules-dir", default="rules")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    family, major = os_family_major(args.os_id)
    cands = extend_candidates(args.db, args.framework, args.os_id)
    id2path = rule_id_to_path(args.rules_dir)

    applied, skipped_plat, skipped_generic, skipped_dup, skipped_other = [], [], [], [], []
    used_rules = set()  # one os-ref per rule (schema allows one vuln per os per rule)
    for c in cands:
        path = id2path.get(c["rule_id"])
        if not path:
            skipped_other.append((c, "rule file not found"))
            continue
        if c["kind"] == "config" and c["value"] in GENERIC_CONFIG_KEYS:
            skipped_generic.append(c)
            continue
        doc = load_yaml(path)
        if not platform_covers(doc, family, major):
            skipped_plat.append(c)
            continue
        if c["rule_id"] in used_rules:
            skipped_dup.append(c)
            continue
        used_rules.add(c["rule_id"])
        if args.apply:
            ok, reason = insert_ref(path, args.framework, args.os_id,
                                    c["control_id"], c["stig_id"], c["severity"])
            if ok:
                applied.append((c, reason))
            else:
                used_rules.discard(c["rule_id"])
                skipped_other.append((c, reason))
        else:
            applied.append((c, "would add"))

    verb = "applied" if args.apply else "would apply"
    print(f"=== {args.framework} {args.os_id}: {verb} {len(applied)} | "
          f"skipped: platform-mismatch {len(skipped_plat)}, generic-key {len(skipped_generic)}, "
          f"rule-already-used {len(skipped_dup)}, other {len(skipped_other)} ===")
    for c, _ in applied[:80]:
        print(f"  + {c['control_id']:12} -> {c['rule_id']:34} [{c['kind']}:{c['value']}]")
    if skipped_generic:
        print(f"  -- {len(skipped_generic)} generic-key matches (manual review): "
              + ", ".join(sorted({c['value'] for c in skipped_generic})))
    if skipped_dup:
        print(f"  -- {len(skipped_dup)} controls mapped to an already-cited rule (need their own rule / net-new)")
    if skipped_plat:
        print(f"  -- {len(skipped_plat)} cross-OS matches skipped (rule does not run on {args.os_id})")
    for c, reason in skipped_other:
        print(f"  ! {c['control_id']} {c['rule_id']}: {reason}")


if __name__ == "__main__":
    main()
