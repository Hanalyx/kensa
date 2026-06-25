#!/usr/bin/env python3
"""Split combined multi-key sysctl rules into one rule per key.

A "combined" sysctl rule checks several kernel parameters in one composed check
(checks: list) and sets them in one remediation (steps: list). The schema allows
only one vuln_id / section per (framework, os) per rule, so a combined rule can
be CITED for only one of its keys' controls — the others show net-new in the
crosswalk despite being implemented. Splitting into one rule per key lets each
cite its own control.

Behaviour-preserving: the N split rules together check + set exactly the keys the
combined rule did (sysctl_value / sysctl_set, byte-perfect either way).

STIG references derive PER KEY from the catalog's control_target (the control's
own check named that exact sysctl key — precise). CIS / nist / pci references
can't be split per key (CIS controls have no extracted target), so they're kept
on the FIRST split rule to preserve existing coverage. The combined rule is
replaced by the split rules.

Usage: split_combined_sysctl.py --db bin/kensa-catalog.db [--apply]   (dry run by default)
"""
import argparse
import glob
import os
import re
import sqlite3

SEV_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


def stig_refs_for_key(con, key):
    rows = con.execute(
        """SELECT b.os, c.control_id, c.secondary_id, c.severity
           FROM control c JOIN benchmark b ON c.benchmark_id = b.id
           JOIN control_target ct ON ct.control_pk = c.id
           WHERE b.framework = 'stig' AND ct.kind = 'sysctl' AND ct.value = ?""",
        (key,)).fetchall()
    return {osid: (cid, sid, sev) for osid, cid, sid, sev in rows}


def key_slug(key):
    return "sysctl-" + key.replace(".", "-").replace("_", "-")


def section_lines(text, header_re):
    """Verbatim block lines for a top-level (0-indent) section like 'platforms:'."""
    lines = text.splitlines()
    out = []
    for i, ln in enumerate(lines):
        if re.match(header_re, ln):
            for j in range(i + 1, len(lines)):
                if lines[j].strip() == "":
                    continue
                if re.match(r"^\S", lines[j]):
                    break
                out.append(lines[j])
            break
    return out


def ref_keep_block(text):
    """Verbatim cis/nist/pci/iso/cci lines under references (NOT stig)."""
    lines = text.splitlines()
    out, in_refs = [], False
    for i, ln in enumerate(lines):
        if re.match(r"^references:\s*$", ln):
            in_refs = True
            continue
        if in_refs:
            if re.match(r"^\S", ln):
                break
            m = re.match(r"^(\s+)(cis|nist_800_53|pci_dss_4|iso27001|cci):", ln)
            if m:
                indent = len(m.group(1))
                out.append(ln)
                for j in range(i + 1, len(lines)):
                    if lines[j].strip() == "":
                        continue
                    if len(lines[j]) - len(lines[j].lstrip()) <= indent:
                        break
                    out.append(lines[j])
    return out


def render(rule_id, title, rationale, severity, category, tags, stig_refs, keep, platforms, key, value):
    L = [f"id: {rule_id}",
         f"title: {title}",
         "description: >",
         f"  The kernel parameter {key} must be set to {value} to enforce this",
         "  network/kernel security control.",
         "rationale: >",
         f"  {rationale}",
         f"severity: {severity}",
         f"category: {category}",
         f"tags: [{', '.join(tags)}]",
         "",
         "references:"]
    if stig_refs:
        L.append("  stig:")
        for osid in sorted(stig_refs):
            vuln, sid, sev = stig_refs[osid]
            L.append(f"    {osid}:")
            L.append(f'      vuln_id: "{vuln}"')
            if sid:
                L.append(f'      stig_id: "{sid}"')
            L.append(f'      severity: "{SEV_CAT.get((sev or "").lower(), "CAT II")}"')
    L.extend(keep)
    if not stig_refs and not keep:
        L.append('  nist_800_53: ["CM-6"]')
    L += ["", "platforms:"]
    L += platforms
    L += ["", "implementations:", "  - default: true", "    check:",
          "      method: sysctl_value", f"      key: {key}", f'      expected: "{value}"',
          "    remediation:", "      mechanism: sysctl_set", f"      key: {key}", f'      value: "{value}"']
    return "\n".join(L) + "\n"


def main():
    import yaml
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="bin/kensa-catalog.db")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    con = sqlite3.connect(args.db)

    plan = []
    for f in glob.glob("rules/**/*.yml", recursive=True):
        text = open(f).read()
        try:
            d = yaml.safe_load(text)
        except Exception:
            continue
        if not isinstance(d, dict) or len(d.get("implementations") or []) != 1:
            continue
        chk = d["implementations"][0].get("check") or {}
        subs = chk.get("checks")
        if not (isinstance(subs, list) and len(subs) > 1 and {s.get("method") for s in subs} == {"sysctl_value"}):
            continue
        pairs = [(s["key"], str(s["expected"])) for s in subs if s.get("key")]
        if len(pairs) < 2:
            continue
        plan.append((f, text, d, pairs))

    total_new = sum(len(p[3]) for p in plan)
    print(f"=== split {len(plan)} combined sysctl rules -> {total_new} per-key rules ({'APPLY' if args.apply else 'dry run'}) ===")
    for f, text, d, pairs in plan:
        keep = ref_keep_block(text)
        platforms = section_lines(text, r"^platforms:\s*$") or ["  - family: rhel", "    min_version: 8"]
        rationale = (d.get("rationale") or "Improper kernel parameters weaken system security.").strip().replace("\n", " ")
        tags = [str(t) for t in (d.get("tags") or ["sysctl", "hardening"])]
        print(f"\n  {d['id']} ->")
        for i, (key, value) in enumerate(pairs):
            refs = stig_refs_for_key(con, key)
            body = render(key_slug(key), f"Ensure {key} is set to {value}", rationale,
                          d.get("severity", "medium"), d.get("category", "network"), tags,
                          refs, keep if i == 0 else [], platforms, key, value)
            stig_os = ",".join(sorted(refs)) or "none"
            print(f"     {key_slug(key):42} stig:[{stig_os}]{' +cis/nist' if i == 0 and keep else ''}")
            if args.apply:
                open(os.path.join(os.path.dirname(f), key_slug(key) + ".yml"), "w").write(body)
        if args.apply:
            os.remove(f)
    con.close()


if __name__ == "__main__":
    main()
