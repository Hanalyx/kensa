#!/usr/bin/env python3
"""Cross-distro CIS reference extension.

CIS recommendations are largely shared across distro benchmarks (the same
hardening control, often re-numbered per distro). A rule that already cites
cis.<source> section X therefore almost always corresponds to a cis.<target>
recommendation with the SAME title. This tool bridges them: for each rule
citing cis.<source>, it looks up that section's title in the source benchmark
PDF, finds the target benchmark's section with the matching title, and adds the
cis.<target> reference.

Only the section number + level + type (Automated/Manual) are written — facts,
not the copyrighted prose. Titles are used only at dev time to drive the match.

Guardrails: the rule's platforms must already cover the target OS; the rule must
not already cite cis.<target>; an unmatched title is skipped + reported.

Usage:
    apply_cis_cross_distro.py --source rhel9 --target ubuntu24 [--apply]
Default is a dry run.
"""
import argparse
import json
import os
import re
import subprocess

SOT = "docs/research/SOT"
PDF = {
    "rhel8": "CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v4.0.0.pdf",
    "rhel9": "CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0.pdf",
    "rhel10": "CIS_Red_Hat_Enterprise_Linux_10_Benchmark_v1.0.1.pdf",
    "ubuntu22": "CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v3.0.0.pdf",
    "ubuntu24": "CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v2.0.0.pdf",
}
RHEL_ALIASES = {"rhel", "redhat", "centos", "almalinux", "rocky", "ol", "oracle"}
NUMHDR = re.compile(r"^\s*(\d+(?:\.\d+){2,6})\s+(Ensure\s+\S.*|Configure\s+\S.*|Disable\s+.*|Enable\s+.*)$")


def os_family_major(os_id):
    m = re.match(r"([a-z]+)(\d+)$", os_id)
    return m.group(1), int(m.group(2))


def norm_title(t):
    t = re.sub(r"\s*\((Automated|Manual)\)\s*$", "", t)
    t = re.sub(r"\s*\.{2,}.*$", "", t)       # trailing dot leaders / page nums
    t = re.sub(r"[^a-z0-9 ]", " ", t.lower())
    return re.sub(r"\s+", " ", t).strip()


def extract_sections(os_id):
    """section -> normalized title, and normalized title -> section (target index)."""
    txt = subprocess.run(["pdftotext", "-layout", f"{SOT}/{PDF[os_id]}", "-"],
                         capture_output=True, text=True).stdout
    sec2title, title2sec = {}, {}
    for line in txt.splitlines():
        m = NUMHDR.match(line)
        if not m:
            continue
        sec, raw = m.group(1), m.group(2)
        nt = norm_title(raw)
        if len(nt) < 6:
            continue
        sec2title.setdefault(sec, nt)
        title2sec.setdefault(nt, sec)   # first wins (benchmarks are ordered)
    return sec2title, title2sec


def facts_index(os_id):
    """section -> (level, 'Automated'|'Manual') from the facts JSON."""
    p = f"catalog/sources/cis/cis_facts_{os_id}.json"
    out = {}
    for r in json.load(open(p))["recommendations"]:
        out[r["section"]] = (r.get("level", "L1"),
                             "Automated" if r.get("automatable") else "Manual")
    return out


def platform_covers(doc, family, major):
    fam_set = RHEL_ALIASES if family == "rhel" else {family}
    for p in (doc.get("platforms") or []):
        if isinstance(p, dict) and str(p.get("family", "")).lower() in fam_set:
            mv = p.get("min_version")
            try:
                if mv is None or int(str(mv).split(".")[0]) <= major:
                    return True
            except ValueError:
                return True
    return False


def insert_cis_ref(path, target, section, level, ctype):
    with open(path) as f:
        lines = f.readlines()
    # find "  cis:" under references
    cis_idx = cis_indent = None
    for i, ln in enumerate(lines):
        m = re.match(r"^(\s+)cis:\s*$", ln)
        if m:
            cis_idx, cis_indent = i, len(m.group(1))
            break
    if cis_idx is None:
        return False, "no references.cis block"
    end = len(lines)
    for j in range(cis_idx + 1, len(lines)):
        if lines[j].strip() == "":
            continue
        if len(lines[j]) - len(lines[j].lstrip()) <= cis_indent:
            end = j
            break
    # Scoped idempotency: does the cis block already have a `<target>:` key
    # (either flow `target: {` or block `target:`)? Detect both styles.
    entry_pat = re.compile(rf"^\s{{{cis_indent + 2}}}{re.escape(target)}:(\s|$|\s*\{{)")
    for j in range(cis_idx + 1, end):
        if entry_pat.match(lines[j]):
            return False, "already cites cis.%s" % target
    pad = " " * (cis_indent + 2)
    lines[end:end] = [f'{pad}{target}: {{ section: "{section}", level: "{level}", type: "{ctype}" }}\n']
    with open(path, "w") as f:
        f.writelines(lines)
    return True, "added"


def main():
    import yaml
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--rules-dir", default="rules")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    fam, major = os_family_major(args.target)
    src_sec2title, _ = extract_sections(args.source)
    _, tgt_title2sec = extract_sections(args.target)
    tgt_facts = facts_index(args.target)

    matched, no_title, no_target, plat_skip, already = [], [], [], [], []
    for root, _, files in os.walk(args.rules_dir):
        for fn in files:
            if not fn.endswith(".yml"):
                continue
            path = os.path.join(root, fn)
            doc = yaml.safe_load(open(path))
            if not isinstance(doc, dict):
                continue
            cis = ((doc.get("references") or {}).get("cis") or {})
            srcref = cis.get(args.source)
            if not isinstance(srcref, dict) or not srcref.get("section"):
                continue
            sx = str(srcref["section"])
            title = src_sec2title.get(sx)
            if not title:
                no_title.append((doc["id"], sx))
                continue
            ty = tgt_title2sec.get(title)
            if not ty or ty not in tgt_facts:
                # No title match, or the matched section is not an authoritative
                # control in the target facts (would drift the catalog).
                no_target.append((doc["id"], sx, title))
                continue
            if not platform_covers(doc, fam, major):
                plat_skip.append((doc["id"], ty))
                continue
            level, ctype = tgt_facts.get(ty, ("L1", "Automated"))
            if args.apply:
                ok, reason = insert_cis_ref(path, args.target, ty, level, ctype)
                (matched if ok else already).append((doc["id"], sx, ty, title))
            else:
                matched.append((doc["id"], sx, ty, title))

    verb = "applied" if args.apply else "would add"
    print(f"=== cis {args.source} -> {args.target}: {verb} {len(matched)} | "
          f"title-not-in-source {len(no_title)}, no-target-match {len(no_target)}, "
          f"platform-skip {len(plat_skip)}, already/other {len(already)} ===")
    for rid, sx, ty, title in matched[:40]:
        print(f"  + {rid:34} cis.{args.source} {sx} -> {args.target} {ty}  [{title[:42]}]")
    if no_target:
        print(f"  -- {len(no_target)} source titles not found in {args.target} (distro-specific; skipped)")


if __name__ == "__main__":
    main()
