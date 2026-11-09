#!/usr/bin/env python3
"""Derive CANDIDATE NIST SP 800-171 mappings for Kensa rules. Layer 1 only.

WHAT THIS IS NOT
    Not a coverage claim. Not customer-facing. Not a mapping.

    Every row this emits is a HYPOTHESIS that a rule might bear on a requirement,
    produced by composing published NIST crosswalks. The composition is
    many-to-many at every hop, so a row means "a reviewer should look at this",
    never "this requirement is satisfied". Reporting these numbers as coverage
    would manufacture exactly the false-PASS class the adversarial panel caught
    four times in the STIG citation work: a control cited on a rule that checks a
    neighbouring property.

    The reviewed mapping is Layer 2, is per 800-171A assessment objective, and is
    the only thing that may reach a customer.

THE TWO PATHS
    Path B (this file): rule -> 800-53 ref -> CUI overlay -> Rev 3 requirement
                             -> change analysis -> Rev 2 requirement
    Path A (separate):  rule -> 800-53 ref -> Rev 2 Appendix D -> Rev 2 requirement

    Both are run and diffed. Agreement raises confidence. DISAGREEMENT IS THE
    REVIEW QUEUE, ranked first, because two independent NIST-authored routes
    disagreeing is where a wrong mapping hides.

SOURCES (docs/research/SOT/nist/, gitignored, acquired 2026-07-29)
    sp800-171r3-cui-overlay.xlsx      800-53r5 -> 800-171r3, with tailoring
    sp800-171r2-to-r3-analysis.xlsx   Rev 2 <-> Rev 3, with change class
    NIST.SP.800-171A.pdf              the 320 Rev 2 assessment objectives

Usage:
    ./.venv-tools/bin/python scripts/derive_800171_candidates.py
"""
import collections
import json
import pathlib
import re
import sys

import openpyxl

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOT = ROOT / "docs" / "research" / "SOT" / "nist"
OUT = SOT / "candidates_800171.json"

# Tailoring decisions in the CUI overlay. Only CUI rows were carried into the
# 800-171 baseline. FED is federal-only and ORC is an organization
# responsibility; treating either as in-scope would inflate the candidate set,
# which is why this is an explicit allowlist rather than "not NCO".
IN_SCOPE_TAILORING = {"CUI"}

# Families no host-configuration scanner can produce evidence for. Kept as data
# so the count is derived rather than asserted, and so the honest-limitations
# article and this pipeline cannot drift apart.
NO_SCANNER_EVIDENCE = {"AT", "CP", "IR", "PE", "PL", "PS", "RA", "SR"}


def ctl(s):
    """Normalize an 800-53 id: 'AC-01-00-02' or 'AC-01' -> 'AC-1'."""
    m = re.match(r"([A-Z]{2})-0*(\d+)", str(s or ""))
    return f"{m.group(1)}-{int(m.group(2))}" if m else None


def load_overlay():
    """800-53 control -> set of Rev 3 requirement ids, CUI-tailored rows only."""
    ws = openpyxl.load_workbook(SOT / "sp800-171r3-cui-overlay.xlsx",
                                read_only=True, data_only=True)["CUI Overlay"]
    out = collections.defaultdict(set)
    for r in ws.iter_rows(min_row=2, values_only=True):
        if (r[2] or "").strip() not in IN_SCOPE_TAILORING:
            continue
        c = ctl(r[0])
        q = re.search(r"(03\.\d{2}\.\d{2})", str(r[4] or ""))
        if c and q:
            out[c].add(q.group(1))
    return out


def load_r2r3():
    """Rev 3 id -> (Rev 2 id, change class). Withdrawn and new rows recorded."""
    ws = openpyxl.load_workbook(SOT / "sp800-171r2-to-r3-analysis.xlsx",
                                read_only=True, data_only=True)["Change Analysis 800-171 R2-R3"]
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    r3_to_r2, meta = {}, {}
    for r in rows:
        r2id = str(r[2] or "").strip()
        r3id = str(r[6] or "").strip()
        flags = {
            "no_significant_change": bool(r[9]),
            "significant_change": bool(r[10]),
            "minor_change": bool(r[11]),
            "new_odp": bool(r[12]),
            "new_requirement": bool(r[13]),
            "withdrawn": bool(r[14]),
        }
        if re.fullmatch(r"03\.\d{2}\.\d{2}", r3id):
            if re.fullmatch(r"3\.\d+\.\d+", r2id):
                r3_to_r2[r3id] = r2id
            meta[r3id] = flags
    return r3_to_r2, meta


def load_objectives():
    """Rev 2 requirement -> objective labels, from 800-171A.

    A requirement with several objectives labels them 3.1.3[a], [b]. A
    requirement with exactly ONE objective carries no bracket at all, which is
    why a naive count of bracketed ids returns 297 instead of 320. That variant
    cost a wrong number once; it is handled explicitly here.
    """
    txt = (SOT / "a.txt")
    if not txt.exists():
        sys.exit("run: pdftotext -layout NIST.SP.800-171A.pdf a.txt")
    t = txt.read_text(encoding="utf8", errors="ignore")
    lettered = collections.defaultdict(set)
    for req, lab in re.findall(r"\b(3\.\d+\.\d+)\[([a-z]{1,2})\]", t):
        lettered[req].add(lab)
    allreq = set(re.findall(r"\b(3\.\d+\.\d+)\b", t))
    return {r: sorted(lettered[r]) if r in lettered else ["(single)"] for r in allreq}


def load_corpus():
    """rule id -> set of 800-53 controls it cites."""
    out = {}
    for p in sorted((ROOT / "rules").glob("*/*.yml")):
        text = p.read_text(encoding="utf8", errors="ignore")
        m = re.search(r"nist_800_53:\s*(\[[^\]]*\]|(?:\n\s+-\s*.*)+)", text)
        if not m:
            continue
        controls = {c for c in (ctl(x) for x in re.findall(r"[A-Z]{2}-\d+", m.group(1))) if c}
        if controls:
            out[p.stem] = controls
    return out


def main():
    overlay = load_overlay()
    r3_to_r2, r3_meta = load_r2r3()
    objectives = load_objectives()
    corpus = load_corpus()

    total_objectives = sum(len(v) for v in objectives.values())
    cand = collections.defaultdict(lambda: {"r3": set(), "r2": set(), "via": set()})
    for rule, controls in corpus.items():
        for c in controls:
            for r3 in overlay.get(c, ()):
                cand[rule]["r3"].add(r3)
                cand[rule]["via"].add(c)
                if r3 in r3_to_r2:
                    cand[rule]["r2"].add(r3_to_r2[r3])

    r2_hit = set().union(*(v["r2"] for v in cand.values())) if cand else set()
    r3_hit = set().union(*(v["r3"] for v in cand.values())) if cand else set()
    obj_reachable = sum(len(objectives.get(q, [])) for q in r2_hit)

    print(f"corpus rules citing 800-53          : {len(corpus)}")
    print(f"rules with >=1 candidate            : {len(cand)}")
    print(f"Rev 2 requirements with a candidate : {len(r2_hit)} of 110")
    print(f"Rev 3 requirements with a candidate : {len(r3_hit)} of 97 active")
    print(f"Rev 2 objectives under those reqs   : {obj_reachable} of {total_objectives}")

    fam = collections.Counter(q.split(".")[1] for q in r2_hit)
    FAM = {"1": "AC", "2": "AT", "3": "AU", "4": "CM", "5": "IA", "6": "IR", "7": "MA",
           "8": "MP", "9": "PS", "10": "PE", "11": "RA", "12": "CA", "13": "SC", "14": "SI"}
    print("\ncandidate Rev 2 requirements by family:")
    for k in sorted(fam, key=int):
        flag = "  <- no scanner evidence possible" if FAM[k] in NO_SCANNER_EVIDENCE else ""
        print(f"  {FAM[k]:<4}{fam[k]:>4}{flag}")

    payload = {
        "_warning": "CANDIDATES ONLY. Not coverage. Not customer-facing. See module docstring.",
        "layer": 1,
        "path": "B (CUI overlay -> change analysis)",
        "totals": {
            "rules_with_candidates": len(cand),
            "rev2_requirements_hit": len(r2_hit),
            "rev3_requirements_hit": len(r3_hit),
            "rev2_objectives_under_hit_requirements": obj_reachable,
            "rev2_objectives_total": total_objectives,
        },
        "rules": {
            r: {"rev2": sorted(v["r2"]), "rev3": sorted(v["r3"]), "via_800_53": sorted(v["via"])}
            for r, v in sorted(cand.items())
        },
    }
    OUT.write_text(json.dumps(payload, indent=2))
    print(f"\nwrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
