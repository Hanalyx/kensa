#!/usr/bin/env python3
"""Corroborate Path B candidates against Rev 2 Appendix D, where Appendix D has data.

WHY THIS IS NOT THE "TWO INDEPENDENT PATHS" THE PLAN DESCRIBED
    The plan called for Path A (Rev 2 Appendix D) and Path B (Rev 3 CUI overlay
    composed with the Rev 2-to-Rev 3 change analysis) as co-equal derivations,
    diffed against each other. That was wrong on two counts and this file
    implements the corrected, smaller thing.

    1. Appendix D is not cheaply extractable. NIST publishes Rev 2 as CSV and
       XLSX, but those carry "the same data as the PDF with one addition, a
       sort-as column", and neither has an 800-53 column. There is no
       machine-readable Appendix D. The PDF table uses vertically merged cells
       where one control block spans several requirement rows, which defeated
       word coordinates, pdfplumber table detection, and cell-rectangle
       containment in turn. Each heuristic fixed some rows and broke others,
       which is the signature of a wrong approach rather than an incomplete one.
       A silently wrong Path A is worse than none, because it manufactures
       disagreements that consume the review attention Layer 2 needs.

    2. The independence was overstated. Appendix D and the CUI overlay are both
       NIST's own derivations of the same relationship, by the same authors, one
       for Rev 2 and one for Rev 3. They are two renderings, not independent
       evidence. Genuine independence for this mapping comes from comparing a
       rule's actual check semantics against the 800-171A objective text, which
       is Layer 2 and cannot be substituted by a second crosswalk.

WHAT THIS DOES INSTEAD
    Extracts the unambiguous part of Appendix D: requirements whose 800-53
    control sits on their own id-line. That resolves cleanly for most
    requirements and is left UNRESOLVED for those inside a merged block. Then,
    for each rule-to-requirement candidate Path B produced, it asks whether
    Rev 2's own appendix also links the rule's cited control to that
    requirement.

    Absence of Appendix D data is reported as "no data", never as disagreement.
    Conflating the two would be the same false-signal error the whole pipeline
    exists to avoid.

    A disagreement is meaningful: it means Path B reached a Rev 2 requirement by
    routing through Rev 3, while Rev 2's own appendix does not connect that
    control to that requirement. That is usually the Rev 2-to-Rev 3
    restructure showing through, and it is the right place for a reviewer to
    start.

Usage:
    ./.venv-tools/bin/python scripts/diff_800171_paths.py
"""
import collections
import json
import pathlib
import re
import sys

import pdfplumber

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOT = ROOT / "docs" / "research" / "SOT" / "nist"
CAND = SOT / "candidates_800171.json"
OUT = SOT / "path_corroboration.json"

REQ_RE = re.compile(r"^3\.\d+\.\d+$")
CTL_RE = re.compile(r"^([A-Z]{2})-(\d+)(\(\d+\))?$")
PAGES = range(74, 98)
SAME_ROW = 6.0    # points: a control on the same visual row may sit slightly higher


def ctl_norm(fam, num, enh):
    """Drop the enhancement: our corpus cites controls at family-number level."""
    return f"{fam}-{int(num)}"


def appendix_d():
    """requirement -> set(800-53), plus the set left unresolved by merged cells."""
    resolved = collections.defaultdict(set)
    all_reqs = set()
    with pdfplumber.open(SOT / "NIST.SP.800-171r2.pdf") as pdf:
        for idx in PAGES:
            if idx >= len(pdf.pages):
                break
            words = pdf.pages[idx].extract_words()
            reqs = sorted((w["top"], w["text"]) for w in words
                          if w["x0"] < 180 and REQ_RE.match(w["text"]))
            ctls = sorted((w["top"], ctl_norm(*CTL_RE.match(w["text"]).groups()))
                          for w in words if 200 <= w["x0"] <= 340 and CTL_RE.match(w["text"]))
            all_reqs |= {r for _, r in reqs}
            # Only attribute a control to a requirement on the SAME visual row.
            # Anything below the row is inside a merged block and is left out
            # rather than guessed at.
            for rtop, rid in reqs:
                for ctop, c in ctls:
                    if abs(ctop - rtop) <= SAME_ROW:
                        resolved[rid].add(c)
    unresolved = sorted(all_reqs - set(resolved), key=lambda s: [int(x) for x in s.split(".")])
    return resolved, all_reqs, unresolved


def main():
    if not CAND.exists():
        sys.exit("run scripts/derive_800171_candidates.py first")
    cand = json.loads(CAND.read_text())["rules"]
    d, all_reqs, unresolved = appendix_d()

    print(f"Appendix D requirements seen        : {len(all_reqs)} of 110")
    print(f"  resolved (control on the id-line) : {len(d)}")
    print(f"  unresolved (merged cell block)    : {len(unresolved)}")
    print(f"  pairs extracted                   : {sum(len(v) for v in d.values())}")

    agree = disagree = nodata = 0
    detail = []
    for rule, v in cand.items():
        for req in v["rev2"]:
            cited = set(v["via_800_53"])
            if req not in d:
                nodata += 1
                continue
            if cited & d[req]:
                agree += 1
            else:
                disagree += 1
                detail.append({"rule": rule, "rev2": req,
                               "rule_cites": sorted(cited),
                               "appendix_d_lists": sorted(d[req])})

    total = agree + disagree + nodata
    print(f"\ncandidate rule-to-requirement pairs : {total}")
    print(f"  corroborated by Appendix D        : {agree}")
    print(f"  not corroborated                  : {disagree}")
    print(f"  no Appendix D data (merged cell)  : {nodata}")
    if total - nodata:
        print(f"  corroboration rate where data exists: "
              f"{agree / (total - nodata) * 100:.1f}%")

    by_req = collections.Counter(x["rev2"] for x in detail)
    if by_req:
        print("\nrequirements with the most uncorroborated candidates:")
        for req, n in by_req.most_common(8):
            print(f"  {req:<9} {n}")

    OUT.write_text(json.dumps({
        "_warning": "CANDIDATES ONLY. Corroboration is not coverage. See module docstring.",
        "_method": "Path B candidates checked against the unambiguous part of Rev 2 Appendix D",
        "appendix_d": {"resolved": len(d), "unresolved": unresolved,
                       "pairs": sum(len(v) for v in d.values())},
        "totals": {"pairs": total, "corroborated": agree,
                   "uncorroborated": disagree, "no_data": nodata},
        "uncorroborated": sorted(detail, key=lambda x: (x["rev2"], x["rule"])),
    }, indent=2))
    print(f"\nwrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
