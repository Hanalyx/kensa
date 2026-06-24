#!/usr/bin/env python3
"""Extract non-copyrightable CIS recommendation FACTS from the benchmark PDFs.

Output per benchmark: section number, profile level (L1/L2), and automatable flag.
NO titles or prose: CIS text is copyrighted and is never emitted here. The PDFs in
docs/research/SOT/ stay gitignored; this facts JSON is the committable artifact the
catalog ingests. Validated by requiring one record per 'Profile Applicability:'
block (the same ground truth the crosswalk used).

Usage: cis_facts.py <pdf-dir>
  <pdf-dir> holds the gitignored CIS benchmark PDFs (default docs/research/SOT)."""
import json, re, subprocess, sys
from pathlib import Path

PDF = {
    "rhel8":    ("CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v4.0.0.pdf", "v4.0.0"),
    "rhel9":    ("CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0.pdf", "v2.0.0"),
    "rhel10":   ("CIS_Red_Hat_Enterprise_Linux_10_Benchmark_v1.0.1.pdf", "v1.0.1"),
    "ubuntu22": ("CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v3.0.0.pdf", "v3.0.0"),
    "ubuntu24": ("CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v2.0.0.pdf", "v2.0.0"),
}
REPO = Path(__file__).resolve().parents[3]
SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "docs/research/SOT"
OUT = Path(__file__).resolve().parent
NUMHDR = re.compile(r"^\s*(\d+(?:\.\d+){1,6})\s+(\S.*)$")

def extract(pdf_path):
    txt = subprocess.run(["pdftotext", "-layout", str(pdf_path), "-"],
                         capture_output=True, text=True).stdout
    lines = txt.splitlines()
    recs = {}  # section -> {level, automatable}
    pa = [i for i, l in enumerate(lines) if l.strip().startswith("Profile Applicability")]
    for i in pa:
        # backward: nearest recommendation-number header + Automated/Manual tag
        num = typ = None
        for j in range(i - 1, max(i - 15, -1), -1):
            m = NUMHDR.match(lines[j])
            if not m or m.group(1).count(".") < 1:
                continue
            num = m.group(1)
            span = " ".join(lines[k] for k in range(j, i))
            typ = "Automated" if "(Automated)" in span else ("Manual" if "(Manual)" in span else None)
            break
        if not num:
            continue
        # forward: profile level within the applicability block
        window = " ".join(lines[i:i + 8])
        level = "L1" if "Level 1" in window else ("L2" if "Level 2" in window else "")
        recs.setdefault(num, {"section": num, "level": level,
                              "automatable": typ == "Automated"})
    return recs, len(pa)

for os_, (fn, ver) in PDF.items():
    recs, pa = extract(SRC / fn)
    assert len(recs) == pa, f"{os_}: parsed {len(recs)} != {pa} Profile-Applicability blocks"
    doc = {"framework": "cis", "os": os_, "version": ver,
           "recommendations": sorted(recs.values(), key=lambda r: r["section"])}
    (OUT / f"cis_facts_{os_}.json").write_text(json.dumps(doc, indent=1))
    auto = sum(1 for r in recs.values() if r["automatable"])
    l1 = sum(1 for r in recs.values() if r["level"] == "L1")
    print(f"{os_:10} {ver:8} recs={len(recs):4} automatable={auto:4} L1={l1:4}  -> cis_facts_{os_}.json")
