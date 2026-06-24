#!/usr/bin/env python3
"""Derive slim, vendorable NIST 800-53 Rev 5 facts from the authoritative public-
domain sources, so the heavy raw files (10 MB OSCAL catalog, 3 MB CCI XML) need not
be committed. Both sources are US Government works (public domain).

Raw inputs (download once; not vendored):
  - NIST OSCAL 800-53 r5 catalog:
    https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
  - DISA CCI list (U_CCI_List.zip -> U_CCI_List.xml):
    https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip

Usage: derive_nist_facts.py <raw-dir>
  expects <raw-dir>/nist_800-53_r5_catalog.json and <raw-dir>/U_CCI_List.xml

Emits, next to this script:
  - nist_800-53_r5_controls.json : [{id, family, title}]  (1196 controls)
  - cci_800-53_r5_edges.json     : [{cci, control}]        (rev5 edges only)
"""
import json, re, sys, xml.etree.ElementTree as ET
from pathlib import Path

OUT = Path(__file__).resolve().parent
INDEX_RE = re.compile(r"^([A-Za-z]{2})-(\d+)(?:\s*\((\d+)\))?")

def derive_controls(catalog_path):
    cat = json.load(open(catalog_path))["catalog"]
    out = []
    def walk(family, c):
        out.append({"id": c["id"], "family": family, "title": c.get("title", "")})
        for e in c.get("controls", []):
            walk(family, e)
    for g in cat["groups"]:
        for c in g.get("controls", []):
            walk(g["id"], c)
    return out

def normalize(index):
    m = INDEX_RE.match(index.strip())
    if not m:
        return ""
    cid = m.group(1).lower() + "-" + m.group(2)
    if m.group(3):
        cid += "." + m.group(3)
    return cid

def derive_edges(cci_path):
    ns = "{http://iase.disa.mil/cci}"
    root = ET.parse(cci_path).getroot()
    edges = []
    for item in root.iter(ns + "cci_item"):
        cci = item.get("id")
        seen = set()
        refs = item.find(ns + "references")
        if refs is None:
            continue
        for ref in refs.findall(ns + "reference"):
            if ref.get("version") != "5":
                continue
            cid = normalize(ref.get("index", ""))
            if cid and cid not in seen:
                seen.add(cid)
                edges.append({"cci": cci, "control": cid})
    return edges

def main():
    if len(sys.argv) != 2:
        sys.exit("usage: derive_nist_facts.py <raw-dir>")
    raw = Path(sys.argv[1])
    controls = derive_controls(raw / "nist_800-53_r5_catalog.json")
    edges = derive_edges(raw / "U_CCI_List.xml")
    (OUT / "nist_800-53_r5_controls.json").write_text(json.dumps(controls, indent=1))
    (OUT / "cci_800-53_r5_edges.json").write_text(json.dumps(edges, indent=1))
    print(f"derived {len(controls)} controls, {len(edges)} cci->800-53 rev5 edges")

if __name__ == "__main__":
    main()
