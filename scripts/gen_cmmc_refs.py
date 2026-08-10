#!/usr/bin/env python3
"""Emit CMMC Level 2 practice references onto rules, derived from their
reviewed NIST SP 800-171 Rev 2 references.

WHY THIS IS A RENAMING AND NOT A MAPPING
    32 CFR 170 defines CMMC Level 2 as the 110 NIST SP 800-171 Rev 2
    requirements, one for one, and names each practice `<FAMILY>.L2-<req>`. So
    a practice identifier follows from a reviewed requirement citation with no
    new judgment, and emitting it asserts nothing the 800-171 reference did not
    already assert.

    That is the entire justification for doing this mechanically. The 800-53 to
    800-171 hop is many-to-many at every step, which is why it produces
    CANDIDATES that a person reviews before anything ships. Nothing here is a
    candidate.

WHAT IT REFUSES TO DO
    It reads only the `nist_800_171` refs already written into rule YAML, which
    are reviewed. It never reads the Layer 1 candidate set. A rule with no
    800-171 refs gets no CMMC refs; derivation does not invent a mapping for an
    unmapped rule.

THE FAMILY MAP IS DERIVED, NOT REMEMBERED
    This script extracts the requirement-group to family-prefix mapping from
    32 CFR 170 itself and fails if the regulation does not cover all 14 groups
    unambiguously. It then checks that map against the one compiled into
    internal/mappings/cmmc.go, so the two cannot drift.

GRANULARITY
    Kensa cites 800-171 at 800-171A assessment-objective granularity, because
    that is the unit a C3PAO scores. CMMC practices exist only at requirement
    granularity, so 3.1.7[a] and 3.1.7[d] on one rule collapse to one
    AC.L2-3.1.7. Emitting one practice per objective would multiply a single
    claim into several.

USAGE
    ./.venv-tools/bin/python scripts/gen_cmmc_refs.py [--check]
        --check  report what would change and exit non-zero if anything would
"""
import argparse
import collections
import glob
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CFR = ROOT / "docs" / "research" / "SOT" / "nist" / "32CFR170_as-of_2026-07-28.xml"
GO_MAP = ROOT / "internal" / "mappings" / "cmmc.go"

EXPECTED_GROUPS = [f"3.{n}" for n in range(1, 15)]
OBJECTIVE_SUFFIX = re.compile(r"\[[a-z]\]$")


def family_map_from_regulation():
    """requirement group -> family prefix, read from 32 CFR 170."""
    if not CFR.is_file():
        sys.exit(f"32 CFR 170 not found at {CFR}; the family map cannot be derived")
    xml = CFR.read_text(errors="replace")
    fam = collections.defaultdict(set)
    for prefix, _lvl, _req, group in re.findall(
            r"\b([A-Z]{2})\.L([123])-(3\.(\d+)\.\d+)\b", xml):
        fam[f"3.{group}"].add(prefix)

    missing = [g for g in EXPECTED_GROUPS if g not in fam]
    ambiguous = {g: sorted(p) for g, p in fam.items() if len(p) > 1}
    if missing or ambiguous:
        sys.exit(f"family map is not usable: missing groups {missing}, "
                 f"ambiguous {ambiguous}")
    return {g: next(iter(fam[g])) for g in EXPECTED_GROUPS}


def go_family_map():
    """The map compiled into the engine, so the two can be compared."""
    src = GO_MAP.read_text()
    return dict(re.findall(r'"(3\.\d+)":\s*"([A-Z]{2})"', src))


def practices_for(refs, fammap):
    out = set()
    for r in refs:
        req = OBJECTIVE_SUFFIX.sub("", str(r).strip())
        parts = req.split(".")
        if len(parts) != 3:
            continue
        group = f"{parts[0]}.{parts[1]}"
        if group in fammap:
            out.add(f"{fammap[group]}.L2-{req}")
    return sorted(out)


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="report what would change; exit non-zero if anything would")
    a = ap.parse_args()

    fammap = family_map_from_regulation()
    compiled = go_family_map()
    if compiled != fammap:
        sys.exit("internal/mappings/cmmc.go disagrees with 32 CFR 170:\n"
                 f"  regulation {fammap}\n  compiled   {compiled}")

    changed, emitted, rules_touched = [], 0, 0
    for path in sorted(glob.glob(str(ROOT / "rules" / "**" / "*.yml"), recursive=True)):
        text = pathlib.Path(path).read_text(errors="replace")
        try:
            d = yaml.safe_load(text)
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        refs = (d.get("references") or {})
        want = practices_for(as_list(refs.get("nist_800_171")), fammap)
        have = [str(x) for x in as_list(refs.get("cmmc_l2"))]
        if sorted(have) == want:
            continue
        changed.append((path, sorted(have), want))
        if want:
            rules_touched += 1
            emitted += len(want)
        if not a.check:
            write_refs(path, text, want)

    if a.check:
        for p, have, want in changed[:10]:
            print(f"  {pathlib.Path(p).name}: have {have} want {want}")
        if changed:
            print(f"{len(changed)} rule(s) differ from the derivation")
            return 1
        print("cmmc refs match the derivation")
        return 0

    print(f"emitted {emitted} cmmc_l2 refs across {rules_touched} rules "
          f"({len(changed)} files rewritten)")
    return 0


def write_refs(path, text, want):
    """Insert or replace the cmmc_l2 block under references:, in place.

    Rewriting the YAML through the parser would reflow every rule file and bury
    the change in noise, so this is a targeted textual edit: the refs are
    generated, and a generated change should read as one line per practice in
    the diff.
    """
    p = pathlib.Path(path)
    lines = text.split("\n")
    # Drop any existing cmmc_l2 block first.
    out, i = [], 0
    while i < len(lines):
        if re.match(r"^  cmmc_l2:", lines[i]):
            i += 1
            while i < len(lines) and re.match(r"^\s*-\s", lines[i]):
                i += 1
            continue
        out.append(lines[i])
        i += 1
    if not want:
        p.write_text("\n".join(out))
        return
    # Insert after the last entry of the references block.
    block = ["  cmmc_l2:"] + [f'    - "{w}"' for w in want]
    for idx, line in enumerate(out):
        if re.match(r"^references:", line):
            end = idx + 1
            while end < len(out) and (out[end].startswith("  ") or out[end].strip() == ""):
                if out[end].strip() == "" and end + 1 < len(out) and not out[end + 1].startswith("  "):
                    break
                end += 1
            out[end:end] = block
            break
    p.write_text("\n".join(out))


if __name__ == "__main__":
    sys.exit(main())
