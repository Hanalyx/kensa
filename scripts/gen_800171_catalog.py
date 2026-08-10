#!/usr/bin/env python3
"""Generate the embedded NIST SP 800-171 Rev 2 objective catalog.

WHY THIS EXISTS
    The reviewed corpus lives in scratchpad/cmmc/, which is gitignored, so the
    engine cannot read it. `kensa coverage --framework nist_800_171` needs a
    denominator, and a denominator the binary cannot see is not a denominator.

    This emits the SMALLEST artifact that answers the question: per objective,
    its family and its feasibility tier. No objective text. The denominator
    needs to know that 3.1.1[a] is a T4 determination, not what it says, and
    shipping the text would put a copy of 800-171A in the repository for no
    gain.

WHAT IT DOES NOT DO
    It does not decide anything. Every tier here was assigned by a reviewer in
    S-1 and S-2 and lives in the corpus; this copies them. An objective with no
    tier is emitted as unclassified rather than guessed, which is what
    KN-KN-029 is about: 39 objectives (CA, MA, MP) are classified by nobody,
    and at least 3.8.7 has a shipped rule, so neither "assessable" nor
    "boundary" is a safe default.

    Coverage verdicts are read from scratchpad/cmmc/mappings/ and are the
    numerator, kept separate from the tier on purpose. A tier says whether an
    objective CAN be evidenced; a verdict says whether it IS.

USAGE
    ./.venv-tools/bin/python scripts/gen_800171_catalog.py
    # writes internal/coverage/embedded/nist_800_171_r2.json
"""
import collections
import glob
import hashlib
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "scratchpad" / "cmmc"
OUT = ROOT / "internal" / "coverage" / "embedded" / "nist_800_171_r2.json"

# Per-family objective counts from NIST SP 800-171A. The generator refuses to
# emit a catalog that disagrees, because a silently short catalog inflates every
# percentage computed from it.
EXPECT = {"3.1": 70, "3.2": 9, "3.3": 29, "3.4": 44, "3.5": 25, "3.6": 14,
          "3.7": 10, "3.8": 15, "3.9": 4, "3.10": 16, "3.11": 9, "3.12": 14,
          "3.13": 41, "3.14": 20}
EXPECT_TOTAL = 320

# Families NIST writes as organizational: awareness and training, incident
# response, personnel security, physical protection, risk assessment. Their
# objectives ask about people, plans, and premises, so no configuration scanner
# can evidence them from a host. They are boundary regardless of whether a
# reviewer tiered them individually.
BOUNDARY_FAMILIES = {"AT", "IR", "PS", "PE", "RA"}

# The seven objectives whose feasibility depends on where identity lives
# (DEC-2). Assessable on a local-accounts fleet; a partial handoff on a
# directory-joined one.
IDENTITY_CONDITIONAL = {
    "3.1.1[d]", "3.5.3[c]", "3.5.3[d]", "3.5.6[b]",
    "3.5.7[c]", "3.5.7[d]", "3.5.8[b]",
}


def main():
    if not CORPUS.is_dir():
        sys.exit(f"reviewed corpus not found at {CORPUS}; nothing to generate from")

    objectives = {}
    src = hashlib.sha256()
    for f in sorted(glob.glob(str(CORPUS / "*" / "*.yml"))):
        if "/mappings/" in f:
            continue
        raw = pathlib.Path(f).read_bytes()
        src.update(raw)
        d = yaml.safe_load(raw)
        if not isinstance(d, dict):
            continue
        fam = d.get("family")
        for o in d.get("objectives") or []:
            oid = str(o.get("id"))
            objectives[oid] = {
                "family": fam,
                # tier is what a reviewer decided; absent means nobody has.
                "tier": o.get("feasibility") or "",
            }

    # The verdicts are a separate artifact and a separate question.
    verdicts = {}
    for f in sorted(glob.glob(str(CORPUS / "mappings" / "*.yml"))):
        src.update(pathlib.Path(f).read_bytes())
        d = yaml.safe_load(open(f))
        if not isinstance(d, dict):
            continue
        for o in d.get("objectives") or []:
            c = o.get("coverage")
            if c:
                verdicts[str(o.get("id"))] = c

    by_family = collections.Counter(k.rsplit(".", 1)[0].rsplit("[", 1)[0]
                                    for k in objectives)
    group = collections.Counter()
    for oid in objectives:
        group[".".join(oid.split(".")[:2])] += 1
    bad = {g: (n, EXPECT.get(g)) for g, n in group.items() if EXPECT.get(g) != n}
    if bad or len(objectives) != EXPECT_TOTAL:
        sys.exit(f"catalog does not match 800-171A: total={len(objectives)} "
                 f"(want {EXPECT_TOTAL}), mismatched groups={bad}")

    out = {
        "_generated_by": "scripts/gen_800171_catalog.py",
        "_source_digest": src.hexdigest(),
        "revision": "r2",
        "total": len(objectives),
        "boundary_families": sorted(BOUNDARY_FAMILIES),
        "identity_conditional": sorted(IDENTITY_CONDITIONAL),
        "objectives": {
            oid: {
                "family": v["family"],
                "tier": v["tier"],
                "verdict": verdicts.get(oid, ""),
            }
            for oid, v in sorted(objectives.items())
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1, sort_keys=False) + "\n")

    tiers = collections.Counter(v["tier"] or "unclassified" for v in objectives.values())
    verd = collections.Counter(verdicts.values())
    print(f"wrote {OUT.relative_to(ROOT)}")
    print(f"  objectives {len(objectives)}  digest {out['_source_digest'][:12]}")
    print(f"  tiers    {dict(tiers)}")
    print(f"  verdicts {dict(verd)}")


if __name__ == "__main__":
    main()
