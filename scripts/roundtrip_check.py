#!/usr/bin/env python3
"""Gate a round-trip run against the recorded baseline.

A number that is reported gets ignored. A number that fails the build gets
fixed. This is the same ratchet `make catalog-check` applies to the catalog:
the baseline is a checked-in file, drift fails, and the only way to move it is a
deliberate re-baseline that shows up as a reviewable diff.

Two things fail here, and the second matters as much as the first.

  1. A REGRESSION. A rule that round-tripped cleanly no longer does.

  2. SHRINKING COVERAGE. The run exercised fewer rules than the baseline. This
     is the failure mode that makes a green run worthless: a harness that
     quietly stops testing looks exactly like a harness with nothing to report.
     A container matrix run in this project once reported success while 10 of
     its 17 images were unreachable and contributed nothing.

Improvements never fail. They print a note asking for a re-baseline, so the
better number has to be recorded on purpose rather than drifting in.

    scripts/roundtrip_check.py results.json --baseline scripts/roundtrip_baseline.json
    scripts/roundtrip_check.py results.json --baseline B --update    # re-baseline
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

GOOD = "ok"


def load(p: Path) -> dict:
    return json.loads(p.read_text())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("results", type=Path, nargs="+",
                    help="one report, or several shards from parallel hosts")
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--update", action="store_true",
                    help="write the current run as the new baseline")
    a = ap.parse_args()

    # Shards from parallel clones are merged before comparison. `exercised` is
    # summed because each shard covers a distinct slice of rules; if two shards
    # ever report the same rule the run is malformed, so say so rather than let
    # one silently win.
    runs = [load(p) for p in a.results]
    current: dict[str, str] = {}
    for path, run in zip(a.results, runs):
        for r in run["results"]:
            if r["rule"] in current and current[r["rule"]] != r["outcome"]:
                print(f"CONFLICT  {r['rule']} appears in more than one shard "
                      f"with different outcomes ({current[r['rule']]} vs "
                      f"{r['outcome']}); shards must cover disjoint rules")
                return 1
            current[r["rule"]] = r["outcome"]
    run = {"exercised": sum(r["exercised"] for r in runs),
           "results": [r for x in runs for r in x["results"]]}

    if a.update or not a.baseline.exists():
        a.baseline.write_text(json.dumps(
            {"exercised": run["exercised"], "rules": dict(sorted(current.items()))},
            indent=2, sort_keys=True) + "\n")
        print(f"baseline written: {len(current)} rules, "
              f"{run['exercised']} exercised -> {a.baseline}")
        return 0

    base = load(a.baseline)
    base_rules = base.get("rules", {})

    regressions = [
        (r, base_rules[r], current.get(r, "absent"))
        for r in sorted(base_rules)
        if base_rules[r] == GOOD and current.get(r) != GOOD
    ]
    improvements = [
        (r, base_rules.get(r, "new"), current[r])
        for r in sorted(current)
        if current[r] == GOOD and base_rules.get(r) != GOOD
    ]
    shrank = run["exercised"] < base.get("exercised", 0)

    for r, was, now in regressions:
        print(f"REGRESSION  {r:<42} {was} -> {now}")
    if shrank:
        print(f"COVERAGE SHRANK  exercised {run['exercised']} < "
              f"baseline {base['exercised']}")
        print("  a run that measures less than last time is not a passing run")
    for r, was, now in improvements:
        print(f"improved    {r:<42} {was} -> {now}")

    if regressions or shrank:
        print(f"\nFAIL: {len(regressions)} regression(s)"
              f"{', coverage shrank' if shrank else ''}")
        print("If the change is intended, re-baseline with --update and commit "
              "the diff so the decision is on the record.")
        return 1

    print(f"OK: {run['exercised']} exercised, no regressions"
          f"{f', {len(improvements)} improved (re-baseline to record)' if improvements else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
