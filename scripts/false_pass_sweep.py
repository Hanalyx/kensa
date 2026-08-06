#!/usr/bin/env python3
"""Sweep the rule corpus for checks that can report compliance without verifying it.

Four defects of this shape were found one at a time while mapping 800-171 to
rules, each by a different accident. This looks for the classes they belong to,
deliberately, and across the whole corpus.

  A  always-pass        the command check can only ever exit 0
  B  absent-means-pass  a package/command absence guard returns success on a rule
                        whose title states a REQUIREMENT rather than a prohibition
  C  divergent default  the default implementation checks a different thing than
                        the capability-gated one it stands in for
  D  passes where a peer fails   the rule passes on every measured host while a
                        rule citing the same framework control fails there

Every class produces CANDIDATES, not verdicts. Class B and C in particular
depend on reading a title, which is a heuristic; the earlier passes over this
corpus over-matched three times before being hand-checked. Read each one.

    scripts/false_pass_sweep.py [scan.json ...]

Classes A and C are also enforced as corpus tests in
internal/rule/false_pass_test.go, which is the gate. B needs a title read
and D needs scan output, so both stay here as tools a human reviews.
"""
import re, sys, json, glob, pathlib, collections
import yaml

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

# A requirement asserts something must be present or configured; a prohibition
# asserts something must be absent or restricted. "Package absent, therefore
# compliant" is honest for a prohibition and a false pass for a requirement.
REQUIREMENT = re.compile(r'^(ensure|configure|set|enable|install|allocate|require|'
                         r'store|employ|deploy|generate)\b', re.I)
PROHIBITION = re.compile(r'\b(disable|remove|absent|prevent|prohibit|restrict|deny|'
                         r'not be|must not|no unauthorized)\b', re.I)
ABSENCE_GUARD = re.compile(
    r'if\s*!\s*(?:rpm -q|dpkg[^;\n]*|command -v)[^;\n]*;\s*then[^\n]*exit 0'
    r'|(?:rpm -q|dpkg -l|command -v)[^\n|]*\|\|\s*\{[^}]*exit 0')


def always_passes(run):
    joined = run.replace("\\\n", " ")
    exits = re.findall(r'\bexit\s+(\d+)', joined)
    body = [l.strip() for l in joined.strip().split("\n") if l.strip()]
    if not body:
        return False
    tail = body[-1].split(";")[-1].strip()
    return bool(exits) and all(e == "0" for e in exits) and tail.startswith("exit 0")


# Shell plumbing carries no information about WHAT a check inspects.
NOISE = {"if", "then", "else", "fi", "for", "do", "done", "case", "esac", "echo",
         "exit", "printf", "test", "true", "false", "set", "local", "return",
         "grep", "awk", "sed", "cut", "tr", "head", "tail", "sort", "uniq", "wc",
         "xargs", "cat", "read", "while", "eval", "command"}


def targets(check):
    """What a check actually looks at, so two implementations can be compared.

    Paths and service names alone were not enough: the gated implementation of
    nftables-default-deny runs `nft list ruleset`, which names no path and no
    unit, so it compared as empty against a default that names firewalld and the
    defect scored as no-difference. Subject binaries are the missing signal.
    """
    blob = json.dumps(check, sort_keys=True)
    paths = set(re.findall(r'/(?:etc|proc|sys|var|usr)/[A-Za-z0-9._/-]+', blob))
    units = set(re.findall(r'\b(?:is-active|is-enabled)\s+([A-Za-z0-9._-]+)', blob))
    pkgs = set(re.findall(r'\b(?:rpm -q|dpkg -l)\s+([A-Za-z0-9._-]+)', blob))
    cmds = {w for w in re.findall(r'(?:^|[;&|]|\\n)\s*([a-z][a-z0-9._-]{1,20})\b', blob)
            if w not in NOISE}
    return paths | units | pkgs | cmds


def main():
    rules = {}
    for f in sorted(glob.glob(str(ROOT / "rules/**/*.yml"), recursive=True)):
        d = yaml.safe_load(open(f))
        if d and d.get("id"):
            rules[d["id"]] = (d, pathlib.Path(f).relative_to(ROOT))

    observed = collections.defaultdict(dict)
    for p in sys.argv[1:]:
        try:
            scan = json.load(open(p))
        except Exception:
            continue
        host = pathlib.Path(p).stem
        for o in scan.get("Outcomes") or []:
            observed[o["RuleID"]][host] = o["Status"]

    A, B, C, D = [], [], [], []
    for rid, (d, path) in rules.items():
        title = d.get("title", "")
        impls = d.get("implementations") or []
        for i in impls:
            run = str((i.get("check") or {}).get("run", ""))
            if not run.strip():
                continue
            if always_passes(run):
                A.append((rid, path))
                break
            if ABSENCE_GUARD.search(run) and not i.get("when"):
                if REQUIREMENT.match(title) and not PROHIBITION.search(title):
                    B.append((rid, title[:52]))
                break
        gated = [i for i in impls if i.get("when")]
        dflt = [i for i in impls if i.get("default")]
        if gated and dflt:
            gt = set().union(*(targets(i.get("check") or {}) for i in gated))
            dt = set().union(*(targets(i.get("check") or {}) for i in dflt))
            if gt and dt and not (gt & dt):
                C.append((rid, sorted(gt)[:2], sorted(dt)[:2]))

    # D compares only rules that plausibly check THE SAME THING. A shared 800-53
    # control is far too broad: dozens of rules cite AC-6 or CM-6, and any host
    # failing one of them would flag every other as suspicious. Restricting to
    # 800-171 objective granularity AND requiring overlapping subjects is what
    # isolates the real signal, which is two rules disagreeing about one fact.
    by_control = collections.defaultdict(set)
    for rid, (d, _) in rules.items():
        for c in (d.get("references") or {}).get("nist_800_171") or []:
            by_control[("nist_800_171", c)].add(rid)
    for (fam, ctl), members in sorted(by_control.items()):
        if len(members) < 2:
            continue
        for rid in members:
            obs = observed.get(rid, {})
            if not obs or set(obs.values()) - {"pass"}:
                continue
            mine = set().union(*(targets(i.get("check") or {})
                                 for i in (rules[rid][0].get("implementations") or [])))
            peers = []
            for p in members:
                if p == rid or "fail" not in set(observed.get(p, {}).values()):
                    continue
                theirs = set().union(*(targets(i.get("check") or {})
                                       for i in (rules[p][0].get("implementations") or [])))
                if mine & theirs:
                    peers.append(p)
            if peers:
                D.append((rid, f"{fam}:{ctl}", sorted(peers)[:2]))

    print(f"corpus: {len(rules)} rules, observed on {len(set().union(*observed.values())) if observed else 0} hosts\n")
    print(f"A always-pass ................ {len(A)}")
    for r, p in sorted(A):
        print(f"     {r:34} {p}")
    print(f"\nB absent-means-pass on a requirement ... {len(B)}")
    for r, t in sorted(B):
        print(f"     {r:34} {t}")
    print(f"\nC default checks a different thing than the gate it replaces ... {len(C)}")
    for r, g, dd in sorted(C):
        print(f"     {r:34} gated={g} default={dd}")
    seen = set()
    print(f"\nD passes everywhere while a same-control peer fails ... {len(D)}")
    for r, ctl, peers in sorted(D):
        if r in seen:
            continue
        seen.add(r)
        print(f"     {r:34} {ctl:22} peer fails: {peers}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
