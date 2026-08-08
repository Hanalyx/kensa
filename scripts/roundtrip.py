#!/usr/bin/env python3
"""Run each rule backwards through the engine and assert the verdict tracks reality.

The static gates in internal/rule/false_pass_test.go read rule TEXT. They catch a
check that can only exit 0, a default implementation that checks something other
than the gated one, and a failure branch made unreachable by an `fi`. They cannot
catch a check whose verdict is wrong only under a particular host state, because
nothing in the source says so.

This closes that by using the engine against itself. On a host where a rule
fails:

    scan      -> expect fail
    remediate -> expect the check now passes
    rollback  -> expect the check fails again, and /etc is byte-identical

Three properties fall out of one loop. The check's verdict tracks a real state
change in BOTH directions, the remediation converges, and the rollback restores
what it captured. The deepest false-pass class this finds is a check that does
not observe what its own remediation changes: remediation reports FIXED, the host
really changed, and the verdict never moves.

Nothing here is authored per rule. The mutation is the remediation run backwards,
so there is no second corpus to drift out of sync with the first. A rule that
changes brings its own test along.

    scripts/roundtrip.py --host 192.168.1.161 --rules-from list.txt --out rt.json
    scripts/roundtrip.py --host H --mechanism audit_rule_set --rules-dir rules

Outcomes per rule:

    ok                   fail -> pass -> fail, /etc restored
    check_not_flipped    remediation reported success, the check never passed
    remediate_failed     the engine could not apply it
    rollback_not_flipped the check still passes after rollback
    residue              verdicts correct, /etc did not come back
    not_failing          the rule already passed, so there was nothing to test
    error                the harness itself could not complete the rule

`not_failing` and `error` are NOT successes. They are the harness measuring less
than it claims to, which is the failure mode that makes a green run meaningless.
Both are counted and reported separately for that reason.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
KENSA = REPO / "bin" / "kensa"

# Every kensa invocation writes the SQLite transaction log at .kensa/results.db
# in the working directory. Parallel shards sharing one file contend for its
# lock, and the failures surface as unrelated-looking scan and remediate errors
# rather than as anything that mentions the database. Each run therefore gets
# its own ledger, which also stops one shard's transaction lookups from seeing
# another's. Set in main(); `--db` is a TOP-LEVEL flag, so it precedes the
# subcommand.
DB: list[str] = []


def sh(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


class Host:
    """A target host, with one reused SSH connection.

    Each command otherwise pays connection setup, which dominates: an /etc
    manifest of 579 files took 20 seconds over a fresh connection and well under
    a second over a shared one.
    """

    def __init__(self, addr: str, user: str, key: str):
        self.addr, self.user, self.key = addr, user, key
        self.ctl = Path(tempfile.mkdtemp(prefix="rt-")) / "cs"
        self._base = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
            "-o", f"ControlPath={self.ctl}", "-i", key,
        ]
        sh(self._base + ["-o", "ControlMaster=auto", "-o", "ControlPersist=600",
                         "-fN", f"{user}@{addr}"], timeout=30)

    def run(self, script: str, timeout: int = 120) -> tuple[int, str]:
        rc, out, _ = sh(self._base + [f"{self.user}@{self.addr}", script], timeout)
        return rc, out.strip()

    def manifest(self) -> dict[str, str]:
        """path -> content hash for every file under /etc.

        The full map rather than one digest, so residue can be ATTRIBUTED
        instead of merely detected. The first residue this harness found took
        manual forensics on a host that was minutes from being destroyed; the
        delta below would have named the file immediately.
        """
        rc, out = self.run(
            "sudo find /etc -type f -exec sha256sum {} + 2>/dev/null | sort",
            timeout=180)
        if rc != 0 or not out:
            return {}
        m = {}
        for line in out.splitlines():
            h, _, path = line.partition("  ")
            if path:
                m[path] = h
        return m

    def close(self) -> None:
        sh(self._base + ["-O", "exit", f"{self.user}@{self.addr}"], timeout=15)


def scan(host: Host, rule: Path) -> tuple[str, str]:
    """Return (status, stderr) for one rule; status is 'error' if it did not run.

    The stderr comes back with it because an `error` outcome with no explanation
    is undiagnosable. A whole parallel run once returned 17 of them and the
    cause, SQLite lock contention on a shared ledger, was invisible from the
    report alone.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    try:
        _, _, err = sh(
            [str(KENSA), *DB, "check", "-H", host.addr, "-u", host.user,
             "-k", host.key, "--sudo", "-r", str(rule), "--output", f"json:{out}"],
            timeout=300)
        with open(out) as fh:
            outcomes = json.load(fh).get("Outcomes") or []
        if len(outcomes) == 1:
            return outcomes[0]["Status"], ""
        return "error", err.strip()[-300:]
    except (OSError, ValueError, KeyError, IndexError) as exc:
        return "error", f"{type(exc).__name__}: {exc}"[:300]
    finally:
        if os.path.exists(out):
            os.unlink(out)


def remediate(host: Host, rule: Path) -> tuple[bool, str]:
    rc, out, err = sh([str(KENSA), *DB, "remediate", "-H", host.addr, "-u", host.user,
                       "-k", host.key, "--sudo", str(rule)], timeout=300)
    text = out + err
    return ("FIXED" in text), text


def last_txn(host: Host, rule_id: str) -> str | None:
    """Most recent committed transaction for this rule.

    `kensa history` reads a LOCAL ledger and takes no connection flags, so this
    is a client-side lookup rather than a call to the host.
    """
    _, out, _ = sh([str(KENSA), *DB, "history", "--format", "json"], timeout=60)
    try:
        txns = json.loads(out).get("Transactions", [])
    except (ValueError, TypeError):
        return None
    # The ledger is NOT ordered by time, so position cannot stand in for
    # recency. Pick the newest committed entry for this rule by its own
    # timestamp; otherwise a rule round-tripped twice can roll back the
    # earlier run and leave the later one applied.
    mine = [t for t in txns
            if t.get("RuleID") == rule_id and t.get("Status") == "committed"]
    if not mine:
        return None
    return max(mine, key=lambda t: t.get("StartedAt") or "").get("ID")


def rollback(host: Host, txn: str) -> bool:
    rc, out, err = sh([str(KENSA), *DB, "rollback", "--txn", txn, "-H", host.addr,
                       "-u", host.user, "-k", host.key, "--sudo"], timeout=300)
    return rc == 0


def rule_id_of(path: Path) -> str:
    m = re.search(r"^id:\s*(\S+)", path.read_text(), re.M)
    return m.group(1) if m else path.stem


def roundtrip(host: Host, rule: Path, before: dict) -> tuple[dict, dict]:
    """Run one rule and return (result, manifest_after) for reuse as the next before.

    Per-step timings are recorded because the loop is the unit of cost for the
    whole harness: 55 rules at five minutes each is five hours, which is too
    slow to run nightly. Knowing which step dominates is what makes it tunable.
    """
    rid = rule_id_of(rule)
    r = {"rule": rid, "path": str(rule.relative_to(REPO))}
    t: dict[str, float] = {}
    r["seconds"] = t
    mark = time.time()

    def lap(name: str) -> None:
        nonlocal mark
        now = time.time()
        t[name] = round(now - mark, 1)
        mark = now

    s0, err0 = scan(host, rule)
    lap("scan_before")
    r["scan_before"] = s0
    if err0:
        r["detail"] = err0
    if s0 != "fail":
        r["outcome"] = "not_failing" if s0 in ("pass", "skipped") else "error"
        return r, before

    ok, text = remediate(host, rule)
    lap("remediate")
    if not ok:
        r["outcome"] = "remediate_failed"
        r["detail"] = text.strip().splitlines()[-1][:200] if text.strip() else ""
        return r, host.manifest()

    s1, err1 = scan(host, rule)
    lap("scan_after_remediate")
    if err1:
        r["detail"] = err1
    r["scan_after_remediate"] = s1
    if s1 != "pass":
        # The host changed but the verdict did not. This is the class the
        # static gates cannot see.
        r["outcome"] = "check_not_flipped"
        return r, host.manifest()

    txn = last_txn(host, rid)
    rolled = bool(txn) and rollback(host, txn)
    lap("rollback")
    if not rolled:
        r["outcome"] = "error"
        r["detail"] = "no committed transaction to roll back" if not txn else "rollback failed"
        return r, host.manifest()

    s2, err2 = scan(host, rule)
    lap("scan_after_rollback")
    if err2:
        r["detail"] = err2
    r["scan_after_rollback"] = s2
    after = host.manifest()
    lap("manifest")
    if s2 != "fail":
        r["outcome"] = "rollback_not_flipped"
        return r, after

    if before and after and before != after:
        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        changed = sorted(k for k in set(before) & set(after) if before[k] != after[k])
        r["outcome"] = "residue"
        r["residue"] = {"added": added[:20], "removed": removed[:20],
                        "changed": changed[:20]}
        r["detail"] = ("; ".join(
            f"{label} {', '.join(paths[:4])}" + (" ..." if len(paths) > 4 else "")
            for label, paths in (("added", added), ("removed", removed),
                                 ("changed", changed)) if paths))[:300]
        return r, after

    r["outcome"] = "ok"
    return r, after


def collect(rules_dir: Path, mechanism: str | None, from_file: Path | None) -> list[Path]:
    if from_file:
        return [REPO / line.split("\t")[-1].strip()
                for line in from_file.read_text().splitlines() if line.strip()]
    out = []
    for p in sorted(rules_dir.rglob("*.yml")):
        if mechanism:
            m = re.search(r"remediation:(.*?)(?=\n\S|\Z)", p.read_text(), re.S)
            if not m or mechanism not in m.group(1):
                continue
        out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", default="owadmin")
    ap.add_argument("--key", default=str(Path.home() / ".ssh" / "id_ed25519"))
    ap.add_argument("--rules-dir", default=str(REPO / "rules"), type=Path)
    ap.add_argument("--mechanism", help="only rules whose remediation uses this")
    ap.add_argument("--rules-from", type=Path, help="file of rule paths, one per line")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--db", help="ledger path; defaults to one beside --out, so "
                                 "parallel shards never share a SQLite file")
    ap.add_argument("--list", action="store_true",
                    help="print the selected rule paths and exit, so a caller "
                         "can split them across parallel hosts")
    a = ap.parse_args()

    if a.list:
        for p in collect(a.rules_dir, a.mechanism, a.rules_from)[: a.limit or None]:
            print(p)
        return 0
    if not a.out:
        print("--out is required unless --list is given", file=sys.stderr)
        return 2

    if not KENSA.exists():
        print(f"build {KENSA} first", file=sys.stderr)
        return 2

    global DB
    db = Path(a.db) if a.db else a.out.with_suffix(".ledger.db")
    db.parent.mkdir(parents=True, exist_ok=True)
    DB = ["--db", str(db)]

    rules = collect(a.rules_dir, a.mechanism, a.rules_from)
    if a.limit:
        rules = rules[: a.limit]
    if not rules:
        print("no rules selected", file=sys.stderr)
        return 2

    host = Host(a.host, a.user, a.key)
    started = time.time()
    manifest = host.manifest()
    if not manifest:
        print(f"could not read a manifest from {a.host}; is it reachable?", file=sys.stderr)
        return 2

    results = []
    try:
        for i, rule in enumerate(rules, 1):
            res, manifest = roundtrip(host, rule, manifest)
            results.append(res)
            print(f"[{i}/{len(rules)}] {res['rule']:<42} {res['outcome']}", flush=True)
            if res["outcome"] in ("residue", "rollback_not_flipped"):
                # State leaked. Anything after this on the same host is suspect.
                print("  host state is dirty; stopping so later rules are not "
                      "measured against it", flush=True)
                break
    finally:
        host.close()

    counts: dict[str, int] = {}
    for r in results:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    report = {
        "host": a.host,
        "selected": len(rules),
        "attempted": len(results),
        "exercised": counts.get("ok", 0) + sum(
            counts.get(k, 0) for k in
            ("check_not_flipped", "rollback_not_flipped", "residue", "remediate_failed")),
        "counts": counts,
        "seconds": round(time.time() - started, 1),
        "results": results,
    }
    a.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"\n{report['exercised']}/{report['selected']} exercised in "
          f"{report['seconds']}s -> {a.out}")
    for k in sorted(counts):
        print(f"  {k:<22} {counts[k]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
