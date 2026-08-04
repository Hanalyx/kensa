---
name: sample-remediation-run
description: >
  Run an end-to-end Kensa exercise against one live host: scan, report every rule that can only
  be remediated by hand, remediate a random sample of ten machine-remediable failing rules, roll
  back two of them, and produce a findings report. Use when asked to exercise scan/remediate/
  rollback on a real host, to sample corpus behavior, or to produce a manual-remediation
  inventory. This MUTATES a live host. Read the safety section before running anything.
---

# Sample remediation run

One host, five steps: scan → manual-remediation inventory → remediate 10 → roll back 2 →
report. Every step verifies against the host rather than against Kensa's own output.

**The governing rule:** a `FIXED` row is a *claim*. The evidence is host state before and
after. Most of the work below is collecting that evidence.

## Before anything

**This mutates a live host as root.** Use a snapshotted fleet host, never production, and never
a host someone else is using. `192.168.1.202` (RHEL 8.10), `.211` (9.6), `.213` (9.7), `.247`
(10.1), `.250` (Ubuntu 22.04); login `owadmin`, passwordless sudo.

**Build fresh, statically, immediately before the run:**

```bash
CGO_ENABLED=0 go build -tags netgo -ldflags "-X main.version=$(cat VERSION)" -o bin/kensa ./cmd/kensa
sha256sum bin/kensa    # record it in the report
```

Static is mandatory on RHEL 8 (a dynamic build's agent needs `GLIBC_2.34`). Fresh is mandatory
everywhere: a run against a stale binary once applied to a live host the exact payload the new
guard existed to reject.

**Fix the seed and record it**, so the sample is reproducible:

```bash
SEED=${SEED:-$(date +%s)}; echo "seed=$SEED"
```

Use it for every random choice: `shuf --random-source=<(yes "$SEED")`.

## Step 1: scan

```bash
./bin/kensa check -H "$HOST" -u owadmin --sudo -r rules --output json:scan.json
./bin/kensa check -H "$HOST" -u owadmin --sudo -r rules          # human rows
```

`Outcomes[]` is the canonical verdict; each entry has `RuleID`, `Status`
(`pass`/`fail`/`skipped`/`error`), `Severity`, `FrameworkRefs`. **Do not read
`Transactions[]` for compliance**; on the check path it is a legacy encoding where
`committed`/`rolled_back` double as compliant/non-compliant.

Record totals per status. `skipped` is usually platform gating, not a defect.

## Step 2: manual-remediation inventory

Kensa expresses "a human must do this" as `mechanism: manual`:

```bash
grep -rl "mechanism: manual" rules/ | sort > /tmp/manual-rules.txt
```

Report those as the answer. **Also report, separately, the rules Kensa will not or cannot fix
in-session**. A reader asking "what must I do by hand" needs these too, and they are not
`manual`:

| category | why it isn't automatic |
|---|---|
| `command_exec` | non-capturable: runs, but cannot be rolled back |
| `crypto_policy_subpolicy` | non-capturable |
| `grub_parameter_set` / `_remove` | PENDING until the operator reboots |

Write the report to **`docs/rules/manual-remediation-<host>-<date>.md`**. Include for each rule:
ID, title, severity, frameworks, and its scan verdict from step 1. A manual rule that already
passes needs no operator action, and that distinction is the report's main value.

**`docs/` is gitignored except `docs/guide/`, so this file is local-only and will not appear in
a PR.** Say so in the report itself.

## Step 3: remediate ten

**Sample only from rules that FAILED in step 1.** Remediating a passing rule exercises the
already-compliant skip path and proves nothing about remediation.

Exclude, and state the exclusions in the report:

- every rule in the manual inventory (required by the task)
- `grub_parameter_*`: the change is PENDING until reboot, so it cannot be verified or rolled
  back in-session, and it arms the boot guard

```bash
# failing rule IDs, minus exclusions, sampled with the recorded seed
python3 - <<'PY' > /tmp/candidates.txt
import json
d = json.load(open("scan.json"))
print("\n".join(o["RuleID"] for o in d["Outcomes"] if o["Status"] == "fail"))
PY
grep -vxFf /tmp/excluded.txt /tmp/candidates.txt | shuf --random-source=<(yes "$SEED") -n 10 > /tmp/sample.txt
```

If fewer than ten candidates remain, **use them all and say so**. Do not widen the pool by
including passing or manual rules to reach the number.

Snapshot the host state each sampled rule touches, *before* remediating: `sha256sum` for files,
`systemctl show -p UnitFileState -p ActiveState` for units (**both** properties, read by name,
`--value` prints them in systemd's order, not yours), `sysctl -n` for kernel params.

**Snapshot what the rule TARGETS, not what you assume it targets.** Read each rule's
`remediation` block first: a `file_permissions` rule with `find_paths` walks a whole tree, so
hashing the one obvious file will show it unchanged and make a correct `FIXED` look like a false
claim. In a live run this produced a phantom finding that took a second pass to clear.

```bash
./bin/kensa remediate -H "$HOST" -u owadmin --sudo \
  $(sed 's|^|--rule rules/|; s|$|.yml|' /tmp/sample.txt)   # or -r on a staged dir
```

Then **verify each one against the host**, not against the output row. A rule that reports
`FIXED` while the host is unchanged is the finding you are looking for.

## Step 4: roll back two

Pick two of the ten *that actually committed*:

```bash
shuf --random-source=<(yes "$SEED") -n 2 /tmp/remediated.txt > /tmp/rollback.txt
```

Map rule → transaction UUID, then roll back individually (`--start` would revert the whole
session):

```bash
./bin/kensa history --format json -H "$HOST" | python3 -c "
import json,sys
for t in json.load(sys.stdin)['Transactions']:      # object, not a bare array
    print(t['RuleID'], t['ID'], t['Status'])"

./bin/kensa rollback --txn "$TXN" -H "$HOST" -u owadmin --sudo
```

**Verify byte-perfect restoration** against the step-3 snapshot: identical sha256, identical
unit state on *both* layers. Restoring the enable layer while leaving the unit stopped is a
failure, and is exactly the defect this corpus has shipped before.

## Step 5: report

Write to `docs/rules/sample-run-<host>-<date>.md`. It must contain:

- **Provenance**: host, OS, binary sha256, seed, timestamps, the exact commands.
- **Scan totals** by status.
- **Manual inventory**: count, plus the separate non-automatic categories.
- **The ten**: rule ID, mechanism, verdict before, result, and *host evidence* before/after.
  The evidence cell must carry **measurements, not summaries**: name the specific paths, hashes
  or modes that changed, and how many objects the remediation touched versus how many were
  actually non-compliant. A cell reading "offenders 1+ -> 0" is a claim wearing evidence's
  clothes. In a live run that exact phrasing hid a rule that chmod'd 23 files to correct 1,
  widening 13 of them, and the defect surfaced only when a reader asked what the cell meant.
- **The two rollbacks**: byte-perfect or not, with the hashes.
- **Residue check**: `atq`, `systemctl list-units --type=timer | grep kensa`,
  `/var/lib/kensa/deadman/`, `/run/kensa/deadman/`, `/tmp/kensa-rollback-*`. A clean restore
  that leaves an armed timer is still a failure: it fires later against a committed transaction.
- **Final host state**: every touched item, and confirmation it matches the pre-run snapshot.
- **Findings**: anything where Kensa's report and the host disagreed. This is the point of the
  exercise; a run with no findings should say so explicitly rather than omitting the section.

## Restore the host

Roll back or manually revert the eight that were not rolled back, then re-verify against the
step-3 snapshot. **Do not assume the rollback did it**; check. Report any item you could not
restore, loudly, with what it is now.

## Known traps

- **`-r` on a shared directory** pulls in every rule there; a mutually-exclusive-rules error
  aborts the whole run. Stage sampled rules in their own directory.
- **Agent mode is the `remediate` default.** `KENSA_NO_AGENT=1` selects the shell path. They are
  different code; say which one you exercised.
- **The deadman only arms for the six control-channel mechanisms**
  (`internal/engine/preflight.go`). If the run is meant to exercise it, check the arm actually
  happened; the CLI output does not say.
- **`rollback --start` reverts the whole session**, not a subset. Use `--txn` for individual
  transactions.
- A rule whose filename stem does not match its `id` fails validation; run
  `./bin/kensa-validate` on anything you author.
