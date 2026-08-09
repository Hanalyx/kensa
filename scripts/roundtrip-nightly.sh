#!/usr/bin/env bash
# Provision disposable hosts, round-trip a mechanism across them in parallel,
# tear them down, then gate the merged result against the recorded baseline.
#
# The round-trip mutates a host and rolls it back. It must never run against
# anything anyone else is using, so this clones templates, uses the clones, and
# destroys them. A clone that survives the run is a bug, which is why cleanup
# is on a trap rather than at the end of the happy path.
#
# Sharding is what makes this affordable. One rule takes roughly two minutes, so
# a hundred rules is over three hours on a single host and about half an hour
# across six. Shards cover disjoint rules and the gate rejects any overlap.
#
# Configuration comes from the environment so no site addresses live in the
# repo:
#
#   RT_NODE      user@host of the hypervisor            (required)
#   RT_TEMPLATE  VMID of the template to clone from     (required)
#   RT_BASE_ID   first disposable VMID; shards use N+i  (required)
#   RT_SHARDS    how many clones to run at once         (default 4)
#   RT_MECH      remediation mechanism to cover         (default audit_rule_set)
#
# RT_TEMPLATE has to suit the mechanism. mount_option_set needs a template with
# SEPARATE FILESYSTEMS for /tmp, /var, /var/log, /var/log/audit, /var/tmp and
# /home, or thirteen of its rules come back `not_failing` because there is no
# mount to set an option on. The STIG-partitioned templates on node pve02
# (VMIDs 130 to 146) are built for this; the cloud templates are not.
#   RT_OUTDIR    where shard reports are written        (default bin/roundtrip)
#
#   RT_NODE=root@10.0.0.1 RT_TEMPLATE=113 RT_BASE_ID=900 RT_SHARDS=6 \
#     scripts/roundtrip-nightly.sh
#
# Exit codes: 0 clean, 1 the gate failed, 2 the harness could not run. The
# difference matters. A 2 means we measured nothing and must not be read as a
# pass.
set -uo pipefail

: "${RT_NODE:?set RT_NODE=user@hypervisor}"
: "${RT_TEMPLATE:?set RT_TEMPLATE=<template vmid>}"
: "${RT_BASE_ID:?set RT_BASE_ID=<first disposable vmid>}"
RT_SHARDS="${RT_SHARDS:-4}"
RT_MECH="${RT_MECH:-audit_rule_set}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RT_OUTDIR="${RT_OUTDIR:-$REPO/bin/roundtrip}"
# One baseline per mechanism; see the Makefile for why a shared file cannot
# work. audit_rule_set keeps the original filename.
if [ "$RT_MECH" = "audit_rule_set" ]; then
  BASELINE="$REPO/scripts/roundtrip_baseline.json"
else
  BASELINE="$REPO/scripts/roundtrip_baseline_$RT_MECH.json"
fi

node() { ssh -o BatchMode=yes -o ConnectTimeout=15 "$RT_NODE" "$@"; }

CLONES=()
cleanup() {
  for v in "${CLONES[@]:-}"; do
    [ -n "$v" ] || continue
    node "qm stop $v >/dev/null 2>&1; sleep 2; qm destroy $v --purge >/dev/null 2>&1" || true
    echo "clone $v destroyed"
  done
}
trap cleanup EXIT

# The host clock has to be right before anything is measured. Three rules in
# the corpus compute against the current date, and a host whose clock lags an
# advisory date computes a negative age and PASSES. That is a false pass
# produced by the environment rather than the rule, and it would be recorded
# here as a real result.
if ! node "chronyc tracking 2>/dev/null | grep -q 'Leap status *: Normal'"; then
  echo "hypervisor clock is not synchronized; refusing to record a run" >&2
  exit 2
fi

mkdir -p "$RT_OUTDIR"; rm -f "$RT_OUTDIR"/shard-*.json

# Selection is DERIVED from the corpus, never a checked-in list of rule names.
# A hand-maintained list is the thing that silently stops covering new rules.
python3 "$REPO/scripts/roundtrip.py" --host unused --mechanism "$RT_MECH" --list \
  > "$RT_OUTDIR/all.txt" || { echo "could not enumerate rules" >&2; exit 2; }
total=$(wc -l < "$RT_OUTDIR/all.txt")
[ "$total" -gt 0 ] || { echo "no rules selected for $RT_MECH" >&2; exit 2; }
echo "$total rules for $RT_MECH across $RT_SHARDS shards"

# Round-robin, not contiguous. Rules that actually fail cluster alphabetically
# (audit-priv-* mostly pass on a cloud image, audit-cmd-* mostly fail), so a
# contiguous split hands one shard every slow full loop while another races
# through skips. A measured run split 4/3/3/17/9/15 before this changed.
awk -v n="$RT_SHARDS" -v d="$RT_OUTDIR" \
    '{printf "%s\n", $0 > sprintf("%s/shard-%02d", d, NR % n)}' "$RT_OUTDIR/all.txt"

pids=()
i=0
for f in "$RT_OUTDIR"/shard-[0-9]*; do
  [ -s "$f" ] || continue
  vmid=$((RT_BASE_ID + i)); i=$((i + 1))
  if node "qm status $vmid" >/dev/null 2>&1; then
    echo "vmid $vmid already exists; refusing to reuse it" >&2; exit 2
  fi
  node "qm clone $RT_TEMPLATE $vmid --name rt-$vmid --full 0" >/dev/null 2>&1 || {
    echo "clone $vmid failed" >&2; exit 2; }
  CLONES+=("$vmid")
  ip="$(node "/root/vm-ip.sh $vmid" 2>/dev/null | tail -1)"
  if [ -z "$ip" ] || [ "$ip" = "none" ]; then
    echo "clone $vmid never reported an address" >&2; exit 2
  fi
  echo "shard $(basename "$f") -> vmid $vmid at $ip"
  python3 "$REPO/scripts/roundtrip.py" --host "$ip" --rules-from "$f" \
    --out "$RT_OUTDIR/$(basename "$f").json" > "$RT_OUTDIR/$(basename "$f").log" 2>&1 &
  pids+=($!)
done

fail=0
for p in "${pids[@]}"; do wait "$p" || fail=1; done
[ "$fail" -eq 0 ] || echo "at least one shard did not complete cleanly" >&2

reports=("$RT_OUTDIR"/shard-*.json)
if [ ! -e "${reports[0]}" ]; then
  echo "no shard produced a report" >&2; exit 2
fi
python3 "$REPO/scripts/roundtrip_check.py" "${reports[@]}" --baseline "$BASELINE"
