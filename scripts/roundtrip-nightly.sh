#!/usr/bin/env bash
# Provision disposable hosts, round-trip a mechanism across them, tear them
# down, then gate the merged result against the recorded baseline.
#
# The round-trip mutates a host and rolls it back. It must never run against
# anything anyone else is using, so this clones templates, uses the clones, and
# destroys them. A clone that survives the run is a bug, which is why cleanup
# is on a trap rather than at the end of the happy path.
#
# Every hypervisor action goes through scripts/lab_gate.py. It reserves
# capacity under the lab lock before anything is created, rechecks before each
# clone and each start, samples headroom while the run executes, and destroys
# only guests that carry this run's id. This script never calls qm or pvesh.
#
# Sharding is what makes a large mechanism affordable. One rule takes roughly
# two minutes, so a hundred rules is over three hours on a single host. The
# default is ONE guest. More shards run only when the lab budget
# (scripts/lab_budget.json) allows that many test guests and the combined
# request passes every capacity check.
#
# Configuration comes from the environment so no site addresses live in the
# repo:
#
#   RT_NODE        user@host of the Proxmox management endpoint (required;
#                  must match management_endpoint in the lab budget)
#   RT_TEMPLATE    VMID of the template to clone from           (required)
#   RT_BASE_ID     first disposable VMID; shards use N+i        (required)
#   RT_GUEST_USER  login user on the template's clones          (required;
#                  templates differ, so there is no default)
#   RT_SHARDS      how many clones to run at once               (default 1)
#   RT_MECH        remediation mechanism to cover               (default audit_rule_set)
#   RT_OWNER       who owns this run, recorded in the ledger    (default user@host)
#   RT_OUTDIR      parent of the per-run output directories     (default bin/roundtrip)
#
# Each run writes only into its own directory, RT_OUTDIR/run-<id>, so two
# invocations cannot overwrite each other's evidence. On a clean finish,
# RT_OUTDIR/latest points at it; `make roundtrip-check` reads from there.
#
# RT_TEMPLATE has to suit the mechanism. mount_option_set needs a template with
# SEPARATE FILESYSTEMS for /tmp, /var, /var/log, /var/log/audit, /var/tmp and
# /home, or thirteen of its rules come back `not_failing` because there is no
# mount to set an option on. Confirm the template's layout before choosing it;
# a template's name is only a hint.
#
#   RT_NODE=root@<mgmt> RT_TEMPLATE=<vmid> RT_BASE_ID=900 RT_GUEST_USER=<user> \
#     scripts/roundtrip-nightly.sh
#
# Exit codes: 0 clean, 1 the gate failed, 2 the harness could not run (this
# includes a capacity refusal, an incomplete run, lost monitoring and a failed
# cleanup). A 2 means we measured nothing reliable and must not be read as a
# pass.
set -uo pipefail

: "${RT_NODE:?set RT_NODE=user@management-endpoint}"
: "${RT_TEMPLATE:?set RT_TEMPLATE=<template vmid>}"
: "${RT_BASE_ID:?set RT_BASE_ID=<first disposable vmid>}"
: "${RT_GUEST_USER:?set RT_GUEST_USER=<login user on the clones>}"
RT_SHARDS="${RT_SHARDS:-1}"
RT_MECH="${RT_MECH:-audit_rule_set}"
RT_OWNER="${RT_OWNER:-$(id -un)@$(hostname)}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RT_OUTDIR="${RT_OUTDIR:-$REPO/bin/roundtrip}"
# RT_GATE exists so tests can substitute a stub; it is not a way to skip the gate.
GATE="${RT_GATE:-python3 $REPO/scripts/lab_gate.py --mgmt $RT_NODE}"
# How long to wait for the monitor's first successful sample.
RT_MONITOR_READY_SECONDS="${RT_MONITOR_READY_SECONDS:-180}"
# One baseline per mechanism; see the Makefile for why a shared file cannot
# work. audit_rule_set keeps the original filename.
if [ "$RT_MECH" = "audit_rule_set" ]; then
  BASELINE="$REPO/scripts/roundtrip_baseline.json"
else
  BASELINE="$REPO/scripts/roundtrip_baseline_$RT_MECH.json"
fi

gate() { $GATE "$@"; }

RUN_ID="$(gate new-run-id)" || { echo "could not create a run id" >&2; exit 2; }
case "$RUN_ID" in
  *[!a-z0-9]*|"") echo "gate returned an invalid run id" >&2; exit 2 ;;
esac
# Allocate this run's own directory before writing anything.
RUN_DIR="$RT_OUTDIR/run-$RUN_ID"
mkdir -p "$RT_OUTDIR" && mkdir "$RUN_DIR" || { echo "could not create $RUN_DIR" >&2; exit 2; }
STOP_FILE="$RUN_DIR/stop-admission"
DONE_FILE="$RUN_DIR/done"
EVIDENCE="$RUN_DIR/evidence"
RESERVED=0
MONITOR_PID=""
final_rc=0

monitor_alive() { [ -n "$MONITOR_PID" ] && kill -0 "$MONITOR_PID" 2>/dev/null; }

cleanup() {
  local rc=$?
  touch "$DONE_FILE"
  if [ -n "$MONITOR_PID" ]; then kill "$MONITOR_PID" 2>/dev/null; wait "$MONITOR_PID" 2>/dev/null; fi
  if [ "$RESERVED" -eq 2 ]; then
    # The reserve outcome is unknown, but no guest can exist yet: releasing
    # either drops a reservation that was written or confirms there is none.
    gate release --run-id "$RUN_ID" > "$RUN_DIR/release.json" || {
      echo "could not reconcile reservation $RUN_ID; see $RUN_DIR/release.json" >&2; rc=2; }
  elif [ "$RESERVED" -eq 1 ]; then
    if gate cleanup --run-id "$RUN_ID" --evidence-dir "$EVIDENCE" > "$RUN_DIR/cleanup.json"; then
      if ! gate release --run-id "$RUN_ID" > "$RUN_DIR/release.json"; then
        echo "reservation $RUN_ID was not released; see $RUN_DIR/release.json" >&2
        rc=2
      fi
    else
      # Keep the reservation: the capacity it covers may still be in use, and
      # the ledger entry is how an operator finds what was left behind.
      echo "cleanup of run $RUN_ID did not finish; reservation kept, see $RUN_DIR/cleanup.json" >&2
      rc=2
    fi
  fi
  [ "$final_rc" -ne 0 ] && [ "$rc" -eq 0 ] && rc=$final_rc
  exit "$rc"
}
trap cleanup EXIT

# The host clock has to be right before anything is measured. Three rules in
# the corpus compute against the current date, and a host whose clock lags an
# advisory date computes a negative age and PASSES. That is a false pass
# produced by the environment rather than the rule, and it would be recorded
# here as a real result. This is a read; it provisions nothing.
if ! ssh -o BatchMode=yes -o ConnectTimeout=15 "$RT_NODE" \
     "chronyc tracking 2>/dev/null | grep -q 'Leap status *: Normal'"; then
  echo "hypervisor clock is not synchronized; refusing to record a run" >&2
  exit 2
fi

# Selection is DERIVED from the corpus, never a checked-in list of rule names.
# A hand-maintained list is the thing that silently stops covering new rules.
python3 "$REPO/scripts/roundtrip.py" --host unused --mechanism "$RT_MECH" --list \
  > "$RUN_DIR/all.txt" || { echo "could not enumerate rules" >&2; exit 2; }
total=$(wc -l < "$RUN_DIR/all.txt")
[ "$total" -gt 0 ] || { echo "no rules selected for $RT_MECH" >&2; exit 2; }

# Reserve capacity for every shard at once, under the lab lock. Nothing exists
# yet, so a refusal here leaves the lab exactly as it was.
gate reserve --template "$RT_TEMPLATE" --vms "$RT_SHARDS" --run-id "$RUN_ID" \
  --owner "$RT_OWNER" --purpose "roundtrip $RT_MECH" > "$RUN_DIR/reserve.json"
case $? in
  0) RESERVED=1 ;;
  3) echo "capacity gate refused $RT_SHARDS guest(s); see $RUN_DIR/reserve.json" >&2; exit 2 ;;
  *) RESERVED=2; echo "capacity gate could not run, or its outcome is uncertain" >&2; exit 2 ;;
esac
echo "run $RUN_ID: $total rules for $RT_MECH across $RT_SHARDS shard(s), output in $RUN_DIR"

# Monitoring is a precondition for admission. Start it, and admit nothing
# until its first successful sample, or if it ever stops. The gate enforces
# the same rule on the management node: each sample is recorded there, and
# provision and start refuse a run whose monitor is missing, stale or stopped.
gate monitor --run-id "$RUN_ID" --stop-file "$STOP_FILE" --until-file "$DONE_FILE" --interval 30 \
  > "$RUN_DIR/monitor.log" 2>&1 &
MONITOR_PID=$!
waited=0
until grep -q '"problems": \[\]' "$RUN_DIR/monitor.log" 2>/dev/null; do
  if ! monitor_alive || [ -e "$STOP_FILE" ] || [ "$waited" -ge "$((RT_MONITOR_READY_SECONDS * 2))" ]; then
    echo "monitoring did not start cleanly; see $RUN_DIR/monitor.log" >&2
    exit 2
  fi
  sleep 0.5; waited=$((waited + 1))
done

# Round-robin, not contiguous. Rules that actually fail cluster alphabetically
# (audit-priv-* mostly pass on a cloud image, audit-cmd-* mostly fail), so a
# contiguous split hands one shard every slow full loop while another races
# through skips. A measured run split 4/3/3/17/9/15 before this changed.
awk -v n="$RT_SHARDS" -v d="$RUN_DIR" \
    '{printf "%s\n", $0 > sprintf("%s/shard-%02d", d, NR % n)}' "$RUN_DIR/all.txt"

pids=()
i=0
for f in "$RUN_DIR"/shard-[0-9]*; do
  [ -s "$f" ] || continue
  vmid=$((RT_BASE_ID + i)); i=$((i + 1))
  if ! monitor_alive; then
    echo "monitor stopped; no further shards started" >&2; final_rc=2; break
  fi
  # Recheck immediately before each clone and each start. A refusal stops
  # admitting more guests; shards already running finish, and the run is
  # reported incomplete.
  gate provision --run-id "$RUN_ID" --vmid "$vmid" --stop-file "$STOP_FILE" > "$RUN_DIR/provision-$vmid.json"
  case $? in
    0) ;;
    3) echo "admission refused for vmid $vmid; no further shards started" >&2; final_rc=2; break ;;
    *) echo "provisioning vmid $vmid failed or is uncertain" >&2; final_rc=2; break ;;
  esac
  # Cloning can take a while; the monitor may have died meanwhile. The gate
  # also refuses a stale or stopped monitor, but check here first.
  if ! monitor_alive; then
    echo "monitor stopped during cloning; vmid $vmid not started" >&2; final_rc=2; break
  fi
  gate start --run-id "$RUN_ID" --vmid "$vmid" --stop-file "$STOP_FILE" > "$RUN_DIR/start-$vmid.json"
  case $? in
    0) ;;
    3) echo "start refused for vmid $vmid; no further shards started" >&2; final_rc=2; break ;;
    *) echo "starting vmid $vmid failed or is uncertain" >&2; final_rc=2; break ;;
  esac
  ip="$(gate address --run-id "$RUN_ID" --vmid "$vmid")" || {
    echo "clone $vmid never reported an address" >&2; final_rc=2; break; }
  echo "shard $(basename "$f") -> vmid $vmid at $ip"
  python3 "$REPO/scripts/roundtrip.py" --host "$ip" --user "$RT_GUEST_USER" --rules-from "$f" \
    --out "$RUN_DIR/$(basename "$f").json" > "$RUN_DIR/$(basename "$f").log" 2>&1 &
  pids+=($!)
done

fail=0
for p in "${pids[@]:-}"; do [ -n "$p" ] && { wait "$p" || fail=1; }; done
[ "$fail" -eq 0 ] || echo "at least one shard did not complete cleanly" >&2

if ! monitor_alive; then
  echo "monitoring stopped during the run; see $RUN_DIR/monitor.log" >&2
  final_rc=2
fi
if [ "$final_rc" -ne 0 ]; then
  echo "run $RUN_ID is incomplete; its result is not gated" >&2
  exit 2
fi
reports=("$RUN_DIR"/shard-*.json)
if [ ! -e "${reports[0]}" ]; then
  echo "no shard produced a report" >&2; exit 2
fi
ln -sfn "run-$RUN_ID" "$RT_OUTDIR/latest"
python3 "$REPO/scripts/roundtrip_check.py" "${reports[@]}" --baseline "$BASELINE"
