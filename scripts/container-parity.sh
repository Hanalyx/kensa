#!/usr/bin/env bash
# Enterprise-Linux derivative parity check.
#
# Scans three version-matched EL 9 containers over the real SSH transport and
# diffs the per-rule verdicts. The baseline is RHEL (ubi9); Rocky and AlmaLinux
# are the derivatives under test.
#
# The diff is the signal, not the absolute pass rate. Container base images are
# minimal, so many /etc files a real host would have are simply absent, and the
# resulting FAIL rows are artifacts of the image rather than defects. Those
# artifacts appear identically in all three scans and cancel. What survives the
# diff is genuine derivative divergence: a package named differently, a path
# that moved, a capability probe that answers differently.
#
# This is the QUICK tier. It cannot exercise sysctl, kernel modules, mount
# options, SELinux booleans, audit rules, systemd unit state, the bootloader, or
# dconf, because none of those are namespaced or present in a container. Those
# need a live host. See CLAUDE.md, "Testing tiers".
#
# Usage:
#   scripts/container-parity.sh                      # full corpus, EL 9
#   scripts/container-parity.sh rules/network        # a subtree, for a fast loop
#   EL=8 scripts/container-parity.sh rules/logging   # a different EL release
#
# EL selects the Enterprise Linux major release under test (8, 9, or 10). The
# baseline and both derivatives are always the same release, so a divergence is
# attributable to the distribution rather than to a version-gated rule.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${1:-$REPO/rules}"
EL="${EL:-9}"
WORK="$(mktemp -d)"
trap 'cleanup' EXIT

case "$EL" in
  8)  BASE_IMG="redhat/ubi8:latest";  ROCKY="rockylinux/rockylinux:8"; ALMA="almalinux:8"  ;;
  9)  BASE_IMG="redhat/ubi9:latest";  ROCKY="rockylinux/rockylinux:9"; ALMA="almalinux:9"  ;;
  10) BASE_IMG="redhat/ubi10:latest"; ROCKY="rockylinux/rockylinux:10"; ALMA="almalinux:10" ;;
  *)  echo "EL must be 8, 9, or 10 (got '$EL')"; exit 2 ;;
esac

# distro:image:port
TARGETS=(
  "rhel:$BASE_IMG:$((2200+EL*10+1))"
  "rocky:$ROCKY:$((2200+EL*10+2))"
  "almalinux:$ALMA:$((2200+EL*10+3))"
)

cleanup() {
  for t in "${TARGETS[@]}"; do
    docker rm -f "kensa-parity-el${EL}-${t%%:*}" >/dev/null 2>&1
  done
  rm -rf "$WORK"
}

say() { printf '\n== %s\n' "$*"; }

say "building static binary"
CGO_ENABLED=0 go build -tags netgo -o "$WORK/kensa" ./cmd/kensa || exit 1

say "generating ephemeral key"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/id" -C kensa-parity

cat >"$WORK/Dockerfile" <<'EOF'
ARG BASE
FROM ${BASE}
RUN dnf install -y openssh-server sudo >/dev/null 2>&1 && dnf clean all >/dev/null 2>&1
RUN ssh-keygen -A && mkdir -p /root/.ssh && chmod 700 /root/.ssh
COPY id.pub /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
EOF
cp "$WORK/id.pub" "$WORK/id.pub.ctx" && mv "$WORK/id.pub.ctx" "$WORK/id.pub"

for t in "${TARGETS[@]}"; do
  distro="${t%%:*}"; rest="${t#*:}"; port="${rest##*:}"; image="${rest%:*}"
  say "starting $distro ($image) on port $port"
  docker build -q --build-arg BASE="$image" -t "kensa-parity-el${EL}-$distro" \
    -f "$WORK/Dockerfile" "$WORK" >/dev/null || { echo "build failed: $distro"; exit 1; }
  docker rm -f "kensa-parity-el${EL}-$distro" >/dev/null 2>&1
  docker run -d --name "kensa-parity-el${EL}-$distro" -p "127.0.0.1:$port:22" \
    "kensa-parity-el${EL}-$distro" >/dev/null || { echo "run failed: $distro"; exit 1; }
done

say "waiting for sshd"
for i in $(seq 1 30); do
  ready=1
  for t in "${TARGETS[@]}"; do
    port="${t##*:}"
    ssh -q -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -i "$WORK/id" -p "$port" \
        root@127.0.0.1 true 2>/dev/null || ready=0
  done
  [ "$ready" = 1 ] && break
  sleep 1
done
[ "$ready" = 1 ] || { echo "sshd did not come up"; exit 1; }

for t in "${TARGETS[@]}"; do
  distro="${t%%:*}"; port="${t##*:}"
  say "scanning $distro"
  "$WORK/kensa" check -H 127.0.0.1 -P "$port" -u root -k "$WORK/id" \
    --no-strict-host-keys --rules-dir "$RULES" \
    -o "json:$WORK/$distro.json" >/dev/null 2>"$WORK/$distro.err" \
    || echo "  (scan exited non-zero; findings are expected to do that)"
  printf '  outcomes: '
  python3 - "$WORK/$distro.json" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
except Exception as e:
    print("unreadable:",e); raise SystemExit
o=d.get("outcomes") or d.get("Outcomes") or []
print(len(o))
PY
done

say "derivative parity diff (baseline = rhel/ubi$EL)"
python3 - "$WORK" <<'PY'
import json,os,sys
work=sys.argv[1]
def load(name):
    p=os.path.join(work,name+".json")
    if not os.path.exists(p): return None
    d=json.load(open(p))
    o=d.get("outcomes") or d.get("Outcomes") or []
    out={}
    for r in o:
        rid=r.get("rule_id") or r.get("RuleID") or r.get("id")
        st=r.get("status") or r.get("Status")
        if rid: out[rid]=st
    return out

base=load("rhel")
if not base:
    print("  no baseline scan; cannot diff"); raise SystemExit(1)
print(f"  baseline rules: {len(base)}")
exit_bad=0
for d in ("rocky","almalinux"):
    cur=load(d)
    if cur is None:
        print(f"  {d}: MISSING"); exit_bad=1; continue
    only_base=sorted(set(base)-set(cur))
    only_cur=sorted(set(cur)-set(base))
    diff=sorted(k for k in set(base)&set(cur) if base[k]!=cur[k])
    print(f"\n  {d}: {len(diff)} verdict divergence(s), "
          f"{len(only_base)} missing, {len(only_cur)} extra")
    for k in diff[:40]:
        print(f"    {k}: rhel={base[k]}  {d}={cur[k]}")
    if len(diff)>40: print(f"    ... {len(diff)-40} more")
    for k in only_base[:20]: print(f"    ABSENT on {d}: {k}")
    if diff or only_base or only_cur: exit_bad=1
print("\n  PARITY OK" if not exit_bad else "\n  DIVERGENCE FOUND: triage above")
raise SystemExit(exit_bad)
PY
rc=$?
say "done (exit $rc)"
exit $rc
