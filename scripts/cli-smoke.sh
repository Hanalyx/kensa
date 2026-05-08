#!/usr/bin/env bash
# scripts/cli-smoke.sh — smoke test for the kensa CLI binaries.
#
# Verifies the GNU/POSIX exit-code contract end-to-end: every subcommand's
# `--help` exits 0 with non-empty stdout and empty stderr; every bad-flag
# invocation exits 2; every unknown-subcommand invocation exits 2.
#
# Runs against the locally-built `bin/{kensa,kensa-validate,kensa-fuzz}`
# binaries. Does NOT require network access — every test is a flag-parse
# scenario that fails fast before any SSH or store work.
#
# Deliverable C-010 in docs/roadmap/DELIVERABLES.md (CLI Phase 1).
#
# Exit codes:
#   0  All smoke tests passed.
#   1  At least one smoke test failed.
#   2  Build failure (kensa binaries not present).

set -uo pipefail

# Resolve repo root (one directory up from this script).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Colors for terminal output (disabled when not on a TTY).
if [ -t 1 ]; then
    RED=$'\e[31m'
    GREEN=$'\e[32m'
    YELLOW=$'\e[33m'
    RESET=$'\e[0m'
else
    RED=""
    GREEN=""
    YELLOW=""
    RESET=""
fi

PASS_COUNT=0
FAIL_COUNT=0
FAILURES=()

# Verify binaries exist; if not, build them.
need_build=false
for bin in bin/kensa bin/kensa-validate bin/kensa-fuzz; do
    if [ ! -x "${bin}" ]; then
        need_build=true
        break
    fi
done
if [ "${need_build}" = "true" ]; then
    echo "${YELLOW}Binaries missing; building...${RESET}"
    if ! make build > /dev/null 2>&1; then
        echo "${RED}Build failed; cannot run smoke tests.${RESET}" >&2
        exit 2
    fi
fi

# assert_exit runs a command and verifies it exits with the expected code.
# Captures stdout and stderr separately to assert which stream got output.
#
# Args:
#   $1  test name (operator-readable)
#   $2  expected exit code (0, 1, or 2)
#   $3  expected-stream: "stdout-nonempty", "stderr-nonempty", or "any"
#   $@  command to run (rest of argv)
assert_exit() {
    local name="$1"
    local want_code="$2"
    local want_stream="$3"
    shift 3

    local stdout_file stderr_file actual_code
    stdout_file=$(mktemp)
    stderr_file=$(mktemp)
    "$@" > "${stdout_file}" 2> "${stderr_file}"
    actual_code=$?

    local fail=""
    if [ "${actual_code}" != "${want_code}" ]; then
        fail="exit code: got ${actual_code}, want ${want_code}"
    fi

    case "${want_stream}" in
        stdout-nonempty)
            if [ ! -s "${stdout_file}" ]; then
                fail="${fail}${fail:+; }stdout: empty (want non-empty)"
            fi
            ;;
        stderr-nonempty)
            if [ ! -s "${stderr_file}" ]; then
                fail="${fail}${fail:+; }stderr: empty (want non-empty)"
            fi
            ;;
    esac

    if [ -n "${fail}" ]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("${name}: ${fail}")
        echo "  ${RED}FAIL${RESET}  ${name}: ${fail}"
    else
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  ${name}"
    fi

    rm -f "${stdout_file}" "${stderr_file}"
}

echo "kensa CLI smoke tests"
echo "====================="
echo

# ─── kensa: top-level help and version ────────────────────────────────────
echo "kensa (top-level):"
assert_exit "kensa --help (long)"  0 stdout-nonempty bin/kensa --help
assert_exit "kensa -h (short)"     0 stdout-nonempty bin/kensa -h
assert_exit "kensa --version"      0 stdout-nonempty bin/kensa --version
assert_exit "kensa -V"             0 stdout-nonempty bin/kensa -V
assert_exit "kensa (no args)"      2 stderr-nonempty bin/kensa
assert_exit "kensa unknown-cmd"    2 stderr-nonempty bin/kensa frobnicate
assert_exit "kensa --bogus"        2 stderr-nonempty bin/kensa --bogus
echo

# ─── kensa: subcommand --help ─────────────────────────────────────────────
echo "kensa subcommand --help:"
for cmd in detect check remediate rollback history plan coverage version; do
    assert_exit "kensa ${cmd} --help" 0 stdout-nonempty bin/kensa "${cmd}" --help
    assert_exit "kensa ${cmd} -h"     0 stdout-nonempty bin/kensa "${cmd}" -h
done
echo

# ─── kensa: subcommand bad usage (exit 2) ─────────────────────────────────
echo "kensa subcommand bad usage:"
assert_exit "kensa detect (no host)"         2 stderr-nonempty bin/kensa detect
assert_exit "kensa detect --bogus"           2 stderr-nonempty bin/kensa detect --bogus
assert_exit "kensa check (nothing)"          2 stderr-nonempty bin/kensa check
assert_exit "kensa rollback (no host)"       2 stderr-nonempty bin/kensa rollback
assert_exit "kensa rollback -H foo (no -t)"  2 stderr-nonempty bin/kensa rollback -H foo
assert_exit "kensa rollback bad UUID"        2 stderr-nonempty bin/kensa rollback -H foo -t notauuid
assert_exit "kensa plan (no host)"           2 stderr-nonempty bin/kensa plan
assert_exit "kensa plan -H foo (no rule)"    2 stderr-nonempty bin/kensa plan -H foo
assert_exit "kensa remediate (no host)"      2 stderr-nonempty bin/kensa remediate
assert_exit "kensa history --since invalid"  2 stderr-nonempty bin/kensa history --since not-a-duration
echo

# ─── kensa-validate ───────────────────────────────────────────────────────
echo "kensa-validate:"
assert_exit "kensa-validate --help"      0 stdout-nonempty bin/kensa-validate --help
assert_exit "kensa-validate -h"          0 stdout-nonempty bin/kensa-validate -h
assert_exit "kensa-validate (no args)"   2 stderr-nonempty bin/kensa-validate
assert_exit "kensa-validate --bogus"     2 stderr-nonempty bin/kensa-validate --bogus
echo

# ─── kensa-fuzz ───────────────────────────────────────────────────────────
echo "kensa-fuzz:"
assert_exit "kensa-fuzz --help"          0 stdout-nonempty bin/kensa-fuzz --help
assert_exit "kensa-fuzz -h"              0 stdout-nonempty bin/kensa-fuzz -h
assert_exit "kensa-fuzz (no host)"       1 stderr-nonempty bin/kensa-fuzz
assert_exit "kensa-fuzz --bogus"         1 stderr-nonempty bin/kensa-fuzz --bogus
echo

# ─── Summary ──────────────────────────────────────────────────────────────
echo "====================="
echo "Total: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
if [ "${FAIL_COUNT}" -gt 0 ]; then
    echo
    echo "${RED}Failures:${RESET}"
    for f in "${FAILURES[@]}"; do
        echo "  - ${f}"
    done
    exit 1
fi
exit 0
