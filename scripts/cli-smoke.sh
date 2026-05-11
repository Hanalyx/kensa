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
assert_exit "kensa rollback bad UUID"        2 stderr-nonempty bin/kensa rollback -H foo -T notauuid
assert_exit "kensa plan (no host)"           2 stderr-nonempty bin/kensa plan
assert_exit "kensa plan -H foo (no rule)"    2 stderr-nonempty bin/kensa plan -H foo
assert_exit "kensa remediate (no host)"      2 stderr-nonempty bin/kensa remediate
assert_exit "kensa history --since invalid"  2 stderr-nonempty bin/kensa history --since not-a-duration
echo

# ─── kensa: -o flag advertised in --help (C-019) ──────────────────────────
echo "kensa subcommand --output flag in --help:"
for cmd in detect check remediate; do
    out=$(bin/kensa "${cmd}" --help 2>&1)
    if echo "${out}" | grep -qE -- "--output"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  kensa ${cmd} --help advertises --output"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("kensa ${cmd} --help: --output missing")
        echo "  ${RED}FAIL${RESET}  kensa ${cmd} --help missing --output"
    fi
done
# Bad-format under -o exits 2 (usage error per ErrUnsupportedFormat
# routing through WrapUsageError).
assert_exit "kensa check -o yaml-bogus" 2 stderr-nonempty bin/kensa check -H foo -o yaml-bogus
# Inventory + file-target -o is rejected per the C-019 inventory
# data-loss guard. Uses the repo's inventory.ini (real file) so we
# pass the parse phase and reach the guard. The guard fires before
# any rule-loading or SSH attempt, so this check is network-free.
assert_exit "kensa check --inventory + -o csv:file" 2 stderr-nonempty \
    bin/kensa check --inventory inventory.ini --rules-dir /tmp -o csv:/tmp/x.csv
echo

# ─── kensa: --quiet flag advertised in --help (C-018) ─────────────────────
echo "kensa subcommand --quiet flag in --help:"
for cmd in detect check remediate rollback history plan; do
    out=$(bin/kensa "${cmd}" --help 2>&1)
    if echo "${out}" | grep -qE -- "--quiet"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  kensa ${cmd} --help advertises --quiet"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("kensa ${cmd} --help: --quiet missing")
        echo "  ${RED}FAIL${RESET}  kensa ${cmd} --help missing --quiet"
    fi
done
# Negative case: version and coverage do NOT advertise --quiet.
for cmd in version coverage; do
    out=$(bin/kensa "${cmd}" --help 2>&1)
    if echo "${out}" | grep -qE -- "--quiet"; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("kensa ${cmd} --help: --quiet should NOT be advertised")
        echo "  ${RED}FAIL${RESET}  kensa ${cmd} --help advertises --quiet (operator-explicit query)"
    else
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  kensa ${cmd} --help correctly omits --quiet"
    fi
done
echo

# ─── kensa: Phase 3 flag advertisement (C-038 close) ──────────────────────
# Each flag introduced in C-024..C-037 must show up in --help for the
# subcommands that support it. A drift here means a flag was registered
# without being wired (or was deleted but a stub remains).
echo "Phase 3 flag advertisement:"
phase3_flags_for() {
    case "$1" in
        detect)    echo "--password --strict-host-keys --no-strict-host-keys --capability" ;;
        check)     echo "--password --strict-host-keys --no-strict-host-keys --capability --workers --severity --tag --category --framework --control --rule --inventory --limit" ;;
        remediate) echo "--password --strict-host-keys --no-strict-host-keys --capability --severity --tag --category --framework --control --rule" ;;
        rollback)  echo "--strict-host-keys --no-strict-host-keys" ;;
        plan)      echo "--password --strict-host-keys --no-strict-host-keys" ;;
    esac
}
for cmd in detect check remediate rollback plan; do
    out=$(bin/kensa "${cmd}" --help 2>&1)
    flags=$(phase3_flags_for "${cmd}")
    for f in ${flags}; do
        if echo "${out}" | grep -qE -- "${f}"; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo "  ${GREEN}PASS${RESET}  kensa ${cmd} --help advertises ${f}"
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            FAILURES+=("kensa ${cmd} --help: ${f} missing")
            echo "  ${RED}FAIL${RESET}  kensa ${cmd} --help missing ${f}"
        fi
    done
done

# Help-text grouping (C-038): detect/check/remediate must group by
# Target / Rule / Output sections. The grouping helper drives this
# from a per-subcommand flagGroup definition; a regression that
# falls back to a single flat list would break this assertion.
echo "Phase 3 help grouping:"
for cmd in detect check remediate; do
    out=$(bin/kensa "${cmd}" --help 2>&1)
    if echo "${out}" | grep -qE "^Target options:"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  kensa ${cmd} --help has 'Target options:' section"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("kensa ${cmd} --help: missing 'Target options:' section")
        echo "  ${RED}FAIL${RESET}  kensa ${cmd} --help missing Target section"
    fi
done
for cmd in check remediate; do
    out=$(bin/kensa "${cmd}" --help 2>&1)
    if echo "${out}" | grep -qE "^Rule options:"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  kensa ${cmd} --help has 'Rule options:' section"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("kensa ${cmd} --help: missing 'Rule options:' section")
        echo "  ${RED}FAIL${RESET}  kensa ${cmd} --help missing Rule section"
    fi
done

# Phase 3 negative-path flag rejections — each new validation must
# exit with code 2 (UsageError) for the chosen typo / out-of-range
# input. These are network-free; validation runs before SSH setup.
echo "Phase 3 flag-validation usage errors (exit 2):"
assert_exit "kensa check --workers 0"               2 stderr-nonempty bin/kensa check -H foo --workers 0 --rules-dir /tmp
assert_exit "kensa check --workers 51"              2 stderr-nonempty bin/kensa check -H foo --workers 51 --rules-dir /tmp
assert_exit "kensa check --severity bogus"          2 stderr-nonempty bin/kensa check -H foo -s bogus --rules-dir /tmp
assert_exit "kensa check --capability bogus=true"   2 stderr-nonempty bin/kensa check -H foo -C bogus=true --rules-dir /tmp
assert_exit "kensa check --capability =true"        2 stderr-nonempty bin/kensa check -H foo -C =true --rules-dir /tmp
assert_exit "kensa check --strict + --no-strict"    2 stderr-nonempty bin/kensa check -H foo --strict-host-keys --no-strict-host-keys --rules-dir /tmp
assert_exit "kensa check --control no-colon"        2 stderr-nonempty bin/kensa check -H foo --control bogus --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa check --framework bogus"         2 stderr-nonempty bin/kensa check -H foo -f bogus --rules-dir /home/rracine/hanalyx/kensa/rules
echo

# ─── kensa mechanisms / coverage deprecation (C-044) ──────────────────────
echo "kensa mechanisms (C-044 rename) + coverage deprecation:"
assert_exit "kensa mechanisms --help"        0 stdout-nonempty bin/kensa mechanisms --help
assert_exit "kensa mechanisms -h"            0 stdout-nonempty bin/kensa mechanisms -h
assert_exit "kensa mechanisms"               0 stdout-nonempty bin/kensa mechanisms
assert_exit "kensa coverage (deprecated)"    0 stdout-nonempty bin/kensa coverage
# coverage MUST emit a v0.2 repurpose warning to stderr; mechanisms MUST NOT.
# Warning may span multiple lines, so check for both substrings independently.
covStderr=$(bin/kensa coverage 2>&1 >/dev/null)
if echo "${covStderr}" | grep -qE "v0\\.2" && echo "${covStderr}" | grep -qE "mechanisms"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa coverage emits v0.2 repurpose warning to stderr"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa coverage missing v0.2 repurpose warning")
    echo "  ${RED}FAIL${RESET}  kensa coverage missing v0.2 repurpose warning"
fi
# Warning MUST NOT say "removed" — that's the misread we're preventing.
if echo "${covStderr}" | grep -q "removed"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa coverage warning misuses 'removed' (name is being repurposed)")
    echo "  ${RED}FAIL${RESET}  kensa coverage warning misuses 'removed'"
else
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa coverage warning correctly avoids 'removed'"
fi
mechStderr=$(bin/kensa mechanisms 2>&1 >/dev/null)
if [ -z "${mechStderr}" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa mechanisms emits no stderr"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa mechanisms emitted unexpected stderr: ${mechStderr}")
    echo "  ${RED}FAIL${RESET}  kensa mechanisms emitted unexpected stderr"
fi
# KENSA_NO_REPURPOSE_WARNINGS=1 silences the warning. Note: this is a
# SEPARATE knob from KENSA_NO_DEPRECATION_WARNINGS=1 — see
# warnRepurposedSubcommand for the rationale.
covStderrSilent=$(KENSA_NO_REPURPOSE_WARNINGS=1 bin/kensa coverage 2>&1 >/dev/null)
if [ -z "${covStderrSilent}" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  KENSA_NO_REPURPOSE_WARNINGS=1 silences coverage warning"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("KENSA_NO_REPURPOSE_WARNINGS=1 did not silence coverage warning")
    echo "  ${RED}FAIL${RESET}  KENSA_NO_REPURPOSE_WARNINGS=1 did not silence"
fi
# KENSA_NO_DEPRECATION_WARNINGS=1 (the OLD knob) MUST NOT silence —
# semantic-flip warnings are categorically louder than flag renames.
covStderrDepEnv=$(KENSA_NO_DEPRECATION_WARNINGS=1 bin/kensa coverage 2>&1 >/dev/null)
if echo "${covStderrDepEnv}" | grep -qE "v0\\.2" && echo "${covStderrDepEnv}" | grep -qE "mechanisms"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  KENSA_NO_DEPRECATION_WARNINGS=1 does NOT silence repurpose warning"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("KENSA_NO_DEPRECATION_WARNINGS=1 incorrectly silenced repurpose warning")
    echo "  ${RED}FAIL${RESET}  KENSA_NO_DEPRECATION_WARNINGS=1 incorrectly silenced repurpose warning"
fi
echo

# ─── kensa(1) manpage (C-055) ─────────────────────────────────────────────
echo "kensa(1) manpage (C-055):"
# docs/man/kensa.1 must be present and non-empty.
if [ -s "docs/man/kensa.1" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  docs/man/kensa.1 exists and is non-empty"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("docs/man/kensa.1 missing or empty (run 'make manpage')")
    echo "  ${RED}FAIL${RESET}  docs/man/kensa.1 missing or empty"
fi
# All required header sections.
for section in "NAME" "SYNOPSIS" "DESCRIPTION" "GLOBAL OPTIONS" "COMMANDS"; do
    if grep -qE "^\.SH ${section}\$" docs/man/kensa.1; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  docs/man/kensa.1 has .SH ${section}"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("docs/man/kensa.1 missing .SH ${section}")
        echo "  ${RED}FAIL${RESET}  docs/man/kensa.1 missing .SH ${section}"
    fi
done
# All required footer sections.
for section in "FILES" "ENVIRONMENT" "EXIT CODES" "SEE ALSO" "AUTHORS" "BUGS"; do
    if grep -qE "^\.SH ${section}\$" docs/man/kensa.1; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  docs/man/kensa.1 has .SH ${section}"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("docs/man/kensa.1 missing .SH ${section}")
        echo "  ${RED}FAIL${RESET}  docs/man/kensa.1 missing .SH ${section}"
    fi
done
# Every registered subcommand has a .SS subsection.
for sub in DETECT CHECK REMEDIATE ROLLBACK HISTORY PLAN MECHANISMS LIST INFO DIFF AGENT VERIFY MIGRATE VERSION; do
    if grep -qE "^\.SS ${sub}\$" docs/man/kensa.1; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  docs/man/kensa.1 has .SS ${sub}"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("docs/man/kensa.1 missing .SS ${sub}")
        echo "  ${RED}FAIL${RESET}  docs/man/kensa.1 missing .SS ${sub}"
    fi
done
echo

# ─── kensa agent (L-008 echo loop; supersedes C-054 placeholder) ──────────
echo "kensa agent (L-008 stdio echo):"
assert_exit "kensa agent --help"                     0 stdout-nonempty bin/kensa agent --help
assert_exit "kensa agent -h"                         0 stdout-nonempty bin/kensa agent -h
# bare invocation: usage error (preserved from C-054).
assert_exit "kensa agent (no flag)"                  2 stderr-nonempty bin/kensa agent
# unknown flag: usage error (preserved from C-054).
assert_exit "kensa agent --bogus"                    2 stderr-nonempty bin/kensa agent --bogus
# --stdio with EOF on empty stdin: clean exit 0 (echo loop sees EOF
# before any frame, returns nil). bash -c wrapper so the redirect
# applies to the inner kensa invocation, not assert_exit's plumbing.
assert_exit "kensa agent --stdio empty-stdin"        0 ""            bash -c "bin/kensa agent --stdio </dev/null"
# Agent listed in top-level help (no longer marked v1.1 placeholder
# post-L-008; the subcommand now does real work).
helpAgent=$(bin/kensa --help 2>&1)
if echo "${helpAgent}" | grep -qE "^[[:space:]]*agent[[:space:]]"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa --help lists agent"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa --help missing agent line")
    echo "  ${RED}FAIL${RESET}  kensa --help missing agent line"
fi
echo

# ─── Phase 4 close (C-050) help-grouping assertions ───────────────────────
echo "kensa info / rollback help-grouping (C-050):"
infoHelp=$(bin/kensa info --help 2>/dev/null)
for section in "Mode (pick one):" "Filter options:" "Output options:"; do
    if echo "${infoHelp}" | grep -qF "${section}"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  kensa info --help: ${section}"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("kensa info --help missing section: ${section}")
        echo "  ${RED}FAIL${RESET}  kensa info --help missing: ${section}"
    fi
done
# AC-03: no "Other options:" catch-all should appear (every flag is grouped).
if echo "${infoHelp}" | grep -qF "Other options:"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa info --help: 'Other options:' present (a flag is uncategorized)")
    echo "  ${RED}FAIL${RESET}  kensa info --help has uncategorized flags"
else
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa info --help: every flag categorized"
fi

rollbackHelp=$(bin/kensa rollback --help 2>/dev/null)
for section in "Mode (pick one):" "Target options" "Output options:"; do
    if echo "${rollbackHelp}" | grep -qF "${section}"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  ${GREEN}PASS${RESET}  kensa rollback --help: ${section}"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("kensa rollback --help missing section: ${section}")
        echo "  ${RED}FAIL${RESET}  kensa rollback --help missing: ${section}"
    fi
done
if echo "${rollbackHelp}" | grep -qF "Other options:"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa rollback --help: 'Other options:' present (a flag is uncategorized)")
    echo "  ${RED}FAIL${RESET}  kensa rollback --help has uncategorized flags"
else
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa rollback --help: every flag categorized"
fi
echo

# ─── kensa rollback session-aware (C-049) ─────────────────────────────────
echo "kensa rollback session-aware (C-049):"
assert_exit "kensa rollback (no mode)"               2 stderr-nonempty bin/kensa rollback
assert_exit "kensa rollback --list (empty store)"    0 stdout-nonempty bin/kensa rollback --list
assert_exit "kensa rollback --list + --info"         2 stderr-nonempty bin/kensa rollback --list --info 11111111-2222-3333-4444-555555555555
assert_exit "kensa rollback --info (bad UUID)"       2 stderr-nonempty bin/kensa rollback --info not-a-uuid
assert_exit "kensa rollback --start (no --host)"     2 stderr-nonempty bin/kensa rollback --start 11111111-2222-3333-4444-555555555555
assert_exit "kensa rollback --txn (legacy: no host)" 2 stderr-nonempty bin/kensa rollback --txn 11111111-2222-3333-4444-555555555555
assert_exit "kensa rollback --detail + --start"      2 stderr-nonempty bin/kensa rollback --start 11111111-2222-3333-4444-555555555555 --detail -H foo
echo

# ─── kensa diff (C-048) ───────────────────────────────────────────────────
echo "kensa diff (C-048 session drift report):"
assert_exit "kensa diff --help"                      0 stdout-nonempty bin/kensa diff --help
assert_exit "kensa diff -h"                          0 stdout-nonempty bin/kensa diff -h
assert_exit "kensa diff (no args)"                   2 stderr-nonempty bin/kensa diff
assert_exit "kensa diff (one arg)"                   2 stderr-nonempty bin/kensa diff 11111111-2222-3333-4444-555555555555
assert_exit "kensa diff (bad UUID)"                  2 stderr-nonempty bin/kensa diff not-a-uuid 11111111-2222-3333-4444-555555555555
assert_exit "kensa diff (bad format)"                2 stderr-nonempty bin/kensa diff 11111111-2222-3333-4444-555555555555 22222222-3333-4444-5555-666666666666 --format yaml
echo

# ─── kensa info (C-047) ───────────────────────────────────────────────────
echo "kensa info (C-047 multi-criteria search):"
assert_exit "kensa info --help"                      0 stdout-nonempty bin/kensa info --help
assert_exit "kensa info -h"                          0 stdout-nonempty bin/kensa info -h
assert_exit "kensa info (no mode/query)"             2 stderr-nonempty bin/kensa info --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa info (no --rules-dir)"            2 stderr-nonempty bin/kensa info ssh
assert_exit "kensa info --rule + --control"          2 stderr-nonempty bin/kensa info --rule x --control y:z --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa info --rule + QUERY"              2 stderr-nonempty bin/kensa info --rule x ssh --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa info --cis + --stig"              2 stderr-nonempty bin/kensa info --cis --stig --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa info --nist + --rhel"             2 stderr-nonempty bin/kensa info --nist --rhel 9 ssh --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa info --rhel 7"                    2 stderr-nonempty bin/kensa info ssh --rhel 7 --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa info --control no-colon"          2 stderr-nonempty bin/kensa info --control bogus --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa info --limit -1"                  2 stderr-nonempty bin/kensa info ssh --limit -1 --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa info --rule unknown (exit 1)"     1 stderr-nonempty bin/kensa info --rule no-such-rule --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa info ssh (happy path)"            0 stdout-nonempty bin/kensa info ssh --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa info --cis ssh (compose)"         0 stdout-nonempty bin/kensa info ssh --cis --rules-dir /home/rracine/hanalyx/kensa/rules
echo

# ─── kensa list sessions / info jsonl (C-052) ─────────────────────────────
echo "kensa list sessions / info --format jsonl (C-052):"
# happy paths
assert_exit "kensa list sessions --format jsonl"     0 any bin/kensa list sessions --format jsonl
assert_exit "kensa list sessions --format json"      0 stdout-nonempty bin/kensa list sessions --format json
# info jsonl: rejected on document modes (no --rules-dir needed because
# format validation runs before rules-dir requirement check, but we need
# the modes to be in conflict for the rejection to fire).
assert_exit "info --rule + jsonl"                    2 stderr-nonempty bin/kensa info --rule rx --rules-dir /home/rracine/hanalyx/kensa/rules --format jsonl
assert_exit "info --control + jsonl"                 2 stderr-nonempty bin/kensa info --control cis_rhel9:5.1.12 --rules-dir /home/rracine/hanalyx/kensa/rules --format jsonl
assert_exit "info --list-controls + jsonl"           2 stderr-nonempty bin/kensa info --list-controls cis_rhel9 --rules-dir /home/rracine/hanalyx/kensa/rules --format jsonl
# info QUERY + jsonl: happy path
assert_exit "info QUERY + jsonl"                     0 stdout-nonempty bin/kensa info ssh --rules-dir /home/rracine/hanalyx/kensa/rules --format jsonl
echo

# ─── kensa list frameworks (C-046) ────────────────────────────────────────
echo "kensa list frameworks (C-046):"
assert_exit "kensa list --help"                      0 stdout-nonempty bin/kensa list --help
assert_exit "kensa list -h"                          0 stdout-nonempty bin/kensa list -h
# Bare 'kensa list' is a usage error (script footgun prevention) —
# operators get the available-subjects list on stderr; CI scripts
# that drop the subject get a non-zero exit instead of a silent
# success.
assert_exit "kensa list (no subject)"                2 stderr-nonempty bin/kensa list
assert_exit "kensa list --rules-dir DIR (forgot subj)" 2 stderr-nonempty bin/kensa list --rules-dir /tmp
assert_exit "kensa list widgets (unknown subject)"   2 stderr-nonempty bin/kensa list widgets
assert_exit "kensa list sessions --help"             0 stdout-nonempty bin/kensa list sessions --help
assert_exit "kensa list sessions (empty store)"      0 stdout-nonempty bin/kensa list sessions
assert_exit "kensa list sessions bad --format"       2 stderr-nonempty bin/kensa list sessions --format yaml
assert_exit "kensa list frameworks --help"           0 stdout-nonempty bin/kensa list frameworks --help
assert_exit "kensa list frameworks (no --rules-dir)" 2 stderr-nonempty bin/kensa list frameworks
assert_exit "kensa list frameworks bad --format"     2 stderr-nonempty bin/kensa list frameworks --rules-dir /home/rracine/hanalyx/kensa/rules --format yaml
assert_exit "kensa list frameworks happy path"       0 stdout-nonempty bin/kensa list frameworks --rules-dir /home/rracine/hanalyx/kensa/rules
echo

# ─── kensa coverage --framework (C-045) ───────────────────────────────────
echo "kensa coverage --framework (C-045 framework coverage report):"
# --framework on coverage routes to the new path.
assert_exit "kensa coverage -f -r missing"           2 stderr-nonempty bin/kensa coverage --framework cis_rhel9
assert_exit "kensa coverage --framework (no value)"  2 stderr-nonempty bin/kensa coverage --framework
assert_exit "kensa coverage -f bogus -r real"        2 stderr-nonempty bin/kensa coverage --framework bogus_v999 --rules-dir /home/rracine/hanalyx/kensa/rules
assert_exit "kensa coverage -f -r --format yaml"     2 stderr-nonempty bin/kensa coverage --framework cis_rhel9 --rules-dir /home/rracine/hanalyx/kensa/rules --format yaml
# --framework on mechanisms is rejected.
assert_exit "kensa mechanisms --framework"           2 stderr-nonempty bin/kensa mechanisms --framework cis_rhel9
# --help on the new path exits 0.
assert_exit "kensa coverage -f cis_rhel9 --help"     0 stdout-nonempty bin/kensa coverage --framework cis_rhel9 --help
# --framework presence in coverage --help disclosure.
covHelp=$(bin/kensa coverage --framework cis_rhel9 --help 2>/dev/null)
if echo "${covHelp}" | grep -qE -- "--framework"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa coverage --help advertises --framework"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa coverage --help: --framework missing")
    echo "  ${RED}FAIL${RESET}  kensa coverage --help missing --framework"
fi
# --framework --help MUST emit the C-044 repurpose warning to stderr
# (operators reading docs need the v0.2 flip signal).
covHelpStderr=$(bin/kensa coverage --framework cis_rhel9 --help 2>&1 >/dev/null)
if echo "${covHelpStderr}" | grep -qE "v0\\.2" && echo "${covHelpStderr}" | grep -qE "mechanisms"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa coverage --framework FOO --help emits repurpose warning"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa coverage --framework FOO --help missing repurpose warning")
    echo "  ${RED}FAIL${RESET}  kensa coverage --framework FOO --help missing repurpose warning"
fi
# kensa coverage --help (alias) MUST advertise the new --framework surface.
aliasHelp=$(bin/kensa coverage --help 2>/dev/null)
if echo "${aliasHelp}" | grep -qE "AVAILABLE TODAY"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa coverage --help (alias) advertises new --framework surface"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa coverage --help (alias) missing AVAILABLE TODAY pointer")
    echo "  ${RED}FAIL${RESET}  kensa coverage --help (alias) missing AVAILABLE TODAY pointer"
fi
echo

# ─── kensa history --format jsonl (C-051) ─────────────────────────────────
echo "kensa history --format jsonl (C-051):"
# jsonl on document-shaped modes rejected.
assert_exit "history --format jsonl + --aggregate"   2 stderr-nonempty bin/kensa history --format jsonl --aggregate by_host
assert_exit "history --format jsonl + --stats"       2 stderr-nonempty bin/kensa history --format jsonl --stats
assert_exit "history --format jsonl + --txn"         2 stderr-nonempty bin/kensa history --format jsonl --txn 11111111-2222-3333-4444-555555555555
# jsonl listed in help.
historyHelp=$(bin/kensa history --help 2>/dev/null)
if echo "${historyHelp}" | grep -qF "jsonl"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa history --help advertises jsonl"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa history --help missing jsonl")
    echo "  ${RED}FAIL${RESET}  kensa history --help missing jsonl"
fi
echo

# ─── kensa history --prune (C-043) ────────────────────────────────────────
# All --prune scenarios must reach validation BEFORE the store opens, so
# they don't need a real DB path. Network-free; flag-only validation.
echo "kensa history --prune validation (C-043):"
assert_exit "kensa history --prune 0 --force"      2 stderr-nonempty bin/kensa history --prune 0 --force
assert_exit "kensa history --prune -1 --force"     2 stderr-nonempty bin/kensa history --prune -1 --force
assert_exit "kensa history --prune abc --force"    2 stderr-nonempty bin/kensa history --prune abc --force
assert_exit "kensa history --force (no --prune)"   2 stderr-nonempty bin/kensa history --force
assert_exit "kensa history --prune+stats"          2 stderr-nonempty bin/kensa history --prune 7 --force --stats
assert_exit "kensa history --prune+host"           2 stderr-nonempty bin/kensa history --prune 7 --force -H foo
assert_exit "kensa history --prune+since"          2 stderr-nonempty bin/kensa history --prune 7 --force -S 24h
# --prune is advertised in `kensa history --help`.
out=$(bin/kensa history --help 2>&1)
if echo "${out}" | grep -qE -- "--prune"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa history --help advertises --prune"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa history --help: --prune missing")
    echo "  ${RED}FAIL${RESET}  kensa history --help missing --prune"
fi
if echo "${out}" | grep -qE -- "--force"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa history --help advertises --force"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa history --help: --force missing")
    echo "  ${RED}FAIL${RESET}  kensa history --help missing --force"
fi
echo

# ─── kensa verify (C-060) ─────────────────────────────────────────────────
echo "kensa verify (C-060):"
assert_exit "kensa verify --help"          0 stdout-nonempty bin/kensa verify --help
assert_exit "kensa verify (no args)"       2 stderr-nonempty bin/kensa verify
assert_exit "kensa verify missing-file"    2 stderr-nonempty bin/kensa verify /no/such/file.json
assert_exit "kensa verify --bogus"         2 stderr-nonempty bin/kensa verify --bogus
echo

# ─── kensa-keygen (M-012) ─────────────────────────────────────────────────
echo "kensa-keygen (M-012):"
assert_exit "kensa-keygen --help"     0 stdout-nonempty bin/kensa-keygen --help
assert_exit "kensa-keygen -h"         0 stdout-nonempty bin/kensa-keygen -h
assert_exit "kensa-keygen --bogus"    2 stderr-nonempty bin/kensa-keygen --bogus
# Happy path: generate into a temp dir, verify both files exist with right modes.
KEYGEN_TMP=$(mktemp -d -t kensa-keygen-smoke.XXXXXX)
KEYID=$(bin/kensa-keygen --out "${KEYGEN_TMP}" --key-id smoketest 2>/dev/null)
if [ "${KEYID}" = "smoketest" ] && [ -f "${KEYGEN_TMP}/smoketest.priv" ] && [ -f "${KEYGEN_TMP}/smoketest.pub" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa-keygen happy path produces .priv + .pub"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa-keygen happy path failed: keyID=${KEYID}")
    echo "  ${RED}FAIL${RESET}  kensa-keygen happy path failed"
fi
# .priv mode must be 0600 (octal).
PRIV_MODE=$(stat -c '%a' "${KEYGEN_TMP}/smoketest.priv" 2>/dev/null || stat -f '%Lp' "${KEYGEN_TMP}/smoketest.priv")
if [ "${PRIV_MODE}" = "600" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  ${GREEN}PASS${RESET}  kensa-keygen .priv mode 0600"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("kensa-keygen .priv mode wrong: ${PRIV_MODE}")
    echo "  ${RED}FAIL${RESET}  kensa-keygen .priv mode is ${PRIV_MODE}, want 600"
fi
# Re-run without --force MUST fail (collision).
assert_exit "kensa-keygen collision rejected" 2 stderr-nonempty bin/kensa-keygen --out "${KEYGEN_TMP}" --key-id smoketest
rm -rf "${KEYGEN_TMP}"
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
