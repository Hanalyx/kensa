#!/usr/bin/env bash
# Docs-consistency gate: keeps the project's front-door docs present, well-formed,
# and in sync with the release version. Mirrors the other *-check gates.
#
#   make docs-check   (CI job: "Docs consistency")
#
# Checks:
#   1. Required front-door files exist.
#   2. CHANGELOG has an "## Unreleased" section (in-flight work lands there).
#   3. Every CHANGELOG version heading carries an ISO-8601 (YYYY-MM-DD) date.
#   4. VERSION matches the newest stamped CHANGELOG version.
#   5. README states the current version (catches a stale Status section).
#   6. README and CONTRIBUTING both point to SECURITY.md.
set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
fail=0
note() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=1; }
ok()   { printf '  ok    %s\n' "$1"; }

echo "docs-check: front-door documentation consistency"

# 1. Required files.
for f in README.md CONTRIBUTING.md CHANGELOG.md SECURITY.md LICENSE KEYS VERSION; do
	if [ -f "$f" ]; then ok "present: $f"; else note "missing required file: $f"; fi
done

# 2. Unreleased section.
if grep -qE '^## Unreleased([[:space:]]|$)' CHANGELOG.md; then
	ok "CHANGELOG has an ## Unreleased section"
else
	note "CHANGELOG is missing an '## Unreleased' section (stamp releases, don't drop it)"
fi

# 3. ISO date on every version heading (## vX.Y.Z — YYYY-MM-DD).
baddate="$(grep -E '^## v[0-9]' CHANGELOG.md | grep -vE '[0-9]{4}-[0-9]{2}-[0-9]{2}' || true)"
if [ -n "$baddate" ]; then
	note "CHANGELOG version heading(s) without an ISO-8601 (YYYY-MM-DD) date:"
	printf '        %s\n' "$baddate"
else
	ok "all CHANGELOG version headings carry an ISO-8601 date"
fi

# 4. VERSION == newest stamped CHANGELOG version.
version="$(tr -d '[:space:]' < VERSION)"
top_cl="$(grep -m1 -E '^## v[0-9]' CHANGELOG.md | sed -E 's/^## v([0-9][^ ]*).*/\1/')"
if [ "$version" = "$top_cl" ]; then
	ok "VERSION ($version) matches newest CHANGELOG entry (v$top_cl)"
else
	note "VERSION ($version) != newest stamped CHANGELOG version (v$top_cl) — stamp the CHANGELOG or fix VERSION"
fi

# 5. README states the current version.
if grep -qF "$version" README.md; then
	ok "README mentions the current version ($version)"
else
	note "README does not mention the current version ($version) — the Status section is stale"
fi

# 6. SECURITY.md is discoverable from README and CONTRIBUTING.
for f in README.md CONTRIBUTING.md; do
	if grep -qi 'SECURITY.md' "$f"; then ok "$f links SECURITY.md"; else note "$f does not link SECURITY.md"; fi
done

# 7. No STALE Kensa version in the front-door docs. "Stale" = any PRIOR release
#    (every CHANGELOG `## vX.Y.Z` heading except the current VERSION) appearing in
#    README / CONTRIBUTING / SECURITY. Keying off the real release list — not a
#    broad semver regex — asserts *absence* of prior versions without ever
#    mis-flagging a dependency/tool version like `golangci-lint v2.12.2` (2.12.2
#    is not a Kensa release). Exempt a deliberate historical reference with a
#    `docs-check:allow-version` marker on that line.
prior="$(grep -oE '^## v[0-9]+\.[0-9]+\.[0-9]+' CHANGELOG.md | sed 's/^## v//' | grep -vxF "$version" || true)"
stale=""
for f in README.md CONTRIBUTING.md SECURITY.md; do
	for pv in $prior; do
		esc="$(printf '%s' "$pv" | sed 's/\./\\./g')"
		if grep -nE "(^|[^0-9.])v?${esc}([^0-9.]|$)" "$f" 2>/dev/null | grep -qv 'docs-check:allow-version'; then
			stale="$stale $f:v$pv"
		fi
	done
done
if [ -n "$stale" ]; then
	note "stale prior-release version(s) in a front-door doc (current is v$version; mark a deliberate reference with docs-check:allow-version):"
	for s in $stale; do printf '        %s\n' "$s"; done | sort -u
else
	ok "no stale prior-release version in README/CONTRIBUTING/SECURITY"
fi

if [ "$fail" -ne 0 ]; then
	echo "docs-check: FAILED"
	exit 1
fi
echo "docs-check: OK"
