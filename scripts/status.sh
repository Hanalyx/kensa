#!/usr/bin/env bash
# status.sh — emit the current release/coverage state as bin/STATUS.json + a
# human summary. Deterministic and offline (git + the local catalog only; no
# network, no gh). Regenerated on demand via `make status` so it never goes
# stale — the failure mode of the prose version history in the docs.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(cat VERSION 2>/dev/null || echo '?')"
LATEST_TAG="$(git tag --sort=-v:refname 2>/dev/null | grep -E '^v[0-9]' | head -1 || true)"
HEAD_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
AHEAD=0
if [ -n "${LATEST_TAG:-}" ]; then
  AHEAD="$(git rev-list --count "${LATEST_TAG}"..HEAD 2>/dev/null || echo 0)"
fi
CORPUS="$(find rules -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')"

# Build the catalog if the db is missing (needed for the coverage matrix).
DB=bin/kensa-catalog.db
if [ ! -f "$DB" ]; then
  make catalog >/dev/null 2>&1 || true
fi

# Parse `kensa-catalog coverage <fw>` rows into JSON objects.
matrix() {
  local fw="$1"
  ./bin/kensa-catalog -db "$DB" coverage "$fw" 2>/dev/null \
    | awk 'NR>1 && NF>=9 {printf "    {\"os\":\"%s\",\"release\":\"%s\",\"total\":%s,\"covered\":%s,\"cov_pct\":%s,\"verified\":%s,\"ver_pct\":%s},\n",$1,$2,$3,$4,$6,$8,$9}' \
    | sed '$ s/,$//'
}

CIS_ROWS="$(matrix cis || true)"
STIG_ROWS="$(matrix stig || true)"

mkdir -p bin
cat > bin/STATUS.json <<JSON
{
  "version": "${VERSION}",
  "latest_tag": "${LATEST_TAG:-none}",
  "head": "${HEAD_SHA}",
  "branch": "${BRANCH}",
  "commits_ahead_of_tag": ${AHEAD},
  "released": $([ "v${VERSION}" = "${LATEST_TAG:-}" ] && echo true || echo false),
  "corpus_rules": ${CORPUS},
  "coverage": {
    "cis": [
${CIS_ROWS}
    ],
    "stig": [
${STIG_ROWS}
    ]
  }
}
JSON

# Human summary.
echo "Kensa status"
echo "  version ${VERSION}  ·  latest tag ${LATEST_TAG:-none}  ·  HEAD ${HEAD_SHA} (${BRANCH})"
if [ "v${VERSION}" = "${LATEST_TAG:-}" ] && [ "${AHEAD}" = "0" ]; then
  echo "  state: RELEASED (v${VERSION} tagged, main == tag)"
elif [ "${AHEAD}" != "0" ]; then
  echo "  state: ${AHEAD} commit(s) ahead of ${LATEST_TAG:-<no tag>} — unreleased work on ${BRANCH}"
fi
echo "  corpus: ${CORPUS} rules"
echo "  coverage matrix -> bin/STATUS.json"
{ echo "    --- CIS ---"; ./bin/kensa-catalog -db "$DB" coverage cis 2>/dev/null | awk 'NR==1||/rhel|ubuntu/'; \
  echo "    --- STIG ---"; ./bin/kensa-catalog -db "$DB" coverage stig 2>/dev/null | awk 'NR==1||/rhel|ubuntu/'; } | sed 's/^/    /'
