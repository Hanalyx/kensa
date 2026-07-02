#!/usr/bin/env bash
# Reject git conflict markers in the given files, UNCONDITIONALLY.
#
# pre-commit's built-in check-merge-conflict only fires while a merge is in
# progress (MERGE_HEAD present), so it misses markers staged during a rebase or
# pasted by hand — which is exactly how a conflict marker once reached a branch
# and broke the catalog. This guard runs on every commit and in CI.
#
# Matches only the angle-bracket markers ("<<<<<<< " / ">>>>>>> "), which are
# never legitimate content — avoiding false positives on markdown "======="
# heading underlines.
set -euo pipefail

hits="$(grep -nE '^(<<<<<<< |>>>>>>> )' "$@" 2>/dev/null || true)"
if [ -n "$hits" ]; then
  echo "error: git conflict markers found — resolve before committing:" >&2
  printf '%s\n' "$hits" | sed 's/^/  /' >&2
  exit 1
fi
