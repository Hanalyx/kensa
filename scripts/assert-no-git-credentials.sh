#!/usr/bin/env bash
#
# Fail if the checkout left a Git credential behind in the working copy.
#
# actions/checkout writes its token as an http.<url>.extraheader, and with
# persist-credentials left at its default it stays readable by every later step
# in the job, including third-party actions. This script is the runtime check
# that it is gone: declaring persist-credentials: false says what was asked for,
# and this says what actually happened.
#
# It reads the EFFECTIVE configuration, not the local file. checkout does not
# write the header into .git/config; it writes a separate config and pulls it in
# with includeIf.gitdir, and `git config --local` does not follow includes. A
# check scoped to --local would therefore report nothing whether or not the
# credential is present, and would pass for the wrong reason.
#
# Nothing here prints a configuration value. Key names are read with
# --name-only, and the failure message names no value. That is a property of
# this script only; it is not a claim that some other step could not print a
# credential by other means.
set -euo pipefail

cd "${1:-.}"

found=0

# Effective config, so includeIf-provided headers are seen.
if git config --name-only --get-regexp 'http\..*\.extraheader' >/dev/null 2>&1; then
  keys="$(git config --name-only --get-regexp 'http\..*\.extraheader' 2>/dev/null | tr '\n' ' ')"
  echo "::error::a Git credential header is still configured after checkout (${keys}). Set persist-credentials: false on the checkout step." >&2
  found=1
fi

# The include itself is the mechanism that persists the credential, so a
# lingering pointer at a credentials config is a failure even if the header
# above is somehow not resolvable at this moment.
if git config --name-only --get-regexp '^includeif\..*\.path$' >/dev/null 2>&1; then
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    target="$(git config --get "$key" 2>/dev/null || true)"
    case "$target" in
      *git-credentials-*)
        echo "::error::a Git credentials config is still included after checkout (${key}). Set persist-credentials: false on the checkout step." >&2
        found=1
        ;;
    esac
  done <<EOF
$(git config --name-only --get-regexp '^includeif\..*\.path$' 2>/dev/null || true)
EOF
fi

if [ "$found" -ne 0 ]; then
  exit 1
fi

echo "no Git credential persisted after checkout"
