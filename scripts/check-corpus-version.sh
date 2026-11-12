#!/bin/sh
# check-corpus-version.sh: fail unless rules/.corpus-version equals VERSION.
#
# The marker tells a consumer which release of the corpus produced a verdict
# (pkg/kensa.DescribeCorpus). It is a second copy of the version, so it drifts
# unless something checks it, and a stale marker is reported with the same
# confidence as a correct one. Run by scripts/docs_check.sh.
#
# Usage: scripts/check-corpus-version.sh [ROOT]   (ROOT defaults to the repo)
set -eu

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
marker_file="$root/rules/.corpus-version"
version_file="$root/VERSION"

[ -f "$version_file" ] || { echo "check-corpus-version: missing VERSION" >&2; exit 1; }
if [ ! -f "$marker_file" ]; then
	echo "check-corpus-version: missing rules/.corpus-version; the corpus carries no version marker. Run: cp VERSION rules/.corpus-version" >&2
	exit 1
fi
version=$(tr -d '[:space:]' <"$version_file")
marker=$(tr -d '[:space:]' <"$marker_file")
if [ "$marker" != "$version" ]; then
	echo "check-corpus-version: rules/.corpus-version ($marker) != VERSION ($version); bump both in the release commit, or run: cp VERSION rules/.corpus-version" >&2
	exit 1
fi
echo "check-corpus-version: rules/.corpus-version ($marker) matches VERSION"
