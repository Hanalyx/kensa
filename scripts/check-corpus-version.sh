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
# [:space:] below means ASCII whitespace only.
export LC_ALL=C

# trim drops leading and trailing whitespace and keeps everything between,
# the way pkg/kensa reads the marker (strings.TrimSpace). Deleting every
# whitespace character instead would let a marker such as "0. 13.0" pass
# against VERSION 0.13.0 while the API reports "0. 13.0". TrimSpace also
# trims non-ASCII spaces; this does not, so such a marker fails here, the
# cautious direction.
trim() {
	s=$1
	s=${s#"${s%%[![:space:]]*}"}
	s=${s%"${s##*[![:space:]]}"}
	printf '%s' "$s"
}

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
marker_file="$root/rules/.corpus-version"
version_file="$root/VERSION"

[ -f "$version_file" ] || { echo "check-corpus-version: missing VERSION" >&2; exit 1; }
if [ ! -f "$marker_file" ]; then
	echo "check-corpus-version: missing rules/.corpus-version; the corpus carries no version marker. Run: cp VERSION rules/.corpus-version" >&2
	exit 1
fi
version=$(trim "$(cat "$version_file")")
marker=$(trim "$(cat "$marker_file")")
[ -n "$marker" ] || { echo "check-corpus-version: rules/.corpus-version is empty" >&2; exit 1; }
if [ "$marker" != "$version" ]; then
	echo "check-corpus-version: rules/.corpus-version ($marker) != VERSION ($version); bump both in the release commit, or run: cp VERSION rules/.corpus-version" >&2
	exit 1
fi
echo "check-corpus-version: rules/.corpus-version ($marker) matches VERSION"
