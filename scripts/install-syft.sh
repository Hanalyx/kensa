#!/usr/bin/env bash
#
# Install a pinned syft release, verifying it before it is trusted.
#
# Both the CI snapshot job and the release job build the SBOM with syft, so
# both used to pipe an installer script straight from anchore/syft's main
# branch into a shell. That ran unverified code from a moving target, in the
# release job's case alongside the GPG and cosign signing secrets. This script
# replaces both call sites so the two cannot drift apart.
#
# Usage:  install-syft.sh <install-dir>
# Reads SYFT_VERSION (e.g. v1.46.0) and SYFT_SHA256 from the environment.
#
# Every failure is fatal and there is no fallback. A digest or version
# mismatch means the bytes are not the pinned release, and building an SBOM
# with something else would put a false claim in a signed artifact.
set -euo pipefail

install_dir="${1:?usage: install-syft.sh <install-dir>}"
: "${SYFT_VERSION:?SYFT_VERSION must be set (e.g. v1.46.0)}"
: "${SYFT_SHA256:?SYFT_SHA256 must be set (sha256 of the linux_amd64 tar.gz)}"

version_no_v="${SYFT_VERSION#v}"
archive_name="syft_${version_no_v}_linux_amd64.tar.gz"
url="${SYFT_INSTALL_URL:-https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/${archive_name}}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
archive="$tmp_dir/$archive_name"

echo "Downloading $url"
if ! curl -fsSL -o "$archive" "$url"; then
  echo "::error::syft ${SYFT_VERSION} could not be downloaded from ${url}." >&2
  exit 1
fi

echo "Verifying the archive against the pinned digest"
actual="$(sha256sum "$archive" | cut -d' ' -f1)"
if [ "$actual" != "$SYFT_SHA256" ]; then
  echo "::error::syft archive digest mismatch. Expected ${SYFT_SHA256}, got ${actual}. Refusing to extract." >&2
  exit 1
fi

tar -xzf "$archive" -C "$tmp_dir"
if [ ! -f "$tmp_dir/syft" ]; then
  echo "::error::syft archive did not contain a syft binary at its root." >&2
  exit 1
fi
chmod +x "$tmp_dir/syft"

# Check the extracted binary before it is installed, so a bad one never
# reaches a directory on PATH.
want="syft ${version_no_v}"
got="$("$tmp_dir/syft" --version 2>/dev/null || true)"
if [ "$got" != "$want" ]; then
  echo "::error::extracted syft reports '${got}', expected '${want}'." >&2
  exit 1
fi

install -m 0755 "$tmp_dir/syft" "$install_dir/syft"

# And again from the installed path, which is what goreleaser will run.
got_installed="$("$install_dir/syft" --version 2>/dev/null || true)"
if [ "$got_installed" != "$want" ]; then
  echo "::error::installed syft at ${install_dir}/syft reports '${got_installed}', expected '${want}'." >&2
  exit 1
fi

echo "syft ${version_no_v} installed to ${install_dir}/syft"
