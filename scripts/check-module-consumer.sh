#!/usr/bin/env bash
# check-module-consumer.sh: prove what a program that downloads the Kensa
# module actually gets.
#
# A consumer such as OpenWatch pins a Kensa version and embeds its corpus
# (package github.com/Hanalyx/kensa/rules). This check builds such a consumer
# the way a real one resolves the module, and fails unless:
#
#   - the module resolves to the candidate version, with no replacement, from
#     an isolated module cache and never from this checkout;
#   - the embedded corpus equals the rule files tracked at the commit, file for
#     file, by path and sha256;
#   - every dependency hash the consumer records matches Kensa's committed
#     go.sum;
#   - rules/ holds no go.mod, and no cmd/ or pkg/ package links the corpus.
#
# The candidate is built from the commit's tracked contents (git archive),
# never from the working tree, so local edits and untracked files cannot reach
# it. Its checksums are computed from that same artifact, so they show the
# consumer built exactly this artifact, not where the artifact came from.
#
# After a release, run --public VERSION to check that the downloaded module
# contains the expected rules. Separately, verify the release tag's signature
# and confirm that it points to the approved commit. This script does not
# check the tag's signature. Only the candidate check runs automatically, in
# the unit tests; both release checks are manual.
#
# Usage:
#   scripts/check-module-consumer.sh [COMMIT]     candidate from COMMIT (HEAD)
#   scripts/check-module-consumer.sh --public VER released VER, public proxy
set -euo pipefail

module=github.com/Hanalyx/kensa
repo=$(git rev-parse --show-toplevel)
# Resolved, so paths Go reports can be compared with it as plain strings.
work=$(cd "$(mktemp -d)" && pwd -P)
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

fail() { echo "check-module-consumer: FAIL: $*" >&2; exit 1; }
say() { echo "check-module-consumer: $*"; }

public=
if [ "${1:-}" = "--public" ]; then
	public=1
	version=${2:?usage: --public VERSION}
	commit=$(git -C "$repo" rev-parse "$version^{commit}")
else
	commit=$(git -C "$repo" rev-parse "${1:-HEAD}^{commit}")
fi

# The tracked tree at the commit: the source of the candidate, and the
# reference the embedded corpus is compared with.
tree="$work/tree"
mkdir -p "$tree"
git -C "$repo" archive "$commit" | tar -x -C "$tree"

# Structure: a go.mod under rules/ would make rules its own module, separate
# from the engine, and bring back the version mismatch this package prevents.
gomods=$(find "$tree/rules" -name go.mod) || fail "could not search rules/ for go.mod"
[ -z "$gomods" ] || fail "rules/ contains a go.mod; the corpus must stay in the root module"

# The Go toolchain the commit's go.mod selects, resolved once with this
# machine's normal settings (it may be a downloaded toolchain), then pinned
# so nothing below switches toolchains inside the isolated cache.
gobin="$(cd "$tree" && go env GOROOT)/bin"
export PATH="$gobin:$PATH"
say "toolchain $(go env GOVERSION)"

# Isolation from this machine's Go state for everything below. GOENV=off
# also ignores settings saved with `go env -w`, such as a GOPRIVATE that
# would send the candidate lookup straight to version control.
export GOENV=off
export GOWORK=off
export GOFLAGS=-mod=mod
export GOTOOLCHAIN=local
export GOPATH="$work/gopath"
export GOMODCACHE="$work/modcache"
unset GOPRIVATE GONOPROXY GONOSUMDB GOINSECURE

if [ -n "$public" ]; then
	# A released version, fetched the way a consumer gets it: from the public
	# proxy, verified against the public checksum database. This checks what
	# the downloaded module contains. It does not check the release tag's
	# signature, which is verified separately.
	export GOPROXY=https://proxy.golang.org
	export GOSUMDB=sum.golang.org
else
	# Stage the candidate as a module proxy entry, from the tracked tree.
	ts=$(TZ=UTC git -C "$repo" show -s --format=%cd --date=format-local:%Y%m%d%H%M%S "$commit")
	version="v0.0.0-$ts-$(git -C "$repo" rev-parse --short=12 "$commit")"
	cand="$work/proxy/github.com/!hanalyx/kensa/@v"
	mkdir -p "$cand" "$work/zip/$module@$version"
	cp -a "$tree/." "$work/zip/$module@$version/"
	(cd "$work/zip" && zip -qrXD "$cand/$version.zip" "$module@$version")
	cp "$tree/go.mod" "$cand/$version.mod"
	printf '{"Version":"%s","Time":"%s"}\n' "$version" \
		"$(TZ=UTC git -C "$repo" show -s --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ "$commit")" \
		>"$cand/$version.info"
	echo "$version" >"$cand/list"

	# Dependencies come from the pinned graph. Download it into this
	# machine's module cache with the normal proxy and checksum settings, so
	# each dependency is verified against Kensa's go.sum, then serve that
	# cache read-only as a second proxy behind the candidate.
	hostcache=$(env -u GOMODCACHE -u GOPATH -u GOFLAGS go env GOMODCACHE)
	(cd "$tree" && env -u GOMODCACHE -u GOPATH GOFLAGS=-mod=readonly \
		GOPROXY="$(env -u GOPROXY go env GOPROXY)" \
		GOSUMDB="$(env -u GOSUMDB go env GOSUMDB)" \
		go mod download all) || fail "could not download the pinned dependency graph"
	export GOPROXY="file://$work/proxy,file://$hostcache/cache/download"
	# The candidate is not in the public checksum database. Dependency hashes
	# are checked against Kensa's go.sum below instead.
	export GOSUMDB=off
fi

say "commit $commit, version $version"

# The consumer: a module that requires the candidate and embeds its corpus.
consumer="$work/consumer"
mkdir -p "$consumer"
cat >"$consumer/go.mod" <<EOF
module example.com/kensa-consumer

go $(awk '/^go /{print $2; exit}' "$tree/go.mod")
EOF
cat >"$consumer/main.go" <<'EOF'
package main

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/Hanalyx/kensa/pkg/kensa"
	"github.com/Hanalyx/kensa/rules"
)

func main() {
	fsys := rules.FS()
	loaded, err := kensa.LoadRulesFS(fsys, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "LoadRulesFS:", err)
		os.Exit(1)
	}
	fmt.Printf("loaded %d\n", len(loaded))
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yml") {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		fmt.Printf("%x  %s\n", sha256.Sum256(b), p)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "walk:", err)
		os.Exit(1)
	}
}
EOF
if ! (cd "$consumer" && go get "$module@$version") >"$work/get.log" 2>&1; then
	cat "$work/get.log" >&2
	fail "consumer could not resolve $module@$version"
fi
# Record checksums for exactly the modules the consumer builds from (not a
# tidy, which also records modules used only by dependencies' tests).
(cd "$consumer" && go list -deps . >/dev/null) || fail "consumer could not load its packages"

# Resolved graph: the candidate itself, not replaced, read from the isolated
# cache, and no module the consumer builds from resolves into this checkout.
# The graph is taken from the packages actually built, which is what reaches
# the binary.
if grep -qE '^[[:space:]]*replace([[:space:]]|\()' "$consumer/go.mod"; then
	fail "the consumer's go.mod contains a replace directive"
fi
graph=$(cd "$consumer" && go list -deps -f '{{with .Module}}{{.Path}}|{{.Version}}|{{if .Replace}}REPLACED{{end}}|{{.Dir}}{{end}}' .) ||
	fail "could not list the consumer's build graph"
graph=$(sort -u <<<"$graph")
[ -n "$graph" ] || fail "consumer build graph is empty"
found=
while IFS='|' read -r mpath mver mrep mdir; do
	[ -n "$mpath" ] || continue
	[ "$mpath" = example.com/kensa-consumer ] && continue
	[ -z "$mrep" ] || fail "$mpath is replaced in the consumer's module graph"
	case "$mdir" in
	"$GOMODCACHE"/*) ;;
	*) fail "$mpath resolved to $mdir, outside the isolated module cache" ;;
	esac
	if [ "$mpath" = "$module" ]; then
		[ "$mver" = "$version" ] || fail "resolved $module $mver, want $version"
		found=1
	fi
done <<<"$graph"
[ -n "$found" ] || fail "$module is not in the consumer's build graph"

# Dependency checksums: every dependency line the consumer recorded must
# appear, identically, in Kensa's committed go.sum.
while read -r line; do
	case "$line" in "$module "*) continue ;; esac
	grep -qxF "$line" "$tree/go.sum" ||
		fail "consumer go.sum line not in Kensa's go.sum: $line"
done <"$consumer/go.sum"

# Build under readonly, so any go.sum mismatch fails the build.
(cd "$consumer" && GOFLAGS=-mod=readonly go build -o "$work/consumer.bin" .) ||
	fail "consumer build failed"

# Content: the embedded corpus equals the rule files tracked at the commit.
"$work/consumer.bin" >"$work/embedded.txt" || fail "consumer run failed"
loaded=$(awk '/^loaded /{print $2}' "$work/embedded.txt")
grep -v '^loaded ' "$work/embedded.txt" | sort -k2 >"$work/embedded.sha"
(cd "$tree/rules" && find . -type f -name '*.yml' | sed 's#^\./##' | sort |
	while read -r f; do printf '%s  %s\n' "$(sha256sum <"$f" | cut -d' ' -f1)" "$f"; done) |
	sort -k2 >"$work/tracked.sha"
if ! diff -u "$work/tracked.sha" "$work/embedded.sha" >"$work/manifest.diff"; then
	cat "$work/manifest.diff" >&2
	fail "embedded corpus differs from the rule files tracked at $commit"
fi
count=$(wc -l <"$work/tracked.sha")
[ "$count" -gt 0 ] || fail "no rule files tracked"
[ "$loaded" = "$count" ] || fail "LoadRulesFS loaded $loaded rules, $count rule files tracked"

# Standalone binaries: no cmd/ or pkg/ package links the corpus.
deps=$(cd "$tree" && GOFLAGS=-mod=readonly go list -deps -f '{{.ImportPath}}' ./cmd/... ./pkg/...) ||
	fail "could not list the dependencies of cmd/ and pkg/"
if grep -qx "$module/rules" <<<"$deps"; then
	fail "a cmd/ or pkg/ package links $module/rules"
fi

say "PASS: $count rule files embedded and loaded, graph and go.sum verified"
