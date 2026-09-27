#!/bin/sh
# Stage the rule corpus for the kensa-rules package.
#
# rules/ holds the corpus and also the Go package that embeds it for library
# consumers. Only the corpus belongs in the package: every *.yml file under
# rules/, at any depth, plus the corpus README. The layout under rules/ is kept,
# directories are 0755 and files 0644, so the package matches what the corpus
# directory itself would install.
#
# Usage: scripts/stage-corpus.sh <destination>
set -eu

dest=${1:?usage: stage-corpus.sh <destination>}
src=rules

rm -rf "$dest"
mkdir -p "$dest"

find "$src" -type f -name '*.yml' | while IFS= read -r f; do
	rel=${f#"$src"/}
	mkdir -p "$dest/$(dirname "$rel")"
	cp "$f" "$dest/$rel"
done
cp "$src/README.md" "$dest/README.md"

find "$dest" -type d -exec chmod 0755 {} +
find "$dest" -type f -exec chmod 0644 {} +

if find "$dest" -type f ! -name '*.yml' ! -name README.md | grep -q .; then
	echo "stage-corpus: unexpected non-corpus file staged" >&2
	exit 1
fi
