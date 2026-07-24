.PHONY: help build test lint comment-lint comment-lint-all cli-smoke spec-sync spec-parse spec-check spec-coverage spec-coverage-strict spec-ingest spec-graph spec-watch spec-doctor spec-explain manpage manpage-check proto proto-check vuln mod-tidy-check catalog catalog-check catalog-baseline docs-check viewer hooks status clean

help:
	@echo "Kensa — common targets"
	@echo ""
	@echo "  build           Build kensa, kensa-fuzz, kensa-validate, kensa-keygen binaries"
	@echo "  test            Run unit tests"
	@echo "  cli-smoke       Run CLI smoke tests (GNU/POSIX exit-code contract)"
	@echo "  lint            Run golangci-lint"
	@echo ""
	@echo "  spec-doctor     Pre-flight health check (run first when onboarding)"
	@echo "  spec-sync       Run the full Specter pipeline (parse + resolve + check + coverage)"
	@echo "  spec-parse      Parse and validate .spec.yaml files"
	@echo "  spec-check      Type-check across the spec graph (use STRICT=1 for warnings-as-errors)"
	@echo "  spec-coverage   Generate spec-to-test traceability matrix"
	@echo "  spec-coverage-strict  Enforce tier-threshold coverage (P-012 CI gate)"
	@echo "  spec-ingest     Re-run go test + ingest results into .specter-results.json"
	@echo "  spec-graph      Output dependency graph (FORMAT=dot or FORMAT=mermaid)"
	@echo "  spec-watch      Re-run sync on file changes (development loop)"
	@echo "  spec-explain    Show annotation examples (usage: make spec-explain SPEC=id:AC-NN)"
	@echo ""
	@echo "  manpage         Generate dist/kensa.1 from sources"
	@echo "  manpage-check   Verify dist/kensa.1 is in sync with sources (CI gate)"
	@echo ""
	@echo "  vuln            Run govulncheck against the binary call graph (CI gate)"
	@echo "  mod-tidy-check  Verify go.mod + go.sum match 'go mod tidy' output (CI gate)"
	@echo ""
	@echo "  catalog         Rebuild the benchmark control catalog (dev tool) from catalog/sources/ + rules/"
	@echo "  catalog-check   Gate on coverage regression / new reference drift vs catalog/baseline.json (CI gate)"
	@echo "  catalog-baseline  Refresh catalog/baseline.json after an intended coverage change"
	@echo "  viewer          Regenerate the rule-catalog viewer HTML from rules/ (run after rule changes)"
	@echo ""
	@echo "  hooks           Install git pre-commit hooks (conflict-marker/fmt/vet/lint/secret guards)"
	@echo "  status          Print + write bin/STATUS.json — machine-readable current release/coverage state"
	@echo ""
	@echo "  clean           Remove build artifacts"

# Install the pre-commit framework hooks into .git/hooks so local commits run
# the same guards CI runs (check-merge-conflict, go-fmt/vet, golangci-lint,
# detect-secrets). Without this, `git commit` bypasses them — which is how a
# stray conflict marker once reached a branch. Run once per clone.
hooks:
	@# pre-commit refuses to install while core.hooksPath is set; unset it
	@# (git then uses the default .git/hooks, where pre-commit installs).
	@git config --unset-all core.hooksPath 2>/dev/null || true
	pre-commit install
	@echo "hooks installed — 'git commit' now runs check-merge-conflict + fmt/vet/lint/secret guards."

# Machine-readable current state, for humans and agents: version, latest tag,
# commits-ahead delta, corpus size, and the per-framework coverage matrix.
# Regenerated on demand (never committed) so it can never go stale.
status:
	@bash scripts/status.sh

# VERSION drives all five binaries' --version output via -ldflags
# injection (see VERSIONING_PLAN.md "Single Source of Truth"). The
# file at the repo root is the authoritative version string; nothing
# else should hard-code a version.
VERSION := $(shell cat VERSION)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

# Build flags for binary portability:
#   CGO_ENABLED=0  static link, no glibc floor — runs RHEL 8 → 12 → Alpine
#   -tags netgo    force the pure-Go DNS resolver (no getaddrinfo/cgo path)
# Together these let one binary built today run across the supported
# Linux distribution range.
build:
	CGO_ENABLED=0 go build -tags netgo $(LDFLAGS) -o bin/kensa ./cmd/kensa
	CGO_ENABLED=0 go build -tags netgo $(LDFLAGS) -o bin/kensa-fuzz ./cmd/kensa-fuzz
	CGO_ENABLED=0 go build -tags netgo $(LDFLAGS) -o bin/kensa-validate ./cmd/kensa-validate
	CGO_ENABLED=0 go build -tags netgo $(LDFLAGS) -o bin/kensa-keygen ./cmd/kensa-keygen
	CGO_ENABLED=0 go build -tags netgo $(LDFLAGS) -o bin/kensa-systemd-helper ./cmd/kensa-systemd-helper

test:
	go test ./...

# vuln runs govulncheck against the binary call graph. Track S S-005.
#
# Why the GOTOOLCHAIN pin matters: with GOTOOLCHAIN=auto (the default),
# `go run pkg@latest` picks the smallest toolchain that satisfies all
# directives — for govulncheck@latest that means go1.25.x, which then
# can't typecheck source written against go1.26.x. Reading the `go`
# directive from go.mod and pinning GOTOOLCHAIN explicitly forces the
# matching toolchain. Auto-tracks future go.mod bumps.
vuln:
	@TOOLCHAIN=go$$(awk '/^go /{print $$2; exit}' go.mod) && \
	  echo "govulncheck with GOTOOLCHAIN=$$TOOLCHAIN" && \
	  GOTOOLCHAIN=$$TOOLCHAIN go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# mod-tidy-check verifies `go mod tidy` is a no-op against the current
# working tree — i.e., the contributor has already tidied before
# running this. Saves pre-tidy state, runs tidy, diffs against the
# saved state (NOT against HEAD — comparing to HEAD would false-fail
# on intentional in-flight go.mod edits during development).
# Track S S-014.
mod-tidy-check:
	@cp go.mod /tmp/.kensa-go-mod.before
	@cp go.sum /tmp/.kensa-go-sum.before
	@go mod tidy
	@if ! diff -q go.mod /tmp/.kensa-go-mod.before >/dev/null || \
	    ! diff -q go.sum /tmp/.kensa-go-sum.before >/dev/null; then \
	  echo ''; \
	  echo '::error::go mod tidy produced changes — go.mod or go.sum drifted.'; \
	  echo 'Run `go mod tidy` locally and commit the result.'; \
	  diff go.mod /tmp/.kensa-go-mod.before || true; \
	  diff go.sum /tmp/.kensa-go-sum.before || true; \
	  rm -f /tmp/.kensa-go-mod.before /tmp/.kensa-go-sum.before; \
	  exit 1; \
	fi
	@rm -f /tmp/.kensa-go-mod.before /tmp/.kensa-go-sum.before

# cli-smoke runs scripts/cli-smoke.sh — a fast (~5s) end-to-end smoke
# test of the CLI binaries' GNU/POSIX exit-code contract: every
# subcommand --help exits 0, every bad-flag exits 2, etc. No network
# required. Builds binaries first if missing.
cli-smoke:
	scripts/cli-smoke.sh

lint:
	golangci-lint run

# comment-lint fails on planning labels (Phase 3, Option B, ...) in NEW Go
# comments — those added relative to BASE (default origin/main). See the
# "Comments" section of CONTRIBUTING.md.
BASE ?= origin/main
comment-lint:
	go run ./cmd/comment-lint -base $(BASE)

docs-check: ## verify front-door docs (README/CONTRIBUTING/CHANGELOG/SECURITY) present, well-formed, and version-consistent
	bash scripts/docs_check.sh

# comment-lint-all scans every tracked .go comment (for an opt-in legacy sweep).
comment-lint-all:
	go run ./cmd/comment-lint -all

FORMAT ?= dot

spec-doctor:
	specter doctor

spec-sync:
	specter sync --strictness annotation

spec-parse:
	specter parse

spec-check:
ifeq ($(STRICT),1)
	specter check --strict
else
	specter check
endif

spec-coverage:
	specter coverage --tests 'tests/**/*_test.go'

# spec-ingest: regenerate .specter-results.json from a fresh
# `go test -json` run. Required before spec-coverage-strict so
# the gate sees the current pass/fail state.
spec-ingest:
	@go test ./... -json > go-test.json 2>&1 || true
	@specter ingest --go-test go-test.json --output .specter-results.json

# spec-coverage-strict: the P-012 CI gate. Enforces tier-specific
# thresholds (tier1: 100%, tier2: 80%, tier3: 50%) per
# specter.yaml. Fails the build if any spec is below its tier's
# threshold. Runs spec-ingest first so the gate sees fresh results.
spec-coverage-strict: spec-ingest
	specter coverage --strict

spec-graph:
ifeq ($(FORMAT),mermaid)
	specter resolve --mermaid > /tmp/kensa-spec-graph.mmd && \
		echo "Mermaid graph written to /tmp/kensa-spec-graph.mmd (paste into a GitHub PR or Markdown file)"
else
	specter resolve --dot > /tmp/kensa-spec-graph.dot && \
		echo "DOT graph written to /tmp/kensa-spec-graph.dot" && \
		echo "Render with: dot -Tsvg /tmp/kensa-spec-graph.dot > graph.svg"
endif

spec-watch:
	specter watch

spec-explain:
ifndef SPEC
	@echo "Usage: make spec-explain SPEC=spec-id" && \
		echo "   or: make spec-explain SPEC=spec-id:AC-NN" && \
		exit 1
endif
	specter explain $(SPEC)

manpage: build
	@go run man/gen-manpage.go > man/kensa.1
	@echo "wrote man/kensa.1 ($$(wc -c < man/kensa.1) bytes)"
	@mkdir -p dist
	@cp man/kensa.1 dist/kensa.1

manpage-check: build
	@go run man/gen-manpage.go > man/kensa.1.regenerated
	@if ! diff -u man/kensa.1 man/kensa.1.regenerated > /dev/null; then \
		echo "manpage drift detected — committed man/kensa.1 differs from regenerated output"; \
		echo "run 'make manpage' to refresh, then commit man/kensa.1"; \
		diff -u man/kensa.1 man/kensa.1.regenerated; \
		rm -f man/kensa.1.regenerated; \
		exit 1; \
	fi
	@rm -f man/kensa.1.regenerated
	@echo "manpage in sync with sources"

# Regenerate the agent wire-protocol Go bindings from wire.proto.
# Requires `protoc` (install from
# github.com/protocolbuffers/protobuf/releases) and `protoc-gen-go`
# (`go install google.golang.org/protobuf/cmd/protoc-gen-go`, pinned
# via tools.go).
proto:
	@if ! command -v protoc >/dev/null; then \
		echo "protoc not found in PATH; install from github.com/protocolbuffers/protobuf/releases"; \
		exit 1; \
	fi
	@if ! command -v protoc-gen-go >/dev/null; then \
		echo "protoc-gen-go not found; run: go install google.golang.org/protobuf/cmd/protoc-gen-go"; \
		exit 1; \
	fi
	@protoc --go_out=. --go_opt=paths=source_relative internal/agent/wirev1/wire.proto
	@echo "regenerated internal/agent/wirev1/wire.pb.go"

# Verify the checked-in wire.pb.go matches what `protoc` would
# produce today. CI runs this to fail any PR that edits wire.proto
# without regenerating the Go bindings.
#
# Generates into a tempdir and diffs against the committed file —
# the working tree is never mutated by this target. (An earlier
# version had `proto-check: proto` which regenerated in-place; that
# coupled CI reproducibility to clean-checkout state and lost any
# uncommitted edits a developer had on wire.pb.go.)
proto-check:
	@if ! command -v protoc >/dev/null; then \
		echo "protoc not found in PATH; install from github.com/protocolbuffers/protobuf/releases (see CONTRIBUTING.md)"; \
		exit 1; \
	fi
	@if ! command -v protoc-gen-go >/dev/null; then \
		echo "protoc-gen-go not found; run: go install google.golang.org/protobuf/cmd/protoc-gen-go (see CONTRIBUTING.md)"; \
		exit 1; \
	fi
	@tmpdir=$$(mktemp -d) && \
		protoc --go_out="$$tmpdir" --go_opt=paths=source_relative internal/agent/wirev1/wire.proto && \
		if ! diff -q internal/agent/wirev1/wire.pb.go "$$tmpdir/internal/agent/wirev1/wire.pb.go" >/dev/null; then \
			echo "wire.pb.go drift detected — committed file differs from regenerated output"; \
			echo "run 'make proto' to refresh, then commit internal/agent/wirev1/wire.pb.go"; \
			diff -u internal/agent/wirev1/wire.pb.go "$$tmpdir/internal/agent/wirev1/wire.pb.go" | head -40; \
			rm -rf "$$tmpdir"; \
			exit 1; \
		fi; \
		rm -rf "$$tmpdir"
	@echo "wire.pb.go in sync with wire.proto"

# --- Compliance-benchmark catalog (dev tool) ---------------------------------
# kensa-catalog is a dev/CI authoring tool (not shipped). `catalog` rebuilds the
# benchmark control catalog from the vendored sources in catalog/sources/ plus the
# rule corpus; `catalog-check` is the CI gate, failing on coverage regression or
# newly introduced reference drift against catalog/baseline.json. The .db lands in
# bin/ (gitignored) and is fully rebuildable from committed inputs. Re-run
# catalog-baseline after an intended coverage change to refresh the baseline.
CATALOG_DB := bin/kensa-catalog.db

catalog:
	CGO_ENABLED=0 go build -tags netgo -o bin/kensa-catalog ./cmd/kensa-catalog
	@rm -f $(CATALOG_DB)
	./bin/kensa-catalog -db $(CATALOG_DB) build catalog/sources rules

catalog-check: catalog
	./bin/kensa-catalog -db $(CATALOG_DB) check catalog/baseline.json

catalog-baseline: catalog
	./bin/kensa-catalog -db $(CATALOG_DB) baseline > catalog/baseline.json
	@echo "re-baselined catalog/baseline.json"

# Regenerate the rule-catalog viewer (Explorer / Crosswalk / Gallery /
# Spec Sheet) from the current rules/ + catalog verifications. The
# generator lives under docs/research/, which is gitignored — absent in
# a fresh clone or air-gap checkout — so the target no-ops with a note
# rather than failing when it is not present.
viewer:
	@if [ -f docs/research/viewer/generate.py ]; then \
		python3 docs/research/viewer/generate.py; \
	else \
		echo "viewer generator not present (docs/research/ is gitignored) — nothing to regenerate"; \
	fi

clean:
	rm -rf bin/ coverage.txt coverage.html dist/ man/kensa.1.regenerated
