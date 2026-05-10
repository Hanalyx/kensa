.PHONY: help build test lint cli-smoke spec-sync spec-parse spec-check spec-coverage spec-graph spec-watch spec-doctor spec-explain manpage manpage-check clean

help:
	@echo "Kensa Go — common targets"
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
	@echo "  spec-graph      Output dependency graph (FORMAT=dot or FORMAT=mermaid)"
	@echo "  spec-watch      Re-run sync on file changes (development loop)"
	@echo "  spec-explain    Show annotation examples (usage: make spec-explain SPEC=id:AC-NN)"
	@echo ""
	@echo "  manpage         Generate dist/kensa.1 from sources"
	@echo "  manpage-check   Verify dist/kensa.1 is in sync with sources (CI gate)"
	@echo ""
	@echo "  clean           Remove build artifacts"

# Build flags for binary portability (DELIVERABLES.md L-001 + L-002):
#   CGO_ENABLED=0  static link, no glibc floor — runs RHEL 8 → 12 → Alpine
#   -tags netgo    force the pure-Go DNS resolver (no getaddrinfo/cgo path)
# Together these let one binary built today run across the supported
# Linux distribution range; see docs/roadmap/LOW_LEVEL_MIGRATION_V1.md
# Phase 0.
build:
	CGO_ENABLED=0 go build -tags netgo -o bin/kensa ./cmd/kensa
	CGO_ENABLED=0 go build -tags netgo -o bin/kensa-fuzz ./cmd/kensa-fuzz
	CGO_ENABLED=0 go build -tags netgo -o bin/kensa-validate ./cmd/kensa-validate
	CGO_ENABLED=0 go build -tags netgo -o bin/kensa-keygen ./cmd/kensa-keygen

test:
	go test ./...

# cli-smoke runs scripts/cli-smoke.sh — a fast (~5s) end-to-end smoke
# test of the CLI binaries' GNU/POSIX exit-code contract: every
# subcommand --help exits 0, every bad-flag exits 2, etc. No network
# required. Builds binaries first if missing.
cli-smoke:
	scripts/cli-smoke.sh

lint:
	golangci-lint run

FORMAT ?= dot

spec-doctor:
	specter doctor

spec-sync:
	specter sync

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
	@go run docs/man/gen-manpage.go > docs/man/kensa.1
	@echo "wrote docs/man/kensa.1 ($$(wc -c < docs/man/kensa.1) bytes)"
	@mkdir -p dist
	@cp docs/man/kensa.1 dist/kensa.1

manpage-check: build
	@go run docs/man/gen-manpage.go > docs/man/kensa.1.regenerated
	@if ! diff -u docs/man/kensa.1 docs/man/kensa.1.regenerated > /dev/null; then \
		echo "manpage drift detected — committed docs/man/kensa.1 differs from regenerated output"; \
		echo "run 'make manpage' to refresh, then commit docs/man/kensa.1"; \
		diff -u docs/man/kensa.1 docs/man/kensa.1.regenerated; \
		rm -f docs/man/kensa.1.regenerated; \
		exit 1; \
	fi
	@rm -f docs/man/kensa.1.regenerated
	@echo "manpage in sync with sources"

clean:
	rm -rf bin/ coverage.txt coverage.html dist/ docs/man/kensa.1.regenerated
