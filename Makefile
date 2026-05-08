.PHONY: help build test lint spec-sync spec-parse spec-check spec-coverage spec-graph spec-watch spec-doctor spec-explain clean

help:
	@echo "Kensa Go — common targets"
	@echo ""
	@echo "  build           Build kensa, kensa-fuzz, kensa-validate binaries"
	@echo "  test            Run unit tests"
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
	@echo "  clean           Remove build artifacts"

# Build with CGO_ENABLED=0 so the binary links statically against the
# kernel ABI (no glibc floor); see docs/roadmap/LOW_LEVEL_MIGRATION_V1.md
# Phase 0 (deliverable L-001).
build:
	CGO_ENABLED=0 go build -o bin/kensa ./cmd/kensa
	CGO_ENABLED=0 go build -o bin/kensa-fuzz ./cmd/kensa-fuzz
	CGO_ENABLED=0 go build -o bin/kensa-validate ./cmd/kensa-validate

test:
	go test ./...

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

clean:
	rm -rf bin/ coverage.txt coverage.html
