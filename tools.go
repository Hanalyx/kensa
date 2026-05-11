// Tool dependencies pinned to go.mod via blank imports under the
// `tools` build tag. This file is excluded from regular `go build`
// (the build constraint below filters it out) but `go mod tidy`
// resolves the imports — pinning the codegen plugin versions so
// every developer regenerating `wire.pb.go` produces byte-identical
// output.
//
// Build the pinned tools with:
//
//	go install google.golang.org/protobuf/cmd/protoc-gen-go
//
// (or run `make proto`, which invokes `protoc` against an
// installed `protoc-gen-go`).
//
// Standard Go pattern: see
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module

//go:build tools

package tools

import (
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
)
