//go:build tools

// Package tools pins build-time tooling (bpf2go) so `go generate` works
// with a reproducible version. It is never compiled into the binary.
package tools

import _ "github.com/cilium/ebpf/cmd/bpf2go"
