package kensa

import (
	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/scan"
)

// NewScanner returns the standard check-engine [api.ScannerBackend],
// for embedders that compose [api.New] themselves with their own
// [api.TransportFactory] — the scan-only construction path:
//
//	k, _ := api.New(api.Config{
//	    Scanner:          kensa.NewScanner(),
//	    TransportFactory: myFactory, // credentials however you hold them
//	})
//	res, err := k.Scan(ctx, host, rules) // res.Outcomes
//
// [Kensa.Scan] needs only those two Config fields; no engine, store,
// or signer is constructed, which is the right footprint for a
// read-only compliance scanner (e.g. OpenWatch's executor, whose
// system of record is its own database).
//
// Concurrency: the returned backend is stateless across calls — its
// only fields are set here at construction and never mutated — so a
// single shared instance is safe for concurrent Scan calls across
// hosts; each call works exclusively with the transport it is handed.
//
// Remediation is NOT available through a scanner built this way:
// [api.Kensa.Remediate] on a NewScanner-composed instance returns an
// "engine not wired" error, by design — remediation requires the
// transaction engine, store, and signer. Embedders that need
// Remediate with a custom transport use [DefaultWithTransportFactory]
// instead.
func NewScanner() api.ScannerBackend {
	return scan.New(nil)
}
