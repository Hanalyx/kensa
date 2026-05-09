package main

import (
	"context"
	"sync"
)

// fanOutBounded runs fn against each item in items with at most
// `workers` concurrent invocations. Used by runCheckInventory
// to bound the goroutine pool per --workers (C-029).
//
// Acquire-before-spawn semantics: a buffered channel of capacity
// workers acts as a semaphore. We send into it BEFORE the `go`
// statement so we don't allocate a goroutine just to have it
// park on the semaphore — keeps the live goroutine count near
// the configured limit during fan-out.
//
// Context cancellation: if ctx becomes done mid-fan-out, the
// loop breaks before spawning further goroutines. Goroutines
// already in flight are not preempted; they typically observe
// the cancellation through their own ctx-aware operations
// (e.g., ssh.Connect's ctx parameter).
//
// fn must call wg.Done()-equivalent semantics implicitly via
// the helper — the helper handles WaitGroup lifecycle so each
// caller doesn't have to.
func fanOutBounded[T any](ctx context.Context, items []T, workers int, fn func(idx int, item T)) {
	if workers < 1 {
		workers = 1 // defensive; validated upstream by validateWorkers
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, item := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, it T) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(idx, it)
		}(i, item)
	}
	wg.Wait()
}
