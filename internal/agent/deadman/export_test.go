package deadman

// RecoveryClaimForTest exposes the actual claim and notification only to this
// package's external tests; no production test hook or polling sleep is needed.
func (a *Armer) RecoveryClaimForTest() (bool, <-chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.recovering > 0, a.changed
}
