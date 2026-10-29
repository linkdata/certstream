package certstream

import "context"

// SetProviderConcurrency sets one provider's request concurrency.
//
// The domain is the [OperatorDomain] of a CT log URL. A positive value takes
// effect for subsequent requests from current and future streams. The limit
// applies separately to each classic head reader and tiled head, tail, and gap
// client. A non-positive value selects [Config.Concurrency]. Requests already
// in flight may finish above a newly lowered limit. Concurrent calls are safe.
func (cs *CertStream) SetProviderConcurrency(domain string, concurrency int) {
	cs.mu.Lock()
	if cs.providerLimits == nil {
		cs.providerLimits = make(map[string]int)
	}
	cs.providerLimits[domain] = concurrency
	lo := cs.operators[domain]
	if lo != nil {
		lo.setConcurrency(concurrency)
	}
	cs.mu.Unlock()
}

// CurrentProviderConcurrency returns one provider's configured request limit.
//
// The domain is the [OperatorDomain] of a CT log URL. The positive value
// controls request admission for current and future streams. Classic head
// scans use at most 32 workers, and backfill scans are serial. Concurrent
// calls are safe.
func (cs *CertStream) CurrentProviderConcurrency(domain string) (concurrency int) {
	cs.mu.Lock()
	var ok bool
	if concurrency, ok = cs.providerLimits[domain]; !ok {
		concurrency = cs.ProviderConcurrency[domain]
	}
	if concurrency < 1 {
		concurrency = cs.Concurrency
	}
	cs.mu.Unlock()
	return max(1, concurrency)
}

func (lo *LogOperator) setConcurrency(concurrency int) {
	if concurrency < 1 {
		concurrency = lo.Concurrency
	}
	lo.limitMu.Lock()
	lo.limit = max(1, concurrency)
	lo.notifyLimitWaiters()
	if lo.limitChange != nil {
		close(lo.limitChange)
		lo.limitChange = nil
	}
	lo.limitMu.Unlock()
}

func (lo *LogOperator) concurrencyChange() (concurrency int, changed <-chan struct{}) {
	lo.limitMu.Lock()
	concurrency = lo.limit
	if concurrency < 1 {
		concurrency = lo.initialConcurrency()
	}
	if lo.limitChange == nil {
		lo.limitChange = make(chan struct{})
	}
	changed = lo.limitChange
	lo.limitMu.Unlock()
	return
}

func (lo *LogOperator) notifyLimitWaiters() {
	if lo.limitWait != nil {
		close(lo.limitWait)
		lo.limitWait = nil
	}
}

func (lo *LogOperator) acquireRequest(ctx context.Context, tr *retryAfterTransport) (err error) {
	for {
		lo.limitMu.Lock()
		if err = ctx.Err(); err != nil {
			lo.limitMu.Unlock()
			return
		}
		concurrency := lo.limit
		if concurrency < 1 {
			concurrency = lo.initialConcurrency()
		}
		if tr.active < concurrency {
			tr.active++
			lo.limitMu.Unlock()
			return
		}
		if lo.limitWait == nil {
			lo.limitWait = make(chan struct{})
		}
		wait := lo.limitWait
		lo.limitMu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (lo *LogOperator) releaseRequest(tr *retryAfterTransport) {
	lo.limitMu.Lock()
	tr.active--
	lo.notifyLimitWaiters()
	lo.limitMu.Unlock()
}
