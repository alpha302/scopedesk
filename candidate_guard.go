package main

import (
	"context"
	"time"
)

const candidateGuardBatchSize = 256
const candidateGuardMaxAge = 2 * time.Second

// A candidate-only snapshot, owned by one sequential parser or consumer.
// Never use this loader for network requests or result commits.
type candidateGuard struct {
	load     func(context.Context) (ScopeGuard, error)
	now      func() time.Time
	guard    ScopeGuard
	loadedAt time.Time
	uses     int
	valid    bool
}

func newCandidateGuard(load func(context.Context) (ScopeGuard, error)) *candidateGuard {
	return &candidateGuard{load: load, now: time.Now}
}

func (c *candidateGuard) get(ctx context.Context) (ScopeGuard, error) {
	if err := ctx.Err(); err != nil {
		return ScopeGuard{}, err
	}
	now := c.now()
	if !c.valid || c.uses >= candidateGuardBatchSize || now.Sub(c.loadedAt) >= candidateGuardMaxAge {
		// Failed refreshes must never fall back to an old authorization snapshot.
		c.valid = false
		g, err := c.load(ctx)
		if err != nil {
			return ScopeGuard{}, err
		}
		c.guard, c.loadedAt, c.uses, c.valid = g, now, 0, true
	}
	c.uses++
	return c.guard, nil
}

func consumeCandidates(ctx context.Context, stream <-chan Candidate, load func(context.Context) (ScopeGuard, error), accept func(string)) (SourceStats, error) {
	stats := SourceStats{}
	batch := newCandidateGuard(load)
	for {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		case candidate, ok := <-stream:
			if !ok {
				return stats, nil
			}
			stats.Returned++
			g, err := batch.get(ctx)
			if err != nil {
				return stats, err
			}
			host, err := g.AllowHost(candidate.Host)
			if err != nil {
				stats.Discarded++
				continue
			}
			stats.InScope++
			accept(host)
		}
	}
}
