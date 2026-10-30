package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCandidateGuardRefreshBoundsAndFailures(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	calls := 0
	fail := false
	current := ScopeGuard{Scope: sampleScope()}
	batch := newCandidateGuard(func(context.Context) (ScopeGuard, error) {
		calls++
		if fail {
			return ScopeGuard{}, errors.New("fixture refresh failed")
		}
		return current, nil
	})
	batch.now = func() time.Time { return now }
	for range candidateGuardBatchSize {
		if _, err := batch.get(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("snapshot not reused", calls)
	}
	current.Scope.Exclusions = []string{"api.example.com"}
	g, err := batch.get(ctx)
	if err != nil || calls != 2 {
		t.Fatal("candidate-count refresh missing", calls, err)
	}
	if _, err := g.AllowHost("api.example.com"); err == nil {
		t.Fatal("refreshed exclusion ignored")
	}
	now = now.Add(candidateGuardMaxAge)
	current.Blacklist = []string{"blocked.example.com"}
	g, err = batch.get(ctx)
	if err != nil || calls != 3 {
		t.Fatal("time refresh missing", calls, err)
	}
	if _, err := g.AllowHost("blocked.example.com"); err == nil {
		t.Fatal("refreshed blacklist ignored")
	}
	fail = true
	now = now.Add(candidateGuardMaxAge)
	if _, err := batch.get(ctx); err == nil {
		t.Fatal("stale authorization used after refresh failure")
	}
	fail = false
	current.Scope.Confirmed = false
	g, err = batch.get(ctx)
	if err != nil || calls != 5 || g.Valid() == nil {
		t.Fatal("failed snapshot was reused or revocation ignored", calls, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := batch.get(cancelled); !errors.Is(err, context.Canceled) || calls != 5 {
		t.Fatal("cancelled snapshot access", calls, err)
	}
}

func TestCandidateGuardChecksExpiryWithinSnapshot(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Second)
	scope := sampleScope()
	scope.Expires = &expires
	calls := 0
	batch := newCandidateGuard(func(context.Context) (ScopeGuard, error) {
		calls++
		return ScopeGuard{Scope: scope, Now: func() time.Time { return now }}, nil
	})
	batch.now = func() time.Time { return now }
	g, _ := batch.get(context.Background())
	if _, err := g.AllowHost("api.example.com"); err != nil {
		t.Fatal(err)
	}
	now = expires
	g, _ = batch.get(context.Background())
	if _, err := g.AllowHost("api.example.com"); err == nil || calls != 1 {
		t.Fatal("cached snapshot bypasses expiration", calls)
	}
}

func TestCandidateFilteringRefreshesAndFailsClosed(t *testing.T) {
	for _, failure := range []bool{false, true} {
		calls := 0
		load := func(context.Context) (ScopeGuard, error) {
			calls++
			g := ScopeGuard{Scope: sampleScope()}
			if calls > 1 {
				if failure {
					return ScopeGuard{}, errors.New("fixture database unavailable")
				}
				g.Scope.Confirmed = false
			}
			return g, nil
		}
		m := PluginManifest{Name: "guard-fixture", Kind: "collector"}
		m.Output.Format = "jsonl"
		m.Output.Mapping = map[string]string{"host": "host"}
		m.Exec.MaxOutput = 8000000
		result := PluginResult{}
		err := parsePluginStream(context.Background(), strings.NewReader(goodJSONLLines(300)), m, load, &result)
		if (err != nil) != failure || len(result.Records) != 256 || calls != 2 {
			t.Fatal("parser continued with stale scope", len(result.Records), calls, err)
		}
		calls = 0
		stream := make(chan Candidate, 300)
		for range 300 {
			stream <- Candidate{Host: "api.example.com"}
		}
		close(stream)
		accepted := 0
		stats, err := consumeCandidates(context.Background(), stream, load, func(string) { accepted++ })
		if (err != nil) != failure || accepted != 256 || stats.InScope != 256 || calls != 2 {
			t.Fatal("consumer continued with stale scope", accepted, calls, err)
		}
	}
}
