package main

import (
	"context"
	"net/netip"
	"testing"
)

// Characterization, not acceptance tests. Remove the old expectation when the
// corresponding W item is fixed and replace it with its contract/acceptance test.
func TestP0CharacterizeClassification(t *testing.T) {
	for _, host := range []string{"contest.example.test", "capital.example.test"} {
		category, score := categoryScore(host, false)
		if category != "未分类" || score != 10 {
			t.Fatalf("W05 regression for %s: %s/%d", host, category, score)
		}
		t.Logf("W05 boundary regression: host=%s category=%s score=%d", host, category, score)
	}
}

func TestP0CharacterizeEmbeddedIPv4(t *testing.T) {
	for _, raw := range []string{"64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::1", "2002:a00:1::1"} {
		if publicIP(netip.MustParseAddr(raw)) {
			t.Fatal("W02 regression: embedded private IPv4 must be refused")
		}
		t.Logf("W02 classifier refuses %s; no real translator tested", raw)
	}
}

func TestP0LongEventKey(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		t.Fatal("P0 transaction failed")
	}
	defer tx.Rollback(ctx)
	scope := insertScope(t, s, 1)
	if err = addEvent(ctx, tx, scope.ID, 1, 0, "IP_CHANGED", w01LongDetail()); err != nil {
		t.Fatal("W01 regression: legal 64KiB event must succeed")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("W01 regression: transaction must commit")
	}
	t.Log("W01 fixed: legal 64KiB event commits; old failing reproduction is archived with the red acceptance run")
}
