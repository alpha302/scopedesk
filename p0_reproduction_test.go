package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Characterization, not acceptance tests. Remove the old expectation when the
// corresponding W item is fixed and replace it with its contract/acceptance test.
func TestP0CharacterizeClassification(t *testing.T) {
	for _, host := range []string{"contest.example.test", "capital.example.test"} {
		category, score := categoryScore(host, false)
		if category == "未分类" {
			t.Fatalf("baseline changed for %s; update W05 reproduction status", host)
		}
		t.Logf("W05 current false-positive fixture: host=%s category=%s score=%d", host, category, score)
	}
}

func TestP0CharacterizeEmbeddedIPv4(t *testing.T) {
	for _, raw := range []string{"64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::1", "2002:a00:1::1"} {
		if !publicIP(netip.MustParseAddr(raw)) {
			t.Fatal("baseline changed; update W02 classification reproduction status")
		}
		t.Logf("W02 classifier accepts %s; actual NAT64/6to4 routing/dial impact remains unverified", raw)
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
	var detail strings.Builder
	for i := 0; i < 1024; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("p0-long-evidence-%d", i)))
		fmt.Fprintf(&detail, "%x", sum)
	}
	err = addEvent(ctx, tx, 1, 1, 0, "IP_CHANGED", map[string]string{"evidence": detail.String()})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "54000" {
		t.Fatal("expected current oversized B-tree key failure; investigate and update W01 reproduction")
	}
	t.Log("W01 reproduced: addEvent rejected 64KiB synthetic detail with SQLSTATE 54000; transaction rolled back")
}
