package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func w01LongDetail() map[string]any {
	var evidence strings.Builder
	for i := 0; i < 1024; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("w01-evidence-%d", i)))
		fmt.Fprintf(&evidence, "%x", sum)
	}
	return map[string]any{"host": strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), "evidence": evidence.String(), "title": "合法中文证据"}
}

// Acceptance test: fails on the old implementation with SQLSTATE 54000.
func TestW01LongDetailCommits(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		t.Fatal("transaction unavailable")
	}
	defer tx.Rollback(ctx)
	detail := w01LongDetail()
	if err := addEvent(ctx, tx, scope.ID, 1, 0, "IP_CHANGED", detail); err != nil {
		t.Fatalf("64KiB evidence must commit without an oversized index key: %T", err)
	}
	if err := addEvent(ctx, tx, scope.ID, 1, 0, "IP_CHANGED", detail); err != nil {
		t.Fatal("replay must succeed")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("event transaction must commit")
	}
	var count, keyLength int
	var retained, title string
	err = s.DB.QueryRow(ctx, `SELECT count(*),max(length(dedupe_key)),max(detail->>'evidence'),max(detail->>'title') FROM asset_events`).Scan(&count, &keyLength, &retained, &title)
	if err != nil || count != 1 || keyLength != 67 || retained != detail["evidence"] || title != "合法中文证据" {
		t.Fatal("event must be deduplicated, fixed-length and preserve original evidence")
	}
}
