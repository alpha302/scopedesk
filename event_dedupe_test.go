package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func w01LongDetail() map[string]any {
	var evidence strings.Builder
	for i := 0; i < 1024; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("w01-evidence-%d", i)))
		fmt.Fprintf(&evidence, "%x", sum)
	}
	return map[string]any{"host": strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), "evidence": evidence.String(), "title": "合法中文证据"}
}

func TestW01KeyContract(t *testing.T) {
	at := time.Date(2026, 11, 3, 15, 59, 59, 0, time.UTC)
	key := func(scope, asset int64, kind string, when time.Time, detail any) string {
		t.Helper()
		k, _, _, err := eventDedupeKey(scope, asset, kind, when, detail)
		if err != nil {
			t.Fatal("key generation failed")
		}
		if len(k) != 67 || !strings.HasPrefix(k, "v2:") {
			t.Fatal("event key is not fixed-length and versioned")
		}
		return k
	}
	a := json.RawMessage(`{"after":["9.9.9.9","1.1.1.1"],"before":["8.8.8.8"],"title":"中文"}`)
	b := json.RawMessage(`{"title":"中文","before":["8.8.8.8"],"after":["1.1.1.1","9.9.9.9","1.1.1.1"]}`)
	base := key(1, 2, "IP_CHANGED", at, a)
	if base != key(1, 2, "IP_CHANGED", at, b) {
		t.Fatal("object order and IP-set order/duplicates must be equivalent")
	}
	for _, other := range []string{
		key(9, 2, "IP_CHANGED", at, a), key(1, 9, "IP_CHANGED", at, a), key(1, 2, "OTHER", at, a),
		key(1, 2, "IP_CHANGED", at.Add(time.Second), a),
		key(1, 2, "IP_CHANGED", at, json.RawMessage(`{"before":["9.9.9.9","1.1.1.1"],"after":["8.8.8.8"],"title":"中文"}`)),
	} {
		if other == base {
			t.Fatal("different scope/asset/type/Shanghai day/direction must remain distinct")
		}
	}
	if key(1, 2, "OTHER", at, map[string]any{"steps": []string{"a", "b"}}) == key(1, 2, "OTHER", at, map[string]any{"steps": []string{"b", "a"}}) {
		t.Fatal("arbitrary evidence arrays must retain order")
	}
	if key(1, 2, "OTHER", at, json.RawMessage(`{"n":9007199254740992}`)) == key(1, 2, "OTHER", at, json.RawMessage(`{"n":9007199254740993}`)) {
		t.Fatal("large integer evidence must not be rounded")
	}
	if key(1, 2, "NEW_ASSET", at, map[string]any{"sources": []string{"crtsh", "manual"}}) != key(1, 2, "NEW_ASSET", at, map[string]any{"sources": []string{"manual", "crtsh"}}) {
		t.Fatal("source sets must be order independent")
	}
}

func TestW01EvidenceValidation(t *testing.T) {
	for _, tc := range []struct {
		detail any
		want   error
	}{
		{make(chan int), errEventDetailEncoding},
		{json.RawMessage(`{"broken":`), errEventDetailEncoding},
		{map[string]string{"body": strings.Repeat("x", maxEventDetailBytes)}, errEventDetailTooLarge},
	} {
		if _, _, _, err := eventDedupeKey(1, 1, "TEST", time.Now(), tc.detail); !errors.Is(err, tc.want) {
			t.Fatal("invalid or oversized evidence must return explicit sanitized error")
		}
	}
	// Exactly the documented encoded byte boundary is accepted; one more fails.
	for _, n := range []int{maxEventDetailBytes, maxEventDetailBytes + 1} {
		detail := json.RawMessage(`"` + strings.Repeat("x", n-2) + `"`)
		_, _, _, err := eventDedupeKey(1, 1, "TEST", time.Now(), detail)
		if (n == maxEventDetailBytes && err != nil) || (n > maxEventDetailBytes && !errors.Is(err, errEventDetailTooLarge)) {
			t.Fatal("encoded evidence byte boundary incorrect")
		}
	}
}

func TestW01LegacyAndDayCompatibility(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	at := time.Now()
	day := at.In(shanghai).Format("2006-01-02")
	old := json.RawMessage(`{"after":["9.9.9.9","1.1.1.1"],"before":["8.8.8.8"],"label":"旧证据"}`)
	legacy := fmt.Sprintf("1:IP_CHANGED:%s:%x", day, []byte(old))
	p0Exec(t, s, `INSERT INTO event_dedupes(key)VALUES($1)`, legacy)
	p0Exec(t, s, `INSERT INTO asset_events(scope_id,asset_id,job_id,type,detail,dedupe_key,created_at)VALUES($1,1,0,'IP_CHANGED',$2,$3,$4)`, scope.ID, []byte(old), legacy, at)
	reordered := json.RawMessage(`{"label":"旧证据","before":["8.8.8.8"],"after":["1.1.1.1","9.9.9.9"]}`)
	for _, when := range []time.Time{at, at, at.AddDate(0, 0, 1)} {
		tx, err := s.DB.Begin(ctx)
		if err != nil {
			t.Fatal("transaction failed")
		}
		if err := addEventAt(ctx, tx, scope.ID, 1, 99, "IP_CHANGED", reordered, when); err != nil {
			tx.Rollback(ctx)
			t.Fatal("legacy replay failed")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal("legacy replay commit failed")
		}
	}
	var events, oldKeys, newKeys int
	err := s.DB.QueryRow(ctx, `SELECT (SELECT count(*)FROM asset_events),(SELECT count(*)FROM event_dedupes WHERE key=$1),(SELECT count(*)FROM event_dedupes WHERE key LIKE 'v2:%')`, legacy).Scan(&events, &oldKeys, &newKeys)
	if err != nil || events != 2 || oldKeys != 1 || newKeys != 2 {
		t.Fatal("same-day old key must suppress replay, next day must retain event, legacy key must remain unchanged")
	}
	var oldEvidence string
	if err := s.DB.QueryRow(ctx, `SELECT detail->>'label' FROM asset_events WHERE dedupe_key=$1`, legacy).Scan(&oldEvidence); err != nil || oldEvidence != "旧证据" {
		t.Fatal("legacy evidence changed")
	}
}

func TestW01ConcurrentReplayAndRollback(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	detail := w01LongDetail()
	// A rolled-back reservation must not suppress a later successful event.
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		t.Fatal("transaction failed")
	}
	if err := addEvent(ctx, tx, scope.ID, 1, 0, "IP_CHANGED", detail); err != nil {
		tx.Rollback(ctx)
		t.Fatal("rollback fixture failed")
	}
	tx.Rollback(ctx)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx, err := s.DB.Begin(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer tx.Rollback(ctx)
			if err := addEvent(ctx, tx, scope.ID, 1, int64(i), "IP_CHANGED", detail); err != nil {
				errs <- err
				return
			}
			errs <- tx.Commit(ctx)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent event failed: %T", err)
		}
	}
	var events, keys int
	if err := s.DB.QueryRow(ctx, `SELECT (SELECT count(*)FROM asset_events),(SELECT count(*)FROM event_dedupes)`).Scan(&events, &keys); err != nil || events != 1 || keys != 1 {
		t.Fatal("16 concurrent job replays must commit exactly one event")
	}
}

func TestW01WholeResultTransaction(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	run := claimedRun(t, s, scope)
	sources := make([]string, 1024)
	for i := range sources {
		sum := sha256.Sum256([]byte(fmt.Sprintf("fixture-source-%d", i)))
		sources[i] = fmt.Sprintf("fixture-%x", sum)
	}
	obs := []Observation{{Host: "api.example.com", Sources: sources, IPs: []string{}, CNames: []string{}, EvidenceOnly: true, PreserveReachability: true}, {Host: "other.example.com", Sources: []string{"manual"}, IPs: []string{}, CNames: []string{}, EvidenceOnly: true, PreserveReachability: true}}
	if _, err := s.WriteResults(ctx, run, obs, false); err != nil {
		t.Fatalf("large event must not roll back the full result transaction: %T", err)
	}
	var assets, events, snapshots, largeEvidence int
	err := s.DB.QueryRow(ctx, `SELECT (SELECT count(*)FROM assets),(SELECT count(*)FROM asset_events),(SELECT count(*)FROM asset_snapshots),(SELECT max(jsonb_array_length(detail->'sources'))FROM asset_events WHERE type='NEW_ASSET')`).Scan(&assets, &events, &snapshots, &largeEvidence)
	if err != nil || assets != 2 || events != 2 || snapshots != 2 || largeEvidence != 1024 {
		t.Fatal("full result transaction or original event evidence was lost")
	}
}

func TestW01Migration15To16(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.DB)
	defer db.Close()
	if err := goose.DownToContext(ctx, db, "migrations", 15); err != nil {
		t.Fatal("isolated downgrade to v15 failed")
	}
	scope := insertScope(t, s, 1)
	at := time.Now()
	raw := []byte(`{"host":"api.example.com","sources":["manual"]}`)
	legacy := fmt.Sprintf("1:NEW_ASSET:%s:%x", at.In(shanghai).Format("2006-01-02"), raw)
	p0Exec(t, s, `INSERT INTO event_dedupes(key)VALUES($1)`, legacy)
	p0Exec(t, s, `INSERT INTO asset_events(scope_id,asset_id,type,detail,dedupe_key,created_at)VALUES($1,1,'NEW_ASSET',$2,$3,$4)`, scope.ID, raw, legacy, at)
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatal("isolated v15 to v16 migration failed")
	}
	version, err := goose.GetDBVersionContext(ctx, db)
	if err != nil || version != 16 {
		t.Fatal("expected migration 16")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		t.Fatal("migration replay transaction failed")
	}
	if err := addEventAt(ctx, tx, scope.ID, 1, 0, "NEW_ASSET", json.RawMessage(raw), at); err != nil {
		tx.Rollback(ctx)
		t.Fatal("migrated legacy replay failed")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("migrated replay commit failed")
	}
	var events, legacyKeys int
	if err := s.DB.QueryRow(ctx, `SELECT (SELECT count(*)FROM asset_events),(SELECT count(*)FROM event_dedupes WHERE key=$1)`, legacy).Scan(&events, &legacyKeys); err != nil || events != 1 || legacyKeys != 1 {
		t.Fatal("migration/replay changed legacy rows or duplicated event")
	}
	if err := goose.DownToContext(ctx, db, "migrations", 15); err != nil {
		t.Fatal("migration 16 index rollback failed")
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatal("migration 16 reapply failed")
	}
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
