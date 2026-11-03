package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestW05ClassificationContract(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	write := func(o Observation) {
		t.Helper()
		run := claimedRun(t, s, scope)
		if _, err := s.WriteResults(ctx, run, []Observation{o}, false); err != nil {
			t.Fatal(err)
		}
		closeRun(t, s, run)
	}
	read := func() (int64, string, int, map[string]any) {
		t.Helper()
		var id int64
		var category string
		var score int
		var raw []byte
		if err := s.DB.QueryRow(ctx, `SELECT id,category,score,to_jsonb(a)->'classification' FROM assets a WHERE host='api2.example.com'`).Scan(&id, &category, &score, &raw); err != nil {
			t.Fatal(err)
		}
		var detail map[string]any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &detail); err != nil {
				t.Fatal(err)
			}
		}
		return id, category, score, detail
	}
	write(Observation{Host: "api2.example.com", Alive: ptr(true)})
	id, category, score, detail := read()
	if category != "API" || score != 40 || detail["mode"] != "auto" || detail["version"] == nil || detail["keyword"] != "api" || detail["root"] != "example.com" {
		t.Fatalf("missing classification contract: %s/%d %#v", category, score, detail)
	}
	e := &Engine{Store: s}
	patch := func(body string, user User, want int) {
		t.Helper()
		w := apiRecorder()
		e.serve(w, apiRequest("PATCH", fmt.Sprintf("/api/assets/%d", id), body), user)
		if w.Code != want {
			t.Fatalf("patch: %d %s", w.Code, w.Body.String())
		}
	}
	admin := User{ID: 1, Role: "admin"}
	patch(`{"category_override":"业务入口"}`, User{ID: 99, Role: "user"}, 404)
	patch(`{"category_override":"业务入口"}`, User{ID: 1, Role: "readonly"}, 403)
	patch(`{"category_override":"业务入口"}`, admin, 200)
	var snapshots int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM asset_snapshots WHERE asset_id=$1`, id).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	patch(`{"category_override":"业务入口"}`, admin, 200)
	var replaySnapshots int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM asset_snapshots WHERE asset_id=$1`, id).Scan(&replaySnapshots); err != nil || replaySnapshots != snapshots {
		t.Fatal("repeated patch added a snapshot", err)
	}
	// A future rule-version bump refreshes only explicitly automatic/manual rows.
	p0Exec(t, s, `UPDATE assets SET classification=jsonb_set(classification,'{version}','"old-fixture-version"') WHERE id=$1`, id)
	for range 3 {
		write(Observation{Host: "api2.example.com", Alive: ptr(false)})
	}
	_, category, score, detail = read()
	if category != "业务入口" || score != 30 || detail["mode"] != "manual" || detail["version"] != categoryRuleVersion {
		t.Fatalf("override not retained with refreshed score: %s/%d %#v", category, score, detail)
	}
	patch(`{"category_override":null}`, admin, 200)
	_, category, score, detail = read()
	if category != "API" || score != 30 || detail["mode"] != "auto" {
		t.Fatal("reset did not restore automatic classification")
	}
	write(Observation{Host: "api2.example.com", Alive: ptr(true), EvidenceOnly: true})
	_, _, score, _ = read()
	if score != 30 {
		t.Fatal("provider evidence raised live score")
	}
	write(Observation{Host: "api2.example.com", Alive: ptr(true)})
	_, _, score, _ = read()
	if score != 40 {
		t.Fatal("real HTTP recovery did not refresh score")
	}
	for _, bad := range []string{`{"category_override":""}`, `{"category_override":true}`, `{"category_override":123}`, `{"category_override":"a\nb"}`, `{"category_override":"\na"}`} {
		patch(bad, admin, 400)
	}
	patch(mustJSON(map[string]any{"category_override": strings.Repeat("中", 43)}), admin, 400)
}

func TestW05Migration17To18PreservesLegacy(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.DB)
	defer db.Close()
	if err := goose.DownToContext(ctx, db, "migrations", 17); err != nil {
		t.Fatal(err)
	}
	scope := insertScope(t, s, 1)
	p0Exec(t, s, `INSERT INTO assets(scope_id,host,category,score,is_alive,miss_count)VALUES($1,'contest.example.com','旧分类',77,true,2)`, scope.ID)
	var before, after []byte
	if err := s.DB.QueryRow(ctx, `SELECT to_jsonb(a) FROM assets a`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpToContext(ctx, db, "migrations", 18); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, `SELECT to_jsonb(a)-'classification'-'category_override' FROM assets a WHERE classification IS NULL AND category_override IS NULL`).Scan(&after); err != nil || string(before) != string(after) {
		t.Fatal("migration changed a legacy asset", err)
	}
	if err := goose.UpToContext(ctx, db, "migrations", 18); err != nil {
		t.Fatal("migration replay", err)
	}
	var count int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM assets WHERE classification IS NULL AND category_override IS NULL`).Scan(&count); err != nil || count != 1 {
		t.Fatal("migration replay changed provenance", err)
	}
	for _, q := range []string{`UPDATE assets SET classification='[]'::jsonb`, `UPDATE assets SET classification=jsonb_build_object('too_long',repeat('a',8192))`, `UPDATE assets SET category_override=''`, `UPDATE assets SET category_override=repeat('a',129)`} {
		if _, err := s.DB.Exec(ctx, q); err == nil {
			t.Fatal("classification bounds not enforced")
		}
	}
}

func TestW05FirstCreationConflictKeepsManualOverride(t *testing.T) {
	s, _ := p0Store(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scope := insertScope(t, s, 1)
	run := claimedRun(t, s, scope)
	// The other creator holds an uncommitted row. The writer's first SELECT
	// cannot see it, then its INSERT must wait for this creator to commit.
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var pid int
	if err = tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO assets(scope_id,host,category,score,category_override,classification) VALUES($1,'api-conflict.example.com','人工先提交',30,'人工先提交',$2::jsonb)`, scope.ID, mustJSON(evaluateCategory("api-conflict.example.com", false, scope.Domain))); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.WriteResults(ctx, run, []Observation{{Host: "api-conflict.example.com", Alive: ptr(true)}}, false)
		done <- err
	}()
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for waiting := true; waiting; {
		select {
		case err := <-done:
			t.Fatalf("writer finished before conflict barrier: %v", err)
		case <-deadline.C:
			t.Fatal("writer did not reach unique-row lock barrier")
		case <-tick.C:
			var blocked bool
			if err = s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			waiting = !blocked
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	var category string
	var override *string
	var score int
	if err = s.DB.QueryRow(ctx, `SELECT category,category_override,score FROM assets WHERE host='api-conflict.example.com'`).Scan(&category, &override, &score); err != nil {
		t.Fatal(err)
	}
	if category != "人工先提交" || override == nil || *override != "人工先提交" || score != 40 {
		t.Fatalf("creation conflict overwrote manual category: %s/%v/%d", category, override, score)
	}
}

func TestW05ImportAndBatchAtomicity(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	e := &Engine{Store: s}
	admin := User{ID: 1, Role: "admin"}
	w := apiRecorder()
	e.serve(w, apiRequest("POST", "/api/import", fmt.Sprintf(`{"scope_id":%d,"hosts":"api-import.example.com"}`, scope.ID)), admin)
	if w.Code != 200 {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}
	var id int64
	var category string
	var score int
	var raw []byte
	if err := s.DB.QueryRow(ctx, `SELECT id,category,score,classification FROM assets WHERE host='api-import.example.com'`).Scan(&id, &category, &score, &raw); err != nil || category != "API" || score != 30 || !strings.Contains(string(raw), categoryRuleVersion) {
		t.Fatalf("import missed classification: %s/%d %s %v", category, score, raw, err)
	}
	w = apiRecorder()
	e.serve(w, apiRequest("PATCH", "/api/assets/batch", fmt.Sprintf(`{"ids":[%d,99999999],"category_override":"should rollback"}`, id)), admin)
	if w.Code != 404 {
		t.Fatal("partial authorization accepted", w.Code)
	}
	if err := s.DB.QueryRow(ctx, `SELECT category FROM assets WHERE id=$1`, id).Scan(&category); err != nil || category != "API" {
		t.Fatal("partial batch changed valid row", err)
	}
	w = apiRecorder()
	e.serve(w, apiRequest("PATCH", "/api/assets/batch", fmt.Sprintf(`{"ids":[%d,%d],"category_override":"业务入口","note":"retained","security_device_override":false}`, id, id)), admin)
	if w.Code != 200 {
		t.Fatal("batch patch", w.Code, w.Body.String())
	}
	var snapshots int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM asset_snapshots WHERE asset_id=$1 AND payload->>'category'='业务入口' AND payload->>'note'='retained' AND payload->>'security_device_override'='false'`, id).Scan(&snapshots); err != nil || snapshots != 1 {
		t.Fatal("combined patch snapshot inconsistent", snapshots, err)
	}
}

func TestW05LegacyNeedsExplicitOptIn(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	p0Exec(t, s, `INSERT INTO assets(scope_id,host,category,score)VALUES($1,'contest.example.com','旧分类',77)`, scope.ID)
	run := claimedRun(t, s, scope)
	if _, err := s.WriteResults(ctx, run, []Observation{{Host: "contest.example.com", Alive: ptr(true)}}, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, s, run)
	var id int64
	var category string
	var score int
	var raw []byte
	if err := s.DB.QueryRow(ctx, `SELECT id,category,score,to_jsonb(a)->'classification' FROM assets a`).Scan(&id, &category, &score, &raw); err != nil {
		t.Fatal(err)
	}
	if category != "旧分类" || score != 77 || (len(raw) > 0 && string(raw) != "null") {
		t.Fatalf("legacy changed: %s/%d %s", category, score, raw)
	}
	e := &Engine{Store: s}
	w := apiRecorder()
	e.serve(w, apiRequest("PATCH", fmt.Sprintf("/api/assets/%d", id), `{"category_override":null}`), User{ID: 1, Role: "admin"})
	if w.Code != 200 {
		t.Fatalf("opt-in: %d %s", w.Code, w.Body.String())
	}
	if err := s.DB.QueryRow(ctx, `SELECT category,score FROM assets WHERE id=$1`, id).Scan(&category, &score); err != nil {
		t.Fatal(err)
	}
	if category != "未分类" || score != 20 {
		t.Fatal("explicit opt-in did not recompute legacy")
	}
}
