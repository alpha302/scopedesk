package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestPostgresPluginPlanReferencesAndPermissions(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	m := fixturePlugin(t, "jsonl", "jsonl")
	registerFixture(t, s, m)
	a := insertScope(t, s, 1)
	b := insertScope(t, s, 2)
	c := insertScope(t, s, 3)
	for _, p := range []struct {
		id      int64
		enabled bool
		sources string
	}{{a.ID, true, `["fixture","crtsh"]`}, {b.ID, false, `["fixture"]`}, {c.ID, true, `["certspotter"]`}} {
		if _, err := s.DB.Exec(ctx, "INSERT INTO monitor_plans(scope_id,enabled,collectors)VALUES($1,$2,$3)", p.id, p.enabled, p.sources); err != nil {
			t.Fatal(err)
		}
	}
	e := &Engine{Store: s}
	w := apiRecorder()
	e.serve(w, apiRequest("GET", "/api/plugins", ""), User{ID: 1, Role: "admin"})
	var plugins []struct {
		Name    string                `json:"name"`
		Count   int                   `json:"plan_count"`
		Enabled int                   `json:"enabled_plan_count"`
		Refs    []PluginPlanReference `json:"plan_references"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &plugins) != nil {
		t.Fatal(w.Body.String())
	}
	seen := false
	for _, p := range plugins {
		if p.Name == "fixture" {
			seen = true
			if p.Count != 2 || p.Enabled != 1 || len(p.Refs) != 2 || p.Refs[0].ScopeID != a.ID || p.Refs[1].Owner != 2 || p.Refs[1].Enabled {
				t.Fatal("wrong plan impact", p)
			}
		}
		if p.Name == "builtin-dns" && (p.Count != 0 || p.Refs == nil) {
			t.Fatal("empty references not an array", p)
		}
	}
	if !seen {
		t.Fatal("external plugin missing")
	}
	for _, role := range []string{"user", "readonly"} {
		w = apiRecorder()
		e.serve(w, apiRequest("GET", "/api/plugins", ""), User{ID: 1, Role: role})
		if w.Code != 403 {
			t.Fatal("plan references disclosed to non-admin", role, w.Code)
		}
	}
	// Reporting impact must not modify plans when the administrator saves a disable.
	w = apiRecorder()
	e.serve(w, apiRequest("PUT", "/api/plugins/fixture", `{"enabled":false,"params":{}}`), User{ID: 1, Role: "admin"})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var enabled bool
	if err := s.DB.QueryRow(ctx, "SELECT enabled FROM monitor_plans WHERE scope_id=$1", a.ID).Scan(&enabled); err != nil || !enabled {
		t.Fatal("plugin disable silently changed plan", err)
	}
}

func TestPostgresPluginJSONLQualityStatsPersist(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	m := fixturePlugin(t, "jsonl-mixed", "jsonl")
	registerFixture(t, s, m)
	if _, err := s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true"); err != nil {
		t.Fatal(err)
	}
	q := PGQueue{s}
	payload, _ := json.Marshal(map[string]any{"sources": []string{m.Name}, "target": "example.com"})
	if _, err := s.DB.Exec(ctx, "INSERT INTO jobs(scope_id,owner,trigger,payload)VALUES($1,1,'plugin_test',$2)", scope.ID, payload); err != nil {
		t.Fatal(err)
	}
	run, err := q.Claim(ctx, "quality-fixture")
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: s, Queue: &q, root: ctx}
	e.execute(run)
	for _, table := range []string{"plugin_runs", "job_source_stats"} {
		var raw []byte
		if err = s.DB.QueryRow(ctx, "SELECT rejected_fields FROM "+table+" WHERE job_id=$1", run.ID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var fields map[string]int
		if json.Unmarshal(raw, &fields) != nil || fields["malformed_jsonl"] != 1 {
			t.Fatal("bad-line count lost", table, string(raw))
		}
	}
	var status string
	if err = s.DB.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", run.ID).Scan(&status); err != nil || status != "done" {
		t.Fatal("tolerated parse failed test job", status, err)
	}
	w := apiRecorder()
	e.serve(w, apiRequest("GET", "/api/plugins/fixture/runs", ""), User{ID: 1, Role: "admin"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"malformed_jsonl":1`) || strings.Contains(w.Body.String(), "fixture-private-badline") {
		t.Fatal("quality API or redaction", w.Body.String())
	}
	var count int
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM assets").Scan(&count); err != nil || count != 0 {
		t.Fatal("test run wrote assets", count, err)
	}
}

func TestPostgresPluginMalformedOutputSuppressesMissingEvents(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	m := fixturePlugin(t, "jsonl-mixed", "jsonl")
	registerFixture(t, s, m)
	if _, err := s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, "INSERT INTO assets(scope_id,host,miss_count,is_alive)VALUES($1,'missing.example.com',2,true)", scope.ID); err != nil {
		t.Fatal(err)
	}
	q := PGQueue{s}
	job, err := q.Enqueue(ctx, scope, []string{m.Name}, "test")
	if err != nil {
		t.Fatal(err)
	}
	run, err := q.Claim(ctx, "quality-coverage-worker")
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: s, Queue: &q, root: ctx, Pipeline: evidenceTestPipeline(t, s)}
	e.execute(run)
	var raw []byte
	var status string
	if err = s.DB.QueryRow(ctx, "SELECT status,stats FROM jobs WHERE id=$1", job).Scan(&status, &raw); err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Complete         bool `json:"complete"`
		FormatIncomplete bool `json:"format_incomplete"`
		New              int  `json:"new"`
	}
	if json.Unmarshal(raw, &summary) != nil || status != "done" || summary.Complete || !summary.FormatIncomplete || summary.New != 9 {
		t.Fatal("bad lines marked as complete coverage or discarded valid results", status, string(raw))
	}
	var miss, count int
	if err = s.DB.QueryRow(ctx, "SELECT miss_count FROM assets WHERE scope_id=$1 AND host='missing.example.com'", scope.ID).Scan(&miss); err != nil || miss != 2 {
		t.Fatal("bad line caused false missing increment", miss, err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM asset_events WHERE scope_id=$1 AND type='ASSET_DOWN'", scope.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("bad line caused false down event", count, err)
	}
}
