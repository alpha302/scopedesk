package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// PostgreSQL acceptance, not part of the portable Windows policy test command.
func TestUXIncompatibleSourcesNeverCreateJobs(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	s.Plugins = nil
	scope := insertScope(t, s, 1)
	p0Exec(t, s, `UPDATE scopes SET mode='exact',confirmed=true WHERE id=$1`, scope.ID)
	e := &Engine{Store: s, Queue: &PGQueue{s}, root: ctx, WorkerID: "ux-fixture", workers: 1}
	u := User{ID: 1, Role: "admin"}
	for _, tc := range []struct{ path, body, method string }{
		{fmt.Sprintf("/api/scopes/%d/run", scope.ID), `{"sources":["subfinder"],"collection_mode":"profile"}`, "POST"},
		{fmt.Sprintf("/api/scopes/%d/plan", scope.ID), `{"enabled":true,"interval_hours":24,"collectors":["subfinder"],"collection_mode":"profile"}`, "PUT"},
	} {
		w := apiRecorder()
		e.serve(w, apiRequest(tc.method, tc.path, tc.body), u)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "subfinder") {
			t.Fatalf("incompatible source accepted: %d %s", w.Code, w.Body.String())
		}
	}
	p0Exec(t, s, `INSERT INTO monitor_plans(scope_id,enabled,interval_hours,collectors,collection_mode,next_run_at)VALUES($1,true,24,'["subfinder"]','profile',now()-interval '1 minute')ON CONFLICT(scope_id)DO UPDATE SET enabled=true,collectors='["subfinder"]',collection_mode='profile',next_run_at=now()-interval '1 minute',retry_at=NULL`, scope.ID)
	e.scheduleTick()
	var jobs int
	var mode, reason string
	var enabled bool
	if err := s.DB.QueryRow(ctx, `SELECT (SELECT count(*)FROM jobs),s.mode,p.schedule_error,p.enabled FROM scopes s JOIN monitor_plans p ON p.scope_id=s.id WHERE s.id=$1`, scope.ID).Scan(&jobs, &mode, &reason, &enabled); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 || mode != "exact" || !enabled || !strings.Contains(reason, "subfinder") {
		t.Fatalf("scheduler failed to block without altering authorization: jobs=%d mode=%s enabled=%t reason=%s", jobs, mode, enabled, reason)
	}
	// Fixing the saved source selection resumes ordinary scheduling. No worker is
	// started: this only creates a synthetic queue row in the temporary schema.
	p0Exec(t, s, `UPDATE monitor_plans SET collectors='["certspotter"]',retry_at=NULL WHERE scope_id=$1`, scope.ID)
	e.scheduleTick()
	if err := s.DB.QueryRow(ctx, `SELECT count(*)FROM jobs`).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal("valid source did not resume scheduling", jobs, err)
	}
}

func TestUXSavedDefaultsAndTargetHistory(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	s.Plugins = nil
	scope := insertScope(t, s, 1)
	other := insertScope(t, s, 2)
	p0Exec(t, s, `UPDATE scopes SET mode='exact',confirmed=true WHERE id=$1`, scope.ID)
	e := &Engine{Store: s, Queue: &PGQueue{s}, root: ctx, WorkerID: "ux-fixture", workers: 1}
	u := User{ID: 1, Role: "admin"}
	w := projectCall(e, u, "PUT", fmt.Sprintf("/api/scopes/%d/plan", scope.ID), `{"enabled":false,"interval_hours":24,"collectors":["certspotter"],"collection_mode":"evidence_only"}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	path := fmt.Sprintf("/api/scopes/%d/run", scope.ID)
	w = projectCall(e, u, "POST", path, `{"use_saved_config":true,"sources":["subfinder"]}`)
	if w.Code != 400 {
		t.Fatal("saved config override accepted", w.Code)
	}
	w = projectCall(e, User{ID: 2, Role: "user"}, "POST", path, `{"use_saved_config":true}`)
	if w.Code == 200 || w.Code == 202 {
		t.Fatal("saved run bypassed project permission")
	}
	w = projectCall(e, u, "POST", path, `{"use_saved_config":true}`)
	if w.Code != 200 && w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var payload struct {
		Sources []string `json:"sources"`
		Mode    string   `json:"collection_mode"`
	}
	var raw []byte
	if err := s.DB.QueryRow(ctx, "SELECT payload FROM jobs WHERE scope_id=$1", scope.ID).Scan(&raw); err != nil || json.Unmarshal(raw, &payload) != nil || len(payload.Sources) != 1 || payload.Sources[0] != "certspotter" || payload.Mode != "evidence_only" {
		t.Fatal("saved source/mode not shared with manual run", err, string(raw))
	}
	p0Exec(t, s, "UPDATE jobs SET status='done' WHERE scope_id=$1", scope.ID)
	p0Exec(t, s, `INSERT INTO jobs(scope_id,owner,status,payload) SELECT $1,2,'done','{}' FROM generate_series(1,105)`, other.ID)
	p0Exec(t, s, `INSERT INTO assets(scope_id,host)VALUES($1,'example.com'),($2,'example.com')`, scope.ID, other.ID)
	p0Exec(t, s, `INSERT INTO asset_events(asset_id,scope_id,type,detail,dedupe_key)SELECT id,scope_id,'NEW_ASSET','{}','ux-'||id::text FROM assets`)
	for _, endpoint := range []string{"jobs", "events"} {
		w = projectCall(e, u, "GET", fmt.Sprintf("/api/%s?scope_id=%d", endpoint, scope.ID), "")
		var rows []struct {
			ScopeID int64 `json:"scope_id"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &rows) != nil || len(rows) != 1 || rows[0].ScopeID != scope.ID {
			t.Fatal("target history filtered after limit or wrong target", endpoint, w.Code, w.Body.String())
		}
		w = projectCall(e, User{ID: 2, Role: "user"}, "GET", fmt.Sprintf("/api/%s?scope_id=%d", endpoint, scope.ID), "")
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
			t.Fatal("target filter bypassed authorization", endpoint, w.Code, w.Body.String())
		}
		w = projectCall(e, u, "GET", "/api/"+endpoint+"?scope_id=invalid", "")
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
			t.Fatal("invalid target filter expanded to all", endpoint, w.Code)
		}
	}
	for _, q := range []url.Values{{"scope_id": {"-1"}}, {"scope_id": {"0"}}, {"scope_id": {"oops"}}} {
		if scopeFilter(q) != -1 {
			t.Fatal("invalid scope filter")
		}
	}
}

func TestUXEnterpriseHandoffKeepsAuthorizationAndIsIdempotent(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	_, pid := projectFixture(t, s, 1)
	e := &Engine{Store: s}
	u := User{ID: 1, Role: "user"}
	var candidate int64
	if err := s.DB.QueryRow(ctx, `INSERT INTO enterprise_candidates(project_id,domain,company)VALUES($1,'handoff.example.org','Synthetic company')RETURNING id`, pid).Scan(&candidate); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/explorations/candidates/%d", candidate)
	for _, body := range []string{`{"confirmed":false,"mode":"exact"}`, `{"confirmed":true,"mode":"descendants"}`, `{"confirmed":true,"mode":"exact"}`} {
		if w := projectCall(e, u, "POST", path+"/import-scope", body); w.Code != 400 {
			t.Fatal("unconfirmed candidate or wider scope accepted", w.Code)
		}
	}
	if w := projectCall(e, u, "PATCH", path, `{"status":"confirmed"}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := projectCall(e, User{ID: 2, Role: "user"}, "POST", path+"/import-scope", `{"confirmed":true,"mode":"exact"}`); w.Code == 200 || w.Code == 201 {
		t.Fatal("handoff bypassed project permissions")
	}
	var first int64
	for i := 0; i < 2; i++ {
		w := projectCall(e, u, "POST", path+"/import-scope", `{"confirmed":true,"mode":"exact"}`)
		var body struct {
			ID int64 `json:"id"`
		}
		if (w.Code != 200 && w.Code != 201) || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.ID == 0 {
			t.Fatal(w.Code, w.Body.String())
		}
		if i == 0 {
			first = body.ID
		} else if first != body.ID {
			t.Fatal("handoff was not idempotent")
		}
	}
	created, err := s.scopesByID(ctx, first)
	if err != nil || created.ProjectID != pid || created.Domain != "handoff.example.org" || created.Mode != "exact" || created.Active || !created.Confirmed {
		t.Fatal("handoff authorization changed", err)
	}
	plan, err := s.plan(ctx, first)
	var jobs int
	if err != nil || plan.Enabled {
		t.Fatal("handoff enabled a schedule", err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT count(*)FROM jobs").Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("handoff started work", jobs, err)
	}
}
