package main

import (
	"context"
	"fmt"
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
