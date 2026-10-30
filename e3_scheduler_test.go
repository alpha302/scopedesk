package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestCollectorAttemptDeadline(t *testing.T) {
	m := PluginManifest{timeout: 5 * time.Minute}
	c := &ManifestCollector{Plugin: ExternalPlugin{Manifest: m}}
	for _, tc := range []struct {
		name          string
		collector     Collector
		parentTimeout time.Duration
		want          time.Duration
	}{
		{"manifest above old cap", c, time.Hour, 5 * time.Minute},
		{"parent deadline preserved", c, time.Second, time.Second},
		{"builtin unchanged", &CertificateCollector{}, time.Hour, 150 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), tc.parentTimeout)
			defer cancel()
			started := time.Now()
			ctx, stop := collectorAttemptContext(parent, tc.collector)
			defer stop()
			deadline, ok := ctx.Deadline()
			if !ok || deadline.Sub(started) > tc.want+time.Second || deadline.Sub(started) < tc.want-time.Second {
				t.Fatal("unexpected attempt deadline", deadline.Sub(started))
			}
			cancel()
			if ctx.Err() != context.Canceled {
				t.Fatal("parent cancellation was lost")
			}
		})
	}
}

func TestPostgresSchedulerPluginErrorAndRecovery(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	raw, _ := defaultPluginFiles.ReadFile("plugins/subfinder.yaml")
	m, err := parseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	registerFixture(t, s, m)
	if _, err = s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=false WHERE name='subfinder'"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, `INSERT INTO monitor_plans(scope_id,enabled,interval_hours,collectors,next_run_at) VALUES($1,true,6,'["subfinder"]',now()-interval '1 minute')`, scope.ID); err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: s, root: ctx, WorkerID: "scheduler-fixture", workers: 1}
	e.scheduleTick()
	p, err := s.plan(ctx, scope.ID)
	if err != nil || p.ScheduleError == "" || p.RetryAt == nil || p.Last != nil || p.Next == nil || p.Next.After(time.Now()) {
		t.Fatal("silent scheduling failure", p, err)
	}
	firstRetry := *p.RetryAt
	e.scheduleTick()
	p, err = s.plan(ctx, scope.ID)
	if err != nil || !p.RetryAt.Equal(firstRetry) {
		t.Fatal("bad configuration retried without backoff", err)
	}
	// The GET endpoint exposes the additive error fields.
	w := apiRecorder()
	e.serve(w, apiRequest("GET", fmt.Sprintf("/api/scopes/%d/plan", scope.ID), ""), User{ID: 1, Role: "admin"})
	var visible Plan
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &visible) != nil || visible.ScheduleError == "" {
		t.Fatal("plan API hides scheduler error", w.Body.String())
	}
	if _, err = s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true WHERE name='subfinder'"); err != nil {
		t.Fatal(err)
	}
	// Saving a corrected plan removes backoff without waiting five minutes.
	w = apiRecorder()
	e.serve(w, apiRequest("PUT", fmt.Sprintf("/api/scopes/%d/plan", scope.ID), `{"enabled":true,"interval_hours":6,"collectors":["subfinder"]}`), User{ID: 1, Role: "admin"})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	p, err = s.plan(ctx, scope.ID)
	if err != nil || p.ScheduleError != "" || p.RetryAt != nil {
		t.Fatal("saved plan retains error", err)
	}
	if _, err = s.DB.Exec(ctx, "UPDATE monitor_plans SET next_run_at=now()-interval '1 minute' WHERE scope_id=$1", scope.ID); err != nil {
		t.Fatal(err)
	}
	e.scheduleTick()
	p, err = s.plan(ctx, scope.ID)
	if err != nil || p.ScheduleError != "" || p.RetryAt != nil || p.Last == nil || !p.Next.After(time.Now()) {
		t.Fatal("plan did not recover", p, err)
	}
	var jobs int
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE scope_id=$1", scope.ID).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal("recovery job count", jobs, err)
	}
}

func TestPostgresPluginTestQueueIsolationAndExpiry(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	var testID int64
	if err := s.DB.QueryRow(ctx, `INSERT INTO jobs(scope_id,owner,trigger,required_labels)VALUES($1,1,'plugin_test',ARRAY['missing-worker'])RETURNING id`, scope.ID).Scan(&testID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO jobs(scope_id,owner,trigger)VALUES($1,1,'plugin_test')`, scope.ID); err == nil {
		t.Fatal("unbounded parallel tests allowed for same scope")
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO monitor_plans(scope_id,enabled,interval_hours,next_run_at)VALUES($1,true,6,now()-interval '1 minute')`, scope.ID); err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: s, root: ctx, WorkerID: "isolation-fixture", workers: 1}
	e.scheduleTick()
	q := PGQueue{s}
	run, err := q.Claim(ctx, "default-worker")
	if err != nil || run.Trigger != "schedule" {
		t.Fatal("plugin test blocked monitoring", run, err)
	}
	// An expired test cannot race a scheduler cleanup and get claimed first.
	if _, err = s.DB.Exec(ctx, "UPDATE jobs SET created_at=now()-interval '11 minutes' WHERE id=$1", testID); err != nil {
		t.Fatal(err)
	}
	if _, err = q.ClaimWithLabels(ctx, "late-worker", []string{"missing-worker"}); err == nil {
		t.Fatal("expired queued test was claimed")
	}
	e.scheduleTick()
	var status, reason string
	if err = s.DB.QueryRow(ctx, "SELECT status,error FROM jobs WHERE id=$1", testID).Scan(&status, &reason); err != nil || status != "cancelled" || reason == "" {
		t.Fatal("stale test not cancelled", status, reason, err)
	}
	if _, err = q.Enqueue(ctx, scope, []string{"crtsh"}, "manual"); err == nil {
		t.Fatal("monitor overlap guard removed")
	}
}

func TestPostgresSchedulerConflictDoesNotAdvancePlan(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	q := PGQueue{s}
	id, err := q.Enqueue(ctx, scope, []string{"crtsh"}, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, `INSERT INTO monitor_plans(scope_id,enabled,interval_hours,next_run_at)VALUES($1,true,6,now()-interval '1 minute')`, scope.ID); err != nil {
		t.Fatal(err)
	}
	before, _ := s.plan(ctx, scope.ID)
	e := &Engine{Store: s, root: ctx, WorkerID: "conflict-fixture", workers: 1}
	e.scheduleTick()
	after, err := s.plan(ctx, scope.ID)
	if err != nil || !after.Next.Equal(*before.Next) || after.Last != nil || after.ScheduleError == "" {
		t.Fatal("conflict lost a scheduled execution", after, err)
	}
	if _, err = s.DB.Exec(ctx, "UPDATE jobs SET status='done' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, "UPDATE monitor_plans SET retry_at=now()-interval '1 second' WHERE scope_id=$1", scope.ID); err != nil {
		t.Fatal(err)
	}
	e.scheduleTick()
	after, err = s.plan(ctx, scope.ID)
	if err != nil || after.Last == nil || after.ScheduleError != "" || !after.Next.After(time.Now()) {
		t.Fatal("deferred monitoring did not enqueue", after, err)
	}
}

func TestPostgresE3SchedulerMigrationRoundTrip(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.DB)
	defer db.Close()
	if err := goose.DownToContext(ctx, db, "migrations", 5); err != nil {
		t.Fatal(err)
	}
	scope := insertScope(t, s, 1)
	if _, err := s.DB.Exec(ctx, `INSERT INTO jobs(scope_id,owner,trigger)VALUES($1,1,'manual')`, scope.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := goose.UpContext(ctx, db, "migrations"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO jobs(scope_id,owner,trigger)VALUES($1,1,'plugin_test')`, scope.ID); err != nil {
		t.Fatal("migration failed to separate queues", err)
	}
	// Rollback refuses destructive reconciliation of two active jobs.
	if err := goose.DownToContext(ctx, db, "migrations", 5); err == nil {
		t.Fatal("rollback should refuse conflicting active jobs")
	}
	if _, err := s.DB.Exec(ctx, `UPDATE jobs SET status='cancelled' WHERE trigger='plugin_test'`); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownToContext(ctx, db, "migrations", 5); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO jobs(scope_id,owner,trigger)VALUES($1,1,'plugin_test')`, scope.ID); err == nil {
		t.Fatal("original index not restored")
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatal(err)
	}
}
