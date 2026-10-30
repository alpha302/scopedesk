package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestPostgresExecutionBudgetQueueAndLeaseRecovery(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	m := fixturePlugin(t, "lines", "lines")
	m.timeout = 15 * time.Minute
	m.Exec.Timeout = "15m"
	registerFixture(t, s, m)
	s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true")
	q := PGQueue{s}
	id, err := q.Enqueue(ctx, scope, []string{m.Name}, "manual")
	if err != nil {
		t.Fatal(err)
	}
	run, err := q.Claim(ctx, "budget-worker")
	if err != nil {
		t.Fatal(err)
	}
	if run.ExecutionTimeoutSeconds <= 900 {
		t.Fatal("fixed fifteen minute cap remained", run.ExecutionTimeoutSeconds)
	}
	e := &Engine{Store: s, root: ctx}
	jobCtx, stop, err := e.beginExecution(&run)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	deadline, _ := jobCtx.Deadline()
	if time.Until(deadline) < m.timeout+profileBudget || run.DeadlineAt == nil {
		t.Fatal("profile reservation eaten by plugin", deadline)
	}
	if _, err = s.DB.Exec(ctx, "UPDATE jobs SET lease_until=now()-interval '1 second' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := q.Claim(ctx, "recovery-worker")
	if err != nil {
		t.Fatal(err)
	}
	_, stop2, err := e.beginExecution(&reclaimed)
	if err != nil {
		t.Fatal(err)
	}
	defer stop2()
	if !reclaimed.DeadlineAt.Equal(*run.DeadlineAt) {
		t.Fatal("lease recovery reset total deadline")
	}
	// Three maximum-duration plugins exceed the default cap before queue insertion.
	m2, m3 := m, m
	m2.Name = "slow2"
	m3.Name = "slow3"
	s.Plugins.Manifests[m2.Name] = m2
	s.Plugins.Manifests[m3.Name] = m3
	if _, err = s.DB.Exec(ctx, "INSERT INTO plugin_settings(name,enabled)VALUES('slow2',true),('slow3',true)"); err != nil {
		t.Fatal(err)
	}
	other := insertScope(t, s, 2)
	sources := []string{m.Name, m2.Name, m3.Name}
	if _, err = q.Enqueue(ctx, other, sources, "manual"); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatal("over-budget job accepted", err)
	}
	if _, err = s.DB.Exec(ctx, `INSERT INTO monitor_plans(scope_id,enabled,collectors,next_run_at)VALUES($1,true,'["fixture","slow2","slow3"]',now()-interval '1 minute')`, other.ID); err != nil {
		t.Fatal(err)
	}
	e.WorkerID = "schedule-budget-worker"
	e.scheduleTick()
	p, err := s.plan(ctx, other.ID)
	if err != nil || !strings.Contains(p.ScheduleError, "上限") {
		t.Fatal("scheduled budget failure hidden", p, err)
	}
}

func TestPostgresDeterministicPluginFailureDoesNotRequeue(t *testing.T) {
	for _, tc := range []struct {
		mode, code string
		retry      bool
		want       int
	}{{"sleep", "plugin_timeout", false, 1}, {"overflow", "output_limit", false, 1}, {"jsonl-too-many", "invalid_output", false, 1}, {"exit", "exit_nonzero", false, 1}, {"exit", "exit_retryable", true, 3}} {
		t.Run(tc.code, func(t *testing.T) {
			s := integrationStore(t)
			ctx := context.Background()
			scope := insertScope(t, s, 1)
			m := fixturePlugin(t, tc.mode, "jsonl")
			if tc.mode == "sleep" {
				m.timeout = 150 * time.Millisecond
				m.Exec.Timeout = "150ms"
			}
			if tc.mode == "overflow" {
				m.Exec.MaxOutput = 256
			}
			if tc.retry {
				m.Exec.RetryExitCodes = []int{7}
			}
			registerFixture(t, s, m)
			s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true")
			q := PGQueue{s}
			job, err := q.Enqueue(ctx, scope, []string{m.Name}, "manual")
			if err != nil {
				t.Fatal(err)
			}
			run, err := q.Claim(ctx, "failure-worker")
			if err != nil {
				t.Fatal(err)
			}
			e := &Engine{Store: s, Queue: &q, root: ctx, Pipeline: evidenceTestPipeline(t, s)}
			e.execute(run)
			var count, attempts int
			var status, code string
			var retry bool
			if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM plugin_runs WHERE job_id=$1", job).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if err = s.DB.QueryRow(ctx, "SELECT status,error_code,retryable,attempts FROM jobs WHERE id=$1", job).Scan(&status, &code, &retry, &attempts); err != nil {
				t.Fatal(err)
			}
			var assets int
			if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM assets").Scan(&assets); err != nil {
				t.Fatal(err)
			}
			wantStatus, wantCode := "failed", tc.code
			if assets > 0 {
				wantStatus, wantCode = "done", ""
				var complete bool
				if err = s.DB.QueryRow(ctx, "SELECT (stats->>'complete')::boolean FROM jobs WHERE id=$1", job).Scan(&complete); err != nil || complete {
					t.Fatal("partial candidates marked complete", err)
				}
			}
			if count != tc.want || attempts != 1 || status != wantStatus || code != wantCode || retry {
				t.Fatal("nested or deterministic retry", count, attempts, status, code, retry)
			}
			if err = s.DB.QueryRow(ctx, "SELECT attempts FROM job_source_stats WHERE job_id=$1", job).Scan(&count); err != nil || count != tc.want {
				t.Fatal("source attempt count", count, err)
			}
		})
	}
}

func TestPostgresCommitRetryDoesNotRerunPlugin(t *testing.T) {
	for _, sqlstate := range []string{"40001", "23514"} {
		t.Run(sqlstate, func(t *testing.T) {
			s := integrationStore(t)
			ctx := context.Background()
			scope := insertScope(t, s, 1)
			m := fixturePlugin(t, "lines", "lines")
			registerFixture(t, s, m)
			s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true")
			trigger := fmt.Sprintf(`CREATE SEQUENCE retry_fixture_seq;
 CREATE FUNCTION retry_asset_once() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF nextval('retry_fixture_seq')=1 THEN RAISE EXCEPTION 'fixture storage error' USING ERRCODE='%s'; END IF;
 RETURN NEW; END $$;
 CREATE TRIGGER retry_asset_fixture BEFORE INSERT ON assets FOR EACH ROW EXECUTE FUNCTION retry_asset_once();`, sqlstate)
			if _, err := s.DB.Exec(ctx, trigger); err != nil {
				t.Fatal(err)
			}
			q := PGQueue{s}
			job, err := q.Enqueue(ctx, scope, []string{m.Name}, "manual")
			if err != nil {
				t.Fatal(err)
			}
			run, err := q.Claim(ctx, "commit-worker")
			if err != nil {
				t.Fatal(err)
			}
			e := &Engine{Store: s, Queue: &q, root: ctx, Pipeline: evidenceTestPipeline(t, s)}
			e.execute(run)
			var status string
			var plugins, assets, events int
			if err = s.DB.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", job).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM plugin_runs WHERE job_id=$1", job).Scan(&plugins); err != nil {
				t.Fatal(err)
			}
			s.DB.QueryRow(ctx, "SELECT count(*) FROM assets").Scan(&assets)
			s.DB.QueryRow(ctx, "SELECT count(*) FROM asset_events WHERE type='NEW_ASSET'").Scan(&events)
			if plugins != 1 {
				t.Fatal("storage retry reran collector", plugins)
			}
			if sqlstate == "40001" && (status != "done" || assets != 1 || events != 1) {
				t.Fatal("transient commit stage failed or duplicated", status, assets, events)
			}
			if sqlstate == "23514" && (status != "failed" || assets != 0 || events != 0) {
				t.Fatal("deterministic SQL error retried", status, assets, events)
			}
		})
	}
}

func TestPostgresJobTimeoutAndCancellationAreDistinct(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			s := integrationStore(t)
			ctx := context.Background()
			scope := insertScope(t, s, 1)
			q := PGQueue{s}
			job, err := q.Enqueue(ctx, scope, []string{"crtsh"}, "manual")
			if err != nil {
				t.Fatal(err)
			}
			run, err := q.Claim(ctx, "stop-worker")
			if err != nil {
				t.Fatal(err)
			}
			root, stop := context.WithCancel(ctx)
			defer stop()
			if cancelled {
				stop()
			} else if _, err = s.DB.Exec(ctx, "UPDATE jobs SET deadline_at=now()-interval '1 second' WHERE id=$1", job); err != nil {
				t.Fatal(err)
			}
			e := &Engine{Store: s, Queue: &q, root: root}
			e.execute(run)
			var status, code string
			if err = s.DB.QueryRow(ctx, "SELECT status,error_code FROM jobs WHERE id=$1", job).Scan(&status, &code); err != nil {
				t.Fatal(err)
			}
			if cancelled && (status != "cancelled" || code != "cancelled") {
				t.Fatal("cancel misreported", status, code)
			}
			if !cancelled && (status != "failed" || code != "job_timeout") {
				t.Fatal("deadline misreported", status, code)
			}
		})
	}
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	q := PGQueue{s}
	job, err := q.Enqueue(ctx, scope, []string{"crtsh"}, "manual")
	if err != nil {
		t.Fatal(err)
	}
	w := apiRecorder()
	(&Engine{Store: s}).serve(w, apiRequest("POST", fmt.Sprintf("/api/jobs/%d/cancel", job), `{}`), User{ID: 1, Role: "admin"})
	var code string
	var finished bool
	if err = s.DB.QueryRow(ctx, "SELECT error_code,finished_at IS NOT NULL FROM jobs WHERE id=$1", job).Scan(&code, &finished); err != nil || w.Code != 200 || code != "cancelled" || !finished {
		t.Fatal("queued cancellation metadata", w.Code, code, finished, err)
	}
	run := claimedRun(t, s, scope)
	if _, err = s.DB.Exec(ctx, "UPDATE jobs SET cancel_requested=true WHERE id=$1", run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.WriteResults(ctx, run, nil, false); err == nil || classifyExecutionError(err, "").Code != "cancelled" {
		t.Fatal("cancelled submission misclassified as lease loss", err)
	}
}

func TestPostgresExecutionPolicyMigrationRepeat(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.DB)
	defer db.Close()
	if err := goose.DownToContext(ctx, db, "migrations", 7); err != nil {
		t.Fatal(err)
	}
	scope := insertScope(t, s, 1)
	if _, err := s.DB.Exec(ctx, "INSERT INTO jobs(scope_id,owner,status,error)VALUES($1,1,'done','old message')", scope.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := goose.UpContext(ctx, db, "migrations"); err != nil {
			t.Fatal(err)
		}
	}
	var timeout int
	var code, message string
	if err := s.DB.QueryRow(ctx, "SELECT execution_timeout_seconds,error_code,error FROM jobs WHERE scope_id=$1", scope.ID).Scan(&timeout, &code, &message); err != nil || timeout != 0 || code != "" || message != "old message" {
		t.Fatal("migration broke old fields", timeout, code, message, err)
	}
	if err := goose.DownToContext(ctx, db, "migrations", 7); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatal(err)
	}
}
