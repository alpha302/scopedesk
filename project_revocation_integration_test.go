package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func revocationScope(t *testing.T, s *Store, pid int64, n int) int64 {
	t.Helper()
	var id int64
	if err := s.DB.QueryRow(context.Background(), "INSERT INTO scopes(owner,project_id,domain,mode,policy)VALUES(1,$1,$2,'exact','')RETURNING id", pid, fmt.Sprintf("scope-%d.example.com", n)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
func revocationJob(t *testing.T, s *Store, scope int64, status string, used int) int64 {
	t.Helper()
	var id int64
	if err := s.DB.QueryRow(context.Background(), `INSERT INTO jobs(scope_id,owner,status,payload,stats,worker_id,started_at,lease_until,attempts,retryable)VALUES($1,1,$2,'{"sources":["crtsh"]}',jsonb_build_object('requests',$3::integer),'fixture-worker',CASE WHEN $2 IN('running','retrying') THEN now() END,CASE WHEN $2='running' THEN now()+interval '1 hour' END,CASE WHEN $2 IN('running','retrying') THEN 1 ELSE 0 END,true)RETURNING id`, scope, status, used).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
func revocationPolicy(scope ScopeV2) Project {
	return Project{WorkspaceID: scope.WorkspaceID, Name: scope.ProjectName, ProjectPolicy: *scope.ProjectPolicy}
}
func assertRevoked(t *testing.T, s *Store, id int64, used int) {
	t.Helper()
	var status, code string
	var retry, cancel bool
	var finished *time.Time
	var actual int
	err := s.DB.QueryRow(context.Background(), "SELECT status,error_code,retryable,cancel_requested,finished_at,(stats->>'requests')::integer FROM jobs WHERE id=$1", id).Scan(&status, &code, &retry, &cancel, &finished, &actual)
	if err != nil || status != "cancelled" || code != "project_revoked" || retry || !cancel || finished == nil || actual != used {
		t.Fatal("revocation status or historical usage", status, code, retry, cancel, finished, actual, err)
	}
}
func TestPostgresProjectRevokeWaitingJobsAtomicallyAndIdempotently(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	other, _ := projectFixture(t, s, 2)
	ctx := context.Background()
	queued := revocationJob(t, s, scope.ID, "queued", 0)
	retry := revocationJob(t, s, revocationScope(t, s, pid, 1), "retrying", 17)
	running := revocationJob(t, s, revocationScope(t, s, pid, 2), "running", 7)
	foreign := revocationJob(t, s, other.ID, "queued", 0)
	e := &Engine{Store: s}
	p := revocationPolicy(scope)
	p.Enabled = false
	raw, _ := json.Marshal(p)
	for _, want := range []int64{2, 0} {
		w := projectCall(e, User{ID: 1, Role: "user"}, "PUT", fmt.Sprintf("/api/projects/%d", pid), string(raw))
		var result struct {
			Cancelled int64 `json:"cancelled_jobs"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Cancelled != want {
			t.Fatal("revocation count", w.Code, w.Body.String())
		}
	}
	assertRevoked(t, s, queued, 0)
	assertRevoked(t, s, retry, 17)
	for _, tc := range []struct {
		id     int64
		status string
		used   int
	}{{running, "running", 7}, {foreign, "queued", 0}} {
		var status string
		var cancel bool
		var finished *time.Time
		var used int
		if err := s.DB.QueryRow(ctx, "SELECT status,cancel_requested,finished_at,(stats->>'requests')::integer FROM jobs WHERE id=$1", tc.id).Scan(&status, &cancel, &finished, &used); err != nil || status != tc.status || cancel || finished != nil || used != tc.used {
			t.Fatal("revocation changed running or foreign job", tc, status, cancel, finished, used, err)
		}
	}
	var first, timeAgain time.Time
	s.DB.QueryRow(ctx, "SELECT finished_at FROM jobs WHERE id=$1", queued).Scan(&first)
	if n, err := s.sweepRevokedProjects(ctx); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	s.DB.QueryRow(ctx, "SELECT finished_at FROM jobs WHERE id=$1", queued).Scan(&timeAgain)
	if !first.Equal(timeAgain) {
		t.Fatal("repeat sweep rewrote finish time")
	}
}
func TestPostgresProjectExpirySweepsWithoutPlanAndClaimSkipsRevoked(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	other, _ := projectFixture(t, s, 2)
	ctx := context.Background()
	queued := revocationJob(t, s, scope.ID, "queued", 0)
	retryScope := revocationScope(t, s, pid, 3)
	retry := revocationJob(t, s, retryScope, "retrying", 9)
	running := revocationJob(t, s, revocationScope(t, s, pid, 4), "running", 3)
	projectExec(t, s, "INSERT INTO monitor_plans(scope_id,enabled)VALUES($1,false)", retryScope)
	projectExec(t, s, "UPDATE projects SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", pid)
	active := revocationJob(t, s, other.ID, "queued", 0)
	r, err := (&PGQueue{s}).Claim(ctx, "claim-active")
	if err != nil || r.ID != active {
		t.Fatal("claim selected expired project", r, err)
	}
	(&Engine{Store: s, root: ctx}).scheduleTick()
	assertRevoked(t, s, queued, 0)
	assertRevoked(t, s, retry, 9)
	var status string
	if err = s.DB.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", running).Scan(&status); err != nil || status != "running" {
		t.Fatal("expiry changed dispatched task", status, err)
	}
	if n, err := s.sweepRevokedProjects(ctx); err != nil || n != 0 {
		t.Fatal("expiry sweep not idempotent", n, err)
	}
}
func TestPostgresProjectRevocationRollbackPreservesPolicyAndJobs(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	job := revocationJob(t, s, scope.ID, "queued", 0)
	projectExec(t, s, `CREATE FUNCTION reject_fixture_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.error_code='project_revoked' THEN RAISE EXCEPTION 'fixture cancellation rejection'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_fixture_revocation BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION reject_fixture_revocation()`)
	p := revocationPolicy(scope)
	p.Enabled = false
	if _, err := s.updateProjectPolicy(context.Background(), pid, p); err == nil {
		t.Fatal("revocation unexpectedly succeeded")
	}
	var enabled bool
	var status string
	var code string
	if err := s.DB.QueryRow(context.Background(), "SELECT p.enabled,j.status,j.error_code FROM projects p JOIN scopes sc ON sc.project_id=p.id JOIN jobs j ON j.scope_id=sc.id WHERE j.id=$1", job).Scan(&enabled, &status, &code); err != nil || !enabled || status != "queued" || code != "" {
		t.Fatal("partial revocation committed", enabled, status, code, err)
	}
}
func waitProjectBlock(t *testing.T, s *Store, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := s.DB.QueryRow(context.Background(), "SELECT count(*) FROM pg_stat_activity WHERE $1::integer=ANY(pg_blocking_pids(pid))", pid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("operation did not wait for project lock")
}
func TestPostgresProjectRevokeWaitsForInflightEnqueue(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = lockScopeProject(ctx, tx, scope.ID, false); err != nil {
		t.Fatal(err)
	}
	var backend int
	tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&backend)
	type outcome struct {
		n   int64
		err error
	}
	done := make(chan outcome, 1)
	p := revocationPolicy(scope)
	p.Enabled = false
	go func() { n, err := s.updateProjectPolicy(ctx, pid, p); done <- outcome{n, err} }()
	waitProjectBlock(t, s, backend)
	var job int64
	if err = tx.QueryRow(ctx, "INSERT INTO jobs(scope_id,owner)VALUES($1,1)RETURNING id", scope.ID).Scan(&job); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil || result.n != 1 {
		t.Fatal("revocation missed in-flight insert", result)
	}
	var status, code string
	if err = s.DB.QueryRow(ctx, "SELECT status,error_code FROM jobs WHERE id=$1", job).Scan(&status, &code); err != nil || status != "cancelled" || code != "project_revoked" {
		t.Fatal(status, code, err)
	}
}
func TestPostgresProjectRevocationBlocksManualAndPluginEnqueue(t *testing.T) {
	for _, kind := range []string{"manual", "plugin"} {
		t.Run(kind, func(t *testing.T) {
			s := integrationStore(t)
			scope, pid := projectFixture(t, s, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if kind == "plugin" {
				m := fixturePlugin(t, "jsonl", "jsonl")
				registerFixture(t, s, m)
				projectExec(t, s, "UPDATE plugin_settings SET enabled=true")
			}
			tx, err := s.DB.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			var backend int
			if _, err = tx.Exec(ctx, "SELECT id FROM projects WHERE id=$1 FOR UPDATE", pid); err != nil {
				t.Fatal(err)
			}
			tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&backend)
			if _, err = tx.Exec(ctx, "UPDATE projects SET enabled=false WHERE id=$1", pid); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if kind == "manual" {
					_, err := (&PGQueue{s}).Enqueue(ctx, scope, []string{"crtsh"}, "manual")
					done <- err
				} else {
					w := projectCall(&Engine{Store: s}, User{ID: 1, Role: "admin"}, "POST", "/api/plugins/fixture/test", fmt.Sprintf(`{"scope_id":%d,"target":"api.example.com"}`, scope.ID))
					if w.Code < 400 {
						done <- fmt.Errorf("plugin enqueue returned %d: %s", w.Code, w.Body.String())
					} else {
						done <- nil
					}
				}
			}()
			waitProjectBlock(t, s, backend)
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			result := <-done
			if kind == "manual" && result == nil {
				t.Fatal("manual enqueue accepted revoked project")
			}
			if kind == "plugin" && result != nil {
				t.Fatal(result)
			}
			var n int
			if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM jobs").Scan(&n); err != nil || n != 0 {
				t.Fatal("job inserted after revocation", n, err)
			}
		})
	}
}
func TestPostgresProjectClaimDoesNotDeadlockRevocation(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	job := revocationJob(t, s, scope.ID, "queued", 0)
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	projectExecSQL := "UPDATE projects SET enabled=false WHERE id=$1"
	if _, err = tx.Exec(ctx, projectExecSQL, pid); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err = (&PGQueue{s}).Claim(ctx, "race-worker"); !errors.Is(err, pgx.ErrNoRows) || time.Since(start) > time.Second {
		t.Fatal("claim waited on revocation while holding job lock", err)
	}
	if n, err := cancelRevokedProjectJobs(ctx, tx, pid); err != nil || n != 1 {
		t.Fatal("claim retained job lock", n, err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, s, job, 0)
}
func TestPostgresProjectScheduleRevocationLockAndClaimWinner(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	ctx := context.Background()
	projectExec(t, s, "INSERT INTO monitor_plans(scope_id,enabled,next_run_at)VALUES($1,true,now()-interval '1 hour')", scope.ID)
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "UPDATE projects SET enabled=false WHERE id=$1", pid); err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: s, root: ctx}
	done := make(chan struct{})
	go func() { e.scheduleTick(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler blocked on project revocation")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM jobs").Scan(&n); err != nil || n != 0 {
		t.Fatal("scheduler inserted revoked job", n, err)
	}
	projectExec(t, s, "UPDATE projects SET enabled=true WHERE id=$1", pid)
	e.scheduleTick()
	run, err := (&PGQueue{s}).Claim(ctx, "dispatched-winner")
	if err != nil {
		t.Fatal(err)
	}
	p := revocationPolicy(scope)
	p.Enabled = false
	if n, err := s.updateProjectPolicy(ctx, pid, p); err != nil || n != 0 {
		t.Fatal("revocation modified claim winner", n, err)
	}
	var status string
	var cancel bool
	if err = s.DB.QueryRow(ctx, "SELECT status,cancel_requested FROM jobs WHERE id=$1", run.ID).Scan(&status, &cancel); err != nil || status != "running" || cancel {
		t.Fatal(status, cancel, err)
	}
	projectExec(t, s, "UPDATE jobs SET lease_until=now()-interval '1 minute' WHERE id=$1", run.ID)
	recovered, err := (&PGQueue{s}).Claim(ctx, "lease-takeover")
	if err != nil || recovered.ID != run.ID {
		t.Fatal("lost-worker lease recovery was stranded", recovered, err)
	}
	e.Queue = &PGQueue{s}
	e.execute(recovered)
	var code string
	if err = s.DB.QueryRow(ctx, "SELECT status,error_code FROM jobs WHERE id=$1", run.ID).Scan(&status, &code); err != nil || status != "cancelled" || code != "scope_denied" {
		t.Fatal("recovered revoked job did not stop before collection", status, code, err)
	}
}
