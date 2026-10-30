package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestPostgresFailedPluginCandidatesRemainIncomplete(t *testing.T) {
	for _, tc := range []struct {
		mode, strategy string
		want           int
	}{
		{"failed-observer", "all", 1},
		{"partial-timeout", "all", 1},
		{"jsonl-too-few", "all", 8},
		{"retry-observer", "all", 2},
		{"retry-observer", "fallback", 2},
		{"retry-observer", "first_success", 2},
	} {
		t.Run(tc.mode+"/"+tc.strategy, func(t *testing.T) {
			s := integrationStore(t)
			ctx := context.Background()
			scope := insertScope(t, s, 1)
			m := observerMapping(fixturePlugin(t, tc.mode, "jsonl"))
			if tc.mode == "partial-timeout" {
				m.timeout = 500 * time.Millisecond
			}
			if tc.mode == "retry-observer" {
				m.Exec.RetryExitCodes = []int{7}
				m.Exec.Args = append(m.Exec.Args[:len(m.Exec.Args)-1], filepath.Join(t.TempDir(), "counter"), "{{domain}}")
			}
			registerFixture(t, s, m)
			if _, err := s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true; INSERT INTO assets(scope_id,host,miss_count,is_alive) SELECT id,'missing.example.com',2,true FROM scopes"); err != nil {
				t.Fatal(err)
			}
			q := PGQueue{s}
			job, err := q.Enqueue(ctx, scope, []string{m.Name}, "manual")
			if err != nil {
				t.Fatal(err)
			}
			run, err := q.Claim(ctx, "partial-worker")
			if err != nil {
				t.Fatal(err)
			}
			run.PluginStrategy = tc.strategy
			(&Engine{Store: s, Queue: &q, root: ctx, Pipeline: evidenceTestPipeline(t, s)}).execute(run)
			var status string
			var raw []byte
			if err = s.DB.QueryRow(ctx, "SELECT status,stats FROM jobs WHERE id=$1", job).Scan(&status, &raw); err != nil {
				t.Fatal(err)
			}
			var summary struct {
				Complete bool `json:"complete"`
				New      int  `json:"new"`
			}
			if json.Unmarshal(raw, &summary) != nil || status != "done" || summary.Complete || summary.New != tc.want {
				t.Fatal("partial candidates lost or treated as complete", status, string(raw))
			}
			var count, miss int
			if err = s.DB.QueryRow(ctx, "SELECT miss_count FROM assets WHERE host='missing.example.com'").Scan(&miss); err != nil || miss != 2 {
				t.Fatal("partial results incremented passive absence", miss, err)
			}
			if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM asset_events WHERE type='ASSET_DOWN'").Scan(&count); err != nil || count != 0 {
				t.Fatal("partial results caused down event", count, err)
			}
			if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM assets WHERE host<>'api.example.com' AND (title<>'' OR plugin_evidence<>'[]'::jsonb)").Scan(&count); err != nil || count != 0 {
				t.Fatal("failed observation persisted", count, err)
			}
			if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM asset_services WHERE source=$1", m.Name).Scan(&count); err != nil || (tc.mode != "retry-observer" && count != 0) {
				t.Fatal("failed service persisted", count, err)
			}
		})
	}
}

func TestPostgresFailedPluginCandidatesRecheckScope(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	m := observerMapping(fixturePlugin(t, "failed-observer", "jsonl"))
	registerFixture(t, s, m)
	// Revoke the previously accepted host when execution finishes, before the
	// collector hands its candidate stream to the pipeline. Only the test schema changes.
	if _, err := s.DB.Exec(ctx, `UPDATE plugin_settings SET enabled=true;
CREATE FUNCTION revoke_partial_host() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 UPDATE scopes SET exclusions='["failed-only.example.com"]'::jsonb WHERE id=(SELECT scope_id FROM jobs WHERE id=NEW.job_id);
 RETURN NEW; END $$;
CREATE TRIGGER revoke_partial_host AFTER UPDATE ON plugin_runs FOR EACH ROW WHEN (NEW.finished_at IS NOT NULL) EXECUTE FUNCTION revoke_partial_host()`); err != nil {
		t.Fatal(err)
	}
	q := PGQueue{s}
	job, err := q.Enqueue(ctx, scope, []string{m.Name}, "manual")
	if err != nil {
		t.Fatal(err)
	}
	run, err := q.Claim(ctx, "partial-revoke-worker")
	if err != nil {
		t.Fatal(err)
	}
	(&Engine{Store: s, Queue: &q, root: ctx, Pipeline: evidenceTestPipeline(t, s)}).execute(run)
	var accepted, assets int
	var status string
	if err = s.DB.QueryRow(ctx, "SELECT in_scope FROM plugin_runs WHERE job_id=$1", job).Scan(&accepted); err != nil || accepted != 1 {
		t.Fatal("fixture did not validate candidate before revocation", accepted, err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", job).Scan(&status); err != nil || status != "failed" {
		t.Fatal("revoked candidate treated as usable", status, err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM assets").Scan(&assets); err != nil || assets != 0 {
		t.Fatal("revoked candidate saved", assets, err)
	}
}
