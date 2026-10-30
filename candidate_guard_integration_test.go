package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type guardQueryCounter struct{ queries atomic.Int64 }

func (c *guardQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if data.SQL == scopeGuardSQL {
		c.queries.Add(1)
	}
	return ctx
}
func (*guardQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestPostgresCandidateGuard100kQueryCount(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	counter := &guardQueryCounter{}
	cfg := s.DB.Config()
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	s.DB = pool
	load := func(c context.Context) (ScopeGuard, error) { return s.guard(c, scope.ID) }
	m := PluginManifest{Name: "query-count-fixture", Kind: "collector"}
	m.Exec.MaxOutput = 8000000
	m.Output.Format = "jsonl"
	m.Output.Mapping = map[string]string{"host": "host"}
	result := PluginResult{}
	if err = parsePluginStream(ctx, strings.NewReader(goodJSONLLines(100000)), m, load, &result); err != nil || len(result.Records) != 100000 {
		t.Fatal("candidate parse lost hosts", len(result.Records), err)
	}
	parseQueries := counter.queries.Load()
	accepted := 0
	stats, err := consumeCandidates(ctx, pluginCandidates(result), load, func(string) { accepted++ })
	consumeQueries := counter.queries.Load() - parseQueries
	if err != nil || accepted != 100000 || stats.InScope != 100000 {
		t.Fatal("candidate consumption lost hosts", accepted, stats, err)
	}
	// Each stage must refresh at least every 256 candidates; allow additional
	// time-based refreshes on slow hosts without turning this into a timing test.
	for _, count := range []int64{parseQueries, consumeQueries} {
		if count < 391 || count > 1000 {
			t.Fatal("guard query count outside batched bound", parseQueries, consumeQueries)
		}
	}
	t.Logf("100000 candidates: parser guard SQL=%d, consumer guard SQL=%d, total=%d (previously about 400000)", parseQueries, consumeQueries, parseQueries+consumeQueries)
}

func TestPostgresCandidateSnapshotCannotAuthorizeProbeOrCommit(t *testing.T) {
	for _, change := range []string{"revoke", "exclude", "blacklist", "delete"} {
		t.Run(change, func(t *testing.T) {
			s := integrationStore(t)
			ctx := context.Background()
			scope := insertScope(t, s, 1)
			run := claimedRun(t, s, scope)
			batch := newCandidateGuard(func(c context.Context) (ScopeGuard, error) { return s.guard(c, scope.ID) })
			g, err := batch.get(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = g.AllowHost("api.example.com"); err != nil {
				t.Fatal(err)
			}
			var sql string
			switch change {
			case "revoke":
				sql = "UPDATE scopes SET confirmed=false WHERE id=$1"
			case "exclude":
				sql = `UPDATE scopes SET exclusions='["api.example.com"]'::jsonb WHERE id=$1`
			case "blacklist":
				sql = "INSERT INTO global_blacklist(pattern) SELECT 'api.example.com' FROM scopes WHERE id=$1"
			case "delete":
				if _, err = s.DB.Exec(ctx, "UPDATE jobs SET scope_id=NULL WHERE scope_id=$1", scope.ID); err != nil {
					t.Fatal(err)
				}
				sql = "DELETE FROM scopes WHERE id=$1"
			}
			if _, err = s.DB.Exec(ctx, sql, scope.ID); err != nil {
				t.Fatal(err)
			}
			g, err = batch.get(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = g.AllowHost("api.example.com"); err != nil {
				t.Fatal("fixture did not retain a stale candidate-only snapshot", err)
			}
			pipeline := &Pipeline{Guard: s.guard, Resolver: &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("revoked host reached DNS")
				return nil, nil
			}}}
			if _, err = pipeline.Probe(ctx, scope, "api.example.com", nil, &Budget{Limit: 100}); err == nil {
				t.Fatal("candidate snapshot authorized a probe")
			}
			_, err = s.WriteResults(ctx, run, []Observation{{Host: "api.example.com", Alive: ptr(true)}}, true)
			if (change == "revoke" || change == "delete") && err == nil {
				t.Fatal("revoked scope accepted a commit")
			}
			if change != "revoke" && change != "delete" && err != nil {
				t.Fatal(err)
			}
			var assets int
			if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM assets").Scan(&assets); err != nil || assets != 0 {
				t.Fatal("stale candidate persisted", assets, err)
			}
		})
	}
}

// Cancel just the first consumer refresh query after plugin execution. This
// simulates a failed database check without cancelling the job or later commit.
type failConsumerGuardQuery struct {
	armed  atomic.Bool
	failed atomic.Bool
}

func (c *failConsumerGuardQuery) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "UPDATE plugin_runs SET finished_at=") {
		c.armed.Store(true)
	}
	if data.SQL == scopeGuardSQL && c.armed.Load() && c.failed.CompareAndSwap(false, true) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		return cancelled
	}
	return ctx
}
func (*failConsumerGuardQuery) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestPostgresCandidateRefreshFailureSuppressesMissing(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	m := fixturePlugin(t, "lines", "lines")
	registerFixture(t, s, m)
	if _, err := s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true; INSERT INTO assets(scope_id,host,miss_count,is_alive) SELECT id,'missing.example.com',2,true FROM scopes"); err != nil {
		t.Fatal(err)
	}
	q := PGQueue{s}
	job, err := q.Enqueue(ctx, scope, []string{m.Name}, "manual")
	if err != nil {
		t.Fatal(err)
	}
	run, err := q.Claim(ctx, "guard-refresh-failure")
	if err != nil {
		t.Fatal(err)
	}
	trace := &failConsumerGuardQuery{}
	cfg := s.DB.Config()
	cfg.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	s.DB = pool
	(&Engine{Store: s, Queue: &q, root: ctx, Pipeline: evidenceTestPipeline(t, s)}).execute(run)
	var status string
	var raw []byte
	if err = s.DB.QueryRow(ctx, "SELECT status,stats FROM jobs WHERE id=$1", job).Scan(&status, &raw); err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Complete             bool `json:"complete"`
		CollectionIncomplete bool `json:"collection_incomplete"`
	}
	if !trace.failed.Load() || json.Unmarshal(raw, &summary) != nil || status != "done" || summary.Complete || !summary.CollectionIncomplete {
		t.Fatal("failed candidate refresh marked complete", trace.failed.Load(), status, string(raw))
	}
	var sourceError, sourceCode string
	if err = s.DB.QueryRow(ctx, "SELECT error,error_code FROM job_source_stats WHERE job_id=$1", job).Scan(&sourceError, &sourceCode); err != nil || sourceError == "" || sourceCode == "" {
		t.Fatal("candidate refresh failure not reported", sourceError, sourceCode, err)
	}
	var miss, down int
	if err = s.DB.QueryRow(ctx, "SELECT miss_count FROM assets WHERE host='missing.example.com'").Scan(&miss); err != nil || miss != 2 {
		t.Fatal("failed refresh incremented absence", miss, err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM asset_events WHERE type='ASSET_DOWN'").Scan(&down); err != nil || down != 0 {
		t.Fatal("failed refresh caused down event", down, err)
	}
}
