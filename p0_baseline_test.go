package main

// P0 measures the existing implementation. It deliberately does not optimize it.
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type p0Trace struct{ queries atomic.Int64 }

func p0DatabaseAllowed(dsn string) bool {
	u, err := url.Parse(dsn)
	if err != nil || u == nil || u.Path != "/scopedesk_p0" {
		return false
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || cfg.ConnConfig.Database != "scopedesk_p0" {
		return false
	}
	local := func(host string) bool { return host == "127.0.0.1" || host == "localhost" }
	if !local(cfg.ConnConfig.Host) {
		return false
	}
	for _, fallback := range cfg.ConnConfig.Fallbacks {
		if !local(fallback.Host) {
			return false
		}
	}
	return true
}

func (p *p0Trace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	p.queries.Add(1)
	return ctx
}
func (*p0Trace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// This is stricter than the historical integration helper: never accept a remote
// server or a general purpose database. The workflow creates this disposable DB.
func p0Store(t *testing.T) (*Store, *p0Trace) {
	t.Helper()
	if os.Getenv("P0_ISOLATED") != "ephemeral-ci" {
		t.Skip("P0 requires an explicitly disposable PostgreSQL 16 environment")
	}
	if !p0DatabaseAllowed(os.Getenv("DATABASE_URL")) {
		t.Fatal("P0 refuses this database destination (connection details suppressed)")
	}
	s := integrationStore(t)
	var version int
	if err := s.DB.QueryRow(context.Background(), "SELECT current_setting('server_version_num')::int").Scan(&version); err != nil || version/10000 != 16 {
		t.Fatal("P0 requires PostgreSQL 16")
	}
	trace := &p0Trace{}
	cfg := s.DB.Config()
	cfg.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal("P0 tracing pool failed")
	}
	s.DB.Close()
	s.DB = pool // integrationStore cleanup closes the replacement pool too.
	return s, trace
}

func p0Exec(t *testing.T, s *Store, sql string, args ...any) {
	t.Helper()
	if _, err := s.DB.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal("P0 fixture/query failed (details suppressed to protect connection data)")
	}
}

func p0Seed(t *testing.T, s *Store, n int, skew bool) {
	t.Helper()
	p0Exec(t, s, `INSERT INTO workspaces(id,owner,name) VALUES(100,100,'P0 synthetic');
INSERT INTO projects(id,workspace_id,owner,name,allow_active) SELECT i,100,100,'P0-'||i,false FROM generate_series(101,104)i;
INSERT INTO scopes(id,owner,project_id,domain,policy,active) SELECT i,100,101+(i-1)%4,'s'||i||'.example.test','P0 synthetic; no target requests',false FROM generate_series(1,20)i;
INSERT INTO monitor_plans(scope_id,enabled) SELECT id,false FROM scopes;`)
	// Fixed anchor and arithmetic distribution make repeated fixtures identical.
	// 10% wide titles, 5% dual-stack, 20% multiple IPv4; documentation IPs
	// are stored as evidence only and are never passed to a network request.
	p0Exec(t, s, `INSERT INTO assets(id,scope_id,host,ips,sources,title,is_alive,is_cdn,score,dns_at,first_seen,last_seen,plugin_evidence)
SELECT i, sid, 'h'||i||'.s'||sid||'.example.test',
 CASE WHEN i%20=0 THEN ARRAY['192.0.2.1','2001:db8::1'] WHEN i%5=0 THEN ARRAY['192.0.2.1','198.51.100.1'] ELSE ARRAY['192.0.2.1'] END,
 CASE WHEN i%3=0 THEN ARRAY['crtsh'] WHEN i%3=1 THEN ARRAY['certspotter'] ELSE ARRAY['manual','hunter'] END,
 CASE WHEN i%10=0 THEN repeat('合成标题',256) ELSE 'synthetic-'||i END,
 i%4<>0,i%5=0,i%100,CASE WHEN i%4=0 THEN NULL ELSE timestamptz '2026-10-30 00:00:00+00'-(i%30)*interval '1 day' END,
 timestamptz '2026-10-30 00:00:00+00'-(i%30)*interval '1 day',timestamptz '2026-10-30 00:00:00+00',
 CASE WHEN i%100=0 THEN jsonb_build_array(jsonb_build_object('synthetic',repeat(md5(i::text),128))) ELSE '[]'::jsonb END
FROM (SELECT i,CASE WHEN $2::boolean AND i<=$1::int*9/10 THEN 1 WHEN $2::boolean THEN 2+(i%19) ELSE 1+(i%20) END sid FROM generate_series(1,$1::int)i)x`, n, skew)
	p0Exec(t, s, `INSERT INTO asset_services(asset_id,ip,port,scheme,status_code,title) SELECT id,'192.0.2.1',p,CASE WHEN p=443 THEN 'https' ELSE 'http' END,200,title FROM assets CROSS JOIN unnest(ARRAY[80,443])p;
INSERT INTO candidates(scope_id,host,sources) SELECT scope_id,host,sources FROM assets;
INSERT INTO jobs(scope_id,owner,status,trigger,created_at,finished_at,stats)
SELECT s.id,100,'done','p0-fixture',timestamptz '2026-10-30 00:00:00+00'-d*interval '1 day',timestamptz '2026-10-30 00:01:00+00'-d*interval '1 day',jsonb_build_object('synthetic',true,'complete',d%2=0) FROM scopes s CROSS JOIN generate_series(0,29)d;
INSERT INTO job_source_stats(job_id,source,complete,absence_usable) SELECT id,'crtsh',false,false FROM jobs;
INSERT INTO job_source_stats(job_id,source,complete,absence_usable) SELECT id,'certspotter',(id%2=0),false FROM jobs;`)
	// ensurePartitions follows wall time; explicitly create the fixed history window.
	for _, table := range []string{"asset_events", "asset_snapshots"} {
		for _, month := range []string{"202609", "202610"} {
			start, _ := time.Parse("200601", month)
			p0Exec(t, s, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s_%s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')", table, month, table, start.Format("2006-01-02"), start.AddDate(0, 1, 0).Format("2006-01-02")))
		}
	}
	p0Exec(t, s, `INSERT INTO asset_events(asset_id,scope_id,type,detail,dedupe_key,created_at) SELECT id,scope_id,'P0_SYNTHETIC','{"synthetic":true}','p0-'||id,timestamptz '2026-10-30 00:00:00+00'-(id%30)*interval '1 day' FROM assets;
INSERT INTO asset_snapshots(asset_id,scope_id,payload,created_at) SELECT id,scope_id,jsonb_build_object('synthetic',true,'title',title),timestamptz '2026-10-30 00:00:00+00'-(id%30)*interval '1 day' FROM assets;
ANALYZE;`)
	var assets, services, scopes, projects, candidates int
	err := s.DB.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM assets),(SELECT count(*) FROM asset_services),(SELECT count(*) FROM scopes),(SELECT count(*) FROM projects),(SELECT count(*) FROM candidates)`).Scan(&assets, &services, &scopes, &projects, &candidates)
	if err != nil || assets != n || services != 2*n || scopes != 20 || projects != 4 || candidates != n {
		t.Fatal("P0 fixture cardinality mismatch")
	}
}

type p0Sample struct {
	Case      string  `json:"case"`
	Round     int     `json:"round"`
	Queries   int64   `json:"sql_round_trips"`
	ElapsedMS float64 `json:"elapsed_ms"`
	Bytes     int     `json:"response_bytes"`
}

func p0Write(t *testing.T, name string, data any) {
	t.Helper()
	dir := os.Getenv("P0_ARTIFACT_DIR")
	if dir == "" {
		t.Fatal("P0_ARTIFACT_DIR is required; evidence must be retained")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal("cannot create P0 evidence directory")
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal("cannot encode P0 evidence")
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), raw, 0600); err != nil {
		t.Fatal("cannot save P0 evidence")
	}
}

func TestP0ReadBaseline(t *testing.T) {
	for _, n := range []int{1000, 10000} {
		for _, skew := range []bool{false, true} {
			t.Run(fmt.Sprintf("n%d-skew%t", n, skew), func(t *testing.T) {
				s, tr := p0Store(t)
				p0Seed(t, s, n, skew)
				e := &Engine{Store: s}
				u := User{ID: 100, Role: "admin"}
				samples := []p0Sample{}
				for round := 1; round <= 3; round++ {
					for _, c := range []struct{ name, path string }{
						{"assets-first", "/api/assets?page_size=50"},
						{"assets-deep", "/api/assets?page_size=50&page=" + strconv.Itoa(n/50)},
						{"assets-score", "/api/assets?page_size=50&sort=score"},
						{"assets-project", "/api/assets?page_size=50&project_id=101"},
						{"dashboard", "/api/dashboard/summary"},
					} {
						w := httptest.NewRecorder()
						r := httptest.NewRequest("GET", c.path, nil)
						before := tr.queries.Load()
						start := time.Now()
						if c.name == "dashboard" {
							e.dashboard(w, r, u)
						} else {
							e.assets(w, r, u, false)
						}
						elapsed := time.Since(start)
						if w.Code != 200 {
							t.Fatal("P0 handler failed: " + c.name)
						}
						samples = append(samples, p0Sample{c.name, round, tr.queries.Load() - before, float64(elapsed.Microseconds()) / 1000, w.Body.Len()})
					}
					before := tr.queries.Load()
					start := time.Now()
					if _, err := s.scopes(context.Background(), u); err != nil {
						t.Fatal("P0 scopes failed")
					}
					samples = append(samples, p0Sample{"scopes-20", round, tr.queries.Load() - before, float64(time.Since(start).Microseconds()) / 1000, 0})
				}
				// Copy the actual handler SQL without reducing its payload/permission predicates.
				where, args := assetWhere(u, url.Values{})
				args = append(args, 50, 0)
				query := "SELECT to_jsonb(a)||jsonb_build_object('domain',s.domain,'services_count',(SELECT count(*)FROM asset_services svc WHERE svc.asset_id=a.id),'ports_count',(SELECT count(DISTINCT port)FROM asset_services svc WHERE svc.asset_id=a.id)) FROM assets a JOIN scopes s ON s.id=a.scope_id" + where + fmt.Sprintf(" ORDER BY a.id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
				var plan json.RawMessage
				if err := s.DB.QueryRow(context.Background(), "EXPLAIN (ANALYZE,BUFFERS,SETTINGS,FORMAT JSON) "+query, args...).Scan(&plan); err != nil {
					t.Fatal("P0 EXPLAIN failed")
				}
				settings := map[string]string{}
				for _, key := range []string{"server_version", "shared_buffers", "work_mem", "max_connections", "effective_cache_size", "timezone"} {
					var val string
					if err := s.DB.QueryRow(context.Background(), "SELECT current_setting($1)", key).Scan(&val); err != nil {
						t.Fatal("P0 settings failed")
					}
					settings[key] = val
				}
				p0Write(t, t.Name()[len("TestP0ReadBaseline/"):], map[string]any{"fixture_version": 1, "anchor": "2026-10-30T00:00:00Z", "assets": n, "services": 2 * n, "skew90": skew, "samples": samples, "assets_first_explain": plan, "postgres": settings, "go": runtime.Version(), "cpus": runtime.NumCPU(), "limitations": []string{"in-process handlers; no TLS/browser/proxy latency", "three rounds are raw samples, not p95/p99", "read paths only; no write/WAL/HOT or target-network capacity claim", "admin baseline; role matrix remains pending"}})
			})
		}
	}
}

func TestP0ScopesQueryScaling(t *testing.T) {
	for _, n := range []int{0, 1, 100, 1000} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			s, tr := p0Store(t)
			p0Exec(t, s, `INSERT INTO scopes(owner,domain,policy) SELECT 100,'s'||i||'.example.test','P0 synthetic' FROM generate_series(1,$1::int)i`, n)
			samples := []p0Sample{}
			for round := 1; round <= 3; round++ {
				before := tr.queries.Load()
				start := time.Now()
				out, err := s.scopes(context.Background(), User{ID: 100, Role: "admin"})
				if err != nil || len(out) != n {
					t.Fatal("P0 scopes fixture failed")
				}
				samples = append(samples, p0Sample{"scopes", round, tr.queries.Load() - before, float64(time.Since(start).Microseconds()) / 1000, 0})
			}
			p0Write(t, "scopes-"+strconv.Itoa(n), samples)
		})
	}
}
