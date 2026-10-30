package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"golang.org/x/net/dns/dnsmessage"
)

// All lookups resolve to a forbidden local address; no target HTTP is sent.
func evidenceTestPipeline(t *testing.T, s *Store) *Pipeline {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, remote, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buf[:n]) != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: query.Questions}
			for _, q := range query.Questions {
				if q.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				}
			}
			raw, _ := response.Pack()
			conn.WriteTo(raw, remote)
		}
	}()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}
	return &Pipeline{Guard: s.guard, Limit: immediateLimit{}, Resolver: resolver, Rules: &SecurityRuleCache{Load: s.securityRules}}
}

func TestPostgresPluginEvidenceDoesNotRecoverOrOverwriteLiveData(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	run := claimedRun(t, s, scope)
	live := Observation{Host: "api.example.com", IPs: []string{"8.8.8.8"}, DNSChecked: true, Port: 443, StatusCode: 200, Title: "verified title", Server: "verified server", IsCDN: true, Alive: ptr(true), Sources: []string{"crtsh"}, Redirects: []string{}, Fingerprints: []string{}}
	if _, err := s.WriteResults(ctx, run, []Observation{live}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, "UPDATE assets SET miss_count=3,is_alive=false WHERE scope_id=$1", scope.ID); err != nil {
		t.Fatal(err)
	}
	result := parseEvidence(t, `{"host":"api.example.com","ip":"8.8.8.8","port":443,"code":200,"title":"historical title"}
{"host":"api.example.com","ip":"1.1.1.1","port":8443,"code":200,"title":"historical extra service"}
{"host":"api.example.com","title":"host metadata without port","server":"historical server"}`)
	obs := []Observation{}
	for _, r := range result.Records {
		obs = append(obs, *r.Observation)
	}
	summary, err := s.WriteResults(ctx, run, obs, false)
	if err != nil || summary["back"] != 0 {
		t.Fatal("provider metadata revived asset", summary, err)
	}
	var id int64
	var miss, port, code int
	var alive, cdn bool
	var title, server string
	var evidence []byte
	err = s.DB.QueryRow(ctx, "SELECT id,miss_count,is_alive,is_cdn,port,status_code,title,server,plugin_evidence FROM assets WHERE scope_id=$1", scope.ID).Scan(&id, &miss, &alive, &cdn, &port, &code, &title, &server, &evidence)
	if err != nil || miss != 3 || alive || !cdn || port != 443 || code != 200 || title != "verified title" || server != "verified server" || !strings.Contains(string(evidence), "host metadata without port") {
		t.Fatal("live state overwritten", miss, alive, cdn, title, server, string(evidence), err)
	}
	var count int
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM asset_services WHERE asset_id=$1", id).Scan(&count); err != nil || count != 2 {
		t.Fatal("service fabricated or lost", count, err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT title FROM asset_services WHERE asset_id=$1 AND port=443", id).Scan(&title); err != nil || title != "verified title" {
		t.Fatal("live service overwritten", title, err)
	}
	var only bool
	var source string
	if err = s.DB.QueryRow(ctx, "SELECT evidence_only,source FROM asset_services WHERE asset_id=$1 AND port=8443", id).Scan(&only, &source); err != nil || !only || source != "evidence-fixture" {
		t.Fatal("evidence provenance lost", only, source, err)
	}
	// Repeating unchanged metadata must not add snapshots merely due to timestamps.
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM asset_snapshots WHERE asset_id=$1", id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	for i := range obs {
		for j := range obs[i].PluginEvidence {
			obs[i].PluginEvidence[j].ObservedAt = obs[i].PluginEvidence[j].ObservedAt.Add(time.Hour)
		}
	}
	if _, err = s.WriteResults(ctx, run, obs, false); err != nil {
		t.Fatal(err)
	}
	var after int
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM asset_snapshots WHERE asset_id=$1", id).Scan(&after); err != nil || after != count {
		t.Fatal("timestamp-only snapshot", after, count, err)
	}
	// A genuine failed probe still counts, even when accompanied by a provider's 200.
	failure := Observation{Host: live.Host, Alive: ptr(false), DNSChecked: true, IPs: live.IPs}
	if _, err = s.WriteResults(ctx, run, append([]Observation{failure}, obs...), false); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT miss_count FROM assets WHERE id=$1", id).Scan(&miss); err != nil || miss != 4 {
		t.Fatal("provider cleared real probe failure", miss, err)
	}
	// A new asset with metadata alone has unknown reachability.
	unknown := *parseEvidence(t, `{"host":"unknown.example.com","title":"no port"}`).Records[0].Observation
	if _, err = s.WriteResults(ctx, run, []Observation{unknown}, false); err != nil {
		t.Fatal(err)
	}
	var isNull bool
	if err = s.DB.QueryRow(ctx, "SELECT is_alive IS NULL FROM assets WHERE scope_id=$1 AND host=$2", scope.ID, unknown.Host).Scan(&isNull); err != nil || !isNull {
		t.Fatal("unknown marked alive", err)
	}
	w := apiRecorder()
	(&Engine{Store: s}).serve(w, apiRequest("GET", fmt.Sprintf("/api/assets/%d", id), ""), User{ID: 1, Role: "admin"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "plugin_evidence") || !strings.Contains(w.Body.String(), `"evidence_only":true`) {
		t.Fatal("evidence unavailable in detail API", w.Body.String())
	}
	// Only an actual successful measurement recovers the asset.
	summary, err = s.WriteResults(ctx, run, []Observation{live}, false)
	if err != nil || summary["back"] != 1 {
		t.Fatal("real recovery suppressed", summary, err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM asset_events WHERE asset_id=$1 AND type='ASSET_BACK'", id).Scan(&count); err != nil || count != 1 {
		t.Fatal("false recovery events", count, err)
	}
}

func TestPostgresPluginRetryCommitsOnlySuccessfulAttempt(t *testing.T) {
	for _, mode := range []string{"retry-observer", "failed-observer", "invalid-observer"} {
		t.Run(mode, func(t *testing.T) {
			s := integrationStore(t)
			ctx := context.Background()
			scope := insertScope(t, s, 1)
			if mode == "invalid-observer" {
				if _, err := s.DB.Exec(ctx, "INSERT INTO assets(scope_id,host,is_alive,miss_count,title)VALUES($1,'api.example.com',false,3,'verified before down')", scope.ID); err != nil {
					t.Fatal(err)
				}
			}
			m := observerMapping(fixturePlugin(t, mode, "jsonl"))
			if mode == "retry-observer" {
				m.Exec.RetryExitCodes = []int{7}
				m.Exec.Args = append(m.Exec.Args[:len(m.Exec.Args)-1], filepath.Join(t.TempDir(), "counter"), "{{domain}}")
			}
			registerFixture(t, s, m)
			if _, err := s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true"); err != nil {
				t.Fatal(err)
			}
			q := PGQueue{s}
			if _, err := q.Enqueue(ctx, scope, []string{m.Name}, "test"); err != nil {
				t.Fatal(err)
			}
			run, err := q.Claim(ctx, "evidence-fixture-worker")
			if err != nil {
				t.Fatal(err)
			}
			e := &Engine{Store: s, Queue: &q, root: ctx, Pipeline: evidenceTestPipeline(t, s)}
			e.execute(run)
			var assets, badAssets, runs int
			if err = s.DB.QueryRow(ctx, "SELECT count(*),count(*) FILTER(WHERE host LIKE 'failed-only.%') FROM assets").Scan(&assets, &badAssets); err != nil {
				t.Fatal(err)
			}
			if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM plugin_runs WHERE job_id=$1", run.ID).Scan(&runs); err != nil {
				t.Fatal(err)
			}
			want := 1
			wantRuns := 1
			if mode == "failed-observer" {
				want = 1
				wantRuns = 1
			}
			if mode == "retry-observer" {
				want = 2
				wantRuns = 2
			}
			if assets != want || runs != wantRuns {
				t.Fatal("retry evidence or audit runs lost", assets, runs)
			}
			var count int
			if mode != "invalid-observer" {
				if badAssets != 1 {
					t.Fatal("failed attempt candidate lost", badAssets)
				}
				if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM assets WHERE host LIKE 'failed-only.%' AND (title<>'' OR plugin_evidence<>'[]'::jsonb)").Scan(&count); err != nil || count != 0 {
					t.Fatal("failed observation leaked", count, err)
				}
			}
			if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM plugin_runs WHERE error<>'' AND new_count<>0").Scan(&count); err != nil || count != 0 {
				t.Fatal("failed invocation credited with new assets", count, err)
			}
			if mode == "retry-observer" {
				if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM plugin_runs WHERE error<>'' AND output_sample::text LIKE '%failed-only%'").Scan(&count); err != nil || count != 1 {
					t.Fatal("failed output not retained for audit", count, err)
				}
				if err = s.DB.QueryRow(ctx, "SELECT new_count FROM plugin_runs WHERE error=''").Scan(&count); err != nil || count != 1 {
					t.Fatal("successful invocation not credited", count, err)
				}
			}
			if mode == "invalid-observer" {
				var miss int
				var alive bool
				if err = s.DB.QueryRow(ctx, "SELECT miss_count,is_alive FROM assets WHERE scope_id=$1", scope.ID).Scan(&miss, &alive); err != nil || miss != 3 || alive {
					t.Fatal("DNS-only pipeline revived provider candidate", miss, alive, err)
				}
				for _, table := range []string{"plugin_runs", "job_source_stats"} {
					var raw []byte
					if err = s.DB.QueryRow(ctx, "SELECT rejected_fields FROM "+table+" WHERE job_id=$1", run.ID).Scan(&raw); err != nil {
						t.Fatal(err)
					}
					var fields map[string]int
					if json.Unmarshal(raw, &fields) != nil || fields["invalid_port"] != 1 || fields["invalid_status_code"] != 1 || fields["invalid_or_disallowed_ip"] != 1 {
						t.Fatal("rejection statistics lost", table, string(raw))
					}
				}
				if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM asset_services").Scan(&count); err != nil || count != 0 {
					t.Fatal("bad endpoint stored", count, err)
				}
			}
		})
	}
}

func TestPostgresPluginEvidenceMigrationRoundTrip(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.DB)
	defer db.Close()
	if err := goose.DownToContext(ctx, db, "migrations", 6); err != nil {
		t.Fatal(err)
	}
	scope := insertScope(t, s, 1)
	if _, err := s.DB.Exec(ctx, "INSERT INTO assets(scope_id,host,title)VALUES($1,'old.example.com','preserved')", scope.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := goose.UpContext(ctx, db, "migrations"); err != nil {
			t.Fatal(err)
		}
	}
	var title string
	var raw []byte
	if err := s.DB.QueryRow(ctx, "SELECT title,plugin_evidence FROM assets WHERE scope_id=$1", scope.ID).Scan(&title, &raw); err != nil || title != "preserved" || string(raw) != "[]" {
		t.Fatal("migration changed old data", title, string(raw), err)
	}
	if err := goose.DownToContext(ctx, db, "migrations", 6); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatal(err)
	}
}
