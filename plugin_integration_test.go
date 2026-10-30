package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"golang.org/x/net/dns/dnsmessage"
	"gopkg.in/yaml.v3"
)

func registerFixture(t *testing.T, s *Store, m PluginManifest) {
	t.Helper()
	if err := s.initializePlugins(context.Background(), &PluginRegistry{Manifests: map[string]PluginManifest{m.Name: m}}); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresPluginCoreStrategiesAndSourceStats(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	empty := fixturePlugin(t, "empty", "jsonl")
	empty.Name = "fixture-empty"
	result := fixturePlugin(t, "jsonl", "jsonl")
	result.Name = "fixture-result"
	if err := s.initializePlugins(ctx, &PluginRegistry{Manifests: map[string]PluginManifest{empty.Name: empty, result.Name: result}}); err != nil {
		t.Fatal(err)
	}
	s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true")
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, remote, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil {
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
	resolver := &net.Resolver{PreferGo: true, Dial: func(c context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(c, "udp", conn.LocalAddr().String())
	}}
	e := &Engine{Store: s, Queue: &PGQueue{s}, root: ctx, Labels: []string{"default"}, Pipeline: &Pipeline{Guard: s.guard, Limit: immediateLimit{}, Resolver: resolver}}
	for i, strategy := range []string{"all", "first_success", "fallback"} {
		scope := insertScope(t, s, 100+i)
		q := PGQueue{s}
		_, err := q.EnqueueStrategy(ctx, scope, []string{empty.Name, result.Name}, "test", strategy)
		if err != nil {
			t.Fatal(err)
		}
		run, err := q.Claim(ctx, "fixture-worker")
		if err != nil {
			t.Fatal(err)
		}
		e.execute(run)
		var status string
		s.DB.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", run.ID).Scan(&status)
		if status != "done" {
			t.Fatal("core plugin execution failed", strategy, status)
		}
		var count int
		s.DB.QueryRow(ctx, "SELECT count(*)FROM plugin_runs WHERE job_id=$1", run.ID).Scan(&count)
		want := 2
		if strategy == "first_success" {
			want = 1
		}
		if count != want {
			t.Fatal("core strategy attempt count", strategy, count)
		}
		if strategy != "first_success" {
			var returned, inScope, newCount int
			s.DB.QueryRow(ctx, "SELECT returned,in_scope,new_count FROM job_source_stats WHERE job_id=$1 AND source=$2", run.ID, result.Name).Scan(&returned, &inScope, &newCount)
			if returned != 3 || inScope != 2 || newCount != 1 {
				t.Fatal("source statistics changed", returned, inScope, newCount)
			}
			s.DB.QueryRow(ctx, "SELECT new_count FROM plugin_runs WHERE job_id=$1 AND plugin=$2", run.ID, result.Name).Scan(&count)
			if count != 1 {
				t.Fatal("new_count not persisted")
			}
		}
	}
}

func TestPostgresPluginManifestDropInAndSubfinderCompatibility(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	m := fixturePlugin(t, "jsonl", "jsonl")
	dir := t.TempDir()
	raw, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "new-tool.yaml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	registry, err := loadPluginRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.initializePlugins(ctx, registry); err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: s}
	admin := User{ID: 1, Role: "admin"}
	w := apiRecorder()
	e.serve(w, apiRequest("PUT", "/api/plugins/fixture", `{"enabled":true,"params":{}}`), admin)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if !strings.Contains(strings.Join(e.collectorOptions(ctx), ","), "fixture") {
		t.Fatal("manifest source missing from core registry")
	}
	m, params, enabled, err := s.pluginConfig(ctx, "fixture")
	if err != nil || !enabled {
		t.Fatal("drop-in not enabled")
	}
	plugin := fixtureExternal(m)
	plugin.Params = params
	result := plugin.Run(ctx, "example.com")
	if result.Error != "" || len(result.Records) != 1 {
		t.Fatal("drop-in execution failed", result.Error)
	}
	bad := []byte("name: invalid\nexec: {}\n")
	os.WriteFile(filepath.Join(dir, "bad.yaml"), bad, 0600)
	if _, err = loadPluginRegistry(dir); err == nil {
		t.Fatal("invalid manifest silently loaded")
	}
	raw, _ = defaultPluginFiles.ReadFile("plugins/subfinder.yaml")
	sub, err := parseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Name != "subfinder" || sub.timeout != 120000000000 || sub.Exec.MaxOutput != 8000000 || sub.Exec.Limits["as"] != 2147483648 || sub.Exec.Limits["cpu"] != 100 {
		t.Fatal("subfinder execution contract changed")
	}
	if strings.Join(sub.Exec.Args, " ") != "-d {{domain}} -json -silent -duc -rl {{rate}} -timeout 15 -max-time 1" {
		t.Fatal("subfinder flags changed")
	}
	scope := sampleScope()
	scope.RPS = 0.5
	compat := SubfinderCollector{Bin: "/opt/scopedesk-tools/subfinder", Budget: &Budget{Limit: 10}}
	if _, err = compat.Collect(ctx, scope); err == nil {
		t.Fatal("subfinder fractional rate accepted")
	}
}
func TestPostgresPluginLabelsAndRecovery(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	m := fixturePlugin(t, "jsonl", "jsonl")
	m.Requires.Labels = []string{"raw-socket"}
	registerFixture(t, s, m)
	s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true WHERE name='fixture'")
	scope := insertScope(t, s, 1)
	q := PGQueue{s}
	labelled, err := q.Enqueue(ctx, scope, []string{"fixture"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Claim(ctx, "plain"); err != pgx.ErrNoRows {
		t.Fatal("unlabelled claimed restricted job", err)
	}
	claimed, err := q.ClaimWithLabels(ctx, "raw-worker", []string{"default", "raw-socket"})
	if err != nil || claimed.ID != labelled {
		t.Fatal("labelled claim", err)
	}
	s.DB.Exec(ctx, "UPDATE jobs SET lease_until=now()-interval '1 second'WHERE id=$1", labelled)
	if _, err = q.ClaimWithLabels(ctx, "wrong-worker", []string{"default"}); err != pgx.ErrNoRows {
		t.Fatal("lease recovered without labels")
	}
	recovered, err := q.ClaimWithLabels(ctx, "matching-worker", []string{"raw-socket"})
	if err != nil || recovered.Attempts != 2 {
		t.Fatal("matching recovery", err)
	}
	closeRun(t, s, recovered)
	_, err = q.Enqueue(ctx, scope, []string{"crtsh"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := q.Claim(ctx, "plain")
	if err != nil {
		t.Fatal("no-label job not claimable", err)
	}
	closeRun(t, s, plain)
	_, err = q.Enqueue(ctx, scope, []string{"crtsh"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	plain, err = q.ClaimWithLabels(ctx, "rich-worker", []string{"raw-socket"})
	if err != nil {
		t.Fatal("labelled worker cannot claim unrestricted", err)
	}
	closeRun(t, s, plain)
	if labels, err := workerLabels([]string{"worker", "--labels=raw-socket,default"}); err != nil || len(labels) != 2 {
		t.Fatal("CLI labels")
	}
	if _, err = workerLabels([]string{"--labels=cap:net_raw"}); err == nil {
		t.Fatal("forged capability label accepted")
	}
}
func TestPostgresPluginAdminTestWorkflow(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	m := fixturePlugin(t, "jsonl", "jsonl")
	registerFixture(t, s, m)
	engine := &Engine{Store: s, Queue: &PGQueue{s}, root: ctx, WorkerID: "fixture-node", workers: 1, Labels: []string{"default"}}
	admin := User{ID: 1, Role: "admin"}
	scope := insertScope(t, s, 1)
	other := insertScope(t, s, 2)
	for _, method := range []string{"GET", "PUT", "POST"} {
		path := "/api/plugins"
		if method == "PUT" {
			path += "/fixture"
		}
		if method == "POST" {
			path += "/fixture/test"
		}
		w := apiRecorder()
		engine.serve(w, apiRequest(method, path, `{}`), User{ID: 2, Role: "user"})
		if w.Code != 403 {
			t.Fatal("admin plugin permission", method, w.Code)
		}
	}
	w := apiRecorder()
	engine.serve(w, apiRequest("GET", "/api/plugins", ""), admin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatal("new plugin not disabled", w.Body.String())
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("PUT", "/api/plugins/fixture", `{"enabled":true,"params":{"unknown":1}}`), admin)
	if w.Code != 400 {
		t.Fatal("undeclared param accepted")
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("PUT", "/api/plugins/fixture", `{"enabled":true,"params":{}}`), admin)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	for _, body := range []map[string]any{{"scope_id": scope.ID, "target": "outside.net"}, {"scope_id": other.ID, "target": "example.com"}, {"scope_id": scope.ID, "target": "example.com;id"}} {
		w = apiRecorder()
		engine.serve(w, apiRequest("POST", "/api/plugins/fixture/test", mustJSON(body)), admin)
		if w.Code == 202 {
			t.Fatal("unsafe test target queued")
		}
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("POST", "/api/plugins/fixture/test", mustJSON(map[string]any{"scope_id": scope.ID, "target": "example.com"})), admin)
	if w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	q := PGQueue{s}
	run, err := q.ClaimWithLabels(ctx, "fixture-worker", []string{"default"})
	if err != nil {
		t.Fatal(err)
	}
	engine.execute(run)
	var status string
	var results []byte
	s.DB.QueryRow(ctx, "SELECT status,stats FROM jobs WHERE id=$1", run.ID).Scan(&status, &results)
	if status != "done" || !strings.Contains(string(results), "api.example.com") {
		t.Fatal("test results not visible", status, string(results))
	}
	var count int
	s.DB.QueryRow(ctx, "SELECT count(*)FROM assets").Scan(&count)
	if count != 0 {
		t.Fatal("test run modified assets")
	}
	s.DB.QueryRow(ctx, "SELECT count(*)FROM plugin_runs WHERE job_id=$1 AND finished_at IS NOT NULL AND returned=3 AND in_scope=2", run.ID).Scan(&count)
	if count != 1 {
		t.Fatal("plugin run statistics")
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("GET", "/api/plugins/fixture/runs", ""), admin)
	if w.Code != 200 || strings.Contains(w.Body.String(), "fixture-secret") || !strings.Contains(w.Body.String(), "api.example.com") {
		t.Fatal("run listing/redaction")
	}
	// Disabled and active plugins cannot run; settings survive registry reload.
	m.Active = true
	s.Plugins.Manifests[m.Name] = m
	w = apiRecorder()
	engine.serve(w, apiRequest("PUT", "/api/plugins/fixture", `{"enabled":true,"params":{}}`), admin)
	if w.Code != 400 {
		t.Fatal("active plugin enabled")
	}
}
func TestPostgresPluginWorkerWaitAndScheduler(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	m := fixturePlugin(t, "jsonl", "jsonl")
	m.Requires.Labels = []string{"special"}
	registerFixture(t, s, m)
	s.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=true WHERE name='fixture'")
	scope := insertScope(t, s, 1)
	q := PGQueue{s}
	job, err := q.Enqueue(ctx, scope, []string{"fixture"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	s.DB.Exec(ctx, "UPDATE jobs SET created_at=now()-interval '10 minutes'WHERE id=$1", job)
	engine := &Engine{Store: s, Queue: &q, root: ctx, WorkerID: "plain", workers: 1, Labels: []string{"default"}}
	engine.workerHeartbeat(ctx)
	list, err := engine.jobList(ctx, User{ID: 1, Role: "admin"})
	if err != nil || !strings.Contains(string(list[0]), `"waiting_for_worker": true`) {
		t.Fatal("missing worker wait state", err, string(list[0]))
	}
	engine.WorkerID = "special"
	engine.Labels = []string{"special"}
	engine.workerHeartbeat(ctx)
	list, _ = engine.jobList(ctx, User{ID: 1, Role: "admin"})
	if strings.Contains(string(list[0]), `"waiting_for_worker": true`) {
		t.Fatal("matching worker ignored")
	}
	s.DB.Exec(ctx, "UPDATE jobs SET status='cancelled'WHERE id=$1", job)
	raw, _ := json.Marshal([]string{"fixture"})
	s.DB.Exec(ctx, "INSERT INTO monitor_plans(scope_id,enabled,next_run_at,collectors)VALUES($1,true,now()-interval '1 minute',$2)", scope.ID, raw)
	engine.scheduleTick()
	var labels []string
	s.DB.QueryRow(ctx, "SELECT required_labels FROM jobs WHERE trigger='schedule'").Scan(&labels)
	if len(labels) != 1 || labels[0] != "special" {
		t.Fatal("scheduler missed required labels", labels)
	}
}
func TestPostgresPluginNewCountAttribution(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	run := claimedRun(t, s, scope)
	ob := Observation{Host: "api.example.com", Sources: []string{"fixture"}}
	if _, err := s.WriteResults(ctx, run, []Observation{ob}, false); err != nil {
		t.Fatal(err)
	}
	var id int64
	s.DB.QueryRow(ctx, "INSERT INTO plugin_runs(job_id,plugin)VALUES($1,'fixture')RETURNING id", run.ID).Scan(&id)
	engine := &Engine{Store: s}
	engine.updatePluginNewCounts(ctx, run, []PluginResult{{RunID: id, Records: []PluginRecord{{Candidate: Candidate{ob.Host, "fixture"}}}}})
	var count int
	s.DB.QueryRow(ctx, "SELECT new_count FROM plugin_runs WHERE id=$1", id).Scan(&count)
	if count != 1 {
		t.Fatal("plugin new count attribution", count)
	}
}
