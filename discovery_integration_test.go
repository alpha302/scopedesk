package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestPostgresDiscoveryMigrationBackfillAndRepeat(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.DB)
	defer db.Close()
	if err := goose.DownToContext(ctx, db, "migrations", 2); err != nil {
		t.Fatal(err)
	}
	scope := insertScope(t, s, 7)
	_, err := s.DB.Exec(ctx, `INSERT INTO assets(scope_id,host,ips,port,status_code,title,server,favicon_hash,tls_subject,fingerprints,first_seen,last_seen)VALUES
 ($1,'https.example.com',ARRAY['8.8.8.8'],443,200,'TLS portal','nginx','legacy-hash','CN=fixture',ARRAY['nginx'],'2025-01-01','2025-02-01'),
 ($1,'http.example.com',ARRAY['1.1.1.1'],80,200,'Plain portal','Apache','','',ARRAY['Apache'],'2025-01-01','2025-02-01'),
 ($1,'unknown.example.com',ARRAY['invalid','8.8.4.4'],0,200,'Unknown IP','','','CN=fixture','{}','2025-01-01','2025-02-01'),
 ($1,'empty.example.com','{}',0,200,'No IP','','','','{}','2025-01-01','2025-02-01'),
 ($1,'dns.example.com',ARRAY['8.8.4.4'],0,0,'','','','','{}','2025-01-01','2025-02-01')`, scope.ID)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = goose.UpContext(ctx, db, "migrations"); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	s.DB.QueryRow(ctx, "SELECT count(*)FROM asset_services").Scan(&count)
	if count != 4 {
		t.Fatal("backfill duplicated or invented service", count)
	}
	var ip, scheme, title, hash string
	var port int
	var mmh *int32
	var first time.Time
	err = s.DB.QueryRow(ctx, "SELECT host(s.ip),s.port,s.scheme,s.title,s.favicon_legacy_sha256,s.favicon_mmh3,s.first_seen FROM asset_services s JOIN assets a ON a.id=s.asset_id WHERE a.host='https.example.com'").Scan(&ip, &port, &scheme, &title, &hash, &mmh, &first)
	if err != nil || ip != "8.8.8.8" || port != 443 || scheme != "https" || title != "TLS portal" || hash != "legacy-hash" || mmh != nil || first.Year() != 2025 {
		t.Fatal("legacy copy", err)
	}
	var nullIP bool
	s.DB.QueryRow(ctx, "SELECT s.ip IS NULL,s.port FROM asset_services s JOIN assets a ON a.id=s.asset_id WHERE a.host='unknown.example.com'").Scan(&nullIP, &port)
	if !nullIP || port != 443 {
		t.Fatal("unknown IP/TLS inference")
	}
	s.DB.QueryRow(ctx, "SELECT count(*)FROM pg_indexes WHERE schemaname=current_schema() AND indexname IN('asset_services_asset','candidates_scope_status','dns_records_scope_host')").Scan(&count)
	if count != 3 {
		t.Fatal("required indexes missing")
	}
	// State and uniqueness constraints are exercised in isolated statements.
	if _, err = s.DB.Exec(ctx, "INSERT INTO candidates(scope_id,host,status)VALUES($1,'bad.example.com','wrong')", scope.ID); err == nil {
		t.Fatal("candidate state unconstrained")
	}
	if _, err = s.DB.Exec(ctx, "INSERT INTO candidates(scope_id,host)VALUES($1,'candidate.example.com')", scope.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, "INSERT INTO candidates(scope_id,host)VALUES($1,'candidate.example.com')", scope.ID); err == nil {
		t.Fatal("candidate duplicate")
	}
}

func TestPostgresServiceDualWriteMultiPortAndHistory(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 7)
	ob := Observation{Host: "api.example.com", IPs: []string{"8.8.8.8"}, DNSChecked: true, Sources: []string{"fixture"}, Services: []ServiceObservation{
		{IP: "8.8.8.8", Port: 443, Service: ptr("https"), Scheme: ptr("https"), StatusCode: ptr(200), Title: ptr("Fixture TLS"), FaviconMMH3: ptr(int32(-123)), FaviconSHA256: ptr(strings.Repeat("a", 64)), FaviconMeasured: true, Fingerprints: json.RawMessage(`[{"name":"nginx"}]`), ScreenshotRef: ptr("fixture.png")},
		{IP: "8.8.8.8", Port: 22, Service: ptr("ssh"), Banner: ptr("SSH-2.0-Fixture")},
		{Port: 80, Service: ptr("http"), StatusCode: ptr(200), Title: ptr("Fixture plain")},
	}}
	for range 2 {
		run := claimedRun(t, s, scope)
		summary, err := s.WriteResults(ctx, run, []Observation{ob, ob}, false)
		if err != nil {
			t.Fatal(err)
		}
		if summary["new"].(int)+summary["updated"].(int) != 1 {
			t.Fatal("host counted twice")
		}
		closeRun(t, s, run)
	}
	var id int64
	var count, port int
	var title string
	s.DB.QueryRow(ctx, "SELECT id,port,title FROM assets").Scan(&id, &port, &title)
	if port != 443 || title != "Fixture TLS" {
		t.Fatal("legacy summary not dual written", port, title)
	}
	s.DB.QueryRow(ctx, "SELECT count(*)FROM asset_services").Scan(&count)
	if count != 3 {
		t.Fatal("service idempotency", count)
	}
	// A newer field survives an old observation without that field.
	old := Observation{Host: ob.Host, IPs: ob.IPs, StatusCode: 200, Port: 443, Title: "updated", Fingerprints: []string{}, Redirects: []string{}}
	run := claimedRun(t, s, scope)
	if _, err := s.WriteResults(ctx, run, []Observation{old}, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, s, run)
	var mmh int32
	var screenshot, hash string
	s.DB.QueryRow(ctx, "SELECT favicon_mmh3,screenshot_ref,favicon_sha256 FROM asset_services WHERE asset_id=$1 AND port=443", id).Scan(&mmh, &screenshot, &hash)
	if mmh != -123 || screenshot != "fixture.png" || hash != strings.Repeat("a", 64) {
		t.Fatal("old producer erased new fields")
	}
	// Distinct IP and UDP protocol create distinct identities.
	next := Observation{Host: ob.Host, IPs: []string{"1.1.1.1"}, DNSChecked: true, Services: []ServiceObservation{{IP: "1.1.1.1", Port: 443, Protocol: "udp", Service: ptr("quic")}}}
	run = claimedRun(t, s, scope)
	if _, err := s.WriteResults(ctx, run, []Observation{next}, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, s, run)
	s.DB.QueryRow(ctx, "SELECT count(*)FROM dns_records WHERE host=$1 AND rtype='A'", ob.Host).Scan(&count)
	if count != 2 {
		t.Fatal("DNS history was replaced", count)
	}
	s.DB.QueryRow(ctx, "SELECT count(*)FROM asset_ips WHERE asset_id=$1", id).Scan(&count)
	if count != 2 {
		t.Fatal("IP associations missing")
	}
	// Multiple failed service observations increment the asset miss count once.
	failed := Observation{Host: ob.Host, Alive: ptr(false)}
	run = claimedRun(t, s, scope)
	if _, err := s.WriteResults(ctx, run, []Observation{failed, failed}, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, s, run)
	s.DB.QueryRow(ctx, "SELECT miss_count FROM assets WHERE id=$1", id).Scan(&count)
	if count != 1 {
		t.Fatal("duplicate service failure counted per port", count)
	}
	// Reject invalid/private plugin IP evidence atomically; no network request occurs.
	next.Host = "bad.example.com"
	next.Services[0].IP = "127.0.0.1"
	run = claimedRun(t, s, scope)
	if _, err := s.WriteResults(ctx, run, []Observation{next}, false); err == nil {
		t.Fatal("unguarded plugin IP accepted")
	}
	closeRun(t, s, run)
	s.DB.QueryRow(ctx, "SELECT count(*)FROM assets WHERE host='bad.example.com'").Scan(&count)
	if count != 0 {
		t.Fatal("partial asset committed")
	}
}

func TestPostgresServiceAPICompatibilityAndExport(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 7)
	engine := &Engine{Store: s}
	user := User{ID: 7, Role: "user"}
	ob := Observation{Host: "api.example.com", Services: []ServiceObservation{{IP: "8.8.8.8", Port: 443, Service: ptr("https"), StatusCode: ptr(200)}, {IP: "1.1.1.1", Port: 443, Service: ptr("https")}, {Port: 22, Service: ptr("ssh")}}}
	run := claimedRun(t, s, scope)
	if _, err := s.WriteResults(ctx, run, []Observation{ob}, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, s, run)
	var id int64
	s.DB.QueryRow(ctx, "SELECT id FROM assets").Scan(&id)
	for _, tt := range []struct {
		query string
		total int
	}{{"port=443&service=https", 1}, {"port=443&service=ssh", 0}, {"port=22&service=ssh", 1}, {"port=garbage", 0}, {"service=https%27OR%20true--", 0}} {
		w := apiRecorder()
		engine.serve(w, apiRequest("GET", "/api/assets?"+tt.query, ""), user)
		var result struct {
			Total int `json:"total"`
			Items []struct {
				Count int `json:"services_count"`
				Ports int `json:"ports_count"`
			} `json:"items"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Total != tt.total {
			t.Fatal("service filter", w.Body.String())
		}
		if tt.total > 0 && (result.Items[0].Count != 3 || result.Items[0].Ports != 2) {
			t.Fatal("service/port counts")
		}
	}
	w := apiRecorder()
	engine.serve(w, apiRequest("GET", fmt.Sprintf("/api/assets/%d", id), ""), user)
	var detail map[string]json.RawMessage
	json.Unmarshal(w.Body.Bytes(), &detail)
	for _, key := range []string{"asset", "snapshots", "events", "services"} {
		if _, ok := detail[key]; !ok {
			t.Fatal("missing compatible field", key)
		}
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("GET", fmt.Sprintf("/api/assets/%d", id), ""), User{ID: 8, Role: "user"})
	if w.Code != 404 || strings.Contains(w.Body.String(), "8.8.8.8") {
		t.Fatal("service ownership leak")
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("GET", "/api/assets/export?format=csv&port=443&service=https", ""), user)
	records, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(w.Body.String(), "\ufeff"))).ReadAll()
	if err != nil || len(records) != 2 || len(records[0]) != 14 || records[0][2] != "端口" {
		t.Fatal("CSV format changed", err)
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("GET", "/api/assets/export?format=xlsx&port=443", ""), user)
	z, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if w.Code != 200 || err != nil || len(z.File) == 0 {
		t.Fatal("XLSX compatibility", err)
	}
}

func TestPostgresSourceCredentialsEncryptedAndRedacted(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	secret := []byte("fixture-secret-must-never-be-listed")
	if err := s.putSourceCredential(ctx, "fixture", secret, true, SourceQuota{Limit: 100, Remaining: 80, Used: 20}); err != nil {
		t.Fatal(err)
	}
	got, err := s.sourceCredentialKey(ctx, "fixture")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatal("decrypt mismatch")
	}
	var encrypted []byte
	s.DB.QueryRow(ctx, "SELECT key_encrypted FROM source_credentials WHERE source='fixture'").Scan(&encrypted)
	if bytes.Contains(encrypted, secret) || len(encrypted) <= len(secret) {
		t.Fatal("plaintext at rest")
	}
	if _, err = s.decrypt(credentialContext("another-source"), encrypted); err == nil {
		t.Fatal("cross-source decryption allowed")
	}
	// Even legacy/provider errors containing echoed keys are not returned verbatim.
	s.DB.Exec(ctx, "UPDATE source_credentials SET last_error=$1,quota=quota||jsonb_build_object('unknown_key',$1)WHERE source='fixture'", string(secret))
	engine := &Engine{Store: s}
	w := apiRecorder()
	engine.serve(w, apiRequest("GET", "/api/settings/source-credentials", ""), User{ID: 1, Role: "admin"})
	if w.Code != 200 || strings.Contains(w.Body.String(), string(secret)) || strings.Contains(w.Body.String(), "key_encrypted") || !strings.Contains(w.Body.String(), `"key_set":true`) {
		t.Fatal("credential list leakage")
	}
	for _, role := range []string{"user", "readonly"} {
		w = apiRecorder()
		engine.serve(w, apiRequest("GET", "/api/settings/source-credentials", ""), User{ID: 2, Role: role})
		if w.Code != 403 {
			t.Fatal("non-admin credential list")
		}
	}
	if err = s.setSourceCredentialFailure(ctx, "fixture", true); err != nil {
		t.Fatal(err)
	}
	s.DB.Exec(ctx, "UPDATE source_credentials SET enabled=false WHERE source='fixture'")
	if _, err = s.sourceCredentialKey(ctx, "fixture"); err == nil {
		t.Fatal("disabled secret read")
	}
	if err = s.putSourceCredential(ctx, "bad name", secret, true, SourceQuota{}); err == nil {
		t.Fatal("bad source accepted")
	}
	if err = s.putSourceCredential(ctx, "fixture", secret, true, SourceQuota{Limit: -1}); err == nil {
		t.Fatal("bad quota accepted")
	}
}

func TestPostgres100kServicesDetailLatency(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 7)
	if _, err := s.DB.Exec(ctx, "INSERT INTO assets(scope_id,host)SELECT $1,'perf-'||n||'.example.com'FROM generate_series(1,10000)n", scope.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO asset_services(asset_id,ip,port,protocol,service,status_code,title)SELECT a.id,'8.8.8.8'::inet,8000+p,'tcp','http',200,'Fixture service'FROM assets a CROSS JOIN generate_series(1,10)p`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"assets", "asset_services"} {
		if _, err := s.DB.Exec(ctx, "ANALYZE "+table); err != nil {
			t.Fatal(err)
		}
	}
	var id int64
	var count int
	s.DB.QueryRow(ctx, "SELECT min(asset_id),count(*)FROM asset_services").Scan(&id, &count)
	if count != 100000 {
		t.Fatal(count)
	}
	engine := &Engine{Store: s}
	for n := range 5 {
		start := time.Now()
		w := apiRecorder()
		engine.serve(w, apiRequest("GET", fmt.Sprintf("/api/assets/%d", id), ""), User{ID: 7, Role: "user"})
		elapsed := time.Since(start)
		var detail struct {
			Services []json.RawMessage `json:"services"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &detail) != nil || len(detail.Services) != 10 {
			t.Fatal("detail query failed", w.Body.String())
		}
		t.Logf("100k services / 10k hosts x 10 services: detail trial %d = %s", n+1, elapsed)
		if elapsed >= 200*time.Millisecond {
			t.Fatalf("detail exceeds 200ms: %s", elapsed)
		}
	}
	start := time.Now()
	services, err := queryJSON(ctx, s.DB, assetServicesSQL, id)
	t.Logf("service SQL query+decode=%s rows=%d", time.Since(start), len(services))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.DB.Query(ctx, "EXPLAIN (ANALYZE,BUFFERS) SELECT * FROM asset_services WHERE asset_id=$1 ORDER BY port,protocol,ip NULLS FIRST,id", id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var line string
		rows.Scan(&line)
		t.Log(line)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
}
