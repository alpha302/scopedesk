package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestPostgresFaviconMigrationArchivesUnverifiedValues(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.DB)
	defer db.Close()
	if err := goose.DownToContext(ctx, db, "migrations", 8); err != nil {
		t.Fatal(err)
	}
	scope := insertScope(t, s, 1)
	var id int64
	old := strings.Repeat("a", 64)
	if err := s.DB.QueryRow(ctx, "INSERT INTO assets(scope_id,host,favicon_hash)VALUES($1,'old.example.com',$2)RETURNING id", scope.ID, old).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, "INSERT INTO asset_services(asset_id,port,protocol,favicon_sha256,favicon_mmh3)VALUES($1,443,'tcp',$2,0)", id, old); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := goose.UpContext(ctx, db, "migrations"); err != nil {
			t.Fatal(err)
		}
	}
	var mmh, assetMMH, legacyMMH *int32
	var hash, assetHash *string
	var legacy string
	if err := s.DB.QueryRow(ctx, "SELECT a.favicon_mmh3,a.favicon_sha256,svc.favicon_mmh3,svc.favicon_sha256,svc.favicon_legacy_sha256,svc.favicon_legacy_mmh3 FROM assets a JOIN asset_services svc ON svc.asset_id=a.id WHERE a.id=$1", id).Scan(&assetMMH, &assetHash, &mmh, &hash, &legacy, &legacyMMH); err != nil || assetMMH != nil || assetHash != nil || mmh != nil || hash != nil || legacy != old || legacyMMH == nil || *legacyMMH != 0 {
		t.Fatal("unverified history became a fact", assetMMH, assetHash, mmh, hash, legacy, legacyMMH, err)
	}
	if err := goose.DownToContext(ctx, db, "migrations", 8); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, "SELECT favicon_sha256,favicon_mmh3 FROM asset_services WHERE asset_id=$1", id).Scan(&legacy, &mmh); err != nil || legacy != old || mmh == nil || *mmh != 0 {
		t.Fatal("rollback lost original values", legacy, mmh, err)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresFaviconServiceFactsAndAssetProjection(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	write := func(ob Observation) {
		t.Helper()
		ob.Redirects = []string{}
		ob.Fingerprints = []string{}
		run := claimedRun(t, s, scope)
		if _, err := s.WriteResults(ctx, run, []Observation{ob}, false); err != nil {
			t.Fatal(err)
		}
		closeRun(t, s, run)
	}
	assertHash := func(want int32, sha string) {
		t.Helper()
		var mmh *int32
		var got *string
		if err := s.DB.QueryRow(ctx, "SELECT favicon_mmh3,favicon_sha256 FROM assets WHERE scope_id=$1 AND host='api.example.com'", scope.ID).Scan(&mmh, &got); err != nil || mmh == nil || *mmh != want || got == nil || *got != sha {
			t.Fatal("asset projection", mmh, got, err)
		}
	}
	write(Observation{Host: "api.example.com", Services: []ServiceObservation{
		{Port: 80, StatusCode: ptr(200), FaviconMMH3: ptr(int32(0)), FaviconSHA256: &a, FaviconMeasured: true},
		{Port: 443, StatusCode: ptr(200), FaviconMMH3: ptr(int32(-123)), FaviconSHA256: &b, FaviconMeasured: true},
	}})
	assertHash(-123, b)
	// A completed icon check without a valid image clears just that service's fact.
	write(Observation{Host: "api.example.com", Services: []ServiceObservation{{Port: 443, StatusCode: ptr(200), FaviconMeasured: true}}})
	assertHash(0, a)
	write(Observation{Host: "api.example.com", StatusCode: 200, Port: 80, Favicon: c})
	assertHash(0, a)
	// A provider cannot write facts even if its in-memory service claims measurement.
	write(Observation{Host: "api.example.com", EvidenceOnly: true, PluginEvidence: []PluginEvidence{{Source: "provider", Fields: map[string]any{"favicon_sha256": c}}}, Services: []ServiceObservation{{Port: 8443, FaviconMMH3: ptr(int32(9)), FaviconSHA256: &c, FaviconMeasured: true, EvidenceOnly: true, Source: "provider"}}})
	assertHash(0, a)
	var mmh *int32
	var hash *string
	var raw []byte
	if err := s.DB.QueryRow(ctx, "SELECT svc.favicon_mmh3,svc.favicon_sha256,a.plugin_evidence FROM assets a JOIN asset_services svc ON svc.asset_id=a.id WHERE a.scope_id=$1 AND svc.port=8443", scope.ID).Scan(&mmh, &hash, &raw); err != nil || mmh != nil || hash != nil || !strings.Contains(string(raw), c) {
		t.Fatal("provider evidence contaminated facts", mmh, hash, string(raw), err)
	}
	// With no 443 icon, earliest valid icon wins, not numeric port order.
	write(Observation{Host: "api.example.com", Services: []ServiceObservation{{Port: 79, StatusCode: ptr(200), FaviconMMH3: ptr(int32(12)), FaviconSHA256: &b, FaviconMeasured: true}}})
	assertHash(0, a)
}

func TestPostgresFaviconFiltersAndPermissions(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	other := insertScope(t, s, 2)
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var id, otherID int64
	if err := s.DB.QueryRow(ctx, "INSERT INTO assets(scope_id,host)VALUES($1,'api.example.com')RETURNING id", scope.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, "INSERT INTO assets(scope_id,host)VALUES($1,'hidden.example.com')RETURNING id", other.ID).Scan(&otherID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO asset_services(asset_id,port,protocol,favicon_mmh3,favicon_sha256,evidence_only)VALUES($1,80,'tcp',0,$3,false),($1,443,'tcp',-123,$4,false),($2,80,'tcp',0,$3,false),($1,8443,'tcp',99,$3,true)`, id, otherID, a, b); err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: s}
	user := User{ID: 1, Role: "user"}
	for _, tc := range []struct {
		query string
		total int
	}{{"favicon_mmh3=0", 1}, {"favicon_mmh3=-123", 1}, {"favicon_mmh3=0&port=443", 0}, {"favicon_mmh3=-123&favicon_sha256=" + a, 0}, {"favicon_sha256=" + strings.ToUpper(b), 1}, {"favicon_mmh3=99", 0}, {"favicon_mmh3=2147483647", 0}, {"favicon_mmh3=-2147483648", 0}} {
		w := apiRecorder()
		e.serve(w, apiRequest("GET", "/api/assets?"+tc.query, ""), user)
		var result struct {
			Total int `json:"total"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Total != tc.total {
			t.Fatal("hash filter", tc, w.Code, w.Body.String())
		}
	}
	for _, query := range []string{"favicon_mmh3=2147483648", "favicon_mmh3=-2147483649", "favicon_mmh3=abc", "favicon_sha256=not-a-hash"} {
		w := apiRecorder()
		e.serve(w, apiRequest("GET", "/api/assets?"+query, ""), user)
		if w.Code != 400 {
			t.Fatal("invalid filter not rejected", query, w.Code)
		}
	}
	w := apiRecorder()
	e.serve(w, apiRequest("GET", fmt.Sprintf("/api/assets/%d", id), ""), user)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"favicon_mmh3":0`) {
		t.Fatal("zero absent from detail", w.Code, w.Body.String())
	}
	w = apiRecorder()
	e.serve(w, apiRequest("GET", "/api/assets/export?format=csv&favicon_mmh3=0", ""), user)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "api.example.com") || strings.Contains(w.Body.String(), "hidden.example.com") {
		t.Fatal("filtered export or isolation", w.Code, w.Body.String())
	}
}
