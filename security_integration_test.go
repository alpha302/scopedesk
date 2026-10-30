package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestPostgresSecurityRuleAPI(t *testing.T) {
	store := integrationStore(t)
	ctx := context.Background()
	cache := &SecurityRuleCache{Load: store.securityRules}
	engine := &Engine{Store: store, Pipeline: &Pipeline{Rules: cache}}
	admin := User{ID: 1, Role: "admin"}
	if !engine.handles("/api/security-rules") || engine.handles("/api/security-rules-evil") {
		t.Fatal("routing")
	}
	for _, role := range []string{"user", "readonly"} {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			w := apiRecorder()
			engine.serve(w, apiRequest(method, "/api/security-rules", `{}`), User{ID: 2, Role: role})
			if w.Code != 403 {
				t.Fatalf("%s %s: %d", role, method, w.Code)
			}
		}
	}
	rules, err := store.securityRules(ctx)
	if err != nil || len(rules) != 11 {
		t.Fatal("builtin migration", err, len(rules))
	}
	for _, r := range rules {
		if !r.Builtin || !r.Enabled {
			t.Fatal("builtin flags")
		}
	}
	cache.refresh(ctx, true)
	body := SecurityRule{Keyword: `(?i)vpn`, Match: "regex", Fields: []string{"title"}, Enabled: true, Builtin: true}
	w := apiRecorder()
	engine.serve(w, apiRequest("POST", "/api/security-rules", mustJSON(body)), admin)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var saved struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &saved)
	var builtin bool
	store.DB.QueryRow(ctx, "SELECT builtin FROM security_rules WHERE id=$1", saved.ID).Scan(&builtin)
	if builtin {
		t.Fatal("builtin forged")
	}
	cached, _ := cache.refresh(ctx, false)
	if len(cached) != 12 {
		t.Fatal("current process cache not refreshed")
	}
	body.ID = saved.ID
	body.Enabled = false
	w = apiRecorder()
	engine.serve(w, apiRequest("PUT", "/api/security-rules", mustJSON(body)), admin)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cached, _ = cache.refresh(ctx, false)
	for _, r := range cached {
		if r.ID == saved.ID && r.Enabled {
			t.Fatal("disable not applied")
		}
	}
	for _, bad := range []string{`{"keyword":"(","match":"regex","fields":["title"]}`, `{"keyword":"x","match":"contains","fields":["body"]}`} {
		w = apiRecorder()
		engine.serve(w, apiRequest("POST", "/api/security-rules", bad), admin)
		if w.Code != 400 {
			t.Fatal("invalid rule accepted")
		}
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("DELETE", fmt.Sprintf("/api/security-rules?id=%d", saved.ID), `{}`), admin)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	// Builtin deletion persists; listing and cache refresh do not reseed it.
	w = apiRecorder()
	engine.serve(w, apiRequest("DELETE", fmt.Sprintf("/api/security-rules?id=%d", rules[0].ID), `{}`), admin)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("GET", "/api/security-rules", ""), admin)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	rules, _ = store.securityRules(ctx)
	if len(rules) != 10 {
		t.Fatal("rules reseeded")
	}
}

func TestPostgresSecurityEvidenceOverrideAndRescan(t *testing.T) {
	store := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, store, 7)
	engine := &Engine{Store: store}
	user := User{ID: 7, Role: "user"}
	p := Pipeline{Rules: &SecurityRuleCache{Load: store.securityRules}}
	ob := Observation{Host: "vpn.example.com", Title: "VPN user portal", StatusCode: 200, Fingerprints: []string{}, Redirects: []string{}}
	if err := p.classifySecurity(ctx, scope, &ob); err != nil {
		t.Fatal(err)
	}
	run := claimedRun(t, store, scope)
	if _, err := store.WriteResults(ctx, run, []Observation{ob}, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, store, run)
	var id int64
	var marked bool
	var evidence []byte
	err := store.DB.QueryRow(ctx, "SELECT id,is_security_device,security_matches FROM assets WHERE host=$1", ob.Host).Scan(&id, &marked, &evidence)
	if err != nil || !marked || !strings.Contains(string(evidence), `"title"`) {
		t.Fatalf("asset not retained with evidence: %v %s", err, evidence)
	}
	path := fmt.Sprintf("/api/assets/%d", id)
	patch := func(who User, body string, want int) {
		t.Helper()
		w := apiRecorder()
		engine.serve(w, apiRequest("PATCH", path, body), who)
		if w.Code != want {
			t.Fatalf("patch=%d %s", w.Code, w.Body.String())
		}
	}
	patch(User{ID: 8, Role: "user"}, `{"security_device_override":false}`, 404)
	patch(User{ID: 7, Role: "readonly"}, `{"security_device_override":false}`, 403)
	patch(user, `{"security_device_override":true}`, 400)
	patch(user, `{"security_device_override":"false"}`, 400)
	patch(user, `{"security_device_override":false}`, 200)
	run = claimedRun(t, store, scope)
	if _, err := store.WriteResults(ctx, run, []Observation{ob}, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, store, run)
	var override *bool
	store.DB.QueryRow(ctx, "SELECT is_security_device,security_device_override,security_matches FROM assets WHERE id=$1", id).Scan(&marked, &override, &evidence)
	if marked || override == nil || *override || len(evidence) < 3 {
		t.Fatal("rescan lost correction/evidence")
	}
	patch(user, `{"note":"keep override"}`, 200)
	store.DB.QueryRow(ctx, "SELECT security_device_override FROM assets WHERE id=$1", id).Scan(&override)
	if override == nil {
		t.Fatal("omitted field reset override")
	}
	patch(user, `{"security_device_override":null}`, 200)
	store.DB.QueryRow(ctx, "SELECT is_security_device,security_device_override FROM assets WHERE id=$1", id).Scan(&marked, &override)
	if !marked || override != nil {
		t.Fatal("restore auto failed")
	}
	// Batch correction and mixed-owner atomic rejection.
	w := apiRecorder()
	engine.serve(w, apiRequest("PATCH", "/api/assets/batch", fmt.Sprintf(`{"ids":[%d],"security_device_override":false}`, id)), user)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("PATCH", "/api/assets/batch", fmt.Sprintf(`{"ids":[%d,999999],"security_device_override":null}`, id)), user)
	if w.Code != 404 {
		t.Fatal("partial unauthorized batch accepted")
	}
	var snapshots int
	store.DB.QueryRow(ctx, "SELECT count(*)FROM asset_snapshots WHERE asset_id=$1 AND payload ? 'security_matches'", id).Scan(&snapshots)
	if snapshots < 4 {
		t.Fatal("missing evidence snapshots", snapshots)
	}
	// Same classification path exempts the scope's own brand before persistence.
	scope.Domain = "sangfor.com"
	ob.TLSSubject = "CN=Sangfor Inc"
	ob.Title = "Welcome"
	if err = p.classifySecurity(ctx, scope, &ob); err != nil || ob.Security {
		t.Fatal("brand exemption failed", err)
	}
}
