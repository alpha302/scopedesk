package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPostgresScopeImportWorkflowAndPlan(t *testing.T) {
	store := integrationStore(t)
	engine := &Engine{Store: store, Queue: &PGQueue{store}}
	user := User{ID: 7, Role: "user"}
	scope := sampleScope()
	scope.ID = 0
	scope.Policy = "test-only authorization"
	scope.Exclusions = []string{"login.example.com"}
	w := apiRecorder()
	engine.serve(w, apiRequest("POST", "/api/scopes", mustJSON(scope)), user)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var saved struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &saved)
	body := map[string]any{"scope_id": saved.ID, "hosts": "https://api.example.com/path\napi.example.com\nlogin.example.com\nevil-example.com", "preview": false}
	for range 2 {
		w = apiRecorder()
		engine.serve(w, apiRequest("POST", "/api/import", mustJSON(body)), user)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	var count int
	store.DB.QueryRow(context.Background(), "SELECT count(*)FROM assets").Scan(&count)
	if count != 1 {
		t.Fatal("import not filtered/deduplicated")
	}
	store.DB.QueryRow(context.Background(), "SELECT count(*)FROM asset_events WHERE type='NEW_ASSET'").Scan(&count)
	if count != 1 {
		t.Fatal("manual import new events incorrect")
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("GET", "/api/assets?scope_id="+strings.TrimSpace(jsonNumber(saved.ID))+"&status_code=0", ""), user)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "api.example.com") {
		t.Fatal("numeric filters broken", w.Body.String())
	}
	var id int64
	store.DB.QueryRow(context.Background(), "SELECT id FROM assets").Scan(&id)
	w = apiRecorder()
	engine.serve(w, apiRequest("PATCH", "/api/assets/batch", mustJSON(map[string]any{"ids": []int64{id}, "status": "tested", "note": "reviewed fixture", "tags": []string{"integration"}, "assignee": "fixture-user"})), user)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var status string
	store.DB.QueryRow(context.Background(), "SELECT status FROM assets WHERE id=$1", id).Scan(&status)
	if status != "tested" {
		t.Fatal("workflow update failed")
	}
	plan := Plan{Enabled: true, Interval: 6, Collectors: []string{"crtsh", "certspotter"}}
	w = apiRecorder()
	engine.serve(w, apiRequest("PUT", "/api/scopes/"+jsonNumber(saved.ID)+"/plan", mustJSON(plan)), user)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	p, err := store.plan(context.Background(), saved.ID)
	if err != nil || !p.Enabled || p.Next == nil || p.Next.Before(time.Now()) {
		t.Fatal("plan not persisted", err)
	}
	w = apiRecorder()
	engine.serve(w, apiRequest("GET", "/api/assets/"+jsonNumber(id), ""), User{ID: 8, Role: "user"})
	if w.Code != 404 {
		t.Fatal("detail ownership leaked")
	}
}
func jsonNumber(v int64) string { raw, _ := json.Marshal(v); return string(raw) }
