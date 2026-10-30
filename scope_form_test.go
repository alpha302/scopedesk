package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestPostgresScopeOptionalPolicyNoExpiry(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	engine := &Engine{Store: s}
	user := User{ID: 7, Role: "user"}
	request := sampleScope()
	request.Policy = ""
	request.Expires = nil
	raw := map[string]any{}
	json.Unmarshal([]byte(mustJSON(request)), &raw)
	delete(raw, "policy")
	delete(raw, "expires_at")
	w := apiRecorder()
	engine.serve(w, apiRequest("POST", "/api/scopes", mustJSON(raw)), user)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var saved struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &saved)
	scope, err := s.scopesByID(ctx, saved.ID)
	if err != nil || scope.Policy != "" || scope.Expires != nil {
		t.Fatal("missing fields not accepted", err)
	}
	// Old API fields remain accepted, but past/future expiry no longer takes effect.
	for _, when := range []time.Time{time.Now().Add(-time.Hour), time.Now().Add(time.Hour)} {
		raw["expires_at"] = when
		raw["policy"] = "historical policy"
		w = apiRecorder()
		engine.serve(w, apiRequest("PUT", fmt.Sprintf("/api/scopes/%d", saved.ID), mustJSON(raw)), user)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		scope, _ = s.scopesByID(ctx, saved.ID)
		if scope.Expires != nil || scope.Policy != "historical policy" {
			t.Fatal("expiry accepted or policy lost")
		}
	}
	delete(raw, "policy")
	delete(raw, "expires_at")
	w = apiRecorder()
	engine.serve(w, apiRequest("PUT", fmt.Sprintf("/api/scopes/%d", saved.ID), mustJSON(raw)), user)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	scope, _ = s.scopesByID(ctx, saved.ID)
	if scope.Policy != "historical policy" {
		t.Fatal("hidden old content erased")
	}
	raw["confirmed"] = false
	w = apiRecorder()
	engine.serve(w, apiRequest("POST", "/api/scopes", mustJSON(raw)), user)
	if w.Code != 400 {
		t.Fatal("scope confirmation removed")
	}
}
func TestPostgresScopeExpiryMigrationClearsAndPreservesPlan(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.DB)
	defer db.Close()
	if err := goose.DownToContext(ctx, db, "migrations", 4); err != nil {
		t.Fatal(err)
	}
	scope := insertScope(t, s, 7)
	if _, err := s.DB.Exec(ctx, "UPDATE scopes SET expires_at=now()-interval '1 day'WHERE id=$1", scope.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, "INSERT INTO monitor_plans(scope_id,enabled)VALUES($1,false)", scope.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := goose.UpContext(ctx, db, "migrations"); err != nil {
			t.Fatal(err)
		}
	}
	g, err := s.guard(ctx, scope.ID)
	if err != nil || g.Valid() != nil || g.Scope.Expires != nil {
		t.Fatal("hidden historical expiry still blocks scope", err)
	}
	var enabled bool
	s.DB.QueryRow(ctx, "SELECT enabled FROM monitor_plans WHERE scope_id=$1", scope.ID).Scan(&enabled)
	if enabled {
		t.Fatal("migration unexpectedly started monitoring")
	}
	if err = goose.DownToContext(ctx, db, "migrations", 4); err != nil {
		t.Fatal(err)
	}
	err = s.DB.QueryRow(ctx, "SELECT expires_at FROM scopes WHERE id=$1", scope.ID).Scan(&scope.Expires)
	if err != nil || scope.Expires == nil {
		t.Fatal("rollback did not restore historical value")
	}
}
func TestLegacyScopeOptionalPolicy(t *testing.T) {
	s := fixture(t)
	w := apiRecorder()
	s.scope(w, apiRequest("POST", "/api/scopes", `{"domain":"example.com","authorized":true}`), User{ID: 1, Role: "user"})
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	w = apiRecorder()
	s.scope(w, apiRequest("POST", "/api/scopes", `{"domain":"other.com","authorized":false}`), User{ID: 1, Role: "user"})
	if w.Code != 400 {
		t.Fatal("legacy confirmation removed")
	}
}
