package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestW30BoundedPlanQueries(t *testing.T) {
	for _, n := range []int{0, 1, 100, 1000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s, tr := p0Store(t)
			ctx := context.Background()
			p0Exec(t, s, `INSERT INTO scopes(owner,domain,policy)SELECT 100,'s'||i||'.example.test','synthetic' FROM generate_series(1,$1::int)i`, n)
			p0Exec(t, s, `INSERT INTO monitor_plans(scope_id,enabled,interval_hours,collectors,collection_mode)SELECT id,id%4=0,48,'["certspotter"]'::jsonb,'evidence_only' FROM scopes WHERE id%2=0`)
			before := tr.queries.Load()
			out, err := s.scopes(ctx, User{ID: 100, Role: "admin"})
			queries := tr.queries.Load() - before
			if err != nil || len(out) != n {
				t.Fatal("scope listing failed")
			}
			for _, v := range out {
				want, err := s.plan(ctx, v.ID)
				if err != nil || v.Plan == nil || !reflect.DeepEqual(*v.Plan, want) {
					t.Fatal("batched plan changed legacy API")
				}
			}
			if queries > 2 {
				t.Fatalf("W30: scope list makes %d SQL round trips for %d scopes", queries, n)
			}
		})
	}
}

// This intentionally retains the old independent per-scope reader as a
// measurement/reference implementation, never a production fallback.
func w30LegacyPlans(ctx context.Context, s *Store, out []ScopeV2) ([]ScopeV2, error) {
	for i := range out {
		p, err := s.plan(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Plan = &p
	}
	return out, nil
}

func TestW30Measurements(t *testing.T) {
	s, tr := p0Store(t)
	ctx := context.Background()
	p0Seed(t, s, 10000, false)
	p0Exec(t, s, `INSERT INTO scopes(id,owner,project_id,domain,policy,active)SELECT i,100,101+(i-1)%4,'s'||i||'.example.test','synthetic; no network',false FROM generate_series(21,1000)i;
INSERT INTO monitor_plans(scope_id,enabled,interval_hours,collectors,collection_mode)SELECT id,false,48,'["certspotter"]'::jsonb,'evidence_only' FROM scopes WHERE id>20 AND id%2=0;
INSERT INTO workspace_members(workspace_id,user_id,role)VALUES(100,200,'viewer');
INSERT INTO project_members(project_id,user_id,role)VALUES(101,200,'viewer');ANALYZE;`)
	for _, u := range []User{{ID: 100, Role: "admin"}, {ID: 200, Role: "readonly"}, {ID: 300, Role: "user"}} {
		out, err := s.scopes(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		want := 1000
		if u.ID == 200 {
			want = 250
		}
		if u.ID == 300 {
			want = 0
		}
		if len(out) != want {
			t.Fatal("scope authorization changed")
		}
	}
	for round := 1; round <= 3; round++ {
		values := []int64{}
		counts := []int64{}
		for request := 0; request < 20; request++ {
			before := tr.queries.Load()
			at := time.Now()
			out, err := s.scopes(ctx, User{ID: 100, Role: "admin"})
			elapsed := time.Since(at).Nanoseconds()
			if err != nil || len(out) != 1000 {
				t.Fatal("measured scope listing failed")
			}
			values = append(values, elapsed)
			counts = append(counts, tr.queries.Load()-before)
		}
		p0Write(t, fmt.Sprintf("w30-round%d", round), map[string]any{"assets": 10000, "services": 20000, "scopes": 1000, "synthetic_ratio": 1, "elapsed_ns": values, "sql_round_trips": counts, "quantiles": w03Quantiles(values), "note": "shared runner; empirical p99 of 20 samples equals maximum; no production capacity claim"})
	}
	var plan json.RawMessage
	if err := s.DB.QueryRow(ctx, `EXPLAIN(ANALYZE,BUFFERS,SETTINGS,FORMAT JSON)SELECT scope_id,enabled,interval_hours,cron,collectors,next_run_at,last_run_at,schedule_error,retry_at,collection_mode FROM monitor_plans WHERE scope_id=ANY(ARRAY(SELECT id FROM scopes))`).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	p0Write(t, "w30-plan-explain", json.RawMessage(plan))
}
