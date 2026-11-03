package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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
func w30LegacyScopes(ctx context.Context, s *Store, u User, filters ...urlQuery) ([]ScopeV2, error) {
	rows, e := s.DB.Query(ctx, `SELECT s.id,s.owner,s.domain,s.mode,s.policy,s.confirmed,s.active,s.exclusions,s.expires_at,s.rps,s.concurrency,s.request_limit,s.window_start,s.window_end,s.created_at,(SELECT count(*) FROM assets a WHERE a.scope_id=s.id),s.project_id,p.name,p.workspace_id,jsonb_build_object('enabled',p.enabled,'allow_active',p.allow_active,'expires_at',p.expires_at,'rps_limit',p.rps_limit) FROM scopes s JOIN projects p ON p.id=s.project_id WHERE ($1='admin' OR scope_access(s.id,$2)) AND ($3=0 OR s.project_id=$3) ORDER BY s.id DESC`, u.Role, u.ID, projectFilter(filters...))
	if e != nil {
		return nil, e
	}
	out := []ScopeV2{}
	for rows.Next() {
		var v ScopeV2
		var exclusions, projectPolicy []byte
		if e = rows.Scan(&v.ID, &v.Owner, &v.Domain, &v.Mode, &v.Policy, &v.Confirmed, &v.Active, &exclusions, &v.Expires, &v.RPS, &v.Concurrency, &v.RequestLimit, &v.WindowStart, &v.WindowEnd, &v.Created, &v.AssetCount, &v.ProjectID, &v.ProjectName, &v.WorkspaceID, &projectPolicy); e != nil {
			rows.Close()
			return nil, e
		}
		json.Unmarshal(exclusions, &v.Exclusions)
		json.Unmarshal(projectPolicy, &v.ProjectPolicy)
		out = append(out, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for i := range out {
		p, e := s.plan(ctx, out[i].ID)
		if e != nil {
			return nil, e
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
	for _, u := range []User{{ID: 100, Role: "admin"}, {ID: 200, Role: "readonly"}, {ID: 300, Role: "user"}} {
		for _, project := range []string{"", "101", "102", "999", "invalid"} {
			filter := url.Values{}
			if project != "" {
				filter.Set("project_id", project)
			}
			got, err := s.scopes(ctx, u, filter)
			if err != nil {
				t.Fatal(err)
			}
			want, err := w30LegacyScopes(ctx, s, u, filter)
			if err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(got)
			b, _ := json.Marshal(want)
			if string(a) != string(b) {
				t.Fatal("scope JSON or project authorization changed")
			}
		}
	}
	for round := 1; round <= 3; round++ {
		for _, variant := range []string{"legacy", "current"} {
			values := []int64{}
			counts := []int64{}
			for request := 0; request < 20; request++ {
				before := tr.queries.Load()
				at := time.Now()
				var out []ScopeV2
				var err error
				if variant == "legacy" {
					out, err = w30LegacyScopes(ctx, s, User{ID: 100, Role: "admin"})
				} else {
					out, err = s.scopes(ctx, User{ID: 100, Role: "admin"})
				}
				elapsed := time.Since(at).Nanoseconds()
				if err != nil || len(out) != 1000 {
					t.Fatal("measured scope listing failed")
				}
				values = append(values, elapsed)
				counts = append(counts, tr.queries.Load()-before)
			}
			p0Write(t, fmt.Sprintf("w30-%s-round%d", variant, round), map[string]any{"assets": 10000, "services": 20000, "scopes": 1000, "synthetic_ratio": 1, "elapsed_ns": values, "sql_round_trips": counts, "quantiles": w03Quantiles(values), "note": "same fixture/runner/process; legacy reader copied from pre-fix source; sequential order; empirical p99 of 20 equals max, no production capacity claim"})
		}
	}
	ids := make([]int64, 1000)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	for name, query := range map[string]string{"scopes": scopesListSQL, "batched_plans": scopePlansSQL} {
		var plan json.RawMessage
		args := []any{ids}
		if name == "scopes" {
			args = []any{"admin", 100, int64(0)}
		}
		if err := s.DB.QueryRow(ctx, "EXPLAIN(ANALYZE,BUFFERS,SETTINGS,FORMAT JSON) "+query, args...).Scan(&plan); err != nil {
			t.Fatal(err)
		}
		p0Write(t, "w30-"+name+"-explain", json.RawMessage(plan))
	}
}
