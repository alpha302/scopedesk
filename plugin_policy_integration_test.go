package main

import (
	"context"
	"encoding/json"
	"testing"
)

func TestPostgresPluginResourceControlStatus(t *testing.T) {
	s := integrationStore(t)
	m := fixturePlugin(t, "lines", "lines")
	m.Exec.Limits["nproc"] = 128
	registerFixture(t, s, m)
	w := apiRecorder()
	(&Engine{Store: s}).serve(w, apiRequest("GET", "/api/plugins", ""), User{ID: 1, Role: "admin"})
	var list []struct {
		Name      string `json:"name"`
		Available bool   `json:"available"`
		Resource  struct {
			Kind      string `json:"kind"`
			Available bool   `json:"available"`
			TaskLimit uint64 `json:"task_limit"`
		} `json:"resource_control"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, item := range list {
		if item.Name == m.Name {
			if !item.Available || !item.Resource.Available || item.Resource.Kind != "cgroup_v2_pids" || item.Resource.TaskLimit != 128 {
				t.Fatal("resource status or legacy task limit incorrect", item)
			}
			return
		}
	}
	t.Fatal("plugin missing from resource status")
}

func TestPostgresPluginConfigMappingChangesDigest(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	run := claimedRun(t, s, scope)
	m := fixturePlugin(t, "lines", "lines")
	p := fixtureExternal(m)
	p.Store, p.JobID = s, run.ID
	p.Guard = func(c context.Context) (ScopeGuard, error) { return s.guard(c, scope.ID) }
	digests := []string{}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt == 1 {
			p.Manifest.ConfigFiles = []PluginConfigFile{{Source: "missing-policy-" + random()[:16] + ".yaml", Destination: "config/tool/provider.yaml", Optional: true}}
		}
		result := p.Run(ctx, "example.com")
		if result.Error != "" {
			t.Fatal(result)
		}
		var digest string
		if err := s.DB.QueryRow(ctx, "SELECT params_digest FROM plugin_runs WHERE id=$1", result.RunID).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		digests = append(digests, digest)
	}
	if digests[0] == digests[1] || digests[1] != digests[2] {
		t.Fatal("configuration policy absent from stable audit digest", digests)
	}
}
