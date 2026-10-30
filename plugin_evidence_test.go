package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func observerMapping(m PluginManifest) PluginManifest {
	m.Kind = "observer"
	m.Output.Mapping = map[string]string{"host": "host", "ip": "ip", "port": "port", "protocol": "protocol", "status_code": "code", "title": "title", "server": "server"}
	return m
}

func parseEvidence(t *testing.T, raw string) PluginResult {
	t.Helper()
	m := observerMapping(PluginManifest{Name: "evidence-fixture"})
	m.Output.Format = "jsonl"
	m.Exec.MaxOutput = 8000000
	result := PluginResult{}
	guard := func(context.Context) (ScopeGuard, error) { return ScopeGuard{Scope: sampleScope()}, nil }
	if err := parsePluginStream(context.Background(), strings.NewReader(raw), m, guard, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPluginEvidenceMappingKeepsCandidatesAndRejectsFields(t *testing.T) {
	result := parseEvidence(t, `{"host":"valid.example.com","port":443,"ip":"8.8.8.8","code":200,"title":"portal"}
{"host":"noport.example.com","code":200,"title":"keep without port","server":"nginx"}
{"host":"badport.example.com","port":"bad","title":"keep"}
{"host":"badip.example.com","port":443,"ip":"127.0.0.1","title":"keep"}
{"host":"badprotocol.example.com","port":443,"protocol":"icmp","title":"keep"}
{"host":"badcode.example.com","port":443,"code":999,"title":"keep"}
{"host":"badtitle.example.com","title":42,"server":"keep server"}
{"host":"outside.net","title":"reject host"}`)
	if result.Returned != 8 || result.InScope != 7 || len(result.Records) != 7 {
		t.Fatal("valid candidates lost", result)
	}
	for _, record := range result.Records {
		ob := record.Observation
		if ob == nil || ob.Host != record.Candidate.Host || ob.Alive != nil || !ob.EvidenceOnly || len(ob.PluginEvidence) != 1 {
			t.Fatal("observer changes reachability", record)
		}
		if strings.HasPrefix(ob.Host, "noport.") && (len(ob.Services) != 0 || ob.PluginEvidence[0].Fields["title"] != "keep without port") {
			t.Fatal("missing-port evidence lost or port invented", ob)
		}
		if strings.HasPrefix(ob.Host, "badip.") && (len(ob.Services) != 0 || len(ob.IPs) != 0 || ob.PluginEvidence[0].IP != "") {
			t.Fatal("private IP retained", ob)
		}
		if strings.HasPrefix(ob.Host, "badprotocol.") && len(ob.Services) != 0 {
			t.Fatal("invalid service retained")
		}
		if strings.HasPrefix(ob.Host, "badcode.") && (len(ob.Services) != 1 || ob.Services[0].StatusCode != nil) {
			t.Fatal("invalid HTTP code not stripped independently")
		}
	}
	for _, reason := range []string{"invalid_port", "invalid_or_disallowed_ip", "invalid_protocol", "invalid_status_code", "invalid_title", "host_out_of_scope_or_invalid"} {
		if result.RejectedFields[reason] != 1 {
			t.Fatal("rejection counts", reason, result.RejectedFields)
		}
	}
}

func TestPluginEvidenceCannotOverrideProbeGrouping(t *testing.T) {
	ob := *parseEvidence(t, `{"host":"api.example.com","port":443,"ip":"1.1.1.1","code":200,"title":"provider"}`).Records[0].Observation
	live := Observation{Host: ob.Host, DNSChecked: true, IPs: []string{"8.8.8.8"}, Alive: ptr(false), Sources: []string{"dns"}}
	for _, input := range [][]Observation{{ob, live}, {live, ob}} {
		group := groupObservations(input)
		projectService(&group[0], Observation{})
		if len(group) != 1 || group[0].EvidenceOnly || group[0].Alive == nil || *group[0].Alive || group[0].StatusCode != 0 || len(group[0].IPs) != 1 || group[0].IPs[0] != "8.8.8.8" {
			t.Fatal("metadata overrode probe", group)
		}
	}
	group := groupObservations([]Observation{ob})
	projectService(&group[0], Observation{})
	if !group[0].EvidenceOnly || group[0].Alive != nil || group[0].StatusCode != 0 || len(group[0].Services) != 1 {
		t.Fatal("evidence-only service promoted to live", group)
	}
	if len(legacyService(ob)) != 0 {
		t.Fatal("legacy port invented from observer")
	}
}

func TestPluginEvidenceMergeBoundAndSnapshotKey(t *testing.T) {
	a := PluginEvidence{Source: "fixture", Fields: map[string]any{"title": "keep", "server": "old"}, ObservedAt: time.Now()}
	b := a
	b.Fields = map[string]any{"server": "new"}
	b.ObservedAt = b.ObservedAt.Add(time.Hour)
	merged := mergePluginEvidence([]PluginEvidence{a}, []PluginEvidence{b})
	if len(merged) != 1 || merged[0].Fields["title"] != "keep" || merged[0].Fields["server"] != "new" || a.Fields["server"] != "old" {
		t.Fatal("partial merge or immutability", merged)
	}
	a = b
	a.ObservedAt = a.ObservedAt.Add(time.Hour)
	if observationKey(Observation{PluginEvidence: []PluginEvidence{a}}) != observationKey(Observation{PluginEvidence: []PluginEvidence{b}}) {
		t.Fatal("timestamp alone creates snapshots")
	}
	values := []PluginEvidence{}
	for i := range 110 {
		values = append(values, PluginEvidence{Source: fmt.Sprint(i), Fields: map[string]any{}})
	}
	bounded := mergePluginEvidence(nil, values)
	if len(bounded) != 100 || bounded[0].Source != "10" || bounded[99].Source != "109" {
		t.Fatal("evidence payload unbounded")
	}
}

func TestPluginFailedResultsStayOutOfGroupButKeepCandidates(t *testing.T) {
	bad := PluginResult{Error: "exit 7", Records: []PluginRecord{{Candidate: Candidate{Host: "bad.example.com"}}}}
	good := PluginResult{Records: []PluginRecord{{Candidate: Candidate{Host: "good.example.com"}}}}
	for _, strategy := range []string{"all", "fallback", "first_success"} {
		group := PluginGroup{Strategy: strategy, Plugins: []func(context.Context) PluginResult{func(context.Context) PluginResult { return bad }, func(context.Context) PluginResult { return good }}}
		out, runs, _ := group.Run(context.Background())
		if len(runs) != 2 || len(out) != 1 || out[0].Candidate.Host != "good.example.com" {
			t.Fatal("failed records merged", strategy, out, runs)
		}
	}
	stream := pluginCandidates(bad)
	if candidate, ok := <-stream; !ok || candidate.Host != "bad.example.com" {
		t.Fatal("failed candidate lost", candidate, ok)
	}
	if _, ok := <-stream; ok {
		t.Fatal("candidate stream not closed")
	}
}

func TestObserverSourcesRequireLiveMeasurementToRecover(t *testing.T) {
	registry := &PluginRegistry{Manifests: map[string]PluginManifest{"provider": {Kind: "observer"}, "collector": {Kind: "collector"}}}
	if !observerSourcesOnly([]string{"provider"}, registry) || observerSourcesOnly([]string{"provider", "crtsh"}, registry) || observerSourcesOnly([]string{"collector"}, registry) || observerSourcesOnly(nil, registry) {
		t.Fatal("source provenance incorrectly classified")
	}
	provider := *parseEvidence(t, `{"host":"api.example.com","code":200}`).Records[0].Observation
	dns := Observation{Host: provider.Host, DNSChecked: true, IPs: []string{"8.8.8.8"}, PreserveReachability: true}
	for _, input := range [][]Observation{{provider, dns}, {dns, provider}} {
		group := groupObservations(input)
		if !group[0].PreserveReachability || group[0].Alive != nil {
			t.Fatal("provider plus DNS treated as live probe")
		}
	}
	active := dns
	active.PreserveReachability = false
	active.Alive = ptr(true)
	group := groupObservations([]Observation{provider, dns, active})
	if group[0].PreserveReachability || group[0].Alive == nil || !*group[0].Alive {
		t.Fatal("real probe suppressed by provider metadata")
	}
}
