package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Offline fixtures for later centralized execution. This change compiles them only.
func TestPassiveCertificateKeepsEarlierPages(t *testing.T) {
	calls := 0
	c := &CertificateCollector{Source: "certspotter", Budget: &Budget{Limit: 10}, Client: &http.Client{Transport: policyTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"id":"1","dns_names":["api.example.com","outside.invalid"]}]`))}, nil
		}
		if r.URL.Query().Get("after") != "1" {
			t.Fatal("cursor not advanced")
		}
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader(`error with secret must not be retained`))}, nil
	})}}
	stream, err := c.Collect(context.Background(), sampleScope())
	if err == nil || c.Result.Complete || c.Result.AbsenceUsable || calls != 2 {
		t.Fatal("partial pagination promoted or retried", err, c.Result)
	}
	hosts := []string{}
	for candidate := range stream {
		hosts = append(hosts, candidate.Host)
	}
	if len(hosts) != 1 || hosts[0] != "api.example.com" || strings.Contains(err.Error(), "secret") {
		t.Fatal("partial records lost or error leaked", hosts, err)
	}
}
func TestPassiveCertificateCompletenessMarkers(t *testing.T) {
	for _, tc := range []struct {
		source, body string
		complete     bool
	}{{"crtsh", "[]", false}, {"certspotter", "null", false}, {"certspotter", "[]", true}} {
		c := &CertificateCollector{Source: tc.source, Budget: &Budget{Limit: 10}, Client: &http.Client{Transport: policyTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}}
		result := c.CollectPassive(context.Background(), sampleScope())
		if result.Complete != tc.complete {
			t.Fatal("zero response interpreted without provider contract", tc, result)
		}
	}
}
func TestPassiveProviderGuardAndHistory(t *testing.T) {
	if p, err := loadPassiveProvider("hunter"); err != nil || p.Endpoint != "https://hunter.qianxin.com/openApi/search" {
		t.Fatal("reviewed Hunter unavailable", err)
	}
	for _, raw := range []string{"https://fofa.info.evil.invalid/api/v1/search/all", "https://fofa.info:443/api/v1/search/all", "http://fofa.info/api/v1/search/all", "https://fofa.info/other", "https://key@fofa.info/api/v1/search/all"} {
		if officialPassiveEndpoint(raw) {
			t.Fatal("unreviewed destination", raw)
		}
	}
	if !officialPassiveEndpoint("https://fofa.info/api/v1/search/all?key=fixture") {
		t.Fatal("official endpoint rejected")
	}
	p, err := loadPassiveProvider("fofa")
	if err != nil {
		t.Fatal(err)
	}
	row := []any{"https://api.example.com:8443", "8.8.8.8", "8443", "Old title", "Old server", "https", "2025-01-02 03:04:05"}
	raw, _ := json.Marshal(map[string]any{"error": false, "results": []any{row}, "query": `domain="example.com"`, "page": 1, "size": 1})
	result, _, _, err := parseFOFAPage(raw, p, ScopeGuard{Scope: sampleScope()}, `domain="example.com"`, 1)
	if err != nil || len(result.records) != 1 {
		t.Fatal("valid historical record rejected", err)
	}
	ob := result.records[0].Observation
	ev := ob.PluginEvidence[0]
	if !ob.EvidenceOnly || !ob.PreserveReachability || ob.Alive != nil || len(ob.Services) > 0 || len(ob.IPs) > 0 || ob.StatusCode != 0 || ob.Title != "" {
		t.Fatal("provider claim escaped evidence boundary", ob)
	}
	if ev.ProviderTime != nil || ev.ProviderTimeRaw == nil || ev.ProviderTimeMeaning != "provider_updated_at" || ev.ObtainedAt == nil || !ev.ObservedAt.Equal(*ev.ObtainedAt) {
		t.Fatal("provider time guessed or observed_at changed meaning", ev)
	}
	row[len(row)-1] = nil
	raw, _ = json.Marshal(map[string]any{"error": false, "results": []any{row}})
	missing, _, _, err := parseFOFAPage(raw, p, ScopeGuard{Scope: sampleScope()}, "", 1)
	if err != nil || missing.records[0].Observation.PluginEvidence[0].ProviderTimeRaw != nil {
		t.Fatal("missing time fabricated")
	}
	a, b := int64(1), int64(2)
	now := time.Now().UTC()
	merged := mergePluginEvidence(nil, []PluginEvidence{{Source: "fofa", AccountID: &a, ObservedAt: now}, {Source: "fofa", AccountID: &b, ObservedAt: now}})
	if len(merged) != 2 {
		t.Fatal("accounts merged together")
	}
}
func TestPassiveModesAndExecutionBudget(t *testing.T) {
	if _, err := validateCollectionMode("evidence_only", []string{"subfinder"}); err == nil {
		t.Fatal("external tool accepted as controlled evidence-only")
	}
	if mode, err := validateCollectionMode("", []string{"crtsh"}); err != nil || mode != "profile" {
		t.Fatal("legacy mode changed")
	}
	if mode, err := validateCollectionMode("evidence_only", []string{"fofa", "hunter", "crtsh"}); err != nil || mode != "evidence_only" {
		t.Fatal("builtin evidence-only rejected")
	}
	t.Setenv("RECON_MAX_JOB_DURATION", "")
	duration, err := jobExecutionBudget([]string{"fofa"}, "manual", nil)
	if err != nil || duration != 150*time.Second+profileBudget+commitBudget {
		t.Fatal("billable source got retry budget or external labels", duration, err)
	}
	if err := validSources([]string{"fofa", "fofa"}); err == nil {
		t.Fatal("duplicate billable source accepted")
	}
}

func TestPassiveRootQueryRespectsFreshBlacklist(t *testing.T) {
	original := sampleScope()
	original.Mode = "subdomains"
	g := ScopeGuard{Scope: original}
	if err := passiveQueryGuard(g, original); err != nil {
		t.Fatal("query root mistaken for an apex scan", err)
	}
	g.Blacklist = []string{"example.com"}
	if err := passiveQueryGuard(g, original); err == nil {
		t.Fatal("passive query root bypassed blacklist")
	}
	g.Blacklist = nil
	g.Scope.Domain = "changed.example.com"
	if err := passiveQueryGuard(g, original); err == nil {
		t.Fatal("stale query scope accepted")
	}
}
