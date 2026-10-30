package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func testRule(t *testing.T, id int64, keyword, match string, fields ...string) SecurityRule {
	t.Helper()
	r, err := compileSecurityRule(SecurityRule{ID: id, Keyword: keyword, Match: match, Fields: fields, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestSecurityRuleMatching(t *testing.T) {
	rules := []SecurityRule{testRule(t, 1, "sangfor", "contains", "tls"), testRule(t, 2, "vpn", "contains", "title"), testRule(t, 3, `(?i)forti(gate|net)`, "regex", "server", "fingerprint")}
	disabled := testRule(t, 4, "portal", "contains", "title")
	disabled.Enabled = false
	rules = append(rules, disabled)
	tests := []struct {
		name, domain string
		o            Observation
		want         int
		id           int64
		fields       string
	}{
		{"own brand", "sangfor.com", Observation{TLSSubject: "CN=Sangfor Inc"}, 0, 0, ""},
		{"own brand nested", "a.sangfor.com", Observation{TLSSubject: "CN=Sangfor Inc"}, 0, 0, ""},
		{"foreign brand", "example.com", Observation{TLSSubject: "CN=Sangfor Inc"}, 1, 1, "tls"},
		{"VPN ordinary site", "example.com", Observation{Title: "VPN user portal"}, 1, 2, "title"},
		{"regex multiple fields", "example.com", Observation{Server: "FortiGate", Fingerprints: []string{"Fortinet"}}, 1, 3, "server,fingerprint"},
		{"disabled", "example.com", Observation{Title: "portal"}, 0, 0, ""},
		{"wrong field", "example.com", Observation{Server: "VPN"}, 0, 0, ""},
		{"unmatched", "example.com", Observation{Title: "Welcome"}, 0, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hits := matchSecurityRules(rules, ScopeV2{Domain: tt.domain}, tt.o)
			if len(hits) != tt.want {
				t.Fatalf("hits=%+v", hits)
			}
			if tt.want > 0 && (hits[0].RuleID != tt.id || strings.Join(hits[0].Fields, ",") != tt.fields) {
				t.Fatalf("evidence=%+v", hits)
			}
		})
	}
	for _, domain := range []string{"sangfor.co.uk", "*.sangfor.com", "SANGFOR.COM"} {
		if scopeBrand(domain) != "sangfor" {
			t.Fatalf("root brand for %s", domain)
		}
	}
	for _, domain := range []string{"1.1.1.1", "2001:4860:4860::8888", "1.1.1.0/24"} {
		if scopeBrand(domain) != "" {
			t.Fatal("IP brand extracted")
		}
	}
}
func TestSecurityRuleValidation(t *testing.T) {
	for _, r := range []SecurityRule{
		{Keyword: "", Match: "contains", Fields: []string{"title"}},
		{Keyword: "x", Match: "other", Fields: []string{"title"}},
		{Keyword: "(", Match: "regex", Fields: []string{"title"}},
		{Keyword: "x", Match: "contains"},
		{Keyword: "x", Match: "contains", Fields: []string{"body"}},
		{Keyword: "x", Match: "contains", Fields: []string{"tls", "tls"}},
		{Keyword: strings.Repeat("x", 513), Match: "contains", Fields: []string{"title"}},
	} {
		if _, err := compileSecurityRule(r); err == nil {
			t.Fatalf("invalid rule accepted: %+v", r)
		}
	}
	r := testRule(t, 1, "vpn", "regex", "title")
	if len(matchSecurityRules([]SecurityRule{r}, ScopeV2{Domain: "example.com"}, Observation{Title: "VPN"})) != 0 {
		t.Fatal("regex case behavior changed")
	}
}
func TestSecurityRuleCacheRefreshAndFailure(t *testing.T) {
	now := time.Unix(1000, 0)
	loads := 0
	bad := false
	cache := &SecurityRuleCache{Now: func() time.Time { return now }, Load: func(context.Context) ([]SecurityRule, error) {
		loads++
		if bad {
			return nil, errors.New("fixture failure")
		}
		return []SecurityRule{testRule(t, 1, "vpn", "contains", "title")}, nil
	}}
	ctx := context.Background()
	for range 2 {
		if _, err := cache.refresh(ctx, false); err != nil {
			t.Fatal(err)
		}
	}
	if loads != 1 {
		t.Fatal("cache missed")
	}
	now = now.Add(59 * time.Second)
	cache.refresh(ctx, false)
	if loads != 1 {
		t.Fatal("early refresh")
	}
	now = now.Add(time.Second)
	cache.refresh(ctx, false)
	if loads != 2 {
		t.Fatal("60 second refresh missed")
	}
	bad = true
	now = now.Add(time.Minute)
	rules, err := cache.refresh(ctx, false)
	if err != nil || len(rules) != 1 {
		t.Fatal("last good rules lost")
	}
	failedLoads := loads
	cache.refresh(ctx, false)
	if loads != failedLoads {
		t.Fatal("refresh failure retried once per host")
	}
	cache.loaded = false
	if _, err = cache.refresh(ctx, true); err == nil {
		t.Fatal("initial load failure hidden")
	}
	cache.Load = func(context.Context) ([]SecurityRule, error) {
		return []SecurityRule{{Keyword: "(", Match: "regex", Fields: []string{"title"}}}, nil
	}
	if _, err = cache.refresh(ctx, true); err == nil {
		t.Fatal("invalid cached regex accepted")
	}
}
func TestSecurityRuleCacheConcurrentClassification(t *testing.T) {
	cache := &SecurityRuleCache{Load: func(context.Context) ([]SecurityRule, error) {
		return []SecurityRule{testRule(t, 1, "vpn", "contains", "title")}, nil
	}}
	p := Pipeline{Rules: cache}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				o := Observation{Title: "VPN portal"}
				if err := p.classifySecurity(context.Background(), ScopeV2{Domain: "example.com"}, &o); err != nil || !o.Security || len(o.SecurityMatches) != 1 {
					t.Error("concurrent classification failed")
				}
			}
		}()
	}
	wg.Wait()
	if err := (&Pipeline{}).classifySecurity(context.Background(), ScopeV2{}, &Observation{}); err == nil {
		t.Fatal("missing rules allowed")
	}
}
