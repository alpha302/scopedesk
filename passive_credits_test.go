package main

import (
	"context"
	"encoding/base64"
	"net/url"
	"testing"
)

func TestPassiveCreditsOnlyPolicy(t *testing.T) {
	for _, tc := range []struct {
		source, raw string
		allowed     bool
	}{
		{"hunter", `{"code":200,"data":{"rest_free_point":495,"rest_equity_point":0,"day_free_point":500}}`, true},
		{"hunter", `{"code":"200","data":{"rest_free_point":495,"rest_equity_point":1}}`, false},
		{"fofa", `{"error":false,"fcoin":0,"fofa_point":48040}`, true},
		{"fofa", `{"error":false,"fcoin":1,"fofa_point":48040}`, false},
		{"fofa", `{"error":false,"fofa_point":48040}`, false},
	} {
		snapshot, err := parsePassiveCredits(tc.source, []byte(tc.raw))
		if err != nil {
			t.Fatal(err)
		}
		if (creditsOnlyAllowed(snapshot, 20) == nil) != tc.allowed {
			t.Fatal("paid fallback or unknown balance accepted", tc.source)
		}
	}
}
func TestPassiveHunterQuotaAndRequest(t *testing.T) {
	for _, raw := range []string{"5", "消耗积分：-1", "其他积分：5", "消耗积分：5(权益)", "消耗积分：1,000"} {
		if hunterQuota(raw, hunterConsumedPattern) != nil {
			t.Fatal("ambiguous amount accepted")
		}
	}
	if n := hunterQuota("消耗积分：5", hunterConsumedPattern); n == nil || *n != 5 {
		t.Fatal("observed quota text rejected")
	}
	p, err := loadPassiveProvider("hunter")
	if err != nil {
		t.Fatal(err)
	}
	query := `domain="example.com"`
	req, err := passiveSearchRequest(context.Background(), p, passiveReservation{Key: []byte("offline-fixture"), PageSize: 10}, query, 1)
	if err != nil {
		t.Fatal(err)
	}
	q, e := url.ParseQuery(req.URL.RawQuery)
	if e != nil || q.Get("search") != base64.URLEncoding.EncodeToString([]byte(query)) || q.Get("page_size") != "10" || q.Get("is_web") != "3" {
		t.Fatal("wire parameters")
	}
	result, err := parseHunterPage([]byte(`{"code":200,"data":{"total":1,"arr":[{"domain":"api.example.com","ip":"8.8.8.8","port":443,"web_title":"Old","status_code":200,"updated_at":"2025-01-01 00:00:00","component":[{"name":"nginx","version":"1"}]}],"consume_quota":"消耗积分：5","rest_quota":"今日剩余积分：495"}}`), p, ScopeGuard{Scope: sampleScope()})
	if err != nil || len(result.Records) != 1 || result.Actual == nil || *result.Actual != 5 || result.Remaining == nil || *result.Remaining != 495 {
		t.Fatal("Hunter record/quota mapping", err)
	}
	ob := result.Records[0].Observation
	if !ob.EvidenceOnly || ob.Alive != nil || ob.StatusCode != 0 || ob.PluginEvidence[0].ProviderTime != nil || ob.PluginEvidence[0].ProviderTimeRaw == nil {
		t.Fatal("history escaped evidence boundary")
	}
}
