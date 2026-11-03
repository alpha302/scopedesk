package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestW26WireNegativeEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		code        dnsmessage.RCode
	}{
		{"NXDOMAIN", "nxdomain_pending", dnsmessage.RCodeNameError},
		{"NODATA", "nodata", dnsmessage.RCodeSuccess},
		{"SERVFAIL", "servfail", dnsmessage.RCodeServerFailure},
		{"REFUSED", "refused", dnsmessage.RCodeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver, _ := p0NegativeResolver(t, tc.code)
			scope := sampleScope()
			scope.Active = true
			calls := 0
			p := Pipeline{Resolver: resolver, Limit: immediateLimit{}, Guard: func(context.Context, int64) (ScopeGuard, error) { return ScopeGuard{Scope: scope}, nil }, httpTransport: policyTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected HTTP") })}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			o, err := p.Probe(ctx, scope, "api.example.com", []string{"fixture"}, &Budget{Limit: 100})
			if err != nil || o.Alive != nil || o.DNSChecked || calls != 0 {
				t.Fatal("negative DNS changed HTTP state")
			}
			raw, _ := json.Marshal(o)
			var doc struct {
				DNS *DNSObservation `json:"dns_observation"`
			}
			json.Unmarshal(raw, &doc)
			if doc.DNS == nil || doc.DNS.State != tc.state || len(doc.DNS.Replies) == 0 {
				t.Fatal("W26: independent wire DNS evidence missing or misclassified")
			}
		})
	}
}
