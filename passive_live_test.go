package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in only. Keys are supplied in process environment, never source,
// command-line arguments, raw errors, logs or captured provider-response files.
func TestPassiveLiveCreditsOnlyWire(t *testing.T) {
	if os.Getenv("SCOPEDESK_PASSIVE_LIVE") != "1" {
		t.Skip("live credit tests require explicit opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	client, cleanup := passiveClient(nil)
	defer cleanup()
	get := func(source string, req *http.Request) []byte {
		response, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: connection failure (request URL and key redacted)", source)
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 1_000_001))
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || len(raw) > 1_000_000 {
			t.Fatalf("%s: response unavailable or over limit (body redacted)", source)
		}
		return raw
	}
	for _, source := range []string{"fofa", "hunter"} {
		key := os.Getenv("SCOPEDESK_" + strings.ToUpper(source) + "_KEY")
		if key == "" {
			t.Fatalf("%s: key missing", source)
		}
		account := func() PassiveCredits {
			req, e := passiveAccountRequest(ctx, source, []byte(key))
			if e != nil {
				t.Fatal("account request creation failed")
			}
			credit, e := parsePassiveCredits(source, get(source, req))
			if e != nil {
				t.Fatal("account response could not be verified")
			}
			return credit
		}
		before := account()
		if creditsOnlyAllowed(before, 10) != nil {
			t.Fatalf("%s: credit-only precondition not satisfied; search not sent", source)
		}
		p, e := loadPassiveProvider(source)
		if e != nil {
			t.Fatal("provider template unavailable")
		}
		size := 1
		if source == "hunter" {
			size = 10
		}
		p.PageSize = size
		fields := []string{}
		for _, f := range p.Fields {
			if f != p.ProviderTimeField {
				fields = append(fields, f)
			}
		}
		if source == "fofa" {
			p.Fields = fields
		}
		req, e := passiveSearchRequest(ctx, p, passiveReservation{Key: []byte(key), PageSize: size}, `ip="47.103.214.77"`, 1)
		if e != nil {
			t.Fatal("search request creation failed")
		}
		raw := get(source, req)
		// Query only the previously authorized server in the vendor index. This guard
		// filters returned records locally; no DNS, HTTP or port request goes to it.
		g := ScopeGuard{Scope: ScopeV2{Domain: "47.103.214.77/32", Mode: "cidr", Confirmed: true}}
		count := 0
		var consumed *int64
		if source == "hunter" {
			data, e := parseHunterPage(raw, p, g)
			if e != nil {
				t.Fatal("Hunter response parser rejected live response (body redacted)")
			}
			count = data.Count
			consumed = data.Actual
			if consumed == nil {
				t.Fatal("Hunter did not report an unambiguous point charge")
			}
		} else {
			data, _, _, e := parseFOFAPage(raw, p, g, `ip="47.103.214.77"`, 1)
			if e != nil {
				t.Fatal("FOFA response parser rejected live response (body redacted)")
			}
			count = len(data.rows)
		}
		after := account()
		if after.PaidBalance == nil || *after.PaidBalance != 0 {
			t.Fatalf("%s: post-test paid balance is nonzero or unknown; stop", source)
		}
		amount := "unknown"
		if consumed != nil {
			amount = strconv.FormatInt(*consumed, 10)
		}
		remaining := "unknown"
		if after.Credits != nil {
			remaining = strconv.FormatInt(*after.Credits, 10)
		}
		t.Logf("source=%s searches=1 returned=%d reported_points=%s credits_after=%s paid_balance_after=0", source, count, amount, remaining)
	}
}
