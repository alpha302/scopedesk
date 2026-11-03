package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// These tests define W02's desired boundary. They are intentionally red until
// W02 is implemented; they do not change publicIP or any production policy.
func TestW02AddressBoundary(t *testing.T) {
	for _, tc := range []struct {
		ip    string
		allow bool
	}{
		{"1.1.1.1", true}, {"2606:4700:4700::1111", true},
		{"127.0.0.1", false}, {"10.0.0.1", false}, {"169.254.169.254", false},
		{"::1", false}, {"::ffff:127.0.0.1", false}, {"2001:db8::1", false},
		{"64:ff9b::7f00:1", false}, {"64:ff9b::a00:1", false},
		{"2002:7f00:1::1", false}, {"2002:a00:1::1", false},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			got := publicIP(netip.MustParseAddr(tc.ip))
			if got != tc.allow {
				t.Errorf("W02 address classification: allowed=%t, expected=%t", got, tc.allow)
			}
		})
	}
}

func TestW02ControlledDial(t *testing.T) {
	if os.Getenv("W02_NETWORK_NONE") != "confirmed" {
		t.Skip("requires isolated network-none namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal("cannot inspect namespace")
	}
	owned := map[string]bool{}
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
			t.Fatal("non-loopback interface is up; refusing test")
		}
		if i.Flags&net.FlagLoopback != 0 {
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				prefix, err := netip.ParsePrefix(a.String())
				if err == nil {
					owned[prefix.Addr().String()] = true
				}
			}
		}
	}
	for index, raw := range []string{"64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::1", "2002:a00:1::1"} {
		t.Run(fmt.Sprintf("embedded-private-%d", index+1), func(t *testing.T) {
			if !owned[raw] {
				t.Fatal("fixture destination not owned by loopback; refusing dial")
			}
			var hits, packets atomic.Int64
			var deny atomic.Bool
			ln, err := net.Listen("tcp", net.JoinHostPort(raw, "80"))
			if err != nil {
				t.Fatal("local IPv6 HTTP fixture unavailable")
			}
			srv := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.URL.Path == "/favicon.ico" {
					w.Header().Set("Content-Type", "image/png")
					w.Write(faviconPNG())
					return
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<title>W02 local fixture</title><link rel="icon" href="/favicon.ico">`)
			})}
			go srv.Serve(ln)
			defer srv.Close()
			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal("local DNS fixture unavailable")
			}
			defer udp.Close()
			go func() {
				buf := make([]byte, 2048)
				for {
					n, addr, err := udp.ReadFrom(buf)
					if err != nil {
						return
					}
					var q dnsmessage.Message
					if q.Unpack(buf[:n]) != nil {
						continue
					}
					packets.Add(1)
					res := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: q.Questions}
					for _, question := range q.Questions {
						if question.Type == dnsmessage.TypeAAAA {
							res.Answers = append(res.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(raw).As16()}})
						}
					}
					b, err := res.Pack()
					if err == nil {
						udp.WriteTo(b, addr)
					}
				}
			}()
			scope := sampleScope()
			scope.Domain = "w02.example.test"
			scope.Mode = "exact"
			scope.Active = true
			var checks atomic.Int64
			p := &Pipeline{Limit: NewRateLimiter(), Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", udp.LocalAddr().String())
			}}, Guard: func(context.Context, int64) (ScopeGuard, error) {
				checks.Add(1)
				g := ScopeGuard{Scope: scope}
				if deny.Load() {
					g.Blacklist = []string{raw}
				}
				return g, nil
			}, Rules: &SecurityRuleCache{Load: func(context.Context) ([]SecurityRule, error) { return []SecurityRule{}, nil }}}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			budget := &Budget{Limit: 100}
			ob, probeErr := p.Probe(ctx, scope, scope.Domain, []string{"local_fixture"}, budget)
			initialHits := hits.Load()
			deny.Store(true)
			_, blacklistErr := p.Probe(ctx, scope, scope.Domain, []string{"local_fixture"}, &Budget{Limit: 100})
			blacklistBlocked := hits.Load() == initialHits
			p0Write(t, fmt.Sprintf("w02-dial-%d", index+1), map[string]any{"destination": raw, "owned_by_loopback": true, "network": "none", "classifier_allowed": publicIP(netip.MustParseAddr(raw)), "http_requests": initialHits, "status_code": ob.StatusCode, "probe_returned_error": probeErr != nil, "dns_udp_requests": packets.Load(), "billed_operations": budget.Used, "scopeguard_checks": checks.Load(), "blacklist_no_additional_http": blacklistBlocked, "blacklist_probe_returned_error": blacklistErr != nil, "limiter": "unchanged LocalRateLimiter, platform 5 RPS, scope 5 RPS", "meaning": "locally routed IPv6 address; NOT a deployed NAT64/6to4 translator or proof of reaching embedded IPv4"})
			t.Logf("W02 local route: classifier_allowed=%t http_requests=%d status=%d blacklist_prevents_additional_http=%t", publicIP(netip.MustParseAddr(raw)), initialHits, ob.StatusCode, blacklistBlocked)
			if !blacklistBlocked {
				t.Error("blacklist failed to stop subsequent local fixture HTTP")
			}
			if probeErr != nil {
				t.Error("controlled fixture returned an unexpected pipeline error")
			}
			if publicIP(netip.MustParseAddr(raw)) && ob.StatusCode != 200 {
				t.Error("fixture inconclusive: permitted locally owned endpoint was not reached")
			}
			if initialHits != 0 {
				t.Error("W02 acceptance failed: embedded-private IPv6 reached controlled HTTP fixture")
			}
		})
	}
}
