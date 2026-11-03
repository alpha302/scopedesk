package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type w02RateObserver struct {
	RateLimiter
	atHTTP func()
}

func (l w02RateObserver) Wait(ctx context.Context, id int64, rps float64) error {
	if err := l.RateLimiter.Wait(ctx, id, rps); err != nil {
		return err
	}
	pcs := make([]uintptr, 16)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if strings.Contains(f.Function, "(*Pipeline).httpURL") {
			l.atHTTP()
			break
		}
		if !more {
			break
		}
	}
	return nil
}

func TestW02ControlledTransitions(t *testing.T) {
	if os.Getenv("W02_NETWORK_NONE") != "confirmed" {
		t.Skip("requires isolated network-none namespace")
	}
	for _, mode := range []string{"native-ipv6", "dual-stack", "rebind", "redirect", "revoke"} {
		t.Run(mode, func(t *testing.T) {
			var changed atomic.Bool
			var v4hits, v6hits, badhits atomic.Int64
			for _, entry := range []struct {
				ip   string
				hits *atomic.Int64
			}{{"1.1.1.1", &v4hits}, {"2606:4700:4700::1111", &v6hits}, {"64:ff9b::a00:1", &badhits}} {
				counter := entry.hits
				ln, err := net.Listen("tcp", net.JoinHostPort(entry.ip, "80"))
				if err != nil {
					t.Fatal("loopback-owned HTTP endpoint unavailable")
				}
				srv := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					counter.Add(1)
					if mode == "redirect" && r.Host == "ok.example.test" {
						http.Redirect(w, r, "http://blocked.example.test/", 302)
						return
					}
					if r.URL.Path == "/favicon.ico" {
						w.Header().Set("Content-Type", "image/png")
						w.Write(faviconPNG())
						return
					}
					fmt.Fprint(w, "<title>W02 safe fixture</title>")
				})}
				go srv.Serve(ln)
				defer srv.Close()
			}
			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal("local DNS unavailable")
			}
			defer udp.Close()
			go func() {
				buf := make([]byte, 4096)
				for {
					n, addr, err := udp.ReadFrom(buf)
					if err != nil {
						return
					}
					var req dnsmessage.Message
					if req.Unpack(buf[:n]) != nil {
						continue
					}
					res := dnsmessage.Message{Header: dnsmessage.Header{ID: req.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: req.Questions}
					for _, q := range req.Questions {
						host := strings.TrimSuffix(q.Name.String(), ".")
						forbidden := host == "blocked.example.test" || (mode == "rebind" && changed.Load())
						h := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 0}
						if q.Type == dnsmessage.TypeA && !forbidden && mode != "native-ipv6" {
							res.Answers = append(res.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}})
						}
						if q.Type == dnsmessage.TypeAAAA && (forbidden || mode == "dual-stack" || mode == "native-ipv6") {
							ip := "64:ff9b::a00:1"
							if mode == "native-ipv6" && !forbidden {
								ip = "2606:4700:4700::1111"
							}
							res.Answers = append(res.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(ip).As16()}})
						}
					}
					b, err := res.Pack()
					if err == nil {
						udp.WriteTo(b, addr)
					}
				}
			}()
			scope := sampleScope()
			scope.Domain = "example.test"
			scope.Active = true
			p := &Pipeline{Limit: w02RateObserver{NewRateLimiter(), func() {
				if mode == "rebind" || mode == "revoke" {
					changed.Store(true)
				}
			}}, Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", udp.LocalAddr().String())
			}}, Guard: func(context.Context, int64) (ScopeGuard, error) {
				s := scope
				if mode == "revoke" && changed.Load() {
					s.Confirmed = false
				}
				return ScopeGuard{Scope: s}, nil
			}, Rules: &SecurityRuleCache{Load: func(context.Context) ([]SecurityRule, error) { return []SecurityRule{}, nil }}}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			budget := &Budget{Limit: 100}
			ob, probeErr := p.Probe(ctx, scope, "ok.example.test", []string{"controlled"}, budget)
			if badhits.Load() != 0 {
				t.Fatal("forbidden IPv6 endpoint received HTTP")
			}
			switch mode {
			case "native-ipv6":
				if ob.StatusCode != 200 || v6hits.Load() == 0 {
					t.Fatal("ordinary authorized IPv6 stopped working")
				}
			case "dual-stack":
				if ob.StatusCode != 200 || v4hits.Load() == 0 {
					t.Fatal("safe IPv4 dual-stack fallback stopped working")
				}
			case "redirect":
				if v4hits.Load() == 0 {
					t.Fatal("redirect origin fixture was not reached")
				}
			case "rebind", "revoke":
				if !changed.Load() || len(ob.IPs) == 0 || v4hits.Load() != 0 || v6hits.Load() != 0 {
					t.Fatal("fresh DNS/authorization did not prevent HTTP after controlled change")
				}
			}
			p0Write(t, "w02-transition-"+mode, map[string]any{"mode": mode, "v4_http_requests": v4hits.Load(), "native_v6_http_requests": v6hits.Load(), "forbidden_http_requests": badhits.Load(), "status_code": ob.StatusCode, "probe_error": probeErr != nil, "billed_operations": budget.Used, "controlled_change_applied": changed.Load(), "scope_rps": scope.RPS, "network": "none"})
		})
	}
}
