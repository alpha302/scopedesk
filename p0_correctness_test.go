package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Observe the resolver's wire response separately from DNSError. The fixture
// never uses a real resolver, provider, or target and cannot grant authorization.
func p0NegativeResolver(t *testing.T, code dnsmessage.RCode) (*net.Resolver, *atomic.Int64) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot start local DNS fixture")
	}
	t.Cleanup(func() { conn.Close() })
	packets := &atomic.Int64{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if request.Unpack(buf[:n]) != nil {
				continue
			}
			packets.Add(1)
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, Authoritative: true, RecursionAvailable: true, RCode: code}, Questions: request.Questions}
			raw, err := response.Pack()
			if err == nil {
				conn.WriteTo(raw, addr)
			}
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}, packets
}

func TestP0DNSNegativeEvidence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     dnsmessage.RCode
		notFound bool
	}{
		{"NXDOMAIN", dnsmessage.RCodeNameError, true},
		{"NODATA", dnsmessage.RCodeSuccess, true},
		{"SERVFAIL", dnsmessage.RCodeServerFailure, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver, packets := p0NegativeResolver(t, tc.code)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := resolver.LookupIPAddr(ctx, "api.example.com")
			var dnsErr *net.DNSError
			if !errors.As(err, &dnsErr) || dnsErr.IsNotFound != tc.notFound {
				t.Fatal("resolver negative-result characterization changed")
			}
			packets.Store(0)
			scope := sampleScope()
			scope.Active = true
			var httpCalls atomic.Int64
			p := Pipeline{Resolver: resolver, Limit: immediateLimit{}, Guard: func(context.Context, int64) (ScopeGuard, error) { return ScopeGuard{Scope: scope}, nil }, httpTransport: policyTransport(func(*http.Request) (*http.Response, error) {
				httpCalls.Add(1)
				return nil, errors.New("unexpected HTTP fixture request")
			})}
			budget := &Budget{Limit: 100}
			ob, err := p.Probe(ctx, scope, "api.example.com", []string{"fixture"}, budget)
			if err != nil || ob.Alive != nil || ob.DNSChecked || httpCalls.Load() != 0 || ob.Error == "" {
				t.Fatal("negative DNS must remain unknown HTTP reachability without HTTP requests")
			}
			t.Logf("W26 fixture=%s rcode=%d IsNotFound=%t billed_dns_operations=%d observed_udp_requests=%d http_requests=0; current observation has generic DNS error, no independent RCODE evidence", tc.name, tc.code, dnsErr.IsNotFound, budget.Used, packets.Load())
		})
	}
}

func TestP0CharacterizeSourceUnqualifiedMissing(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	p0Exec(t, s, `INSERT INTO assets(scope_id,host,sources,is_alive)VALUES($1,'api.example.com',ARRAY['manual','hunter'],true)`, scope.ID)
	q := PGQueue{s}
	for range 3 {
		if _, err := q.Enqueue(ctx, scope, []string{"certspotter"}, "test"); err != nil {
			t.Fatal("P0 enqueue failed")
		}
		run, err := q.Claim(ctx, "p0-worker")
		if err != nil {
			t.Fatal("P0 claim failed")
		}
		if _, err := s.WriteResults(ctx, run, nil, true); err != nil {
			t.Fatal("P0 missing-source reproduction failed")
		}
		closeRun(t, s, run)
	}
	var miss, events int
	var alive bool
	if err := s.DB.QueryRow(ctx, `SELECT miss_count,is_alive FROM assets WHERE host='api.example.com'`).Scan(&miss, &alive); err != nil {
		t.Fatal("P0 asset read failed")
	}
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM asset_events WHERE type='ASSET_DOWN'`).Scan(&events); err != nil {
		t.Fatal("P0 event read failed")
	}
	if miss != 3 || alive || events != 1 {
		t.Fatal("baseline changed; update W04 source-limited missing reproduction")
	}
	t.Log("W04 writer-boundary reproduction: three complete CertSpotter runs mark manual/Hunter-only asset missing=3, is_alive=false, ASSET_DOWN=1; this test does not call collectors")
}

func TestP0CharacterizeCDNRotation(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	for _, ip := range []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"} {
		run := claimedRun(t, s, scope)
		ob := Observation{Host: "api.example.com", IPs: []string{ip}, CNames: []string{}, Sources: []string{"fixture"}, DNSChecked: true, NetworkMeasured: true, NetworkEvidence: []NetworkEvidence{}, IsCDN: true}
		if _, err := s.WriteResults(ctx, run, []Observation{ob}, false); err != nil {
			t.Fatal("P0 CDN fixture write failed")
		}
		closeRun(t, s, run)
	}
	var events, snapshots int
	var cdn bool
	if err := s.DB.QueryRow(ctx, `SELECT (SELECT count(*) FROM asset_events WHERE type='IP_CHANGED'),(SELECT count(*) FROM asset_snapshots),(SELECT is_cdn FROM assets LIMIT 1)`).Scan(&events, &snapshots, &cdn); err != nil {
		t.Fatal("P0 CDN fixture read failed")
	}
	if events != 2 || snapshots != 3 || !cdn {
		t.Fatal("baseline changed; update W27 CDN rotation reproduction")
	}
	t.Log("W27 writer-boundary reproduction: stable host with CDN=true and three single-IP observations produces 2 IP_CHANGED events and 3 snapshots; no claim of real provider identity")
}

func TestP0CharacterizeDistributedLoginAttempts(t *testing.T) {
	s := fixture(t)
	for i := 1; i <= 9; i++ {
		r := httptest.NewRequest("POST", "http://127.0.0.1/api/login", strings.NewReader(`{"name":"admin","password":"p0-incorrect-password"}`))
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", i)
		w := httptest.NewRecorder()
		s.login(w, r)
		if w.Code != 401 {
			t.Fatal("baseline changed; update W37 distributed account-limit reproduction")
		}
	}
	if len(s.attempts) != 9 {
		t.Fatal("expected nine distinct current IP buckets")
	}
	t.Log("W37 reproduced: nine failures against one account from distinct fixture IPs all reach password verification; no account-level bucket, no real network requests")
}
