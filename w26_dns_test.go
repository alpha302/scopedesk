package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
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

func TestW26MixedAliasTimeoutAndFluctuation(t *testing.T) {
	for _, mode := range []string{"aaaa_only", "alias_negative", "timeout", "fluctuate"} {
		t.Run(mode, func(t *testing.T) {
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var phase atomic.Bool
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
					if mode == "timeout" {
						continue
					}
					r := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: request.Questions}
					if mode == "alias_negative" {
						r.RCode = dnsmessage.RCodeNameError
						target := dnsmessage.MustNewName("edge.example.com.")
						r.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: target}}}
					}
					if mode == "fluctuate" && !phase.Load() {
						r.RCode = dnsmessage.RCodeNameError
					}
					for _, q := range request.Questions {
						if q.Type == dnsmessage.TypeAAAA && (mode == "aaaa_only" || mode == "fluctuate" && phase.Load()) {
							r.Answers = append(r.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11}}})
						}
					}
					raw, err := r.Pack()
					if err == nil {
						conn.WriteTo(raw, addr)
					}
				}
			}()
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
			}}
			scope := sampleScope()
			scope.Active = false
			p := Pipeline{Resolver: r, Limit: immediateLimit{}, Guard: func(context.Context, int64) (ScopeGuard, error) { return ScopeGuard{Scope: scope}, nil }}
			for round := 0; round < 2; round++ {
				ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
				o, err := p.Probe(ctx, scope, "api.example.com", []string{"fixture"}, &Budget{Limit: 100})
				cancel()
				if err != nil || o.DNSObservation == nil || o.Alive != nil {
					t.Fatal("DNS fixture changed HTTP reachability")
				}
				want := "unknown"
				switch mode {
				case "aaaa_only":
					want = "answer"
				case "timeout":
					want = "timeout"
				case "fluctuate":
					want = "nxdomain_pending"
					if phase.Load() {
						want = "answer"
					}
				}
				if o.DNSObservation.State != want {
					t.Fatalf("mode=%s round=%d state=%s want=%s", mode, round, o.DNSObservation.State, want)
				}
				phase.Store(true)
			}
		})
	}
}

func TestW26PersistAndRecoverDNSWithoutChangingHTTP(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	p0Exec(t, s, `INSERT INTO assets(scope_id,host,ips,is_alive,miss_count)VALUES($1,'api.example.com',ARRAY['1.1.1.1'],true,2)`, scope.ID)
	for _, state := range []string{"nxdomain_pending", "servfail", "answer"} {
		run := claimedRun(t, s, scope)
		o := Observation{Host: "api.example.com", DNSObserved: true, DNSObservation: &DNSObservation{State: state, At: time.Now().UTC(), Basis: "synthetic wire evidence", Replies: []DNSReply{}}}
		if _, err := s.WriteResults(ctx, run, []Observation{o}, false); err != nil {
			t.Fatal(err)
		}
		closeRun(t, s, run)
		var got string
		var alive bool
		var miss int
		if err := s.DB.QueryRow(ctx, `SELECT dns_observation->>'state',is_alive,miss_count FROM assets WHERE host='api.example.com'`).Scan(&got, &alive, &miss); err != nil || got != state || !alive || miss != 2 {
			t.Fatal("DNS evidence persistence altered HTTP fact")
		}
	}
	run := claimedRun(t, s, scope)
	if _, err := s.WriteResults(ctx, run, []Observation{{Host: "api.example.com", EvidenceOnly: true, DNSObserved: true, DNSObservation: &DNSObservation{State: "nxdomain_pending"}}}, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, s, run)
	var state string
	var events int
	if err := s.DB.QueryRow(ctx, `SELECT dns_observation->>'state' FROM assets WHERE host='api.example.com'`).Scan(&state); err != nil || state != "answer" {
		t.Fatal("third-party evidence replaced real DNS")
	}
	if err := s.DB.QueryRow(ctx, `SELECT count(*)FROM asset_events WHERE type IN('ASSET_DOWN','ASSET_BACK')`).Scan(&events); err != nil || events != 0 {
		t.Fatal("DNS evidence emitted HTTP transition")
	}
}

func TestW26ConflictingAndTruncatedRepliesStayUnknown(t *testing.T) {
	for _, replies := range [][]DNSReply{
		{{Name: "api.example.com", Type: 1, RCode: 3}, {Name: "api.example.com", Type: 28, RCode: 0}},
		{{Name: "api.example.com", Type: 1, RCode: 3, Truncated: true}, {Name: "api.example.com", Type: 28, RCode: 3}},
		{{Name: "edge.example.com", Type: 1, RCode: 3}, {Name: "edge.example.com", Type: 28, RCode: 3}},
	} {
		c := &dnsCapture{replies: replies}
		if c.observation("api.example.com", errors.New("fixture")).State != "unknown" {
			t.Fatal("uncertain response became NXDOMAIN")
		}
	}
}
