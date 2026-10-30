package main

import (
	"context"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/url"
	"testing"
)

type immediateLimit struct{}

func (immediateLimit) Wait(context.Context, int64, float64) error { return nil }
func TestRedirectScopeAndPorts(t *testing.T) {
	s := sampleScope()
	s.Active = true
	p := Pipeline{Guard: func(context.Context, int64) (ScopeGuard, error) { return ScopeGuard{Scope: s}, nil }, Limit: immediateLimit{}}
	for _, raw := range []string{"https://outside.net/", "http://127.0.0.1/", "http://api.example.com:8080/", "file:///etc/passwd", "https://user:password@api.example.com/"} {
		u, _ := url.Parse(raw)
		if err := p.redirectAllowed(context.Background(), s.ID, u, &Budget{Limit: 10}); err == nil {
			t.Fatalf("accepted redirect %s", raw)
		}
	}
	u, _ := url.Parse("https://api.example.com/path")
	if err := p.redirectAllowed(context.Background(), s.ID, u, &Budget{Limit: 10}); err != nil {
		t.Fatal(err)
	}
}
func TestDNSPrivateAnswersNeverReachHTTP(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, remote, e := conn.ReadFrom(buffer)
			if e != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: query.Questions}
			for _, q := range query.Questions {
				header := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
				switch q.Type {
				case dnsmessage.TypeA:
					header.Type = dnsmessage.TypeA
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				case dnsmessage.TypeAAAA:
					header.Type = dnsmessage.TypeAAAA
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{15: 1}}})
				}
			}
			raw, _ := response.Pack()
			conn.WriteTo(raw, remote)
		}
	}()
	s := sampleScope()
	s.Active = true
	p := Pipeline{Guard: func(context.Context, int64) (ScopeGuard, error) { return ScopeGuard{Scope: s}, nil }, Limit: immediateLimit{}, Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}}
	o, err := p.Probe(context.Background(), s, "api.example.com", []string{"fixture"}, &Budget{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.IPs) != 0 || o.StatusCode != 0 || o.Alive != nil {
		t.Fatal("private DNS answer reached HTTP probe")
	}
}
