package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func sampleScope() ScopeV2 {
	return ScopeV2{ID: 1, Owner: 1, Domain: "example.com", Mode: "descendants", Confirmed: true, RPS: 5, Concurrency: 2, RequestLimit: 100, WindowEnd: 24}
}
func TestScopeGuardBoundaries(t *testing.T) {
	scope := sampleScope()
	scope.Exclusions = []string{"login.example.com", "*.external.example.com", "8.8.8.0/24"}
	g := ScopeGuard{Scope: scope, Blacklist: []string{"blocked.example.com", "9.9.9.0/24"}}
	for _, raw := range []string{"example.com", "api.example.com", "https://API.Example.com:443/path"} {
		if _, err := g.AllowHost(raw); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{"evil-example.com", "example.com.attacker.net", "login.example.com", "a.external.example.com", "blocked.example.com", "sub.blocked.example.com", "-arg.example.com", "api.example.com;whoami"} {
		if _, err := g.AllowHost(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "100.64.0.1", "8.8.8.8", "9.9.9.9"} {
		if err := g.AllowIP(ip); err == nil {
			t.Fatalf("accepted IP %s", ip)
		}
	}
	if err := g.AllowIP("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	g.Scope.Mode = "exact"
	if _, err := g.AllowHost("api.example.com"); err == nil {
		t.Fatal("exact allowed child")
	}
	g.Scope.Mode = "subdomains"
	if _, err := g.AllowHost("example.com"); err == nil {
		t.Fatal("wildcard included apex")
	}
	g.Scope.Domain = "xn--fsqu00a.xn--0zwm56d"
	g.Scope.Mode = "exact"
	if _, err := g.AllowHost("例子.测试"); err != nil {
		t.Fatal("IDNA:", err)
	}
	past := time.Now().Add(-time.Minute)
	g.Scope.Expires = &past
	if _, err := g.AllowHost(g.Scope.Domain); err == nil {
		t.Fatal("expired scope allowed")
	}
}
func TestActiveWindowAndRate(t *testing.T) {
	s := sampleScope()
	g := ScopeGuard{Scope: s}
	if g.ActiveAllowed() == nil {
		t.Fatal("active enabled by default")
	}
	g.Scope.Active = true
	g.Scope.WindowStart = 22
	g.Scope.WindowEnd = 6
	g.Now = func() time.Time { return time.Date(2026, 10, 27, 23, 0, 0, 0, shanghai) }
	if err := g.ActiveAllowed(); err != nil {
		t.Fatal(err)
	}
	g.Now = func() time.Time { return time.Date(2026, 10, 27, 12, 0, 0, 0, shanghai) }
	if g.ActiveAllowed() == nil {
		t.Fatal("window not applied")
	}
	l := NewRateLimiter()
	start := time.Now()
	for range 4 {
		if err := l.Wait(context.Background(), 1, 5); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) < 550*time.Millisecond {
		t.Fatal("rate exceeded")
	}
}
func TestPipelineRejectsBeforeDNS(t *testing.T) {
	s := sampleScope()
	calls := 0
	p := Pipeline{Guard: func(context.Context, int64) (ScopeGuard, error) {
		return ScopeGuard{Scope: s, Blacklist: []string{"blocked.example.com"}}, nil
	}, Limit: NewRateLimiter(), Resolver: &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("test DNS must not be contacted")
	}}}
	for _, h := range []string{"outside.com", "blocked.example.com"} {
		if _, err := p.Probe(context.Background(), s, h, []string{"fixture"}, &Budget{Limit: 100}); err == nil {
			t.Fatal("outside target accepted")
		}
	}
	if calls != 0 {
		t.Fatal("DNS used before guard")
	}
}
func TestEncryptionAndSMTPValidation(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 32))
	aead, _ := cipher.NewGCM(block)
	s := Store{AEAD: aead}
	raw, err := s.encrypt("smtp", []byte(`{"password":"example-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "example-secret") {
		t.Fatal("plaintext secret stored")
	}
	decoded, err := s.decrypt("smtp", raw)
	if err != nil || !strings.Contains(string(decoded), "example-secret") {
		t.Fatal("decrypt failed")
	}
	raw[len(raw)-1] ^= 1
	if _, err = s.decrypt("smtp", raw); err == nil {
		t.Fatal("tamper accepted")
	}
	c := defaultSMTP()
	c.Host = "smtp.example.com"
	c.From = "owner@example.com"
	c.Recipients = []string{"member@example.com"}
	if err = c.validate(); err != nil {
		t.Fatal(err)
	}
	c.From = "owner@example.com\r\nBcc: attacker@example.com"
	if c.validate() == nil {
		t.Fatal("mail header injection accepted")
	}
}
func TestCollectorDecodingAndNoCommandInjection(t *testing.T) {
	scope := sampleScope()
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: ioReadCloser{strings.NewReader(`[{"name_value":"api.example.com\n*.example.com\noutside.net"}]`)}, Header: http.Header{}}, nil
	})}
	c := CertificateCollector{Source: "crtsh", Client: client, Limit: NewRateLimiter(), Budget: &Budget{Limit: 10}}
	stream, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range stream {
		count++
	}
	if count != 3 {
		t.Fatal(count)
	}
	for _, host := range []string{"-d evil.com", "example.com;id", "example.com | cat"} {
		scope.Domain = host
		sub := SubfinderCollector{Bin: "/tmp/untrusted", Budget: &Budget{Limit: 10}}
		if _, err = sub.Collect(context.Background(), scope); err == nil {
			t.Fatal("unsafe external invocation accepted")
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type ioReadCloser struct{ *strings.Reader }

func (ioReadCloser) Close() error { return nil }
func TestPlanAndAssetFilterSQL(t *testing.T) {
	p := Plan{Interval: 6}
	now := time.Now()
	next, err := nextPlan(p, now)
	if err != nil || next.Sub(now) != 6*time.Hour {
		t.Fatal(err)
	}
	p.Cron = "* * * * *"
	if _, err = nextPlan(p, now); err == nil {
		t.Fatal("sub-minute plan accepted")
	}
	p.Cron = "0 9 * * *"
	if _, err = nextPlan(p, now); err != nil {
		t.Fatal(err)
	}
	q := httptest.NewRequest("GET", "http://localhost?q=%27%3BDROP+TABLE+assets%3B--&status=new", nil).URL.Query()
	where, args := assetWhere(User{ID: 7, Role: "user"}, q)
	if strings.Contains(where, "DROP") || len(args) != 4 {
		t.Fatal("query not parameterized")
	}
}
func TestBudgetIsAtomic(t *testing.T) {
	b := Budget{Limit: 10}
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() { defer wg.Done(); b.Take() }()
	}
	wg.Wait()
	if b.Used != 10 {
		t.Fatal(b.Used)
	}
}
func TestReadonlyAPIDeniesMutation(t *testing.T) {
	e := &Engine{}
	r := httptest.NewRequest("POST", "http://localhost/api/scopes", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	e.serve(w, r, User{ID: 1, Role: "readonly"})
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestXLSXValuesCannotBecomeFormulas(t *testing.T) {
	v := exportValues([]any{"=cmd()", "+formula", "@SUM(1)", "normal"}, true)
	if v[0] != "'=cmd()" || v[3] != "normal" {
		t.Fatal(v)
	}
	raw, _ := json.Marshal(v)
	if len(raw) == 0 {
		t.Fatal("empty")
	}
}
