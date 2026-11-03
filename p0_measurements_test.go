package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/dns/dnsmessage"
)

type p0MeasurementKey string

const p0Correlation p0MeasurementKey = "correlation"
const p0SQLStart p0MeasurementKey = "sql-start"

type p0SQLSample struct {
	Correlation string `json:"correlation"`
	Kind        string `json:"kind"`
	ElapsedNS   int64  `json:"elapsed_ns"`
	Success     bool   `json:"success"`
}
type p0SQLBegin struct {
	id, kind string
	at       time.Time
}
type p0MeasureTrace struct {
	mu      sync.Mutex
	samples []p0SQLSample
}

func (p *p0MeasureTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	id, _ := ctx.Value(p0Correlation).(string)
	// Retain statement category only, never SQL arguments, URLs or error text.
	fields := strings.Fields(d.SQL)
	kind := "unknown"
	if len(fields) > 0 {
		kind = strings.ToUpper(fields[0])
	}
	return context.WithValue(ctx, p0SQLStart, p0SQLBegin{id, kind, time.Now()})
}
func (p *p0MeasureTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	b, ok := ctx.Value(p0SQLStart).(p0SQLBegin)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.samples = append(p.samples, p0SQLSample{b.id, b.kind, time.Since(b.at).Nanoseconds(), d.Err == nil})
}
func (p *p0MeasureTrace) snapshot() []p0SQLSample {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]p0SQLSample{}, p.samples...)
}
func (p *p0MeasureTrace) count(id string) int {
	n := 0
	for _, s := range p.snapshot() {
		if s.Correlation == id {
			n++
		}
	}
	return n
}
func p0MeasurementStore(t *testing.T) (*Store, *p0MeasureTrace) {
	t.Helper()
	s, _ := p0Store(t)
	tr := &p0MeasureTrace{}
	cfg := s.DB.Config()
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal("measurement pool unavailable")
	}
	s.DB.Close()
	s.DB = pool
	return s, tr
}
func p0MeasurementContext(id string) context.Context {
	return context.WithValue(context.Background(), p0Correlation, id)
}

type p0RestrictedSample struct {
	Host       string `json:"host"`
	Operation  string `json:"operation"`
	ID         string `json:"correlation"`
	SQLQueries int    `json:"pg_query_round_trips"`
	ElapsedNS  int64  `json:"elapsed_ns"`
	Success    bool   `json:"success"`
}
type p0MeasuredLimiter struct {
	inner   *PGRateLimiter
	trace   *p0MeasureTrace
	mu      sync.Mutex
	samples []p0RestrictedSample
	dnsOps  map[string]int
}

func (l *p0MeasuredLimiter) Wait(ctx context.Context, id int64, rps float64) error {
	host, _ := ctx.Value(p0Correlation).(string)
	op := "unknown"
	pcs := make([]uintptr, 12)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if strings.HasSuffix(f.Function, "(*Pipeline).dns") {
			op = "dns"
			break
		}
		if strings.HasSuffix(f.Function, "(*Pipeline).redirectAllowed") {
			op = "http_redirect"
			break
		}
		if strings.HasSuffix(f.Function, "(*Pipeline).httpURL") {
			op = "http_initial"
			break
		}
		if !more {
			break
		}
	}
	l.mu.Lock()
	index := len(l.samples)
	correlation := fmt.Sprintf("%s/op%d", host, index)
	if op == "dns" {
		l.dnsOps[host]++
		if l.dnsOps[host]%2 == 1 {
			op = "dns_cname"
		} else {
			op = "dns_ipaddr"
		}
	}
	l.samples = append(l.samples, p0RestrictedSample{Host: host, Operation: op, ID: correlation})
	l.mu.Unlock()
	start := time.Now()
	err := l.inner.Wait(context.WithValue(ctx, p0Correlation, correlation), id, rps)
	l.mu.Lock()
	l.samples[index].SQLQueries = l.trace.count(correlation)
	l.samples[index].ElapsedNS = time.Since(start).Nanoseconds()
	l.samples[index].Success = err == nil
	l.mu.Unlock()
	return err
}

type p0WireSample struct {
	Host     string `json:"host"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	AtNS     int64  `json:"at_ns"`
}
type p0WireLog struct {
	mu      sync.Mutex
	samples []p0WireSample
	start   time.Time
}

func (w *p0WireLog) add(host, protocol, action string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.samples = append(w.samples, p0WireSample{strings.TrimSuffix(strings.ToLower(host), "."), protocol, action, time.Since(w.start).Nanoseconds()})
}
func (w *p0WireLog) snapshot() []p0WireSample {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]p0WireSample{}, w.samples...)
}

func p0MeasurementTLS(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture TLS key unavailable")
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "P0 disposable fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture CA failed")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"*.s1.example.test"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture certificate failed")
	}
	certFile := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600) != nil {
		t.Fatal("fixture CA file failed")
	}
	t.Setenv("SSL_CERT_FILE", certFile)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
}

func p0MeasurementNetwork(t *testing.T, modes map[string]string) (*net.Resolver, *p0WireLog) {
	t.Helper()
	if os.Getenv("P0_NETWORK_NONE") != "confirmed" {
		t.Fatal("measurements require network-none fixture container")
	}
	// The workflow binds 1.1.1.1 only to loopback in a network-none namespace.
	// Prove local ownership before opening standard product ports; no public dial.
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal("cannot inspect fixture interface")
	}
	owned := false
	for _, i := range interfaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if strings.HasPrefix(a.String(), "1.1.1.1/") && i.Flags&net.FlagLoopback != 0 {
				owned = true
			}
		}
	}
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
			t.Fatal("non-loopback interface is up; refusing target probe")
		}
	}
	if !owned {
		t.Fatal("fixture IP is not owned by loopback; refusing probe")
	}
	wire := &p0WireLog{start: time.Now()}
	cert := p0MeasurementTLS(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		mode, ok := modes[host]
		if !ok {
			http.Error(w, "fixture host rejected", 403)
			return
		}
		wire.add(host, "http", r.Method+" "+r.URL.Path)
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/png")
			w.Write(faviconPNG())
			return
		}
		if mode == "redirect" && r.URL.Path == "/" {
			http.Redirect(w, r, "/final", 302)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<title>P0 measured fixture</title><link rel="icon" href="/favicon.ico">`)
	})
	for _, port := range []string{"80", "443"} {
		listener, err := net.Listen("tcp", "1.1.1.1:"+port)
		if err != nil {
			t.Fatal("standard fixture port unavailable")
		}
		srv := &http.Server{Handler: handler, ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: 5 * time.Second}
		if port == "443" {
			listener = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				wire.add(hello.ServerName, "tls", "client_hello")
				if modes[hello.ServerName] == "fallback" {
					return nil, errors.New("fixture intentional HTTPS rejection")
				}
				if _, ok := modes[hello.ServerName]; !ok {
					return nil, errors.New("fixture unknown host")
				}
				return &cert, nil
			}})
		}
		go srv.Serve(listener)
		t.Cleanup(func() { srv.Close() })
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("DNS fixture unavailable")
	}
	t.Cleanup(func() { udp.Close() })
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
				mode, ok := modes[host]
				wire.add(host, "dns_udp", q.Type.String())
				if !ok || mode == "nxdomain" {
					res.RCode = dnsmessage.RCodeNameError
					continue
				}
				if q.Type == dnsmessage.TypeA {
					res.Answers = append(res.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}})
				}
			}
			raw, err := res.Pack()
			if err == nil {
				udp.WriteTo(raw, addr)
			}
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", udp.LocalAddr().String())
	}}, wire
}

func TestP0Item2Measurements(t *testing.T) {
	if os.Getenv("P0_NETWORK_NONE") != "confirmed" {
		t.Skip("requires explicit network-none container")
	}
	s, tr := p0MeasurementStore(t)
	p0Seed(t, s, 10000, false)
	p0Exec(t, s, `UPDATE scopes SET active=true WHERE id=1;UPDATE projects SET allow_active=true WHERE id=(SELECT project_id FROM scopes WHERE id=1)`)
	scope, err := s.scopesByID(context.Background(), 1)
	if err != nil {
		t.Fatal("measurement scope unavailable")
	}
	// Four hosts per scenario, all selected from the fixed 10k asset dataset.
	rows, err := s.DB.Query(context.Background(), `SELECT host FROM assets WHERE scope_id=1 ORDER BY id LIMIT 16`)
	if err != nil {
		t.Fatal("fixture hosts unavailable")
	}
	hosts := []string{}
	for rows.Next() {
		var host string
		if rows.Scan(&host) != nil {
			t.Fatal("host read failed")
		}
		hosts = append(hosts, host)
	}
	rows.Close()
	if len(hosts) != 16 {
		t.Fatal("fixture host cardinality failed")
	}
	modes := map[string]string{}
	names := []string{"https", "fallback", "redirect", "nxdomain"}
	for i, h := range hosts {
		modes[h] = names[i/4]
	}
	resolver, wire := p0MeasurementNetwork(t, modes)
	limiter := &p0MeasuredLimiter{inner: &PGRateLimiter{s}, trace: tr, dnsOps: map[string]int{}}
	p := &Pipeline{Guard: s.guard, Limit: limiter, Resolver: resolver, Rules: &SecurityRuleCache{Load: s.securityRules}}
	fingerprints, err := loadFingerprintEngine()
	if err != nil {
		t.Fatal("fingerprint fixture setup failed")
	}
	p.Fingerprints = fingerprints
	for round := 1; round <= 3; round++ {
		for _, host := range hosts {
			id := fmt.Sprintf("round%d/%s", round, host)
			before := len(wire.snapshot())
			opStart := len(limiter.samples)
			sqlStart := len(tr.snapshot())
			budget := &Budget{Limit: 100}
			ctx, cancel := context.WithTimeout(p0MeasurementContext(id), 30*time.Second)
			start := time.Now()
			ob, err := p.Probe(ctx, scope, host, []string{"p0_fixture"}, budget)
			elapsed := time.Since(start)
			cancel()
			if err != nil {
				t.Fatal("controlled product probe failed")
			}
			mode := modes[host]
			if mode == "nxdomain" {
				if ob.Alive != nil || ob.StatusCode != 0 {
					t.Fatal("negative DNS unexpectedly reached HTTP")
				}
			} else if ob.StatusCode != 200 || ob.Title != "P0 measured fixture" || ob.FaviconSHA256 == nil {
				t.Fatal("positive product probe/HTTP fallback/favicon fixture did not complete")
			}
			ops := append([]p0RestrictedSample{}, limiter.samples[opStart:]...)
			dns, httpOps := 0, 0
			for _, op := range ops {
				if strings.HasPrefix(op.Operation, "dns_") {
					dns++
				} else if strings.HasPrefix(op.Operation, "http_") {
					httpOps++
				} else {
					t.Fatal("unclassified restricted operation")
				}
				if !op.Success {
					t.Fatal("PG limiter failed")
				}
			}
			if budget.Used != dns+httpOps {
				t.Fatal("budget and classified operations disagree")
			}
			wireSamples := wire.snapshot()[before:]
			httpRequests, dnsPackets, tlsAttempts := 0, 0, 0
			for _, v := range wireSamples {
				switch v.Protocol {
				case "dns_udp":
					dnsPackets++
				case "http":
					httpRequests++
				case "tls":
					tlsAttempts++
				}
			}
			p0Write(t, fmt.Sprintf("item2-host-round%d-%s", round, host), map[string]any{"round": round, "host": host, "scenario": mode, "billed_dns_operations": dns, "billed_http_operations": httpOps, "budget_used": budget.Used, "observed_dns_udp_requests": dnsPackets, "observed_http_requests": httpRequests, "observed_tls_client_hellos": tlsAttempts, "elapsed_ns": elapsed.Nanoseconds(), "restricted_operations": ops, "wire": wireSamples, "sql": tr.snapshot()[sqlStart:], "rps_platform": 5, "rps_scope": scope.RPS, "rps_project": scope.ProjectPolicy.RPSLimit, "http_transport": "unmodified product transport and TLS validation"})
		}
		t.Logf("round %d: 16 hosts, real product dial/TLS/DNS, original PG limiter and budget; raw samples saved", round)
	}
	p0MeasureScopes(t, s, tr)
	p0MeasureIdleWorkers(t, s, tr)
	p0MeasureLogin(t)
}

func p0MeasureScopes(t *testing.T, s *Store, tr *p0MeasureTrace) {
	for _, n := range []int{0, 1, 20, 100, 1000} {
		// Extra ranges remain inactive, with no plans; preserve default-plan semantics.
		if n > 20 {
			p0Exec(t, s, `INSERT INTO scopes(id,owner,project_id,domain,policy)SELECT i,100,101,'extra'||i||'.example.test','P0 fixture' FROM generate_series(21,$1::int)i ON CONFLICT DO NOTHING`, n)
		}
		for round := 1; round <= 3; round++ {
			id := fmt.Sprintf("scopes-%d-round%d", n, round)
			ctx := p0MeasurementContext(id)
			// Isolate the requested cardinality through temporary membership of a
			// dedicated project; do not change the product SQL or permission logic.
			p0Exec(t, s, `UPDATE scopes SET project_id=CASE WHEN id<=$1 THEN 101 ELSE 102 END`, n)
			start := time.Now()
			out, err := s.scopes(ctx, User{ID: 100, Role: "admin"}, url.Values{"project_id": []string{"101"}})
			elapsed := time.Since(start)
			if err != nil || len(out) != n {
				t.Fatal("scopes measurement failed")
			}
			p0Write(t, id, map[string]any{"round": round, "scope_count": n, "pg_query_round_trips": tr.count(id), "elapsed_ns": elapsed.Nanoseconds(), "sql": filterP0SQL(tr.snapshot(), id), "role": "admin", "project_filter": 101, "dataset_assets": 10000})
		}
	}
}

func filterP0SQL(samples []p0SQLSample, id string) []p0SQLSample {
	out := []p0SQLSample{}
	for _, s := range samples {
		if s.Correlation == id {
			out = append(out, s)
		}
	}
	return out
}

func p0MeasureIdleWorkers(t *testing.T, s *Store, tr *p0MeasureTrace) {
	// All 600 fixture jobs are done. Calling worker directly excludes heartbeat,
	// scheduler, and partition maintenance; no active or queued jobs can execute.
	for _, workers := range []int{1, 4} {
		for round := 1; round <= 3; round++ {
			id := fmt.Sprintf("idle-%d-round%d", workers, round)
			ctx, cancel := context.WithCancel(p0MeasurementContext(id))
			e := &Engine{root: ctx, Store: s, Queue: &PGQueue{s}}
			var wg sync.WaitGroup
			start := time.Now()
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func(i int) { defer wg.Done(); e.worker(fmt.Sprintf("p0-idle-%d", i)) }(i)
			}
			time.Sleep(5200 * time.Millisecond)
			cancel()
			wg.Wait()
			elapsed := time.Since(start)
			samples := filterP0SQL(tr.snapshot(), id)
			success := 0
			for _, v := range samples {
				if v.Success {
					success++
				}
			}
			p0Write(t, id, map[string]any{"round": round, "workers": workers, "elapsed_ns": elapsed.Nanoseconds(), "pg_query_round_trips": len(samples), "successful_queries": success, "queries_per_second": float64(len(samples)) / elapsed.Seconds(), "sql": samples, "jobs": "600 done; no queued/running/retrying jobs", "includes": "real worker ClaimWithLabels; BEGIN, SELECT, ROLLBACK", "excludes": "worker heartbeat, scheduler, maintenance and unrelated API"})
		}
	}
}

func p0MeasureLogin(t *testing.T) {
	// Block profiles capture the actual login's sync.Mutex.Lock callsite. The
	// observer is a separate lock user; its waits are not attributed to login.
	runtime.SetBlockProfileRate(1)
	defer runtime.SetBlockProfileRate(0)
	for round := 1; round <= 3; round++ {
		s := fixture(t)
		startGate := make(chan struct{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		requests := []map[string]any{}
		waits := []map[string]any{}
		for worker := 0; worker < 8; worker++ {
			wg.Add(1)
			go func(worker int) {
				defer wg.Done()
				<-startGate
				for i := 0; i < 3; i++ {
					r := httptest.NewRequest("POST", "http://127.0.0.1/api/login", strings.NewReader(`{"name":"admin","password":"p0-incorrect-password"}`))
					r.RemoteAddr = fmt.Sprintf("192.0.2.%d:%d", worker+1, 1000+i)
					w := httptest.NewRecorder()
					start := time.Now()
					s.login(w, r)
					duration := time.Since(start)
					mu.Lock()
					requests = append(requests, map[string]any{"worker": worker, "request": i, "elapsed_ns": duration.Nanoseconds(), "status": w.Code})
					mu.Unlock()
				}
			}(worker)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate
			for i := 0; i < 24; i++ {
				time.Sleep(2 * time.Millisecond)
				start := time.Now()
				s.mu.Lock()
				elapsed := time.Since(start)
				s.mu.Unlock()
				mu.Lock()
				waits = append(waits, map[string]any{"sample": i, "wait_ns": elapsed.Nanoseconds()})
				mu.Unlock()
			}
		}()
		close(startGate)
		wg.Wait()
		for _, r := range requests {
			if r["status"] != 401 {
				t.Fatal("login workload unexpectedly rate limited or succeeded")
			}
		}
		name := fmt.Sprintf("login-round%d", round)
		p0Write(t, name, map[string]any{"round": round, "concurrency": 8, "request_count": 24, "hash_parameters": "unchanged 600000 PBKDF2 iterations", "requests": requests, "mutex_observer_waits": waits, "observer_definition": "time from independent test goroutine immediately before s.mu.Lock to lock acquisition; includes scheduling and test observer perturbation; NOT per-login intrinsic wait", "profile": "block profiles cumulative; subtract previous round for callsite-specific delay"})
		path := filepath.Join(os.Getenv("P0_ARTIFACT_DIR"), name+".block.pprof")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal("profile file failed")
		}
		err = pprof.Lookup("block").WriteTo(f, 0)
		f.Close()
		if err != nil {
			t.Fatal("profile capture failed")
		}
	}
}
