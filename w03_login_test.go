package main

import (
	"fmt"
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func w03Request(name, pass, ip string) *httptest.ResponseRecorder { return nil }

func TestW03HashDoesNotBlockExistingSession(t *testing.T) {
	s := fixture(t)
	cookie, _ := signin(t, s, "bob")
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	s.loginHash = func(value, salt string) string { close(entered); <-release; return password(value, salt) }
	loginDone := make(chan int, 1)
	go func() {
		r := httptest.NewRequest("POST", "http://127.0.0.1/api/login", strings.NewReader(`{"name":"admin","password":"test-password-2026"}`))
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		s.login(w, r)
		loginDone <- w.Code
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("login never reached hash boundary")
	}
	apiDone := make(chan int, 1)
	go func() { apiDone <- call(s, "GET", "/api/me", "", cookie, "").Code }()
	blocked := false
	select {
	case status := <-apiDone:
		if status != 200 {
			t.Error("existing session no longer usable")
		}
	case <-time.After(500 * time.Millisecond):
		blocked = true
	}
	unblock()
	if blocked {
		if status := <-apiDone; status != 200 {
			t.Error("existing API failed after releasing hash")
		}
	}
	if status := <-loginDone; status != 200 {
		t.Fatal("control login failed")
	}
	if blocked {
		t.Fatal("W03: password hashing holds the global mutex and blocks an existing session API")
	}
}

func w03Quantiles(values []int64) map[string]any {
	sorted := append([]int64{}, values...)
	slices.Sort(sorted)
	q := func(p float64) int64 { rank := int(math.Ceil(p*float64(len(sorted)))) - 1; return sorted[max(0, rank)] }
	return map[string]any{"samples": len(sorted), "unit": "ns", "method": "nearest-rank empirical quantile; p99 of 20 samples is the observed maximum, not a capacity promise", "median": q(.5), "p95": q(.95), "p99": q(.99)}
}

// Real unchanged PBKDF2, one login at a time plus one existing-session API
// consumer. No parallel-login load or synthetic sleeping hash in this benchmark.
func TestW03SingleUserLatency(t *testing.T) {
	if os.Getenv("W03_MEASURE") != "1" {
		t.Skip("explicit single-user latency measurement only")
	}
	s := fixture(t)
	cookie, _ := signin(t, s, "bob")
	runtime.SetBlockProfileRate(1)
	defer runtime.SetBlockProfileRate(0)
	previous := runtime.SetMutexProfileFraction(1)
	defer runtime.SetMutexProfileFraction(previous)
	for round := 1; round <= 3; round++ {
		name := fmt.Sprintf("w03-single-user-round%d", round)
		dir := os.Getenv("P0_ARTIFACT_DIR")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal("evidence directory unavailable")
		}
		cpu, err := os.Create(filepath.Join(dir, name+".cpu.pprof"))
		if err != nil {
			t.Fatal("CPU profile unavailable")
		}
		if pprof.StartCPUProfile(cpu) != nil {
			cpu.Close()
			t.Fatal("CPU profile start failed")
		}
		latencies := []int64{}
		apiSamples := []int64{}
		loginStatuses := []int{}
		apiStatuses := []int{}
		for request := 0; request < 20; request++ {
			started := make(chan struct{})
			done := make(chan struct{})
			var loginElapsed int64
			var loginStatus int
			go func() {
				defer close(done)
				r := httptest.NewRequest("POST", "http://127.0.0.1/api/login", strings.NewReader(`{"name":"admin","password":"test-password-2026"}`))
				r.RemoteAddr = "192.0.2.1:1234"
				w := httptest.NewRecorder()
				at := time.Now()
				close(started)
				s.login(w, r)
				loginElapsed = time.Since(at).Nanoseconds()
				loginStatus = w.Code
			}()
			<-started
			time.Sleep(2 * time.Millisecond)
			at := time.Now()
			status := call(s, "GET", "/api/me", "", cookie, "").Code
			apiSamples = append(apiSamples, time.Since(at).Nanoseconds())
			apiStatuses = append(apiStatuses, status)
			<-done
			latencies = append(latencies, loginElapsed)
			loginStatuses = append(loginStatuses, loginStatus)
		}
		pprof.StopCPUProfile()
		cpu.Close()
		for _, kind := range []string{"mutex", "block"} {
			f, err := os.Create(filepath.Join(dir, name+"."+kind+".pprof"))
			if err != nil {
				t.Fatal("profile unavailable")
			}
			err = pprof.Lookup(kind).WriteTo(f, 0)
			f.Close()
			if err != nil {
				t.Fatal("profile capture failed")
			}
		}
		for _, statuses := range [][]int{loginStatuses, apiStatuses} {
			for _, status := range statuses {
				if status != 200 {
					t.Fatal("single-user measured request failed")
				}
			}
		}
		p0Write(t, name, map[string]any{"round": round, "load": "one real login plus one existing /api/me request per pair; 20 pairs; no network listener", "login_elapsed_ns": latencies, "existing_session_api_elapsed_ns": apiSamples, "login_quantiles": w03Quantiles(latencies), "api_quantiles": w03Quantiles(apiSamples), "login_statuses": loginStatuses, "api_statuses": apiStatuses, "hash": "PBKDF2 SHA256 600000 iterations, unchanged", "profile_enabled": true, "profile_caveats": "block and mutex profiles cumulative by round; fixture setup excluded from CPU profile; profiling affects observed timing; local httptest only, not production HTTP SLO"})
	}
}
