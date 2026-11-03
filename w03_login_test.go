package main

import (
	"context"
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
	"sync/atomic"
	"testing"
	"time"
)

func w03Gate(s *Server) (<-chan struct{}, func(), *atomic.Int64) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var first, closeGate sync.Once
	calls := &atomic.Int64{}
	s.loginHash = func(value, salt string) string {
		calls.Add(1)
		first.Do(func() { close(entered) })
		<-release
		return password(value, salt)
	}
	return entered, func() { closeGate.Do(func() { close(release) }) }, calls
}
func w03StartLogin(s *Server, ctx context.Context, name, pass, ip string) <-chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("POST", "http://127.0.0.1/api/login", strings.NewReader(fmt.Sprintf(`{"name":%q,"password":%q}`, name, pass))).WithContext(ctx)
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		s.login(w, r)
		done <- w
	}()
	return done
}
func w03Wait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("login state did not reach controlled test boundary")
}

func TestW03CredentialChangesDuringHash(t *testing.T) {
	for _, mode := range []string{"disable", "password", "role", "disable-reenable"} {
		t.Run(mode, func(t *testing.T) {
			s := fixture(t)
			admin, csrf := signin(t, s, "admin")
			entered, release, _ := w03Gate(s)
			defer release()
			done := w03StartLogin(s, context.Background(), "bob", "test-password-2026", "192.0.2.2")
			<-entered
			change := func(body string) {
				t.Helper()
				changed := make(chan int, 1)
				go func() { changed <- call(s, "POST", "/api/user/update", body, admin, csrf).Code }()
				select {
				case status := <-changed:
					if status != 200 {
						t.Fatal("credential change API failed")
					}
				case <-time.After(3 * time.Second):
					release()
					<-done
					t.Fatal("credential change blocked by login hash")
				}
			}
			switch mode {
			case "disable":
				change(`{"id":3,"role":"user","disabled":true,"password":""}`)
			case "password":
				change(`{"id":3,"role":"user","disabled":false,"password":"new-password-2026"}`)
			case "role":
				change(`{"id":3,"role":"readonly","disabled":false,"password":""}`)
			case "disable-reenable":
				change(`{"id":3,"role":"user","disabled":true,"password":""}`)
				change(`{"id":3,"role":"user","disabled":false,"password":""}`)
			}
			release()
			result := <-done
			if result.Code != 401 || len(result.Result().Cookies()) != 0 {
				t.Fatal("credential/state change during hash must prevent issuing a session")
			}
			s.mu.Lock()
			for _, ss := range s.sessions {
				if ss.User == 3 {
					s.mu.Unlock()
					t.Fatal("stale login created a session")
				}
			}
			s.mu.Unlock()
			if call(s, "GET", "/api/me", "", admin, "").Code != 200 {
				t.Fatal("unrelated existing admin session broke")
			}
		})
	}
}

func TestW03LimitReservations(t *testing.T) {
	s := fixture(t)
	entered, release, calls := w03Gate(s)
	defer release()
	s.attempts["192.0.2.1"] = Attempt{Count: 6, Until: time.Now().Add(15 * time.Minute)}
	first := w03StartLogin(s, context.Background(), "admin", "incorrect-password", "192.0.2.1")
	<-entered
	second := w03StartLogin(s, context.Background(), "admin", "incorrect-password", "192.0.2.1")
	w03Wait(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.loginPending["192.0.2.1"] == 2 })
	third := <-w03StartLogin(s, context.Background(), "admin", "incorrect-password", "192.0.2.1")
	if third.Code != 429 {
		t.Fatal("in-flight attempts must count toward the original eight-attempt cap")
	}
	release()
	if (<-first).Code != 401 || (<-second).Code != 401 {
		t.Fatal("admitted failures changed response")
	}
	s.mu.Lock()
	count, pending := s.attempts["192.0.2.1"].Count, s.loginPending["192.0.2.1"]
	s.mu.Unlock()
	if count != 8 || pending != 0 || calls.Load() != 2 {
		t.Fatal("failed attempts or permits were lost")
	}
}

func TestW03QueueBoundCancellationAndRecovery(t *testing.T) {
	s := fixture(t)
	entered, release, calls := w03Gate(s)
	defer release()
	active := w03StartLogin(s, context.Background(), "admin", "incorrect-password", "192.0.2.1")
	<-entered
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	queued1 := w03StartLogin(s, ctx1, "admin", "incorrect-password", "192.0.2.2")
	queued2 := w03StartLogin(s, ctx2, "missing", "incorrect-password", "192.0.2.3")
	w03Wait(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.loginAdmissions) == loginAdmissionLimit })
	for _, name := range []string{"admin", "missing"} {
		if (<-w03StartLogin(s, context.Background(), name, "incorrect-password", "192.0.2.4")).Code != 503 {
			t.Fatal("bounded admission must overload uniformly")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("more than one password hash ran concurrently")
	}
	cancel1()
	cancel2()
	if (<-queued1).Code != 408 || (<-queued2).Code != 408 {
		t.Fatal("queued cancellation must return promptly")
	}
	w03Wait(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.loginAdmissions) == 1 && len(s.loginPending) == 1
	})
	release()
	if (<-active).Code != 401 {
		t.Fatal("active request failed to finish")
	}
	if (<-w03StartLogin(s, context.Background(), "admin", "test-password-2026", "192.0.2.5")).Code != 200 {
		t.Fatal("cancellation or overload leaked a hash/admission permit")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.loginPending) != 0 || len(s.loginHashSlots) != 0 || len(s.loginAdmissions) != 0 || calls.Load() != 2 {
		t.Fatal("login resources did not recover")
	}
}

func TestW03QueueActiveCancellationDoesNotIssueSession(t *testing.T) {
	s := fixture(t)
	entered, release, _ := w03Gate(s)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	done := w03StartLogin(s, ctx, "admin", "test-password-2026", "192.0.2.1")
	<-entered
	cancel()
	release()
	result := <-done
	if result.Code != 408 || len(result.Result().Cookies()) != 0 {
		t.Fatal("canceled verified login must not issue a session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) != 0 || len(s.loginPending) != 0 || len(s.loginAdmissions) != 0 {
		t.Fatal("canceled hash leaked session or reservation")
	}
}

func TestW03HashUnknownAndDisabledUsers(t *testing.T) {
	s := fixture(t)
	var calls atomic.Int64
	s.loginHash = func(value, salt string) string { calls.Add(1); return password(value, salt) }
	s.data.Users[2].Disabled = true
	var previous string
	for i, name := range []string{"missing", "bob", "admin"} {
		w := <-w03StartLogin(s, context.Background(), name, "incorrect-password", fmt.Sprintf("192.0.2.%d", i+1))
		if w.Code != 401 || len(w.Result().Cookies()) != 0 {
			t.Fatal("invalid login exposed account state")
		}
		if previous != "" && previous != w.Body.String() {
			t.Fatal("unknown, disabled and wrong-password responses differ")
		}
		previous = w.Body.String()
	}
	if calls.Load() != 3 {
		t.Fatal("unknown or disabled accounts skipped password computation")
	}
}

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
