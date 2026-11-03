package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Quota tests isolate counting from CPU cost; W03 regressions separately exercise
// the unchanged real PBKDF2 for existing, unknown and disabled accounts.
func w37Fail(t *testing.T, s *Server, name string, n int) int {
	t.Helper()
	return (<-w03StartLogin(s, context.Background(), name, "incorrect-password", fmt.Sprintf("192.0.2.%d", n+1))).Code
}

func TestW37AccountAcrossIPs(t *testing.T) {
	for _, name := range []string{"admin", "nonexistent"} {
		t.Run(name, func(t *testing.T) {
			s := fixture(t)
			s.loginHash = func(string, string) string { return "wrong-hash" }
			for i := 0; i < 8; i++ {
				if w37Fail(t, s, name, i) != 401 {
					t.Fatal("first eight attempts changed")
				}
			}
			if w37Fail(t, s, name, 8) != 429 {
				t.Fatal("W37: changing IP bypasses the account quota")
			}
		})
	}
}

func TestW37AccountSurvivesRestart(t *testing.T) {
	s := fixture(t)
	s.loginHash = func(string, string) string { return "wrong-hash" }
	for i := 0; i < 8; i++ {
		if w37Fail(t, s, "admin", i) != 401 {
			t.Fatal("fixture attempt failed")
		}
	}
	restarted, err := newServer(s.path)
	if err != nil {
		t.Fatal("restart failed")
	}
	restarted.loginHash = s.loginHash
	if w37Fail(t, restarted, "admin", 9) != 429 {
		t.Fatal("W37: restart clears the account quota")
	}
}

func TestW37CanonicalBucketPreservesIdentity(t *testing.T) {
	s := fixture(t)
	s.loginHash = func(string, string) string { return "wrong-hash" }
	variants := []string{"admin", "ADMIN", "Admin", "ＡＤＭＩＮ", " admin ", "ａｄｍｉｎ", "AdMiN", "admin"}
	for i, name := range variants {
		if w37Fail(t, s, name, i) != 401 {
			t.Fatal("identity or generic error changed")
		}
	}
	if w37Fail(t, s, "admin", 9) != 429 {
		t.Fatal("W37: case/Unicode variants bypass the canonical account bucket")
	}
}

func TestW37ExactIdentityAndIPLimitRemain(t *testing.T) {
	s := fixture(t)
	// Bucket normalization is not authentication normalization.
	if w37Fail(t, s, "ADMIN", 0) != 401 {
		t.Fatal("case-sensitive identity changed")
	}
	if (<-w03StartLogin(s, context.Background(), "admin", "test-password-2026", "192.0.2.2")).Code != 200 {
		t.Fatal("correct credentials failed")
	}
	s.loginHash = func(string, string) string { return "wrong-hash" }
	for i := 0; i < 8; i++ {
		if (<-w03StartLogin(s, context.Background(), fmt.Sprintf("missing%d", i), "incorrect-password", "192.0.2.100")).Code != 401 {
			t.Fatal("IP fixture failed")
		}
	}
	if (<-w03StartLogin(s, context.Background(), "bob", "incorrect-password", "192.0.2.100")).Code != 429 {
		t.Fatal("account rotation bypasses original IP limit")
	}
}

func TestW37ReservationsRecoveryAndReset(t *testing.T) {
	l, err := openAccountLimits(filepath.Join(t.TempDir(), "limits.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var receipts []accountReservation
	var denied, failed int
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, limited, err := l.reserve("admin")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
			} else if limited {
				denied++
			} else {
				receipts = append(receipts, r)
			}
		}()
	}
	wg.Wait()
	if len(receipts) != 8 || denied != 24 || failed != 0 {
		t.Fatal("parallel account reservations exceed bound")
	}
	restarted, err := openAccountLimits(l.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, limited, err := restarted.reserve("ADMIN"); err != nil || !limited {
		t.Fatal("restart loses pending reservations")
	}
	for _, r := range receipts {
		if err := l.finish(r, true, false); err != nil {
			t.Fatal(err)
		}
	}
	l.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	r, limited, err := l.reserve("admin")
	if err != nil || limited {
		t.Fatal("fixed recovery window failed")
	}
	if err = l.reset("ADMIN"); err != nil {
		t.Fatal(err)
	}
	newReceipt, limited, err := l.reserve("admin")
	if err != nil || limited {
		t.Fatal("admin reset did not restore quota")
	}
	if err = l.finish(r, true, false); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	b := l.state.Buckets[newReceipt.key]
	l.mu.Unlock()
	if b.Failures != 0 || b.Pending != 1 {
		t.Fatal("old reservation modified post-reset epoch")
	}
	if err = l.finish(newReceipt, false, true); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	n := len(l.state.Buckets)
	l.mu.Unlock()
	if n != 0 {
		t.Fatal("successful login failed to clear completed failures")
	}
}

func TestW37PersistenceFailureAndPrivacy(t *testing.T) {
	s := fixture(t)
	s.loginHash = func(string, string) string { return "wrong-hash" }
	if w37Fail(t, s, "admin", 0) != 401 {
		t.Fatal("fixture failed")
	}
	raw, err := os.ReadFile(s.accountLimits.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"admin", "incorrect-password", "192.0.2.", "csrf", "scopedesk"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("limit state contains request identity or credentials")
		}
	}
	info, err := os.Stat(s.accountLimits.path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("limit state permissions are not private")
	}
	// A directory cannot be replaced by the temporary state file, on any OS.
	s.accountLimits.path = t.TempDir()
	before := len(s.sessions)
	if w37Fail(t, s, "bob", 1) != 503 || len(s.sessions) != before {
		t.Fatal("failed durable reservation did not fail closed")
	}
	if err = os.WriteFile(s.path+".login-limits.json", []byte("{corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = newServer(s.path); err == nil {
		t.Fatal("restart silently reset corrupt account state")
	}
}

func TestW37AdminUnlockPermissionsAuditAndDurability(t *testing.T) {
	s := fixture(t)
	admin, csrf := signin(t, s, "admin")
	bob, bobCSRF := signin(t, s, "bob")
	s.loginHash = func(string, string) string { return "wrong-hash" }
	for i := 0; i < 8; i++ {
		if w37Fail(t, s, "bob", i) != 401 {
			t.Fatal("fixture attempt failed")
		}
	}
	if call(s, "POST", "/api/user/login-unlock", `{"id":3}`, bob, bobCSRF).Code != 403 {
		t.Fatal("member can reset login quota")
	}
	if call(s, "POST", "/api/user/login-unlock", `{"id":3}`, admin, "").Code != 403 {
		t.Fatal("unlock bypasses CSRF")
	}
	if call(s, "POST", "/api/user/login-unlock", `{"id":3}`, admin, csrf).Code != 200 {
		t.Fatal("admin reset failed")
	}
	if s.logs[len(s.logs)-1].Path != "/api/user/login-unlock/3" {
		t.Fatal("unlock target missing from audit")
	}
	restarted, err := newServer(s.path)
	if err != nil {
		t.Fatal(err)
	}
	restarted.loginHash = s.loginHash
	if w37Fail(t, restarted, "bob", 9) != 401 {
		t.Fatal("admin unlock not durable")
	}
	if call(s, "POST", "/api/user/login-unlock", `{"id":999}`, admin, csrf).Code != 404 {
		t.Fatal("unknown target accepted")
	}
}

func TestW37BucketCapacityBound(t *testing.T) {
	l, err := openAccountLimits(filepath.Join(t.TempDir(), "limits.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < accountBucketLimit; i++ {
		l.state.Buckets[accountBucketKey(fmt.Sprintf("missing%d", i))] = accountBucket{Failures: 1, Until: time.Now().Add(accountWindow), Epoch: strings.Repeat("a", 64)}
	}
	if _, _, err = l.reserve("another-missing"); err == nil {
		t.Fatal("unbounded account state")
	}
	if _, limited, err := l.reserve("missing1"); err != nil || limited {
		t.Fatal("capacity incorrectly blocks existing bucket")
	}
}
