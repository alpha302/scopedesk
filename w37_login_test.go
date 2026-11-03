package main

import (
	"context"
	"fmt"
	"testing"
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
