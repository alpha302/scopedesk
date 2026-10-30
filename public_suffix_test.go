package main

import "testing"

func TestPublicSuffixCannotBecomeAuthorization(t *testing.T) {
	s := sampleScope()
	for _, root := range []string{"co.uk", "com.cn", "com"} {
		s.Domain = root
		if err := (ScopeGuard{Scope: s}).Valid(); err == nil {
			t.Fatalf("public suffix accepted: %s", root)
		}
	}
	s.Domain = "example.co.uk"
	if err := (ScopeGuard{Scope: s}).Valid(); err != nil {
		t.Fatal(err)
	}
}
