package main

import "testing"

func TestSourcePolicyCombinations(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cap         SourceCapability
		scope, mode string
		blocked     bool
	}{
		{"exact subfinder", SourceCapability{"subfinder", true, []string{"subdomains", "descendants"}, false}, "exact", "profile", true},
		{"subdomain subfinder", SourceCapability{"subfinder", true, []string{"subdomains", "descendants"}, false}, "subdomains", "profile", false},
		{"evidence subfinder", SourceCapability{"subfinder", true, []string{"subdomains", "descendants"}, false}, "descendants", "evidence_only", true},
		{"builtin exact", SourceCapability{"certspotter", true, []string{"exact", "subdomains", "descendants"}, true}, "exact", "evidence_only", false},
		{"builtin cidr", SourceCapability{"certspotter", true, []string{"exact", "subdomains", "descendants"}, true}, "cidr", "profile", true},
		{"custom declared", SourceCapability{"fixture", true, []string{"exact"}, false}, "descendants", "profile", true},
		{"custom unrestricted", SourceCapability{"fixture", true, nil, false}, "exact", "profile", false},
		{"disabled", SourceCapability{"fixture", false, nil, false}, "exact", "profile", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cap.BlockReason(tc.scope, tc.mode) != ""; got != tc.blocked {
				t.Fatalf("blocked=%t want %t", got, tc.blocked)
			}
		})
	}
}
