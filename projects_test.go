package main

import (
	"testing"
	"time"
)

func TestProjectPolicyAndEffectivePluginRate(t *testing.T) {
	scope := sampleScope()
	scope.Active = true
	scope.ProjectPolicy = &ProjectPolicy{Enabled: true, AllowActive: false, RPSLimit: 0.5}
	if (ScopeGuard{Scope: scope}).ActiveAllowed() == nil {
		t.Fatal("project active cap bypassed")
	}
	if scope.executionRPS() != 0.5 {
		t.Fatal("plugin rate exceeded project cap")
	}
	m := PluginManifest{}
	m.Exec.RateFormat = "integer"
	if _, err := pluginRate(m, scope.executionRPS()); err == nil {
		t.Fatal("integer plugin rounded project limit upward")
	}
	expired := time.Now().Add(-time.Hour)
	scope.ProjectPolicy.AllowActive = true
	scope.ProjectPolicy.Expires = &expired
	if (ScopeGuard{Scope: scope}).Valid() == nil {
		t.Fatal("expired project accepted")
	}
}
