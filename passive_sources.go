package main

import (
	"context"
)

// PassiveResult distinguishes a bounded/failed query from a completed query.
// AbsenceUsable is deliberately separate: third-party coverage is not a live check.
type PassiveResult struct {
	Records       []PluginRecord
	Complete      bool
	AbsenceUsable bool
	Pages         int
	Err           error
}

type PassiveSource interface {
	CollectPassive(context.Context, ScopeV2) PassiveResult
}

func builtinPassive(name string) bool {
	return name == "crtsh" || name == "certspotter" || paidPassive(name)
}

func paidPassive(name string) bool { return name == "fofa" || name == "hunter" }

func passiveCandidates(r PassiveResult) <-chan Candidate {
	return pluginCandidates(PluginResult{Records: r.Records})
}

func passiveFailure(code, message string) error { return executionFailure(code, message, false) }

func validateCollectionMode(mode string, sources []string) (string, error) {
	if mode == "" {
		mode = "profile"
	} // additive field: legacy callers keep their pipeline
	if mode != "profile" && mode != "evidence_only" {
		return "", passiveFailure("execution_policy", "采集模式无效")
	}
	if mode == "evidence_only" {
		for _, source := range sources {
			if !builtinPassive(source) {
				return "", passiveFailure("execution_policy", "仅第三方证据模式只支持受控内置来源；外部插件请使用授权画像模式")
			}
		}
	}
	return mode, nil
}

// A passive root query can enumerate children without authorizing the apex as a
// target, but root exclusions/blacklists still apply at every request boundary.
func passiveQueryGuard(g ScopeGuard, original ScopeV2) error {
	if err := g.Valid(); err != nil {
		return passiveFailure("scope_denied", "当前授权已失效")
	}
	if g.Scope.ID != original.ID || g.Scope.Domain != original.Domain || g.Scope.Mode != original.Mode {
		return passiveFailure("scope_denied", "范围已变化，停止原查询")
	}
	if original.Mode == "cidr" {
		return passiveFailure("source_unsupported", "当前被动适配器仅支持域名范围")
	}
	queryGuard := g
	if queryGuard.Scope.Mode == "subdomains" {
		queryGuard.Scope.Mode = "descendants"
	}
	if _, err := queryGuard.AllowHost(original.Domain); err != nil {
		return passiveFailure("scope_denied", "查询根域名被范围或黑名单规则拒绝")
	}
	return nil
}
