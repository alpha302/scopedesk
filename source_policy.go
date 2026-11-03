package main

import "slices"

// UI hints and pre-queue validation share the same manifest restrictions.
// None of these hints replaces ScopeGuard checks at actual request boundaries.
type SourceCapability struct {
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	ScopeModes   []string `json:"scope_modes"`
	EvidenceOnly bool     `json:"evidence_only"`
}

func (c SourceCapability) BlockReason(scopeMode, collectionMode string) string {
	if !c.Enabled {
		return "数据源未启用或未注册"
	}
	if len(c.ScopeModes) > 0 && !slices.Contains(c.ScopeModes, scopeMode) {
		if c.Name == "subfinder" && scopeMode == "exact" {
			return "精确域名不支持子域枚举工具；未扩大目标范围"
		}
		return "数据源不支持当前目标粒度"
	}
	if collectionMode == "evidence_only" && !c.EvidenceOnly {
		return "仅第三方证据模式不支持外部插件"
	}
	return ""
}
