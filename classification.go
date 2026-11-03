package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/jackc/pgx/v5"
	"golang.org/x/net/publicsuffix"
)

const categoryRuleVersion = "subdomain-tokens-v2"

// Points describe sorting hints, never ownership or vulnerability confidence.
type Classification struct {
	Version           string `json:"version"`
	Mode              string `json:"mode"`
	Root              string `json:"root"`
	Keyword           string `json:"keyword"`
	Label             string `json:"label"`
	AutomaticCategory string `json:"automatic_category"`
	BasePoints        int    `json:"base_points"`
	KeywordPoints     int    `json:"keyword_points"`
	AlivePoints       int    `json:"alive_points"`
}

func evaluateCategory(host string, active bool, scopeRoot string) Classification {
	c := Classification{Version: categoryRuleVersion, Mode: "auto", AutomaticCategory: "未分类", BasePoints: 10}
	labels := ""
	if h, err := normalizeHost(host); err == nil {
		if _, err := netip.ParseAddr(h); err != nil {
			root, err := publicsuffix.EffectiveTLDPlusOne(h)
			if err == nil {
				if s, err := normalizeHost(scopeRoot); err == nil && (s == root || strings.HasSuffix(s, "."+root)) && (h == s || strings.HasSuffix(h, "."+s)) {
					root = s
				}
				c.Root = root
				labels = strings.TrimSuffix(h, root)
			}
		}
	}
	for _, pair := range [][2]string{{"api", "API"}, {"sso", "认证 SSO"}, {"admin", "支撑平台"}, {"dev", "开发测试"}, {"test", "开发测试"}, {"uat", "开发测试"}} {
		for _, label := range strings.Split(labels, ".") {
			if categoryTokenMatch(label, pair[0]) {
				c.Keyword = pair[0]
				c.Label = label
				c.AutomaticCategory = pair[1]
				c.KeywordPoints = 20
				break
			}
		}
		if c.Keyword != "" {
			break
		}
	}
	if active {
		c.AlivePoints = 10
	}
	return c
}

func refreshAssetCategory(a *AssetDoc, root string) {
	c := evaluateCategory(a.Host, a.Alive != nil && *a.Alive, root)
	a.Category = c.AutomaticCategory
	if a.CategoryOverride != nil {
		c.Mode = "manual"
		a.Category = *a.CategoryOverride
	}
	a.Score = c.BasePoints + c.KeywordPoints + c.AlivePoints
	a.Classification = &c
}

func classificationEqual(a, b *Classification) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func storeAssetCategory(ctx context.Context, tx pgx.Tx, a AssetDoc) error {
	raw, err := json.Marshal(a.Classification)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE assets SET category=$2,score=$3,classification=$4::jsonb,category_override=$5 WHERE id=$1`, a.ID, a.Category, a.Score, raw, a.CategoryOverride)
	return err
}
