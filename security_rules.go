package main

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

type SecurityRule struct {
	ID      int64    `json:"id"`
	Keyword string   `json:"keyword"`
	Match   string   `json:"match"`
	Fields  []string `json:"fields"`
	Enabled bool     `json:"enabled"`
	Builtin bool     `json:"builtin"`
	re      *regexp.Regexp
}
type SecurityMatch struct {
	RuleID  int64    `json:"rule_id"`
	Keyword string   `json:"keyword"`
	Match   string   `json:"match"`
	Fields  []string `json:"fields"`
}

func compileSecurityRule(r SecurityRule) (SecurityRule, error) {
	r.Keyword = strings.TrimSpace(r.Keyword)
	if len([]rune(r.Keyword)) == 0 || len([]rune(r.Keyword)) > 512 {
		return r, errors.New("规则关键词须为 1–512 个字符")
	}
	if r.Match != "contains" && r.Match != "regex" {
		return r, errors.New("匹配方式须为 contains 或 regex")
	}
	if len(r.Fields) == 0 || len(r.Fields) > 4 {
		return r, errors.New("请选择 1–4 个匹配字段")
	}
	fields := []string{}
	for _, f := range r.Fields {
		if !slices.Contains([]string{"title", "server", "tls", "fingerprint"}, f) || slices.Contains(fields, f) {
			return r, errors.New("匹配字段无效或重复")
		}
		fields = append(fields, f)
	}
	r.Fields = fields
	if r.Match == "regex" {
		re, err := regexp.Compile(r.Keyword)
		if err != nil {
			return r, errors.New("正则表达式无效")
		}
		r.re = re
	}
	return r, nil
}
func scopeBrand(domain string) string {
	host, err := normalizeHost(domain)
	if err != nil {
		return ""
	}
	if _, err = netip.ParseAddr(host); err == nil {
		return ""
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return strings.SplitN(root, ".", 2)[0]
}
func matchSecurityRules(rules []SecurityRule, scope ScopeV2, o Observation) []SecurityMatch {
	hits := []SecurityMatch{}
	brand := scopeBrand(scope.Domain)
	values := map[string][]string{"title": {o.Title}, "server": {o.Server}, "tls": {o.TLSSubject}, "fingerprint": o.Fingerprints}
	for _, r := range rules {
		if !r.Enabled || (brand != "" && strings.EqualFold(r.Keyword, brand)) {
			continue
		}
		fields := []string{}
		for _, field := range r.Fields {
			for _, value := range values[field] {
				matched := r.Match == "contains" && strings.Contains(strings.ToLower(value), strings.ToLower(r.Keyword))
				if r.Match == "regex" && r.re != nil {
					matched = r.re.MatchString(value)
				}
				if matched {
					fields = append(fields, field)
					break
				}
			}
		}
		if len(fields) > 0 {
			hits = append(hits, SecurityMatch{r.ID, r.Keyword, r.Match, fields})
		}
	}
	return hits
}

type SecurityRuleCache struct {
	mu        sync.Mutex
	rules     []SecurityRule
	loaded    bool
	refreshed time.Time
	Load      func(context.Context) ([]SecurityRule, error)
	Now       func() time.Time
}

func (c *SecurityRuleCache) refresh(ctx context.Context, force bool) ([]SecurityRule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	if c.loaded && !force && now.Sub(c.refreshed) < 60*time.Second {
		return c.rules, nil
	}
	rules, err := c.Load(ctx)
	if err == nil {
		for i := range rules {
			rules[i], err = compileSecurityRule(rules[i])
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		if c.loaded {
			// Bound retries during an outage instead of querying once per host.
			c.refreshed = now
			log.Printf("security rules refresh failed: %v", err)
			return c.rules, nil
		}
		return nil, errors.New("安全设备规则加载失败")
	}
	c.rules = rules
	c.loaded = true
	c.refreshed = now
	return c.rules, nil
}
func (c *SecurityRuleCache) run(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err := c.refresh(refreshCtx, true)
			cancel()
			if err != nil {
				log.Printf("security rules refresh failed: %v", err)
			}
		}
	}
}
func (s *Store) securityRules(ctx context.Context) ([]SecurityRule, error) {
	rows, err := s.DB.Query(ctx, "SELECT id,keyword,match,fields,enabled,builtin FROM security_rules ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := []SecurityRule{}
	for rows.Next() {
		var r SecurityRule
		if err = rows.Scan(&r.ID, &r.Keyword, &r.Match, &r.Fields, &r.Enabled, &r.Builtin); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}
func (p *Pipeline) classifySecurity(ctx context.Context, scope ScopeV2, o *Observation) error {
	if p.Rules == nil {
		return errors.New("安全设备规则未加载")
	}
	rules, err := p.Rules.refresh(ctx, false)
	if err != nil {
		return err
	}
	o.SecurityMatches = matchSecurityRules(rules, scope, *o)
	o.Security = len(o.SecurityMatches) > 0
	o.SecurityRule = ""
	if o.Security {
		o.SecurityRule = o.SecurityMatches[0].Keyword
	}
	return nil
}
