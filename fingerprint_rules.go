package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	xhtml "golang.org/x/net/html"
	"gopkg.in/yaml.v3"
)

//go:embed rules/fingerprints.yaml rules/httpgo.yaml third_party/httpgo/manifest.json
var fingerprintFiles embed.FS

type FingerprintMatcher struct {
	Field         string `json:"field" yaml:"field"`
	Key           string `json:"key,omitempty" yaml:"key,omitempty"`
	Pattern       string `json:"pattern" yaml:"pattern"`
	Kind          string `json:"kind" yaml:"kind"`
	CaseSensitive bool   `json:"case_sensitive,omitempty" yaml:"case_sensitive,omitempty"`
	Negate        bool   `json:"negate,omitempty" yaml:"negate,omitempty"`
	compiled      *regexp.Regexp
}
type FingerprintRule struct {
	ID          string                 `json:"id" yaml:"id"`
	Product     string                 `json:"product" yaml:"product"`
	Combination string                 `json:"combination" yaml:"combination"`
	Confidence  int                    `json:"confidence" yaml:"confidence"`
	Source      string                 `json:"source" yaml:"source"`
	Version     string                 `json:"version" yaml:"version"`
	License     string                 `json:"license" yaml:"license"`
	Path        string                 `json:"path,omitempty" yaml:"path,omitempty"`
	Expression  *FingerprintExpression `json:"expression,omitempty" yaml:"expression,omitempty"`
	Matchers    []FingerprintMatcher   `json:"matchers,omitempty" yaml:"matchers,omitempty"`
}
type FingerprintEvidence struct {
	RuleID     string             `json:"rule_id"`
	Product    string             `json:"product"`
	Confidence int                `json:"confidence"`
	Source     string             `json:"source"`
	Version    string             `json:"version"`
	Matches    []FingerprintMatch `json:"matches"`
}
type FingerprintMatch struct {
	Field   string `json:"field"`
	Key     string `json:"key,omitempty"`
	Pattern string `json:"pattern"`
	Value   string `json:"value"`
	Negated bool   `json:"negated,omitempty"`
}
type FingerprintEngine struct{ Rules []FingerprintRule }

func loadFingerprintEngine() (*FingerprintEngine, error) {
	if path := os.Getenv("RECON_FINGERPRINT_RULES"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return parseFingerprintRules(raw)
	}
	manifestRaw, err := fingerprintFiles.ReadFile("third_party/httpgo/manifest.json")
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		SHA256     string `json:"generated_sha256"`
		ProjectUse bool   `json:"project_use_authorized"`
	}
	if err = json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, err
	}
	if !manifest.ProjectUse {
		return nil, errors.New("httpgo 项目使用授权记录缺失")
	}
	rules := []FingerprintRule{}
	for _, path := range []string{"rules/fingerprints.yaml", "rules/httpgo.yaml"} {
		raw, err := fingerprintFiles.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if path == "rules/httpgo.yaml" {
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != manifest.SHA256 {
				return nil, errors.New("httpgo 固定规则文件校验失败")
			}
		}
		engine, err := parseFingerprintRules(raw)
		if err != nil {
			return nil, err
		}
		if path == "rules/httpgo.yaml" {
			for _, rule := range engine.Rules {
				if rule.Source != manifest.Repository || rule.Version != manifest.Commit || rule.License != "LicenseRef-ScopeDesk-ProjectPermission" {
					return nil, errors.New("httpgo 规则来源与固定快照不一致")
				}
			}
		}
		rules = append(rules, engine.Rules...)
	}
	if len(rules) > 10000 {
		return nil, errors.New("合并指纹数量超过 10000")
	}
	ids := map[string]bool{}
	for _, rule := range rules {
		if ids[rule.ID] {
			return nil, errors.New("指纹规则 ID 跨文件重复")
		}
		ids[rule.ID] = true
	}
	return &FingerprintEngine{rules}, nil
}
func parseFingerprintRules(raw []byte) (*FingerprintEngine, error) {
	if len(raw) > 16<<20 {
		return nil, errors.New("指纹规则文件超过 16 MB")
	}
	var doc struct {
		Schema int               `yaml:"schema"`
		Rules  []FingerprintRule `yaml:"rules"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	if doc.Schema != 1 || len(doc.Rules) > 10000 {
		return nil, errors.New("指纹 schema 或规则数量无效")
	}
	ids := map[string]bool{}
	for i := range doc.Rules {
		rule := &doc.Rules[i]
		if ids[rule.ID] || rule.ID == "" || rule.Product == "" || rule.Source == "" || rule.Version == "" || rule.License == "" || (len(rule.Matchers) == 0 && rule.Expression == nil) || len(rule.Matchers) > 64 || !slices.Contains([]string{"all", "any"}, rule.Combination) || rule.Confidence < 1 || rule.Confidence > 100 {
			return nil, errors.New("指纹规则字段无效")
		}
		ids[rule.ID] = true
		if len(rule.ID) > 128 || len(rule.Product) > 200 || len(rule.Source) > 2048 || len(rule.Version) > 128 {
			return nil, errors.New("指纹元数据过长")
		}
		if rule.Expression != nil {
			if len(rule.Matchers) > 0 {
				return nil, errors.New("表达式与旧匹配器不能混用")
			}
			leaves := 0
			if err := compileFingerprintExpression(rule.Expression, 0, &leaves); err != nil {
				return nil, err
			}
			if !expressionRequiresPositive(rule.Expression) {
				return nil, errors.New("指纹存在仅凭否定条件识别的分支")
			}
		}
		if rule.Expression == nil {
			positives := 0
			for _, m := range rule.Matchers {
				if !m.Negate {
					positives++
				} else if rule.Combination == "any" {
					return nil, errors.New("any 规则不能仅靠否定分支识别")
				}
			}
			if positives == 0 {
				return nil, errors.New("指纹必须包含正向识别条件")
			}
		}
		for j := range rule.Matchers {
			if err := compileFingerprintMatcher(&rule.Matchers[j]); err != nil {
				return nil, fmt.Errorf("指纹规则 %s: %w", rule.ID, err)
			}
		}
	}
	return &FingerprintEngine{doc.Rules}, nil
}
func compileFingerprintMatcher(m *FingerprintMatcher) error {
	if !slices.Contains([]string{"title", "server", "header", "cookie", "body", "favicon_mmh3", "tls_subject", "meta", "script_src", "header_block"}, m.Field) || len(m.Pattern) > 2048 || len(m.Key) > 200 {
		return errors.New("不支持的匹配器或字段超过 2 KB")
	}
	if (m.Field == "header" || m.Field == "cookie" || m.Field == "meta") && m.Key == "" {
		return errors.New("Header/Cookie 匹配器缺少 key")
	}
	if m.Field == "header_block" && strings.ContainsAny(m.Pattern, "\r\n") {
		return errors.New("不支持跨 Header 行的匹配条件")
	}
	if m.Field == "favicon_mmh3" {
		if m.Key != "" && m.Key != "httpgo_legacy" {
			return errors.New("未知图标哈希约定")
		}
		if m.Kind != "exact" {
			return errors.New("图标哈希只接受 exact")
		}
		if _, err := strconv.ParseInt(m.Pattern, 10, 32); err != nil {
			return errors.New("图标 mmh3 无效")
		}
	}
	switch m.Kind {
	case "regex":
		pattern := m.Pattern
		if !m.CaseSensitive {
			pattern = "(?i)" + pattern
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return errors.New("不兼容的 RE2 正则")
		}
		m.compiled = compiled
	case "contains", "exact":
	default:
		return errors.New("不支持的匹配方式")
	}
	return nil
}
func (e *FingerprintEngine) Match(o Observation) ([]string, json.RawMessage) {
	return e.MatchContext(context.Background(), o)
}
func (e *FingerprintEngine) MatchContext(ctx context.Context, o Observation) ([]string, json.RawMessage) {
	names := []string{}
	evidence := []FingerprintEvidence{}
	if e == nil || o.EvidenceOnly {
		return names, json.RawMessage("[]")
	}
	inputs := newFingerprintInputs(o)
	for _, rule := range e.Rules {
		if ctx.Err() != nil {
			break
		}
		if rule.Path != "" && (o.httpURL == nil || o.httpURL.Path != rule.Path) {
			continue
		}
		matchedRule, matches := inputs.matchRule(rule)
		if !matchedRule {
			continue
		}
		fields := map[string]bool{}
		for _, m := range matches {
			if !m.Negated {
				fields[m.Field+":"+strings.ToLower(m.Key)] = true
			}
		}
		confidence := min(rule.Confidence, 80)
		if len(fields) < 2 {
			confidence = min(confidence, 35)
		}
		hit := FingerprintEvidence{rule.ID, rule.Product, confidence, rule.Source, rule.Version, matches}
		candidate := append(slices.Clone(evidence), hit)
		raw, _ := json.Marshal(candidate)
		if len(raw) > 48<<10 {
			break
		}
		evidence = candidate
		names = append(names, rule.Product)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	raw, _ := json.Marshal(evidence)
	return names, raw
}
func boundedFingerprintText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= limit {
		return s
	}
	return strings.ToValidUTF8(s[:limit], "")
}

// Read attributes already in the collected HTML. No script fetch or execution.
func passiveHTMLFeatures(body []byte) (map[string][]string, []string) {
	meta := map[string][]string{}
	scripts := []string{}
	tokenizer := xhtml.NewTokenizer(bytes.NewReader(body))
	for {
		kind := tokenizer.Next()
		if kind == xhtml.ErrorToken {
			break
		}
		if kind != xhtml.StartTagToken && kind != xhtml.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if token.Data != "meta" && token.Data != "script" {
			continue
		}
		attrs := map[string]string{}
		for _, attr := range token.Attr {
			attrs[strings.ToLower(attr.Key)] = attr.Val
		}
		if token.Data == "script" {
			if src := attrs["src"]; src != "" {
				scripts = append(scripts, src)
			}
			continue
		}
		key := attrs["name"]
		if key == "" {
			key = attrs["property"]
		}
		if key != "" {
			meta[strings.ToLower(key)] = append(meta[strings.ToLower(key)], attrs["content"])
		}
	}
	return meta, scripts
}
