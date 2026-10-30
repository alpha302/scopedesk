package main

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// Templates are embedded, reviewed data. They cannot add arbitrary HTTP origins,
// executable commands, authentication methods, response evaluators or redirects.
//go:embed passive_providers/*.yaml
var passiveProviderFiles embed.FS

type PassiveProvider struct {
	Name                 string            `yaml:"name"`
	Verified             bool              `yaml:"verified"`
	Reference            string            `yaml:"reference"`
	Endpoint             string            `yaml:"endpoint"`
	QueryTemplate        string            `yaml:"query_template"`
	Encoding             string            `yaml:"encoding"`
	PageParameter        string            `yaml:"page_parameter"`
	SizeParameter        string            `yaml:"size_parameter"`
	PageSize             int               `yaml:"page_size"`
	MaxPages             int               `yaml:"max_pages"`
	Fields               []string          `yaml:"fields"`
	Mapping              map[string]string `yaml:"mapping"`
	ProviderTimeField    string            `yaml:"provider_time_field"`
	ProviderTimeMeaning  string            `yaml:"provider_time_meaning"`
	ProviderTimeTimezone string            `yaml:"provider_time_timezone"`
	Pagination           string            `yaml:"pagination"`
	ChargeReporting      string            `yaml:"charge_reporting"`
	ErrorCodes           map[string]string `yaml:"error_codes"`
	PreferredChargeUnit  string            `yaml:"preferred_charge_unit"`
}

func loadPassiveProvider(name string) (PassiveProvider, error) {
	var p PassiveProvider
	if !paidPassive(name) {
		return p, passiveFailure("source_unsupported", "未知被动来源")
	}
	raw, err := passiveProviderFiles.ReadFile("passive_providers/" + name + ".yaml")
	if err != nil {
		return p, err
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if err = d.Decode(&p); err != nil {
		return p, passiveFailure("source_config", "来源模板无效")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return p, passiveFailure("source_config", "来源模板存在额外文档")
	}
	if p.Name != name || p.PageSize < 1 || p.PageSize > 100 || p.MaxPages < 1 || p.MaxPages > 100 {
		return p, passiveFailure("source_config", "来源模板边界无效")
	}
	if !p.Verified {
		return p, passiveFailure("documentation_required", "官方接口字段、积分优先参数与计费规则待核实；来源未启用")
	}
	if name == "hunter" {
		if p.Endpoint != "https://hunter.qianxin.com/openApi/search" || p.QueryTemplate != `domain="{{domain}}"` || p.Encoding != "base64url" || p.PageParameter != "page" || p.SizeParameter != "page_size" || p.ChargeReporting != "explicit_points_text" || p.ProviderTimeField != "updated_at" || p.ProviderTimeMeaning != "provider_reported_updated_at" || p.ProviderTimeTimezone != "unconfirmed" {
			return p, passiveFailure("source_config", "Hunter 模板超出实测适配器能力")
		}
		expected := map[string]string{"host": "domain", "ip": "ip", "port": "port", "title": "web_title", "server": "header_server", "service": "protocol", "protocol": "base_protocol", "status_code": "status_code", "fingerprints": "component", "banner": "banner"}
		for k, v := range p.Mapping {
			if expected[k] != v {
				return p, passiveFailure("source_config", "Hunter 映射未经审核")
			}
		}
		return p, nil
	}
	if name != "fofa" || p.Endpoint != "https://fofa.info/api/v1/search/all" || p.QueryTemplate != `domain="{{domain}}"` || p.Encoding != "base64" || p.PageParameter != "page" || p.SizeParameter != "size" || p.ChargeReporting != "unverified" {
		return p, passiveFailure("source_config", "来源模板超出已审核的内置适配器能力")
	}
	allowed := map[string]bool{"host": true, "ip": true, "port": true, "title": true, "server": true, "protocol": true, "lastupdatetime": true}
	seen := map[string]bool{}
	for _, f := range p.Fields {
		if !allowed[f] || seen[f] {
			return p, passiveFailure("source_config", "来源字段未审核或重复")
		}
		seen[f] = true
	}
	if !seen["host"] || !seen["ip"] || !seen["port"] {
		return p, passiveFailure("source_config", "来源缺少必要映射字段")
	}
	expected := map[string]string{"host": "host", "ip": "ip", "port": "port", "title": "title", "server": "server", "service": "protocol"}
	for field, path := range p.Mapping {
		if expected[field] != path || !seen[path] {
			return p, passiveFailure("source_config", "来源字段映射未审核")
		}
	}
	if p.Mapping["host"] != "host" || p.ProviderTimeField != "lastupdatetime" || p.ProviderTimeMeaning != "provider_updated_at" || p.ProviderTimeTimezone != "unconfirmed" || p.Pagination != "numbered_total_if_present" {
		return p, passiveFailure("source_config", "来源时间或分页语义未审核")
	}
	return p, nil
}
func passiveProviderVerified(source string) bool {
	_, err := loadPassiveProvider(source)
	return err == nil
}
func passiveProviderMetadata() []map[string]any {
	out := []map[string]any{}
	for _, name := range []string{"hunter", "fofa"} {
		p, err := loadPassiveProvider(name)
		note := "仅积分；每次查询前检查账户余额，付费余额非零或未知则停止；未知费用保留待核对"
		if err != nil {
			note = "官方接口资料待核实，尚未开放请求"
		}
		out = append(out, map[string]any{"name": name, "kind": "passive", "mode": "builtin_api", "available": err == nil, "note": note, "reference": p.Reference, "preferred_charge_unit": p.PreferredChargeUnit})
	}
	return out
}
func passiveHTTPStatus(p PassiveProvider, status int) (string, string) {
	if status == 200 {
		return "complete", ""
	}
	state := p.ErrorCodes[fmt.Sprintf("http:%d", status)]
	if state == "" {
		state = "unavailable"
	}
	return state, "source_" + state
}
func passiveQuery(p PassiveProvider, s ScopeV2) (string, error) {
	// Only normalized scope domains enter provider syntax, never user-supplied HQL.
	host, err := normalizeHost(s.Domain)
	if err != nil || strings.ContainsAny(host, `"'`) || s.Mode == "cidr" {
		return "", passiveFailure("source_unsupported", "当前来源仅支持已登记的域名范围")
	}
	return strings.ReplaceAll(p.QueryTemplate, "{{domain}}", host), nil
}
func officialPassiveEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && ((u.Host == "fofa.info" && u.Path == "/api/v1/search/all") || (u.Host == "hunter.qianxin.com" && u.Path == "/openApi/search")) && u.User == nil && u.Fragment == ""
}
