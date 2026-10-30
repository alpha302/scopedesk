package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Collector interface {
	Name() string
	Kind() string
	Collect(context.Context, ScopeV2) (<-chan Candidate, error)
}
type CertificateCollector struct {
	Source string
	Client *http.Client
	Limit  RateLimiter
	Budget *Budget
	Guard  func(context.Context) (ScopeGuard, error)
	Result PassiveResult
}

func (c *CertificateCollector) Name() string { return c.Source }
func (c *CertificateCollector) Kind() string { return "passive" }
func (c *CertificateCollector) Collect(ctx context.Context, s ScopeV2) (<-chan Candidate, error) {
	c.Result = c.CollectPassive(ctx, s)
	return passiveCandidates(c.Result), c.Result.Err
}
func (c *CertificateCollector) CollectPassive(ctx context.Context, s ScopeV2) (result PassiveResult) {
	fail := func(err error) PassiveResult {
		result.Err = err
		result.Complete = false
		result.AbsenceUsable = false
		return result
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 35 * time.Second}
	}
	// Never follow redirects from a third-party source to an arbitrary destination.
	controlled := *client
	controlled.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	after := ""
	seen := map[string]bool{}
	for page := 0; page < 10; page++ {
		g := ScopeGuard{Scope: s}
		if c.Guard != nil {
			var err error
			g, err = c.Guard(ctx)
			if err != nil {
				return fail(err)
			}
		}
		if err := passiveQueryGuard(g, s); err != nil {
			return fail(err)
		}
		if s.Mode == "cidr" {
			return fail(passiveFailure("source_unsupported", "证书源不接受 IP 网段范围"))
		}
		if c.Source != "crtsh" && c.Source != "certspotter" {
			return fail(passiveFailure("source_unsupported", "未知证书来源"))
		}
		if err := c.Budget.Take(); err != nil {
			return fail(passiveFailure("budget_exhausted", "任务请求预算耗尽"))
		}
		if c.Limit != nil {
			if err := c.Limit.Wait(ctx, s.ID, s.RPS); err != nil {
				return fail(err)
			}
		}
		endpoint := ""
		if c.Source == "crtsh" {
			query := s.Domain
			if s.Mode != "exact" {
				query = "%." + query
			}
			endpoint = "https://crt.sh/?" + url.Values{"q": {query}, "output": {"json"}}.Encode()
		} else {
			q := url.Values{"domain": {s.Domain}, "expand": {"dns_names"}, "include_subdomains": {strconv.FormatBool(s.Mode != "exact")}}
			if after != "" {
				q.Set("after", after)
			}
			endpoint = "https://api.certspotter.com/v1/issuances?" + q.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return fail(passiveFailure("source_connection", "来源请求创建失败"))
		}
		req.Header.Set("User-Agent", "ScopeDesk/0.2")
		if c.Guard != nil {
			g, err = c.Guard(ctx)
			if err != nil {
				return fail(err)
			}
		}
		if err = passiveQueryGuard(g, s); err != nil {
			return fail(err)
		}
		res, err := controlled.Do(req)
		if err != nil {
			return fail(passiveFailure("source_connection", "证书来源连接失败或超时；已取得结果保留"))
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 8_000_001))
		res.Body.Close()
		if err != nil {
			return fail(passiveFailure("source_connection", "证书来源响应读取失败"))
		}
		if res.StatusCode != 200 {
			return fail(passiveFailure("source_http", fmt.Sprintf("证书来源 HTTP %d", res.StatusCode)))
		}
		if len(raw) > 8_000_000 {
			return fail(passiveFailure("output_limit", "证书响应超出 8 MB 上限"))
		}
		result.Pages++
		add := func(raw string) {
			// ScopeGuard is repeated by the consumer and at commit. No target lookup here.
			host, err := g.AllowHost(raw)
			if err != nil || seen[host] {
				return
			}
			seen[host] = true
			if len(result.Records) < 100000 {
				result.Records = append(result.Records, PluginRecord{Candidate: Candidate{host, c.Source}})
			}
		}
		if c.Source == "crtsh" {
			var rows []struct {
				Name string `json:"name_value"`
			}
			if err = json.Unmarshal(raw, &rows); err != nil || rows == nil {
				return fail(passiveFailure("invalid_output", "crt.sh 响应格式错误"))
			}
			for _, row := range rows {
				for _, h := range strings.Split(row.Name, "\n") {
					add(h)
				}
			}
			// crt.sh has no verified completeness indicator; even a valid empty array is not proof.
			return fail(passiveFailure("incomplete_source", "crt.sh 未提供可核实的完整性标记；仅保留取得的候选"))
		}
		var rows []struct {
			ID    string   `json:"id"`
			Names []string `json:"dns_names"`
		}
		if err = json.Unmarshal(raw, &rows); err != nil || rows == nil {
			return fail(passiveFailure("invalid_output", "CertSpotter 响应格式错误"))
		}
		// Official CT Search API v1 defines an empty array as the terminal page.
		// https://sslmate.com/help/reference/ct_search_api_v1#issuance-pagination
		if len(rows) == 0 {
			result.Complete = true
			result.AbsenceUsable = true
			return result
		}
		for _, row := range rows {
			for _, h := range row.Names {
				add(h)
			}
		}
		next := rows[len(rows)-1].ID
		if next == "" || next == after {
			return fail(passiveFailure("incomplete_source", "证书分页游标缺失或未推进"))
		}
		after = next
		if len(seen) > 100000 {
			return fail(passiveFailure("output_limit", "证书候选超出上限；已取得结果保留"))
		}
	}
	return fail(passiveFailure("incomplete_source", "证书分页达到上限；已取得结果保留"))
}

// SubfinderCollector keeps legacy callers on the manifest implementation.
type SubfinderCollector struct {
	Bin    string
	Budget *Budget
	Guard  func(context.Context) (ScopeGuard, error)
	Result PassiveResult
}

func (c *SubfinderCollector) Name() string { return "subfinder" }
func (c *SubfinderCollector) Kind() string { return "passive" }
func (c *SubfinderCollector) Collect(ctx context.Context, s ScopeV2) (<-chan Candidate, error) {
	raw, _ := defaultPluginFiles.ReadFile("plugins/subfinder.yaml")
	m, err := parseManifest(raw)
	if err != nil {
		return nil, err
	}
	m.Exec.Bin = c.Bin
	p := ExternalPlugin{Manifest: m, Budget: c.Budget, QueryRoot: true, Guard: func(context.Context) (ScopeGuard, error) { return ScopeGuard{Scope: s}, nil }}
	result := p.Run(ctx, s.Domain)
	return pluginCandidates(result), pluginResultError(result)
}
func pluginCandidates(result PluginResult) <-chan Candidate {
	// Validated hosts remain useful after a failed attempt. The pipeline must
	// recheck them against the current scope; observations are filtered separately.
	stream := make(chan Candidate, len(result.Records))
	for _, record := range result.Records {
		stream <- record.Candidate
	}
	close(stream)
	return stream
}
func pluginResultError(r PluginResult) error {
	if r.Error != "" {
		return executionFailure(r.ErrorCode, r.Error, r.Retryable)
	}
	return nil
}

type ManifestCollector struct {
	Plugin  ExternalPlugin
	Target  string
	Results []PluginResult
}

func (c *ManifestCollector) Name() string { return c.Plugin.Manifest.Name }
func (c *ManifestCollector) Kind() string { return c.Plugin.Manifest.Kind }
func (c *ManifestCollector) Collect(ctx context.Context, s ScopeV2) (<-chan Candidate, error) {
	target := c.Target
	if target == "" {
		target = s.Domain
	}
	result := c.Plugin.Run(ctx, target)
	c.Results = append(c.Results, result)
	return pluginCandidates(result), pluginResultError(result)
}
func pluginHealth() []map[string]any {
	out := []map[string]any{{"name": "crtsh", "kind": "collector", "mode": "builtin", "available": true, "note": "免费证书透明度数据；可能超时或限流"}, {"name": "certspotter", "kind": "collector", "mode": "builtin", "available": true, "note": "证书查询，受服务商分页和额度规则限制"}, {"name": "builtin-dns", "kind": "resolver", "mode": "builtin", "available": true}, {"name": "builtin-http", "kind": "web_prober", "mode": "builtin", "available": true, "note": "范围主动开关开启后才运行；固定验证过的目标 IP"}}
	bin := "/opt/scopedesk-tools/subfinder"
	_, e := os.Stat(bin)
	out = append(out, map[string]any{"name": "subfinder", "kind": "collector", "mode": "external", "path": bin, "available": e == nil, "note": "子进程参数数组、超时、资源和输出上限；供应商内部请求计数不纳入平台精确预算"})
	return out
}
