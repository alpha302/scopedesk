package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Observation struct {
	EvidenceOnly         bool                 `json:"evidence_only,omitempty"`
	PreserveReachability bool                 `json:"-"`
	PluginEvidence       []PluginEvidence     `json:"plugin_evidence"`
	Services             []ServiceObservation `json:"services,omitempty"`
	SecurityMatches      []SecurityMatch      `json:"security_matches"`
	Host                 string               `json:"host"`
	IPs                  []string             `json:"ips"`
	CNames               []string             `json:"cnames"`
	Sources              []string             `json:"sources"`
	Port                 int                  `json:"port"`
	StatusCode           int                  `json:"status_code"`
	Title                string               `json:"title"`
	Server               string               `json:"server"`
	Length               int64                `json:"response_length"`
	Redirects            []string             `json:"redirects"`
	Fingerprints         []string             `json:"fingerprints"`
	TLSSubject           string               `json:"tls_subject"`
	TLSNotAfter          *time.Time           `json:"tls_not_after"`
	Favicon              string               `json:"favicon_hash"`
	FaviconMMH3          *int32               `json:"favicon_mmh3"`
	FaviconSHA256        *string              `json:"favicon_sha256"`
	FaviconMeasured      bool                 `json:"-"`
	FingerprintEvidence  json.RawMessage      `json:"fingerprint_evidence"`
	FingerprintMeasured  bool                 `json:"-"`
	httpBodyComplete     bool
	httpTitleComplete    bool
	httpgoFaviconMMH3    *int32
	httpHeaders          http.Header
	httpBody             []byte
	httpURL              *url.URL
	NetworkEvidence      []NetworkEvidence `json:"network_evidence"`
	NetworkClassifiedAt  *time.Time        `json:"network_classified_at"`
	NetworkMeasured      bool              `json:"-"`
	IsCDN                bool              `json:"is_cdn"`
	Security             bool              `json:"is_security_device"`
	SecurityRule         string            `json:"security_rule"`
	Alive                *bool             `json:"is_alive"`
	DNSChecked           bool              `json:"-"`
	Error                string            `json:"error,omitempty"`
}
type Pipeline struct {
	Fingerprints  *FingerprintEngine
	NetworkRules  *NetworkRules
	Rules         *SecurityRuleCache
	Guard         func(context.Context, int64) (ScopeGuard, error)
	Limit         RateLimiter
	Resolver      *net.Resolver
	httpTransport http.RoundTripper
}

func (p *Pipeline) dns(ctx context.Context, scope int64, host string, b *Budget) ([]string, []string, error) {
	g, e := p.Guard(ctx, scope)
	if e != nil {
		return nil, nil, e
	}
	if _, e = g.AllowHost(host); e != nil {
		return nil, nil, e
	}
	if e = b.Take(); e != nil {
		return nil, nil, e
	}
	if e = p.Limit.Wait(ctx, scope, g.Scope.RPS); e != nil {
		return nil, nil, e
	}
	g, e = p.fresh(ctx, scope, host, false)
	if e != nil {
		return nil, nil, e
	}
	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cnames := []string{}
	canonical, e := resolver.LookupCNAME(ctx, host)
	if e == nil {
		canonical = strings.TrimSuffix(strings.ToLower(canonical), ".")
		if canonical != host {
			cnames = append(cnames, canonical)
			if _, e = g.AllowHost(canonical); e != nil {
				return nil, cnames, errors.New("CNAME 指向范围外域名，未继续解析")
			}
		}
	}
	if e = b.Take(); e != nil {
		return nil, cnames, e
	}
	if e = p.Limit.Wait(ctx, scope, g.Scope.RPS); e != nil {
		return nil, cnames, e
	}
	g, e = p.fresh(ctx, scope, host, false)
	if e != nil {
		return nil, cnames, e
	}
	ips, e := resolver.LookupIPAddr(ctx, host)
	if e != nil {
		return nil, cnames, e
	}
	out := []string{}
	for _, item := range ips {
		ip, err := netip.ParseAddr(item.IP.String())
		if err == nil && g.AllowIP(ip.String()) == nil {
			out = append(out, ip.Unmap().String())
		}
	}
	slices.Sort(out)
	return slices.Compact(out), cnames, nil
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var spacePattern = regexp.MustCompile(`\s+`)

func (p *Pipeline) redirectAllowed(ctx context.Context, id int64, target *url.URL, b *Budget) error {
	if target.Scheme != "http" && target.Scheme != "https" {
		return errors.New("不允许的重定向协议")
	}
	if target.User != nil {
		return errors.New("拒绝带凭据 URL")
	}
	if port := target.Port(); port != "" && port != "80" && port != "443" {
		return errors.New("重定向端口不在标准 HTTP 端口内")
	}
	g, err := p.fresh(ctx, id, target.Hostname(), true)
	if err != nil {
		return err
	}
	if err = b.Take(); err != nil {
		return err
	}
	if err = p.Limit.Wait(ctx, id, g.Scope.RPS); err != nil {
		return err
	}
	_, err = p.fresh(ctx, id, target.Hostname(), true)
	return err
}
func (p *Pipeline) fresh(ctx context.Context, id int64, host string, active bool) (ScopeGuard, error) {
	g, e := p.Guard(ctx, id)
	if e != nil {
		return g, e
	}
	if _, e = g.AllowHost(host); e != nil {
		return g, e
	}
	if active {
		e = g.ActiveAllowed()
	}
	return g, e
}
func (p *Pipeline) Probe(ctx context.Context, scope ScopeV2, host string, sources []string, b *Budget) (Observation, error) {
	o := Observation{Host: host, Sources: sources, IPs: []string{}, CNames: []string{}, Fingerprints: []string{}, Redirects: []string{}}
	if _, e := p.fresh(ctx, scope.ID, host, false); e != nil {
		return o, e
	}
	ips, cnames, dnsErr := p.dns(ctx, scope.ID, host, b)
	o.IPs = ips
	o.CNames = cnames
	o.DNSChecked = dnsErr == nil
	network := p.NetworkRules
	if network == nil {
		network, _ = defaultNetworkRules()
	}
	applyNetworkEvidence(&o, network)
	o.NetworkMeasured = o.DNSChecked || len(o.CNames) > 0 || len(o.IPs) > 0
	if dnsErr != nil {
		o.Error = "DNS 未完成或别名超出范围"
	}
	if !scope.Active {
		return o, nil
	}
	if len(ips) == 0 {
		return o, nil
	}
	if _, e := p.fresh(ctx, scope.ID, host, true); e != nil {
		return o, e
	}
	for _, scheme := range []string{"https", "http"} {
		result, e := p.http(ctx, scope, "/", scheme, host, b)
		if e != nil {
			if ctx.Err() != nil {
				return o, ctx.Err()
			}
			continue
		}
		o.Port = result.Port
		o.StatusCode = result.StatusCode
		o.Title = result.Title
		o.Server = result.Server
		o.Length = result.Length
		o.Redirects = result.Redirects
		o.TLSSubject = result.TLSSubject
		o.TLSNotAfter = result.TLSNotAfter
		o.Alive = result.Alive
		if e := p.classifySecurity(ctx, scope, &o); e != nil {
			return o, e
		}
		o.FaviconMMH3, o.FaviconSHA256, o.httpgoFaviconMMH3, o.FaviconMeasured = p.collectFaviconDetailed(ctx, scope, result, b)
		o.httpBody, o.httpURL, o.httpHeaders = result.httpBody, result.httpURL, result.httpHeaders
		o.httpBodyComplete, o.httpTitleComplete = result.httpBodyComplete, result.httpTitleComplete
		o.Fingerprints, o.FingerprintEvidence = p.Fingerprints.MatchContext(ctx, o)
		if ctx.Err() != nil {
			return o, ctx.Err()
		}
		o.FingerprintMeasured = p.Fingerprints != nil
		if o.FaviconSHA256 != nil {
			o.Favicon = *o.FaviconSHA256
		}

		return o, nil
	}
	// Explicit unsuccessful HTTP attempts are distinct from passive absence.
	alive := false
	o.Alive = &alive
	return o, nil
}
func (p *Pipeline) http(ctx context.Context, scope ScopeV2, path, scheme, host string, b *Budget) (Observation, error) {
	return p.httpURL(ctx, scope, &url.URL{Scheme: scheme, Host: host, Path: path}, b, nil)
}

func (p *Pipeline) httpURL(ctx context.Context, scope ScopeV2, target *url.URL, b *Budget, icon *faviconFetchPolicy) (Observation, error) {
	o := Observation{Redirects: []string{}}
	if target == nil || target.User != nil || (target.Scheme != "http" && target.Scheme != "https") || (target.Port() != "" && target.Port() != "80" && target.Port() != "443") {
		return o, errors.New("HTTP URL 无效或端口不受支持")
	}
	if icon != nil {
		if err := icon.allow(target, icon.origin); err != nil {
			return o, err
		}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		h, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		g, e := p.fresh(ctx, scope.ID, h, true)
		if e != nil {
			return nil, e
		}
		if port != "80" && port != "443" {
			return nil, errors.New("第一阶段仅允许 HTTP 标准端口")
		}
		ips, _, e := p.dns(ctx, scope.ID, h, b)
		if e != nil {
			return nil, e
		}
		if len(ips) == 0 {
			return nil, errors.New("无允许连接的公共 IP")
		}
		for _, ip := range ips {
			if e = g.AllowIP(ip); e != nil {
				continue
			}
			dialer := net.Dialer{Timeout: 5 * time.Second}
			conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if e == nil {
				return conn, nil
			}
		}
		return nil, errors.New("连接验证后的公共 IP 失败")
	}
	defer transport.CloseIdleConnections()
	var rt http.RoundTripper = transport
	if p.httpTransport != nil {
		rt = p.httpTransport
	}
	client := &http.Client{Transport: rt, Timeout: 12 * time.Second}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("重定向超过 5 次")
		}
		if icon != nil {
			if err := icon.allow(req.URL, via[len(via)-1].URL); err != nil {
				return err
			}
		}
		if err := p.redirectAllowed(ctx, scope.ID, req.URL, b); err != nil {
			return err
		}
		o.Redirects = append(o.Redirects, req.URL.String())
		return nil
	}
	g, e := p.fresh(ctx, scope.ID, target.Hostname(), true)
	if e != nil {
		return o, e
	}
	if e = b.Take(); e != nil {
		return o, e
	}
	if e = p.Limit.Wait(ctx, scope.ID, g.Scope.RPS); e != nil {
		return o, e
	}
	if _, e = p.fresh(ctx, scope.ID, target.Hostname(), true); e != nil {
		return o, e
	}
	req, e := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
	if e != nil {
		return o, e
	}
	req.Header.Set("User-Agent", "ScopeDesk/0.2 (authorized asset inventory)")
	res, e := client.Do(req)
	if e != nil {
		return o, errors.New("HTTP 探测失败、证书无效或跳转被范围校验拒绝")
	}
	defer res.Body.Close()
	maxBody := int64(1_048_576)
	if icon != nil {
		maxBody = maxFaviconBytes
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if e != nil {
		return o, e
	}
	o.StatusCode = res.StatusCode
	o.httpBody = raw
	o.httpBodyComplete = int64(len(raw)) <= maxBody
	o.httpTitleComplete = o.httpBodyComplete
	o.httpURL = target
	if res.Request != nil {
		o.httpURL = res.Request.URL
	}
	o.httpHeaders = res.Header.Clone()
	o.Server = res.Header.Get("Server")
	o.Length = int64(len(raw))
	alive := true
	o.Alive = &alive
	o.Port = 80
	if o.httpURL.Scheme == "https" {
		o.Port = 443
	}
	if match := titlePattern.FindSubmatch(raw); len(match) > 1 {
		o.Title = spacePattern.ReplaceAllString(html.UnescapeString(string(match[1])), " ")
		if len(o.Title) > 1000 {
			o.httpTitleComplete = false
			o.Title = o.Title[:1000]
		}
	}
	if res.TLS != nil && len(res.TLS.PeerCertificates) > 0 {
		cert := res.TLS.PeerCertificates[0]
		o.TLSSubject = cert.Subject.String()
		t := cert.NotAfter
		o.TLSNotAfter = &t
	}
	return o, nil
}
func wildcardSignature(ips []string) string {
	copyIPs := append([]string{}, ips...)
	slices.Sort(copyIPs)
	return strings.Join(copyIPs, ",")
}
func (p *Pipeline) Wildcard(ctx context.Context, s ScopeV2, b *Budget) string {
	if s.Mode == "exact" || s.Mode == "cidr" {
		return ""
	}
	signatures := []string{}
	for range 2 {
		h := random()[:16] + "." + s.Domain
		ips, _, e := p.dns(ctx, s.ID, h, b)
		if e != nil || len(ips) == 0 {
			return ""
		}
		signatures = append(signatures, wildcardSignature(ips))
	}
	if signatures[0] == signatures[1] {
		return signatures[0]
	}
	return ""
}
func observationKey(o Observation) string {
	raw, _ := json.Marshal([]any{o.IPs, o.CNames, o.Port, o.StatusCode, o.Title, o.Server, o.Fingerprints, o.FingerprintEvidence, o.TLSSubject, o.TLSNotAfter, o.IsCDN, o.NetworkEvidence, o.Security, o.SecurityRule, o.SecurityMatches, o.Alive, pluginEvidenceContent(o.PluginEvidence), o.FaviconMMH3, o.FaviconSHA256})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func categoryScore(host string, active bool) (string, int) {
	score := 10
	category := "未分类"
	for _, pair := range [][2]string{{"api", "API"}, {"sso", "认证 SSO"}, {"admin", "支撑平台"}, {"dev", "开发测试"}, {"test", "开发测试"}, {"uat", "开发测试"}} {
		if strings.Contains(strings.ToLower(host), pair[0]) {
			category = pair[1]
			score += 20
			break
		}
	}
	if active {
		score += 10
	}
	return category, score
}
func intParam(raw string, fallback, minValue, maxValue int) int {
	v, e := strconv.Atoi(raw)
	if e != nil {
		return fallback
	}
	return max(minValue, min(maxValue, v))
}

var _ = fmt.Sprintf
