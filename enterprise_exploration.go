package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

// EnterpriseSource consumes approved third-party company data only. Implementations
// must use a separately allowlisted provider transport, never probe candidate hosts.
// No ENScan binary, public demo endpoint, Cookie or supplier API is bundled/enabled.
type EnterpriseSource interface {
	Explore(context.Context, EnterpriseQuery, *EnterpriseBudget) EnterpriseSourceResult
}
type EnterpriseQuery struct {
	ProjectID     int64    `json:"project_id"`
	Company       string   `json:"company"`
	Source        string   `json:"source"`
	MaxDepth      int      `json:"max_depth"`
	MaxCompanies  int      `json:"max_companies"`
	MaxCandidates int      `json:"max_candidates"`
	RequestLimit  int      `json:"request_limit"`
	ManualDomains []string `json:"manual_domains,omitempty"`
}
type EnterpriseCandidate struct {
	Domain   string               `json:"domain"`
	Company  string               `json:"company"`
	Depth    int                  `json:"depth"`
	Evidence []EnterpriseEvidence `json:"evidence"`
}
type EnterpriseEvidence struct {
	Dimension string `json:"dimension"`
	Value     string `json:"value"`
	State     string `json:"state"`
}
type EnterpriseSourceResult struct {
	Status     string                `json:"status"`
	ErrorCode  string                `json:"error_code"`
	Complete   bool                  `json:"complete"`
	Candidates []EnterpriseCandidate `json:"candidates"`
}
type EnterpriseBudget struct {
	mu        sync.Mutex
	query     EnterpriseQuery
	requests  int
	companies map[string]bool
}

var errEnterpriseBudget = errors.New("企业探索预算或深度上限已到")

func newEnterpriseBudget(q EnterpriseQuery) *EnterpriseBudget {
	return &EnterpriseBudget{query: q, companies: map[string]bool{q.Company: true}}
}
func (b *EnterpriseBudget) TakeRequest() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.requests >= b.query.RequestLimit {
		return errEnterpriseBudget
	}
	b.requests++
	return nil
}
func (b *EnterpriseBudget) VisitCompany(company string, depth int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	company = strings.TrimSpace(company)
	if company == "" || depth < 0 || depth > b.query.MaxDepth {
		return errEnterpriseBudget
	}
	if !b.companies[company] && len(b.companies) >= b.query.MaxCompanies {
		return errEnterpriseBudget
	}
	b.companies[company] = true
	return nil
}
func (b *EnterpriseBudget) Used() (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.requests, len(b.companies)
}
func validateEnterpriseQuery(q *EnterpriseQuery) error {
	q.Company = strings.TrimSpace(q.Company)
	if q.ProjectID <= 0 || q.Company == "" || utf8.RuneCountInString(q.Company) > 200 || !slices.Contains([]string{"manual", "enscan", "commercial"}, q.Source) {
		return errors.New("项目、企业名称或来源无效")
	}
	if q.MaxDepth < 0 || q.MaxDepth > 5 || q.MaxCompanies < 1 || q.MaxCompanies > 500 || q.MaxCandidates < 1 || q.MaxCandidates > 5000 || q.RequestLimit < 1 || q.RequestLimit > 1000 {
		return errors.New("深度 0–5、企业数 1–500、候选数 1–5000、请求数 1–1000")
	}
	if len(q.ManualDomains) > q.MaxCandidates {
		return errors.New("人工导入超过候选上限")
	}
	if q.Source != "manual" && len(q.ManualDomains) > 0 {
		return errors.New("第三方来源不能混入人工数据")
	}
	return nil
}
func normalizeEnterpriseDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.ContainsAny(raw, "/:*?#@") {
		return "", errors.New("候选必须是完整域名，不接受 URL、IP、通配符或端口")
	}
	host, err := normalizeHost(raw)
	if err != nil {
		return "", err
	}
	if _, err = netip.ParseAddr(host); err == nil {
		return "", errors.New("候选仅接受域名")
	}
	if err = (ScopeGuard{Scope: ScopeV2{Domain: host, Mode: "exact", Confirmed: true}}).Valid(); err != nil {
		return "", err
	}
	return host, nil
}
func manualEnterpriseResult(q EnterpriseQuery) EnterpriseSourceResult {
	result := EnterpriseSourceResult{Status: "complete", Complete: true, Candidates: []EnterpriseCandidate{}}
	for _, raw := range q.ManualDomains {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		result.Candidates = append(result.Candidates, EnterpriseCandidate{Domain: raw, Company: q.Company, Depth: 0, Evidence: []EnterpriseEvidence{{Dimension: "manual", Value: "人工提供的候选归属，尚未经独立验证", State: "claimed"}}})
	}
	return result
}
func normalizeEnterpriseResult(q EnterpriseQuery, result EnterpriseSourceResult, b *EnterpriseBudget) EnterpriseSourceResult {
	if !slices.Contains([]string{"complete", "partial", "auth_expired", "rate_limited", "unavailable", "budget_exhausted", "cancelled", "failed"}, result.Status) {
		result.Status = "failed"
		result.ErrorCode = "invalid_source_status"
	}
	if result.Status != "complete" {
		result.Complete = false
	}
	if result.Status == "complete" && !result.Complete {
		result.Status = "partial"
	}
	// Error codes are enumerated internal labels, never upstream response text.
	if !slices.Contains([]string{"", "not_configured", "credentials_expired", "provider_rate_limited", "provider_unavailable", "provider_error", "request_limit", "candidate_limit", "rejected_candidate_or_limit", "invalid_evidence", "invalid_source_status", "cancelled"}, result.ErrorCode) {
		result.ErrorCode = "provider_error"
	}
	// Error responses may contain uncommitted partial payloads. Accept candidates only
	// when the adapter explicitly reports a complete/partial/budget-limited result.
	if !slices.Contains([]string{"complete", "partial", "budget_exhausted"}, result.Status) {
		result.Candidates = nil
		return result
	}
	clean := []EnterpriseCandidate{}
	seen := map[string]bool{}
	for _, candidate := range result.Candidates {
		if len(clean) >= q.MaxCandidates {
			result.Status = "partial"
			result.Complete = false
			result.ErrorCode = "candidate_limit"
			break
		}
		host, err := normalizeEnterpriseDomain(candidate.Domain)
		if candidate.Company == "" {
			candidate.Company = q.Company
		}
		if err != nil || utf8.RuneCountInString(candidate.Company) > 200 || b.VisitCompany(candidate.Company, candidate.Depth) != nil {
			result.Status = "partial"
			result.Complete = false
			result.ErrorCode = "rejected_candidate_or_limit"
			continue
		}
		candidate.Domain = host
		key := host + "\x00" + candidate.Company
		if seen[key] {
			continue
		}
		seen[key] = true
		evidence := []EnterpriseEvidence{}
		for _, item := range candidate.Evidence {
			if !slices.Contains([]string{"manual", "icp", "ownership", "certificate", "whois", "ns", "page"}, item.Dimension) || !slices.Contains([]string{"claimed", "observed", "unknown"}, item.State) {
				result.Status = "partial"
				result.Complete = false
				result.ErrorCode = "invalid_evidence"
				continue
			}
			item.Value = boundedFingerprintText(item.Value, 2048)
			evidence = append(evidence, item)
			if len(evidence) >= 16 {
				break
			}
		}
		candidate.Evidence = evidence
		clean = append(clean, candidate)
	}
	result.Candidates = clean

	return result
}
func enterpriseEvidenceJSON(candidate EnterpriseCandidate, run int64, source string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"run_id": run, "source": source, "company": candidate.Company, "depth": candidate.Depth, "evidence": candidate.Evidence})
	return raw
}
