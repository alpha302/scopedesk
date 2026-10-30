package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

type PassiveAPICollector struct {
	Source string
	Client *http.Client
	Store  *Store
	Run    Run
	Limit  RateLimiter
	Budget *Budget
	Result PassiveResult
}

func (c *PassiveAPICollector) Name() string { return c.Source }
func (c *PassiveAPICollector) Kind() string { return "passive" }
func (c *PassiveAPICollector) Collect(ctx context.Context, s ScopeV2) (<-chan Candidate, error) {
	c.Result = c.CollectPassive(ctx, s)
	return passiveCandidates(c.Result), c.Result.Err
}
func (c *PassiveAPICollector) CollectPassive(ctx context.Context, s ScopeV2) (result PassiveResult) {
	fail := func(err error) PassiveResult {
		result.Err = err
		result.Complete = false
		result.AbsenceUsable = false
		return result
	}
	p, err := loadPassiveProvider(c.Source)
	if err != nil {
		return fail(err)
	}
	query, err := passiveQuery(p, s)
	if err != nil {
		return fail(err)
	}
	client, cleanup := passiveClient(c.Client)
	defer cleanup()
	var firstAccountID int64
	var expected *int64
	returned := int64(0)
	seenPages := map[string]bool{}
	for page := 1; page <= p.MaxPages; page++ {
		g, err := c.Store.guard(ctx, s.ID)
		if err != nil {
			return fail(err)
		}
		if err = passiveQueryGuard(g, s); err != nil {
			return fail(err)
		}
		if c.Limit != nil {
			if err = c.Limit.Wait(ctx, s.ID, s.RPS); err != nil {
				return fail(err)
			}
		}
		if err = c.Budget.Take(); err != nil {
			return fail(passiveFailure("budget_exhausted", "任务请求预算耗尽"))
		}
		r, err := c.Store.reservePassive(ctx, c.Run, c.Source, query, page, p.PageSize)
		if err != nil {
			return fail(err)
		}
		if firstAccountID == 0 {
			firstAccountID = r.AccountID
		} else if r.AccountID != firstAccountID {
			_ = c.Store.cancelUnsentPassive(r, "execution_policy_changed")
			return fail(passiveFailure("execution_policy_changed", "查询期间账户选择已变化，停止而不换号续查"))
		}
		if err = c.Budget.Take(); err != nil {
			_ = c.Store.cancelUnsentPassive(r, "budget_exhausted")
			return fail(passiveFailure("budget_exhausted", "账户检查请求预算不足"))
		}
		credits, err := c.Store.checkPassiveCredits(ctx, r, c.Run.ID, s.ID, client)
		if err == nil {
			err = creditsOnlyAllowed(credits, r.Units)
		}
		if err != nil {
			failure := classifyExecutionError(err, "source_unavailable")
			_ = c.Store.cancelUnsentPassive(r, failure.Code)
			return fail(failure)
		}
		pageProvider := p
		pageProvider.PageSize = r.PageSize
		if c.Source == "fofa" && !r.ProviderTimeEnabled {
			pageProvider.Fields = []string{}
			for _, field := range p.Fields {
				if field != p.ProviderTimeField {
					pageProvider.Fields = append(pageProvider.Fields, field)
				}
			}
		}
		req, err := passiveSearchRequest(ctx, pageProvider, r, query, page)
		if err != nil {
			_ = c.Store.cancelUnsentPassive(r, "source_config")
			return fail(err)
		}
		g, err = c.Store.guard(ctx, s.ID)
		if err == nil {
			err = passiveQueryGuard(g, s)
		}
		if err != nil {
			_ = c.Store.cancelUnsentPassive(r, "scope_denied")
			return fail(passiveFailure("scope_denied", "请求前授权检查失败"))
		}
		if err = c.Store.markPassiveSent(ctx, r); err != nil {
			return fail(passiveFailure("reconciliation_required", "发送状态保存失败；预约保留且不会自动重查"))
		}
		finish := func(count *int, actual, remaining *int64, status, code string, pc, qc bool) error {
			return c.Store.recordPassiveResponse(r, count, actual, remaining, status, code, pc, qc)
		}
		g, err = c.Store.guard(ctx, s.ID)
		if err == nil {
			err = passiveQueryGuard(g, s)
		}
		if err != nil {
			_ = finish(nil, nil, nil, "failed", "scope_denied", false, false)
			return fail(passiveFailure("scope_denied", "发送边界授权已变化，预约保留待核对"))
		}
		response, err := client.Do(req)
		if err != nil {
			_ = finish(nil, nil, nil, "unavailable", "source_connection", false, false)
			return fail(passiveFailure("source_connection", "来源连接失败或超时，费用待核对"))
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 8_000_001))
		response.Body.Close()
		status, code := passiveHTTPStatus(p, response.StatusCode)
		if status != "complete" {
			_ = finish(nil, nil, nil, status, code, false, false)
			return fail(passiveFailure(code, "来源认证失效、限流或暂不可用；不自动换号"))
		}
		if readErr != nil || len(raw) > 8_000_000 {
			_ = finish(nil, nil, nil, "failed", "invalid_output", false, false)
			return fail(passiveFailure("invalid_output", "来源响应读取失败或超限；费用待核对"))
		}
		data := passivePageData{}
		if c.Source == "hunter" {
			data, err = parseHunterPage(raw, pageProvider, g)
		} else {
			var records fofaPageRecords
			records, data.Total, _, err = parseFOFAPage(raw, pageProvider, g, query, page)
			data.Records = records.records
			data.Count = len(records.rows)
			data.Malformed = records.malformed
		}
		if err != nil {
			failure := classifyExecutionError(err, "invalid_output")
			status = "unavailable"
			if failure.Code == "auth_expired" {
				status = "auth_expired"
			}
			_ = finish(nil, nil, nil, status, failure.Code, false, false)
			return fail(failure)
		}
		for i := range data.Records {
			for j := range data.Records[i].Observation.PluginEvidence {
				id := r.AccountID
				data.Records[i].Observation.PluginEvidence[j].AccountID = &id
			}
		}
		result.Pages++
		result.Records = append(result.Records, data.Records...)
		returned += int64(data.Count)
		consistent := data.Total != nil && *data.Total >= 0
		if page == 1 {
			expected = data.Total
		} else {
			consistent = consistent && expected != nil && *expected == *data.Total
		}
		duplicate := data.Fingerprint != "" && seenPages[data.Fingerprint] && data.Count > 0
		if data.Fingerprint != "" {
			seenPages[data.Fingerprint] = true
		}
		queryComplete := c.Source == "hunter" && consistent && expected != nil && returned == *expected && !data.Malformed && !duplicate
		errCode := ""
		if data.Actual == nil {
			errCode = "reconciliation_required"
		}
		if err = finish(&data.Count, data.Actual, data.Remaining, "complete", errCode, !data.Malformed, queryComplete); err != nil {
			return fail(passiveFailure("reconciliation_required", "证据已保留，结算保存状态需核对"))
		}
		if data.Actual == nil {
			return fail(passiveFailure("reconciliation_required", "已取得证据；上游未提供可核实的本次积分消耗，停止并保留预约"))
		}
		if queryComplete {
			result.Complete = true
			result.AbsenceUsable = false
			return result
		}
		if !consistent || data.Count == 0 || data.Malformed || duplicate || expected != nil && (returned > *expected || returned < *expected && data.Count != r.PageSize) {
			return fail(passiveFailure("incomplete_source", "来源分页元数据不足、变化或重复；已保留合法结果"))
		}
	}
	return fail(passiveFailure("incomplete_source", "来源分页达到任务上限；已保留合法结果"))
}

type fofaPageRecords struct {
	rows      [][]json.RawMessage
	records   []PluginRecord
	malformed bool
}

func parseFOFAPage(raw []byte, p PassiveProvider, g ScopeGuard, query string, page int) (out fofaPageRecords, total *int64, metaOK bool, err error) {
	var body struct {
		Error   *bool               `json:"error"`
		Results [][]json.RawMessage `json:"results"`
		Size    *int64              `json:"size"`
		Page    *int                `json:"page"`
		Query   *string             `json:"query"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Error == nil || *body.Error || body.Results == nil {
		return out, nil, false, passiveFailure("invalid_output", "FOFA 返回失败或响应结构无效，错误原文未记录")
	}
	if len(body.Results) > p.PageSize {
		return out, nil, false, passiveFailure("invalid_output", "FOFA 返回数量超过预约页大小")
	}
	out.rows = body.Results
	total = body.Size
	metaOK = body.Page != nil && *body.Page == page && body.Query != nil && *body.Query == query
	now := time.Now().UTC()
	for _, row := range body.Results {
		if len(row) != len(p.Fields) {
			out.malformed = true
			continue
		}
		values := map[string]any{}
		bad := false
		for i, f := range p.Fields {
			var v any
			d := json.NewDecoder(strings.NewReader(string(row[i])))
			d.UseNumber()
			if d.Decode(&v) != nil {
				bad = true
				break
			}
			if v == nil {
				continue
			}
			switch v.(type) {
			case string, json.Number:
				values[f] = v
			default:
				bad = true
			}
			if text, ok := v.(string); ok && len(text) > 8192 {
				bad = true
			}
		}
		if bad {
			out.malformed = true
			continue
		}
		text := func(key string) string {
			if v, ok := values[key].(string); ok {
				return v
			}
			return ""
		}
		host, hostErr := normalizeHost(text("host"))
		if hostErr != nil {
			out.malformed = true
			continue
		}
		host, hostErr = g.AllowHost(host)
		if hostErr != nil {
			continue
		}
		record := mapPassiveEvidence(values, p, g, host, now)
		out.records = append(out.records, record)
	}
	return out, total, metaOK, nil
}
