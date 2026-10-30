package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var hunterConsumedPattern = regexp.MustCompile(`^消耗积分[：:]\s*([0-9]+)$`)
var hunterRemainingPattern = regexp.MustCompile(`^今日剩余积分[：:]\s*([0-9]+)$`)

func hunterQuota(raw string, pattern *regexp.Regexp) *int64 {
	matches := pattern.FindStringSubmatch(strings.TrimSpace(raw))
	if len(matches) != 2 {
		return nil
	}
	n, e := strconv.ParseInt(matches[1], 10, 64)
	if e != nil {
		return nil
	}
	return &n
}

type passivePageData struct {
	Fingerprint string
	Records     []PluginRecord
	Count       int
	Total       *int64
	Actual      *int64
	Remaining   *int64
	Malformed   bool
}

func passiveSearchRequest(ctx context.Context, p PassiveProvider, r passiveReservation, query string, page int) (*http.Request, error) {
	q := url.Values{p.PageParameter: {strconv.Itoa(page)}, p.SizeParameter: {strconv.Itoa(r.PageSize)}}
	if p.Name == "hunter" {
		q.Set("api-key", string(r.Key))
		q.Set("search", base64.URLEncoding.EncodeToString([]byte(query)))
		q.Set("is_web", "3")
	} else {
		q.Set("key", string(r.Key))
		q.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(query)))
		q.Set("fields", strings.Join(p.Fields, ","))
	}
	endpoint := p.Endpoint + "?" + q.Encode()
	if !officialPassiveEndpoint(endpoint) {
		return nil, passiveFailure("source_config", "来源出口不在官方白名单")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if e == nil {
		req.Header.Set("User-Agent", "ScopeDesk/0.3")
	}
	return req, e
}
func parseHunterPage(raw []byte, p PassiveProvider, g ScopeGuard) (result passivePageData, err error) {
	var body struct {
		Code json.RawMessage `json:"code"`
		Data *struct {
			Total     *int64           `json:"total"`
			Rows      []map[string]any `json:"arr"`
			Consume   string           `json:"consume_quota"`
			Remaining string           `json:"rest_quota"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if decoder.Decode(&body) != nil {
		return result, passiveFailure("invalid_output", "Hunter 响应格式无效")
	}
	code := providerCode(body.Code)
	if code != "200" {
		if code == "401" {
			return result, passiveFailure("auth_expired", "Hunter 认证失效；不自动换号")
		}
		return result, passiveFailure("source_unavailable", "Hunter 返回非成功业务状态，错误原文未记录")
	}
	if body.Data == nil || body.Data.Rows == nil || len(body.Data.Rows) > p.PageSize {
		return result, passiveFailure("invalid_output", "Hunter 数据行缺失或超过预约页大小")
	}
	rowsRaw, _ := json.Marshal(body.Data.Rows)
	result.Fingerprint = fmt.Sprintf("%x", sha256.Sum256(rowsRaw))
	result.Count = len(body.Data.Rows)
	result.Total = body.Data.Total
	result.Actual = hunterQuota(body.Data.Consume, hunterConsumedPattern)
	result.Remaining = hunterQuota(body.Data.Remaining, hunterRemainingPattern)
	now := time.Now().UTC()
	for _, row := range body.Data.Rows {
		rawHost, _ := row["domain"].(string)
		if rawHost == "" {
			rawHost, _ = row["url"].(string)
		}
		host, e := normalizeHost(rawHost)
		if e != nil {
			result.Malformed = true
			continue
		}
		host, e = g.AllowHost(host)
		if e != nil {
			continue
		}
		record := mapPassiveEvidence(row, p, g, host, now)
		fields := record.Observation.PluginEvidence[0].Fields
		if rawCode, ok := row["status_code"]; ok {
			if n, e := strconv.Atoi(toMappingText(rawCode)); e == nil && n >= 100 && n <= 599 {
				fields["status_code"] = n
			}
		}
		if component, ok := row["component"].([]any); ok {
			components := []map[string]string{}
			for _, item := range component {
				if len(components) >= 32 {
					break
				}
				obj, ok := item.(map[string]any)
				if !ok {
					continue
				}
				name, _ := obj["name"].(string)
				version, _ := obj["version"].(string)
				if name != "" && len(name) <= 200 && len(version) <= 100 {
					components = append(components, map[string]string{"name": name, "version": version})
				}
			}
			if len(components) > 0 {
				fields["fingerprints"] = components
			}
		}
		result.Records = append(result.Records, record)
	}
	return result, nil
}
