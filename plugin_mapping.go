package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type PluginRecord struct {
	Candidate   Candidate    `json:"candidate"`
	Observation *Observation `json:"observation,omitempty"`
}
type PluginResult struct {
	ErrorCode            string `json:"error_code"`
	Retryable            bool   `json:"retryable"`
	jsonlLines           int
	deferJSONLValidation bool
	RejectedFields       map[string]int `json:"rejected_fields"`
	RunID                int64          `json:"run_id"`
	Records              []PluginRecord `json:"records"`
	Returned             int            `json:"returned"`
	InScope              int            `json:"in_scope"`
	ExitCode             int            `json:"exit_code"`
	Error                string         `json:"error"`
	Stderr               string         `json:"stderr_excerpt"`
}

func mappedValue(row map[string]any, path string) any {
	var value any = row
	for _, part := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[part]
	}
	return value
}
func mappedString(row map[string]any, path string) string {
	v := mappedValue(row, path)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func parsePluginStream(ctx context.Context, reader io.Reader, m PluginManifest, guard func(context.Context) (ScopeGuard, error), result *PluginResult) error {
	batchGuard := newCandidateGuard(guard)
	if result.RejectedFields == nil {
		result.RejectedFields = map[string]int{}
	}
	seen := map[string]bool{}
	emit := func(row map[string]any) error {
		var hosts []string
		switch value := mappedValue(row, m.Output.Mapping["host"]).(type) {
		case string:
			hosts = []string{value}
		case []any:
			for _, v := range value {
				if s, ok := v.(string); ok {
					hosts = append(hosts, s)
				}
			}
		}
		for _, raw := range hosts {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			result.Returned++
			if result.Returned > 100000 {
				return executionFailure("output_limit", "插件候选数量超过 10 万上限", false)
			}
			g, err := batchGuard.get(ctx)
			if err != nil {
				return err
			}
			host, err := g.AllowHost(raw)
			if err != nil {
				result.RejectedFields["host_out_of_scope_or_invalid"]++
				continue
			}
			result.InScope++
			record := PluginRecord{Candidate: Candidate{Host: host, Source: m.Name}}
			key := host
			if m.Kind == "observer" {
				ob := mapPluginObservation(row, m, g, result)
				ob.Host = host
				if len(ob.Services) > 0 {
					svc := ob.Services[0]
					key += "|" + svc.IP + "|" + strconv.Itoa(svc.Port) + "|" + svc.Protocol
				}
				record.Observation = &ob
			}
			if !seen[key] {
				seen[key] = true
				result.Records = append(result.Records, record)
			}
		}
		return nil
	}
	if m.Output.Format == "lines" || m.Output.Format == "jsonl" {
		scanner := bufio.NewScanner(reader)
		maxLine := pluginMaxLineBytes(m)
		scanner.Buffer(make([]byte, min(4096, int(maxLine))), int(maxLine))
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if strings.TrimSpace(scanner.Text()) == "" {
				continue
			}
			var row map[string]any
			if m.Output.Format == "lines" {
				row = map[string]any{"line": scanner.Text()}
			} else {
				result.jsonlLines++
				if json.Unmarshal(scanner.Bytes(), &row) != nil || row == nil {
					result.RejectedFields["malformed_jsonl"]++
					if result.RejectedFields["malformed_jsonl"] > 20 {
						return executionFailure("invalid_output", "插件 JSONL 格式错误行超过 20 行", false)
					}
					continue
				}
			}
			if err := emit(row); err != nil {
				return err
			}
		}
		if scanner.Err() != nil {
			return executionFailure("invalid_output", "插件输出读取或行长超限", false)
		}
		if m.Output.Format == "jsonl" && !result.deferJSONLValidation {
			return validatePluginJSONL(result)
		}
		return nil
	}
	decoder := json.NewDecoder(reader)
	token, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return executionFailure("invalid_output", "插件 JSON 格式无效", false)
	}
	switch token {
	case json.Delim('['):
		for decoder.More() {
			var row map[string]any
			if decoder.Decode(&row) != nil {
				return executionFailure("invalid_output", "插件 JSON 数组格式无效", false)
			}
			if err = emit(row); err != nil {
				return err
			}
		}
		if _, err = decoder.Token(); err != nil {
			return executionFailure("invalid_output", "插件 JSON 数组未结束", false)
		}
	case json.Delim('{'):
		row := map[string]any{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return executionFailure("invalid_output", "插件 JSON 对象无效", false)
			}
			var value any
			if decoder.Decode(&value) != nil {
				return executionFailure("invalid_output", "插件 JSON 对象无效", false)
			}
			row[key.(string)] = value
		}
		if _, err = decoder.Token(); err != nil {
			return executionFailure("invalid_output", "插件 JSON 对象未结束", false)
		}
		if err = emit(row); err != nil {
			return err
		}
	default:
		return executionFailure("invalid_output", "插件 JSON 须为对象或对象数组", false)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return executionFailure("invalid_output", "插件 JSON 包含额外内容", false)
	}
	return nil
}

// Validate the final ratio, so an early bad line is not judged before later good output.
func validatePluginJSONL(result *PluginResult) error {
	bad := result.RejectedFields["malformed_jsonl"]
	if bad > 20 {
		return executionFailure("invalid_output", "插件 JSONL 格式错误行超过 20 行", false)
	}
	if bad*10 > result.jsonlLines {
		return executionFailure("invalid_output", "插件 JSONL 格式错误行比例超过 10%", false)
	}
	return nil
}
func toMappingText(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return string(v)
	}
	return ""
}

type PluginGroup struct {
	Strategy string
	Plugins  []func(context.Context) PluginResult
}

func (g PluginGroup) Run(ctx context.Context) ([]PluginRecord, []PluginResult, error) {
	if g.Strategy != "all" && g.Strategy != "first_success" && g.Strategy != "fallback" {
		return nil, nil, executionFailure("invalid_output", "插件合并策略无效", false)
	}
	out := []PluginRecord{}
	runs := []PluginResult{}
	seen := map[string]bool{}
	success := false
	failed := false
	for _, run := range g.Plugins {
		if ctx.Err() != nil {
			return out, runs, ctx.Err()
		}
		result := run(ctx)
		runs = append(runs, result)
		ok := result.Error == ""
		success = success || ok
		failed = failed || !ok
		if !ok {
			continue
		}
		for _, record := range result.Records {
			raw, _ := json.Marshal(record)
			key := string(raw)
			if record.Observation == nil {
				key = record.Candidate.Host
			}
			if !seen[key] {
				seen[key] = true
				out = append(out, record)
			}
		}
		if ok && (g.Strategy == "first_success" || (g.Strategy == "fallback" && len(result.Records) > 0)) {
			break
		}
	}
	if !success || (g.Strategy == "all" && failed) {
		return out, runs, executionFailure("invalid_output", "插件组未完整成功", false)
	}
	return out, runs, nil
}

// No provider endpoint is handed to Probe; IP/port/time remain historical claims.
func mapPassiveEvidence(row map[string]any, p PassiveProvider, g ScopeGuard, host string, obtained time.Time) PluginRecord {
	fields := map[string]any{}
	for dest, path := range p.Mapping {
		if dest == "host" || dest == "ip" || dest == "port" {
			continue
		}
		if v, ok := row[path].(string); ok && len(v) <= 8192 {
			fields[dest] = v
		}
	}
	ip := ""
	if raw, ok := row["ip"].(string); ok && g.AllowIP(raw) == nil {
		if addr, err := netip.ParseAddr(raw); err == nil {
			ip = addr.Unmap().String()
		}
	}
	port := 0
	if value, ok := row["port"]; ok {
		n, err := strconv.Atoi(toMappingText(value))
		if err == nil && n > 0 && n <= 65535 {
			port = n
		}
	}
	ev := PluginEvidence{Source: p.Name, IP: ip, Port: port, Fields: fields, ObservedAt: obtained, ObtainedAt: &obtained, ProviderTimeMeaning: p.ProviderTimeMeaning, ProviderTimeTimezone: p.ProviderTimeTimezone}
	if value, ok := row[p.ProviderTimeField].(string); ok && len(value) <= 100 && value != "" {
		ev.ProviderTimeRaw = &value
		// Only offset-bearing timestamps are safely representable as an instant.
		if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
			t = t.UTC()
			ev.ProviderTime = &t
		}
	}
	return PluginRecord{Candidate: Candidate{host, p.Name}, Observation: &Observation{Host: host, Sources: []string{p.Name}, EvidenceOnly: true, PreserveReachability: true, PluginEvidence: []PluginEvidence{ev}}}
}
