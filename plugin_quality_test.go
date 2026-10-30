package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func goodJSONLLines(count int) string {
	var b strings.Builder
	for i := range count {
		fmt.Fprintf(&b, "{\"host\":\"api%d.example.com\"}\n", i)
	}
	return b.String()
}

func TestPluginJSONLToleranceBoundaries(t *testing.T) {
	m := PluginManifest{Name: "quality-fixture", Kind: "collector"}
	m.Exec.MaxOutput = 8000000
	m.Output.Format = "jsonl"
	m.Output.Mapping = map[string]string{"host": "host"}
	bad := "{invalid token=fixture-private-badline}\n"
	for _, tc := range []struct {
		name, raw    string
		bad, records int
		failure      bool
	}{
		{"early bad line then recovery", bad + goodJSONLLines(9), 1, 9, false},
		{"rate over ten percent", goodJSONLLines(8) + bad, 1, 8, true},
		{"twenty at ten percent", strings.Repeat(bad, 20) + goodJSONLLines(180), 20, 180, false},
		{"twenty one always fails", strings.Repeat(bad, 21) + goodJSONLLines(1000), 21, 0, true},
		{"null scalar array and syntax", "null\n[]\n\"text\"\n{broken\n" + goodJSONLLines(36), 4, 36, false},
		{"blank lines do not dilute errors", bad + goodJSONLLines(1) + strings.Repeat(" \n", 100), 1, 1, true},
		{"all malformed", bad, 1, 0, true},
		{"empty output", " \n\t\n", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := PluginResult{}
			guardCalls := 0
			guard := func(context.Context) (ScopeGuard, error) { guardCalls++; return ScopeGuard{Scope: sampleScope()}, nil }
			err := parsePluginStream(context.Background(), strings.NewReader(tc.raw), m, guard, &result)
			if (err != nil) != tc.failure || result.RejectedFields["malformed_jsonl"] != tc.bad || len(result.Records) != tc.records || guardCalls != (tc.records+candidateGuardBatchSize-1)/candidateGuardBatchSize {
				t.Fatal("quality threshold or target guard", err, result.RejectedFields, len(result.Records), guardCalls)
			}
			raw, _ := json.Marshal(result)
			if strings.Contains(string(raw), "fixture-private-badline") || (err != nil && strings.Contains(err.Error(), "fixture-private-badline")) {
				t.Fatal("malformed input leaked")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := parsePluginStream(ctx, strings.NewReader(bad), m, func(context.Context) (ScopeGuard, error) {
		t.Fatal("cancelled parse checked target")
		return ScopeGuard{}, nil
	}, &PluginResult{}); err != context.Canceled {
		t.Fatal("cancellation ignored", err)
	}
	// Whole-document JSON remains strict, and the pre-existing line cap remains enforced.
	m.Output.Format = "json"
	if err := parsePluginStream(context.Background(), strings.NewReader("[{} broken]"), m, nil, &PluginResult{}); err == nil {
		t.Fatal("JSON document became permissive")
	}
	m.Output.Format = "jsonl"
	if err := parsePluginStream(context.Background(), strings.NewReader(strings.Repeat("x", 4*1024*1024+1)), m, nil, &PluginResult{}); err == nil || !strings.Contains(err.Error(), "行长") {
		t.Fatal("line cap weakened", err)
	}
}

func TestExternalPluginJSONLQualityAcrossOutputs(t *testing.T) {
	for _, mode := range []string{"jsonl-mixed", "jsonl-split", "jsonl-too-many", "jsonl-too-few"} {
		t.Run(mode, func(t *testing.T) {
			m := fixturePlugin(t, mode, "jsonl")
			if mode == "jsonl-split" {
				m.Exec.Args = append(m.Exec.Args[:len(m.Exec.Args)-1], "{{out_file}}", "{{domain}}")
			}
			result := fixtureExternal(m).Run(context.Background(), "example.com")
			if mode == "jsonl-mixed" || mode == "jsonl-split" {
				if result.Error != "" || len(result.Records) != 9 || result.RejectedFields["malformed_jsonl"] != 1 {
					t.Fatal("tolerated output failed", result)
				}
			} else {
				want := 0
				if mode == "jsonl-too-few" {
					want = 8
				}
				if result.Error == "" || len(pluginCandidates(result)) != want {
					t.Fatal("quality error or validated candidates lost", result)
				}
				if mode == "jsonl-too-many" && !strings.Contains(result.Error, "20 行") {
					t.Fatal("parser error masked by process cancellation", result.Error)
				}
				if mode == "jsonl-too-few" && !strings.Contains(result.Error, "10%") {
					t.Fatal("quality failure not explained", result.Error)
				}
			}
			raw, _ := json.Marshal(result)
			if strings.Contains(string(raw), "fixture-private-badline") {
				t.Fatal("bad line exposed", string(raw))
			}
		})
	}
}
