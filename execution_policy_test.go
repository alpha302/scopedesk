package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type policyTransport func(*http.Request) (*http.Response, error)

func (f policyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCertificateFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		status  int
		network bool
		retry   bool
	}{{429, false, false}, {503, false, false}, {400, false, false}, {200, true, false}} {
		client := &http.Client{Transport: policyTransport(func(*http.Request) (*http.Response, error) {
			if tc.network {
				return nil, &net.DNSError{IsTimeout: true}
			}
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader("[]"))}, nil
		})}
		collector := &CertificateCollector{Source: "crtsh", Client: client, Budget: &Budget{Limit: 10}, Limit: immediateLimit{}}
		_, err := collector.Collect(context.Background(), sampleScope())
		if err == nil || classifyExecutionError(err, "source_failed").Retryable != tc.retry {
			t.Fatal("source retry classification", tc, err)
		}
	}
	for _, tc := range []struct{ body, code string }{{"{", "invalid_output"}, {strings.Repeat("x", 8_000_001), "output_limit"}} {
		client := &http.Client{Transport: policyTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}
		collector := &CertificateCollector{Source: "crtsh", Client: client, Budget: &Budget{Limit: 10}, Limit: immediateLimit{}}
		_, err := collector.Collect(context.Background(), sampleScope())
		failure := classifyExecutionError(err, "source_failed")
		if failure == nil || failure.Code != tc.code || failure.Retryable {
			t.Fatal("source output error classification", failure)
		}
	}
}

func TestExecutionBudgetAndManifestRetryPolicy(t *testing.T) {
	t.Setenv("RECON_MAX_JOB_DURATION", "")
	registry := &PluginRegistry{Manifests: map[string]PluginManifest{"slow": {timeout: 15 * time.Minute}, "slow2": {timeout: 15 * time.Minute}, "slow3": {timeout: 15 * time.Minute}}}
	budget, err := jobExecutionBudget([]string{"slow"}, "manual", registry)
	want := 3*15*time.Minute + 15*time.Second + 6*time.Second + profileBudget + commitBudget
	if err != nil || budget != want {
		t.Fatal("plugin plus profile budget", budget, want, err)
	}
	testBudget, err := jobExecutionBudget([]string{"slow"}, "plugin_test", registry)
	if err != nil || testBudget != 15*time.Minute+5*time.Second+commitBudget {
		t.Fatal("test budget", testBudget, err)
	}
	if _, err = jobExecutionBudget([]string{"slow", "slow2", "slow3"}, "schedule", registry); err == nil || classifyExecutionError(err, "").Code != "job_budget_exceeded" {
		t.Fatal("global cap silently truncated budget", err)
	}
	t.Setenv("RECON_MAX_JOB_DURATION", "3h")
	if _, err = jobExecutionBudget([]string{"slow", "slow2", "slow3"}, "schedule", registry); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECON_MAX_JOB_DURATION", "invalid")
	if _, err = maxJobDuration(); err == nil {
		t.Fatal("invalid cap accepted")
	}
	t.Setenv("RECON_MAX_JOB_DURATION", "")
	raw, _ := defaultPluginFiles.ReadFile("plugins/subfinder.yaml")
	for _, codes := range []string{"[0]", "[256]", "[7,7]", "[-1]"} {
		input := strings.Replace(string(raw), "  timeout:", "  retry_exit_codes: "+codes+"\n  timeout:", 1)
		if _, err := parseManifest([]byte(input)); err == nil {
			t.Fatal("invalid retry exit codes", codes)
		}
	}
	input := strings.Replace(string(raw), "  timeout:", "  retry_exit_codes: [7,75]\n  timeout:", 1)
	m, err := parseManifest([]byte(input))
	if err != nil || len(m.Exec.RetryExitCodes) != 2 {
		t.Fatal("valid retry exit codes", err)
	}
}

func TestExecutionErrorClassificationAndStageRetry(t *testing.T) {
	for _, tc := range []struct {
		err   error
		retry bool
	}{
		{context.DeadlineExceeded, false}, {context.Canceled, false},
		{executionFailure("invalid_output", "bad", false), false},
		{&net.DNSError{IsTimeout: true}, false}, {syscall.EAGAIN, true},
		{&pgconn.PgError{Code: "40001"}, true}, {&pgconn.PgError{Code: "23514"}, false},
		{errors.New("timeout temporary 40001"), false},
	} {
		if classifyExecutionError(tc.err, "fallback").Retryable != tc.retry {
			t.Fatal("failure classified from text instead of type", tc.err)
		}
	}
	if classifyCommitError(io.EOF).Retryable || classifyCommitError(io.EOF).Code != "commit_uncertain" || !classifyCommitError(&pgconn.PgError{Code: "40001"}).Retryable {
		t.Fatal("unsafe commit retry")
	}
	for _, tc := range []struct {
		name      string
		temporary bool
		success   bool
		want      int
	}{{"temporary then success", true, true, 2}, {"fatal once", false, false, 1}, {"temporary exhausted", true, false, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := retryStage(context.Background(), func() error {
				calls++
				if tc.success && calls == 2 {
					return nil
				}
				return executionFailure("fixture", "fixture", tc.temporary)
			})
			if calls != tc.want || (err == nil) != tc.success {
				t.Fatal(calls, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := retryStage(ctx, func() error { t.Fatal("cancelled operation ran"); return nil }); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestExternalPluginFailureClasses(t *testing.T) {
	for _, tc := range []struct {
		mode, code string
		retry      bool
	}{{"sleep", "plugin_timeout", false}, {"overflow", "output_limit", false}, {"jsonl-too-many", "invalid_output", false}, {"exit", "exit_nonzero", false}, {"exit", "exit_retryable", true}} {
		t.Run(tc.code, func(t *testing.T) {
			m := fixturePlugin(t, tc.mode, "jsonl")
			if tc.mode == "sleep" {
				m.timeout = 150 * time.Millisecond
			}
			if tc.mode == "overflow" {
				m.Exec.MaxOutput = 256
			}
			if tc.retry {
				m.Exec.RetryExitCodes = []int{7}
			}
			result := fixtureExternal(m).Run(context.Background(), "example.com")
			if result.Error == "" || result.ErrorCode != tc.code || result.Retryable != tc.retry {
				t.Fatal(result)
			}
			if failure := classifyExecutionError(pluginResultError(result), ""); failure.Code != tc.code || failure.Retryable != tc.retry {
				t.Fatal("collector lost typed failure", failure)
			}
		})
	}
}
