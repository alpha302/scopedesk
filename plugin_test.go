package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The helper is a Go test subprocess, never a shell script. It performs no network IO.
func TestPluginFixtureProcess(t *testing.T) {
	marker := -1
	for i, arg := range os.Args {
		if arg == "--scopedesk-fixture" {
			marker = i
		}
	}
	if marker < 0 {
		return
	}
	mode := os.Args[marker+1]
	domain := os.Args[len(os.Args)-1]
	emit := func(host string) { fmt.Printf("{\"host\":%q}\n", host) }
	switch mode {
	case "jsonl-mixed", "jsonl-split", "jsonl-too-many", "jsonl-too-few":
		bad := 1
		if mode == "jsonl-too-many" {
			bad = 21
		}
		for range bad {
			fmt.Println("{invalid token=fixture-private-badline}")
		}
		var good strings.Builder
		count := 9
		if mode == "jsonl-too-few" {
			count = 8
		}
		for i := range count {
			fmt.Fprintf(&good, "{\"host\":%q}\n", fmt.Sprintf("api%d.%s", i, domain))
		}
		if mode == "jsonl-split" {
			if os.WriteFile(os.Args[marker+2], []byte(good.String()), 0600) != nil {
				os.Exit(8)
			}
		} else {
			fmt.Print(good.String())
		}
	case "retry-observer":
		path := os.Args[marker+2]
		raw, _ := os.ReadFile(path)
		attempt, _ := strconv.Atoi(string(raw))
		if os.WriteFile(path, []byte(strconv.Itoa(attempt+1)), 0600) != nil {
			os.Exit(8)
		}
		if attempt == 0 {
			fmt.Printf("{\"host\":%q,\"port\":8443,\"code\":200,\"title\":\"failed attempt\"}\n", "failed-only."+domain)
			os.Exit(7)
		}
		fmt.Printf("{\"host\":%q,\"port\":443,\"code\":200,\"title\":\"successful attempt\"}\n", "api."+domain)
	case "failed-observer":
		fmt.Printf("{\"host\":%q,\"port\":443,\"code\":200,\"title\":\"failed attempt\"}\n", "failed-only."+domain)
		os.Exit(7)
	case "partial-timeout":
		fmt.Printf("{\"host\":%q,\"port\":443,\"code\":200,\"title\":\"failed attempt\"}\n", "partial."+domain)
		time.Sleep(10 * time.Second)
	case "invalid-observer":
		fmt.Printf("{\"host\":%q,\"port\":\"bad\",\"ip\":\"127.0.0.1\",\"code\":999,\"title\":\"retained title\"}\n", "api."+domain)
	case "jsonl":
		emit("api." + domain)
		emit("api." + domain)
		emit("outside.net")
		fmt.Fprint(os.Stderr, "token=fixture-secret\n")
	case "lines":
		fmt.Println("api." + domain)
	case "json":
		fmt.Printf("[{\"host\":%q},{\"host\":%q}]", "api."+domain, "outside.net")
	case "sleep":
		time.Sleep(10 * time.Second)
	case "policy-rate":
		fmt.Printf("{\"host\":%q,\"title\":%q}\n", "api."+domain, os.Args[marker+2])
	case "policy-resource", "policy-many-children", "policy-escaped", "policy-escaped-timeout":
		membership, _ := os.ReadFile("/proc/self/cgroup")
		limits, _ := os.ReadFile("/proc/self/limits")
		pid := 0
		if strings.HasPrefix(mode, "policy-escaped") {
			child := exec.Command("/bin/sleep", "10")
			child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if child.Start() != nil {
				os.Exit(8)
			}
			pid = child.Process.Pid
		}
		fmt.Printf("{\"host\":%q,\"title\":%q,\"server\":%q,\"banner\":%q}\n", "api."+domain, strings.TrimSpace(string(membership)), strconv.Itoa(pid), string(limits))
		if mode == "policy-many-children" {
			for range 80 {
				if exec.Command("/bin/sleep", "10").Start() != nil {
					break
				}
			}
		}
		if mode == "policy-escaped-timeout" {
			time.Sleep(10 * time.Second)
		}
	case "overflow":
		for range 100000 {
			emit("api." + domain)
		}
	case "exit":
		emit("partial." + domain)
		os.Exit(7)
	case "env":
		dir, _ := os.Getwd()
		info, _ := os.Stat(dir)
		if info.Mode().Perm() != 0700 || os.Getenv("DATABASE_URL") != "" || os.Getenv("RECON_MASTER_KEY") != "" || os.Getenv("HOME") != dir {
			os.Exit(9)
		}
		fmt.Printf("{\"host\":%q,\"title\":%q}\n", "api."+domain, dir)
	case "stderr":
		fmt.Fprint(os.Stderr, "api_key=fixture-secret\n"+strings.Repeat("diagnostic ", 2000))
		emit("api." + domain)
	case "file":
		os.WriteFile(os.Args[marker+2], []byte("api."+domain+"\n"), 0600)
	case "descendant":
		bin, _ := os.Executable()
		cmd := exec.Command(bin, "-test.run=^TestPluginFixtureProcess$", "--", "--scopedesk-fixture", "sleep", domain)
		if cmd.Start() != nil {
			os.Exit(8)
		}
		fmt.Printf("{\"host\":%q,\"server\":%q}\n", "api."+domain, strconv.Itoa(cmd.Process.Pid))
		time.Sleep(10 * time.Second)
	}
	os.Exit(0)
}
func fixturePlugin(t *testing.T, mode, format string) PluginManifest {
	t.Helper()
	if _, err := os.Stat("/usr/bin/prlimit"); err != nil {
		t.Skip("Linux prlimit required")
	}
	if err := os.MkdirAll("/opt/scopedesk-tools", 0755); err != nil {
		t.Skip("fixture requires write access to tool whitelist")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join("/opt/scopedesk-tools", "scopedesk-fixture-"+random()[:12])
	dest, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Skip("fixture requires write access to tool whitelist")
	}
	_, err = io.Copy(dest, source)
	dest.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	raw, _ := defaultPluginFiles.ReadFile("plugins/subfinder.yaml")
	m, err := parseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	m.Name = "fixture"
	m.Version = "1.0"
	m.Exec.Bin = path
	m.Exec.Args = []string{"-test.run=^TestPluginFixtureProcess$", "--", "--scopedesk-fixture", mode, "{{domain}}"}
	m.Exec.Timeout = "4s"
	m.timeout = 4 * time.Second
	m.Exec.MaxOutput = 65536
	m.Exec.Limits = map[string]uint64{}
	m.Exec.RateFormat = "number"
	m.ScopeModes = nil
	m.ConfigFiles = nil
	m.Output.MaxLineBytes = 0
	m.Output.Format = format
	m.Output.Mapping = map[string]string{"host": "host"}
	if format == "lines" {
		m.Output.Mapping["host"] = "line"
	}
	return m
}
func fixtureExternal(m PluginManifest) *ExternalPlugin {
	return &ExternalPlugin{Manifest: m, Budget: &Budget{Limit: 100}, Guard: func(context.Context) (ScopeGuard, error) { return ScopeGuard{Scope: sampleScope()}, nil }}
}
func TestPluginManifestValidation(t *testing.T) {
	raw, _ := defaultPluginFiles.ReadFile("plugins/subfinder.yaml")
	for _, tt := range []struct{ name, old, new string }{{"path", "/opt/scopedesk-tools/subfinder", "/bin/sh"}, {"traversal", "/opt/scopedesk-tools/subfinder", "/opt/scopedesk-tools/../sh"}, {"placeholder", "{{domain}}", "{{unknown}}"}, {"timeout", "timeout: 120s", "timeout: ''"}, {"max_output", "max_output: 8000000", "max_output: 0"}, {"args array", `args: ["-d", "{{domain}}", "-json", "-silent", "-duc", "-rl", "{{rate}}", "-timeout", "15", "-max-time", "1"]`, `args: "-d {{domain}}"`}, {"post", "post: [normalize, deduplicate, scope_guard]", "post: [shell]"}} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseManifest([]byte(strings.Replace(string(raw), tt.old, tt.new, 1))); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	for _, tt := range []struct {
		p PluginParam
		v any
	}{{PluginParam{Type: "integer", Max: 10}, 11}, {PluginParam{Type: "integer"}, 1.5}, {PluginParam{Type: "boolean"}, "true"}, {PluginParam{Type: "string", Max: 3}, "long"}, {PluginParam{Type: "string", Enum: []any{"ok"}}, "bad"}, {PluginParam{Type: "string", Max: 10}, "-flag"}} {
		if _, err := paramValue(tt.p, tt.v); err == nil {
			t.Fatal("invalid parameter accepted")
		}
	}
	if _, err := paramValue(PluginParam{Type: "string_array", Max: 2}, []any{"a", "b"}); err != nil {
		t.Fatal(err)
	}
}
func TestPluginPathSymlinkAndInjection(t *testing.T) {
	m := fixturePlugin(t, "jsonl", "jsonl")
	link := m.Exec.Bin + "-link"
	if err := os.Symlink("/bin/echo", link); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(link)
	if _, err := trustedPluginBin(link, true); err == nil {
		t.Fatal("symlink escape accepted")
	}
	p := fixtureExternal(m)
	for _, target := range []string{"example.com ;id", "example.com;id", "-example.com", "example.com|cat", "example.com\nmalicious"} {
		result := p.Run(context.Background(), target)
		if result.Error == "" || result.RunID != 0 || len(result.Records) > 0 {
			t.Fatal("unsafe target executed", target)
		}
	}
	p.QueryRoot = true
	p.Guard = func(context.Context) (ScopeGuard, error) {
		s := sampleScope()
		s.Mode = "subdomains"
		return ScopeGuard{Scope: s, Blacklist: []string{"example.com"}}, nil
	}
	if result := p.Run(context.Background(), "example.com"); result.Error == "" {
		t.Fatal("subdomain root query bypassed blacklist")
	}
}
func TestExternalPluginFormatsScopeAndCleanup(t *testing.T) {
	for _, format := range []string{"jsonl", "lines", "json"} {
		t.Run(format, func(t *testing.T) {
			m := fixturePlugin(t, format, format)
			result := fixtureExternal(m).Run(context.Background(), "example.com")
			if result.Error != "" || len(result.Records) != 1 || result.Records[0].Candidate.Source != "fixture" {
				t.Fatalf("result %+v", result)
			}
			if format == "jsonl" && (result.Returned != 3 || result.InScope != 2) {
				t.Fatal("raw statistics", result)
			}
		})
	}
	m := fixturePlugin(t, "env", "jsonl")
	m.Kind = "observer"
	m.Output.Mapping["title"] = "title"
	result := fixtureExternal(m).Run(context.Background(), "example.com")
	if result.Error != "" || len(result.Records) != 1 {
		t.Fatal("environment isolation", result.Error)
	}
	dir := result.Records[0].Observation.Title
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("temporary directory retained")
	}
}
func TestExternalPluginTimeoutOutputExitAndStderr(t *testing.T) {
	for _, mode := range []string{"sleep", "overflow", "exit", "stderr"} {
		t.Run(mode, func(t *testing.T) {
			m := fixturePlugin(t, mode, "jsonl")
			if mode == "sleep" {
				m.timeout = 100 * time.Millisecond
			}
			if mode == "overflow" {
				m.Exec.MaxOutput = 1000
			}
			start := time.Now()
			result := fixtureExternal(m).Run(context.Background(), "example.com")
			if mode == "stderr" {
				if result.Error != "" || len(result.Stderr) > 8192 || strings.Contains(result.Stderr, "fixture-secret") {
					t.Fatal("stderr not bounded/redacted")
				}
			} else if result.Error == "" {
				t.Fatal("failure treated as success", mode)
			}
			if mode == "sleep" && time.Since(start) > 4*time.Second {
				t.Fatal("timeout not enforced")
			}
			if mode == "exit" && (result.ExitCode != 7 || len(result.Records) != 1) {
				t.Fatal("partial results or exit code lost", result)
			}
		})
	}
}
func TestExternalPluginFileAndDescendants(t *testing.T) {
	m := fixturePlugin(t, "file", "lines")
	m.Exec.Args = []string{"-test.run=^TestPluginFixtureProcess$", "--", "--scopedesk-fixture", "file", "{{out_file}}", "{{domain}}"}
	result := fixtureExternal(m).Run(context.Background(), "example.com")
	if result.Error != "" || len(result.Records) != 1 {
		t.Fatal("output file parse", result)
	}
	m = fixturePlugin(t, "descendant", "jsonl")
	m.Kind = "observer"
	m.Output.Mapping["server"] = "server"
	m.timeout = 500 * time.Millisecond
	result = fixtureExternal(m).Run(context.Background(), "example.com")
	if result.Error == "" || len(result.Records) == 0 {
		t.Fatal("descendant timeout")
	}
	pid, _ := strconv.Atoi(result.Records[0].Observation.Server)
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil && !strings.Contains(string(raw), ") Z ") {
		if syscall.Kill(pid, 0) == nil {
			t.Fatal("descendant still alive")
		}
	}
}
func TestPluginGroupsAndMapping(t *testing.T) {
	for _, strategy := range []string{"all", "first_success", "fallback"} {
		calls := 0
		group := PluginGroup{Strategy: strategy, Plugins: []func(context.Context) PluginResult{
			func(context.Context) PluginResult { calls++; return PluginResult{Records: []PluginRecord{}} },
			func(context.Context) PluginResult {
				calls++
				return PluginResult{Records: []PluginRecord{{Candidate: Candidate{"api.example.com", "fixture"}}, {Candidate: Candidate{"api.example.com", "second"}}}}
			},
		}}
		out, _, err := group.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if strategy == "first_success" {
			if calls != 1 || len(out) != 0 {
				t.Fatal("first success semantics")
			}
		} else if calls != 2 || len(out) != 1 {
			t.Fatal("fallback/dedup semantics")
		}
	}
	m := fixturePlugin(t, "jsonl", "jsonl")
	m.Kind = "observer"
	m.Output.Mapping = map[string]string{"host": "target.name", "ip": "ip", "port": "port", "status_code": "code", "title": "title"}
	result := PluginResult{}
	raw := `[{"target":{"name":"api.example.com"},"ip":"8.8.8.8","port":443,"code":200,"title":"Portal","unknown":"ignore"}]`
	m.Output.Format = "json"
	if err := parsePluginStream(context.Background(), strings.NewReader(raw), m, fixtureExternal(m).Guard, &result); err != nil || len(result.Records) != 1 || result.Records[0].Observation.StatusCode != 200 || result.Records[0].Observation.Alive != nil || !result.Records[0].Observation.EvidenceOnly {
		t.Fatal("observation mapping", err)
	}
}
