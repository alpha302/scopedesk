package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestPluginDeclarativePolicyValidation(t *testing.T) {
	raw, _ := defaultPluginFiles.ReadFile("plugins/subfinder.yaml")
	m, err := parseManifest([]byte(strings.Replace(string(raw), "name: subfinder", "name: renamed-tool", 1)))
	if err != nil || m.Exec.RateFormat != "integer" || pluginTaskLimit(m) != 512 || m.Output.MaxLineBytes != 1000000 || len(m.ConfigFiles) != 2 {
		t.Fatal("renamed manifest lost declared policy", m, err)
	}
	for _, tc := range []struct{ old, new string }{
		{"rate_format: integer", "rate_format: unknown"},
		{"scope_modes: [subdomains, descendants]", "scope_modes: [exact, exact]"},
		{"scope_modes: [subdomains, descendants]", "scope_modes: [unknown]"},
		{"task_limit: 512", "task_limit: 65537"},
		{"source: subfinder/config.yaml", "source: ../outside.yaml"},
		{"source: subfinder/config.yaml", "source: /etc/config.yaml"},
		{"destination: config/subfinder/config.yaml", "destination: config/../output"},
		{"destination: config/subfinder/config.yaml", "destination: targets.txt"},
		{"destination: config/subfinder/config.yaml", "destination: config/subfinder/provider-config.yaml"},
		{"max_line_bytes: 1000000", "max_line_bytes: 8000001"},
	} {
		if _, err := parseManifest([]byte(strings.Replace(string(raw), tc.old, tc.new, 1))); err == nil {
			t.Fatal("invalid declaration accepted", tc.new)
		}
	}
	m.Exec.TaskLimit = 512
	m.Exec.Limits["nproc"] = 128
	if pluginTaskLimit(m) != 128 {
		t.Fatal("legacy stricter nproc ignored")
	}
	m.Exec.TaskLimit = 0
	if pluginTaskLimit(m) != 128 {
		t.Fatal("legacy nproc not translated")
	}
	delete(m.Exec.Limits, "nproc")
	if pluginTaskLimit(m) != 512 {
		t.Fatal("old manifests lost default resource bound")
	}
	for _, rate := range []float64{0.5, 0, math.NaN(), math.Inf(1)} {
		if _, err := pluginRate(m, rate); err == nil {
			t.Fatal("invalid integer rate accepted", rate)
		}
	}
	if rate, err := pluginRate(m, 5.9); err != nil || rate != "5" {
		t.Fatal("integer rate exceeds scope", rate, err)
	}
	m.Exec.RateFormat = ""
	if rate, err := pluginRate(m, 0.5); err != nil || rate != "0.5" {
		t.Fatal("old fractional rate changed", rate, err)
	}
}

func TestPluginRenamingPreservesExecutionPolicy(t *testing.T) {
	for _, name := range []string{"subfinder", "another-tool"} {
		m := fixturePlugin(t, "policy-rate", "jsonl")
		m.Name, m.Kind, m.Exec.RateFormat = name, "observer", "integer"
		m.ScopeModes = []string{"descendants", "subdomains"}
		m.Exec.Args = append(m.Exec.Args[:len(m.Exec.Args)-1], "{{rate}}", "{{domain}}")
		m.Output.Mapping["title"] = "title"
		p := fixtureExternal(m)
		scope := sampleScope()
		scope.RPS = 5.9
		p.Guard = func(context.Context) (ScopeGuard, error) { return ScopeGuard{Scope: scope}, nil }
		result := p.Run(context.Background(), "example.com")
		if result.Error != "" || len(result.Records) != 1 || result.Records[0].Observation.Title != "5" {
			t.Fatal("name affected declared rate", name, result)
		}
		scope.RPS = 0.5
		if result := p.Run(context.Background(), "example.com"); result.ErrorCode != "plugin_config" {
			t.Fatal("integer rate policy bypassed", name, result)
		}
		scope.RPS, scope.Mode = 5, "exact"
		if result := p.Run(context.Background(), "example.com"); result.ErrorCode != "scope_denied" {
			t.Fatal("scope mode policy bypassed", name, result)
		}
	}
}

func TestPluginConfigFilesAreBoundedAndContained(t *testing.T) {
	root, dir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "provider"), 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "provider", "settings.yaml")
	if err := os.WriteFile(source, []byte("keys: [fixture-sensitive-value]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	files := []PluginConfigFile{{Source: "provider/settings.yaml", Destination: "config/tool/settings.yaml"}}
	secrets, err := copyPluginConfigs(root, dir, files)
	if err != nil || len(secrets) != 1 || strings.Contains(redactPluginStderr([]byte("value="+secrets[0]), secrets), secrets[0]) {
		t.Fatal("configuration copy or redaction", err)
	}
	info, err := os.Stat(filepath.Join(dir, files[0].Destination))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("config file permission", info, err)
	}
	info, err = os.Stat(filepath.Dir(filepath.Join(dir, files[0].Destination)))
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("config directory permission", info, err)
	}
	for _, tc := range []struct {
		source   string
		optional bool
		fail     bool
	}{
		{"missing.yaml", true, false}, {"missing.yaml", false, true}, {"../escape.yaml", true, true}, {"file-link", true, true}, {"dir-link/settings.yaml", true, true}, {"fifo", true, true}, {"large.yaml", false, true},
	} {
		switch tc.source {
		case "file-link":
			if err := os.Symlink(source, filepath.Join(root, tc.source)); err != nil {
				t.Fatal(err)
			}
		case "dir-link/settings.yaml":
			if err := os.Symlink(filepath.Join(root, "provider"), filepath.Join(root, "dir-link")); err != nil {
				t.Fatal(err)
			}
		case "fifo":
			if err := syscall.Mkfifo(filepath.Join(root, tc.source), 0600); err != nil {
				t.Fatal(err)
			}
		case "large.yaml":
			if err := os.WriteFile(filepath.Join(root, tc.source), make([]byte, pluginConfigMaxBytes+1), 0600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := copyPluginConfigs(root, t.TempDir(), []PluginConfigFile{{Source: tc.source, Destination: "config/tool/settings.yaml", Optional: tc.optional}})
		if (err != nil) != tc.fail {
			t.Fatal("unsafe config accepted", tc.source, err)
		}
	}
}

func TestPluginDeclaredLineLimitSurvivesRename(t *testing.T) {
	for _, name := range []string{"subfinder", "renamed-tool"} {
		m := PluginManifest{Name: name, Kind: "collector"}
		m.Exec.MaxOutput = 10000
		m.Output.Format = "lines"
		m.Output.Mapping = map[string]string{"host": "line"}
		m.Output.MaxLineBytes = 64
		g := func(context.Context) (ScopeGuard, error) { return ScopeGuard{Scope: sampleScope()}, nil }
		if err := parsePluginStream(context.Background(), strings.NewReader(strings.Repeat("x", 100)+".example.com\n"), m, g, &PluginResult{}); err == nil {
			t.Fatal("declared line cap ignored", name)
		}
		m.Output.MaxLineBytes = 0
		if err := parsePluginStream(context.Background(), strings.NewReader("api.example.com\n"), m, g, &PluginResult{}); err != nil {
			t.Fatal(err)
		}
	}
}

func resourceFixture(t *testing.T, mode string) PluginManifest {
	m := fixturePlugin(t, mode, "jsonl")
	m.Kind = "observer"
	m.Output.Mapping = map[string]string{"host": "host", "title": "title", "server": "server", "banner": "banner"}
	return m
}

func TestPluginTaskGroupIsolatesParentThreadsAndLegacyLimit(t *testing.T) {
	stop := make(chan struct{})
	var ready, done sync.WaitGroup
	for range 48 {
		ready.Add(1)
		done.Add(1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer done.Done()
			ready.Done()
			<-stop
		}()
	}
	ready.Wait()
	defer func() { close(stop); done.Wait() }()
	m := resourceFixture(t, "policy-resource")
	m.Exec.TaskLimit = 0
	m.Exec.Limits["nproc"] = 32
	result := fixtureExternal(m).Run(context.Background(), "example.com")
	if result.Error != "" || len(result.Records) != 1 {
		t.Fatal("parent threads consumed plugin task limit", result)
	}
	var raw []byte
	raw, _ = json.Marshal(result.Records[0].Observation.PluginEvidence)
	if !strings.Contains(string(raw), "plugin-") || strings.Contains(string(raw), "Max processes             32") {
		t.Fatal("plugin not isolated or nproc still applied", string(raw))
	}
}

func TestPluginTaskLimitAndEscapedDescendantCleanup(t *testing.T) {
	for _, mode := range []string{"policy-many-children", "policy-escaped", "policy-escaped-timeout", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			fixtureMode := mode
			if mode == "cancel" {
				fixtureMode = "policy-escaped-timeout"
			}
			m := resourceFixture(t, fixtureMode)
			if mode == "policy-many-children" {
				m.Exec.TaskLimit = 32
			}
			if mode == "policy-escaped-timeout" {
				m.timeout = 500 * time.Millisecond
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				timer := time.AfterFunc(500*time.Millisecond, cancel)
				defer timer.Stop()
			}
			result := fixtureExternal(m).Run(ctx, "example.com")
			want := ""
			switch mode {
			case "policy-many-children":
				want = "resource_limit"
			case "policy-escaped-timeout":
				want = "plugin_timeout"
			case "cancel":
				want = "cancelled"
			}
			if result.ErrorCode != want || result.Retryable || len(result.Records) != 1 {
				t.Fatal("resource/cancellation classification", result)
			}
			ob := result.Records[0].Observation
			membership := strings.TrimPrefix(ob.Title, "0::")
			if !strings.Contains(membership, "/plugin-") {
				t.Fatal("fixture not in independent cgroup", membership)
			}
			if _, err := os.Stat(filepath.Join("/sys/fs/cgroup", membership)); !os.IsNotExist(err) {
				t.Fatal("plugin cgroup retained", membership, err)
			}
			if strings.HasPrefix(fixtureMode, "policy-escaped") {
				pid, _ := strconv.Atoi(ob.Server)
				raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if err == nil && !strings.Contains(string(raw), ") Z ") {
					t.Fatal("escaped descendant survived cleanup", pid)
				}
			}
		})
	}
}

func TestPluginMissingDelegationFailsClosed(t *testing.T) {
	if os.Getenv("SCOPEDESK_NO_DELEGATION_FIXTURE") == "1" {
		m := fixturePlugin(t, "lines", "lines")
		result := fixtureExternal(m).Run(context.Background(), "example.com")
		if result.ErrorCode != "plugin_config" || result.Retryable || !strings.Contains(result.Error, "cgroup") || len(result.Records) != 0 {
			t.Fatal("missing delegation ran unbounded plugin", result)
		}
		return
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--unit=scopedesk-no-delegation-"+random()[:12], "--setenv=SCOPEDESK_NO_DELEGATION_FIXTURE=1", bin, "-test.run=^TestPluginMissingDelegationFailsClosed$", "-test.v")
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("no-delegation fixture: %v %s", err, raw)
	}
}

func TestPluginCgroupServiceUser(t *testing.T) {
	g, err := newPluginTaskGroup(32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := g.close(); err != nil {
			t.Error(err)
		}
	}()
	cmd := exec.Command("/bin/cat", "/proc/self/cgroup")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, UseCgroupFD: true, CgroupFD: int(g.fd.Fd())}
	raw, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(raw), filepath.Base(g.dir)) {
		t.Fatalf("atomic cgroup spawn failed: %v %s", err, raw)
	}
	limit, err := os.ReadFile(filepath.Join(g.dir, "pids.max"))
	if err != nil || strings.TrimSpace(string(limit)) != "32" {
		t.Fatal("task bound missing", string(limit), err)
	}
	t.Logf("cgroup spawn/limit/cleanup verified with effective UID %d", os.Geteuid())
}
