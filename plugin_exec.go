package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ExternalPlugin struct {
	Manifest  PluginManifest
	Params    map[string]any
	Guard     func(context.Context) (ScopeGuard, error)
	Budget    *Budget
	Store     *Store
	JobID     int64
	QueryRoot bool
}
type pluginOutput struct {
	mu          sync.Mutex
	writer      io.Writer
	limit, used int64
	exceeded    bool
	cancel      context.CancelFunc
}

func (w *pluginOutput) Write(raw []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.used+int64(len(raw)) > w.limit {
		w.exceeded = true
		w.cancel()
		return 0, errors.New("插件输出超限")
	}
	n, err := w.writer.Write(raw)
	w.used += int64(n)
	return n, err
}

type pluginStderr struct {
	mu   sync.Mutex
	data []byte
}

func (w *pluginStderr) Write(raw []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	left := 8192 - len(w.data)
	if left > 0 {
		w.data = append(w.data, raw[:min(left, len(raw))]...)
	}
	return len(raw), nil
}

var secretTextPattern = regexp.MustCompile(`(?i)(api[_-]?key|token|password|secret|authorization)(["'\s:=]+)[^\s,"'}]+`)
var querySecretPattern = regexp.MustCompile(`(?i)(https?://[^\s?]+\?)[^\s]+`)

func redactPluginStderr(raw []byte, secrets []string) string {
	text := strings.ToValidUTF8(string(raw), "")
	for _, secret := range secrets {
		if len(secret) >= 4 {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	text = querySecretPattern.ReplaceAllString(text, "${1}[redacted]")
	text = secretTextPattern.ReplaceAllString(text, "${1}=[redacted]")
	if len(text) > 8192 {
		text = text[:8192]
	}
	return strings.ToValidUTF8(text, "")
}
func (p *ExternalPlugin) Run(ctx context.Context, target string) (result PluginResult) {
	result = PluginResult{Records: []PluginRecord{}, RejectedFields: map[string]int{}, ExitCode: -1, deferJSONLValidation: true}
	m := p.Manifest
	var err error
	result.ErrorCode = "plugin_setup"
	defer func() {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				result.Error, result.ErrorCode, result.Retryable = "插件执行超时", "plugin_timeout", false
			} else {
				result.Error, result.ErrorCode, result.Retryable = "插件任务已取消", "cancelled", false
			}
		}
		if result.Error == "" {
			result.ErrorCode = ""
			result.Retryable = false
		}
		if p.Store != nil && result.RunID != 0 {
			saveCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			sample := result.Records[:min(50, len(result.Records))]
			raw, _ := json.Marshal(sample)
			p.Store.DB.Exec(saveCtx, "UPDATE plugin_runs SET finished_at=now(),exit_code=$2,returned=$3,in_scope=$4,stderr_excerpt=$5,error=$6,output_sample=$7,rejected_fields=$8,error_code=$9,retryable=$10 WHERE id=$1", result.RunID, result.ExitCode, result.Returned, result.InScope, result.Stderr, result.Error, raw, rejectedFieldsJSON(result.RejectedFields), result.ErrorCode, result.Retryable)
		}
	}()

	digestRaw, _ := json.Marshal(struct {
		Manifest    PluginManifest
		Args        []string
		Params      map[string]any
		Execution   any
		ConfigFiles []PluginConfigFile
	}{m, m.Exec.Args, p.Params, m.Exec, m.ConfigFiles})
	hash := sha256.Sum256(digestRaw)
	if p.Store != nil && p.JobID != 0 {
		err = p.Store.DB.QueryRow(ctx, "INSERT INTO plugin_runs(job_id,plugin,version,params_digest)VALUES($1,$2,$3,$4)RETURNING id", p.JobID, m.Name, m.Version, hex.EncodeToString(hash[:])).Scan(&result.RunID)
		if err != nil {
			result.setFailure(classifyExecutionError(err, "storage_failed"))
			result.Error = "插件运行记录写入失败"
			return result
		}
	}

	values, err := effectiveParams(m, p.Params)
	if err != nil {
		result.setFailure(classifyExecutionError(err, "plugin_config"))
		return result
	}
	if err := validatePluginPolicy(m); err != nil {
		result.ErrorCode, result.Error = "plugin_config", err.Error()
		return result
	}
	if m.Active {
		result.ErrorCode = "plugin_config"
		result.Error = "主动插件尚无受控出口，不允许执行"
		return result
	}
	target, err = normalizeHost(target)
	if err != nil {
		result.ErrorCode = "scope_denied"
		result.Error = "插件目标无效"
		return result
	}
	check := func(ctx context.Context) (ScopeGuard, error) {
		g, err := p.Guard(ctx)
		if err != nil {
			return g, err
		}
		if err = g.Valid(); err != nil {
			return g, err
		}
		if len(m.ScopeModes) > 0 && !slices.Contains(m.ScopeModes, g.Scope.Mode) {
			return g, executionFailure("scope_denied", "插件声明不支持当前范围模式", false)
		}
		if _, err := pluginRate(m, g.Scope.executionRPS()); err != nil {
			return g, executionFailure("plugin_config", err.Error(), false)
		}
		_, err = g.AllowHost(target)
		if err != nil && p.QueryRoot && target == g.Scope.Domain && g.Scope.Mode == "subdomains" {
			// A passive root query may enumerate authorized children, but must
			// still respect blacklists and exclusions on the query root.
			queryGuard := g
			queryGuard.Scope.Mode = "descendants"
			_, err = queryGuard.AllowHost(target)
		}
		return g, err
	}
	g, err := check(ctx)
	if err != nil {
		result.ErrorCode = "scope_denied"
		result.setFailure(classifyExecutionError(err, "scope_denied"))
		if result.ErrorCode == "scope_denied" {
			result.Error = "插件目标被范围校验拒绝"
		}
		return result
	}
	bin, err := trustedPluginBin(m.Exec.Bin, true)
	if err != nil {
		result.setFailure(classifyExecutionError(err, "plugin_config"))
		return result
	}
	dir, err := os.MkdirTemp("", "scopedesk-plugin-")
	if err != nil {
		result.setFailure(classifyExecutionError(err, "plugin_io"))
		result.Error = "插件临时目录创建失败"
		return result
	}
	defer os.RemoveAll(dir)
	if os.Chmod(dir, 0700) != nil {
		result.ErrorCode = "plugin_io"
		result.Error = "插件临时目录权限设置失败"
		return result
	}
	secrets, err := copyPluginConfigs(pluginConfigRoot, dir, m.ConfigFiles)
	if err != nil {
		result.setFailure(classifyExecutionError(err, "plugin_config"))
		return result
	}
	targetsFile := filepath.Join(dir, "targets.txt")
	outFile := filepath.Join(dir, "output")
	if os.WriteFile(targetsFile, []byte(target+"\n"), 0600) != nil {
		result.ErrorCode = "plugin_io"
		result.Error = "插件输入写入失败"
		return result
	}
	rate, _ := pluginRate(m, g.Scope.executionRPS())
	placeholders := map[string]string{"domain": target, "targets_file": targetsFile, "out_file": outFile, "rate": rate, "ports": "", "bandwidth": "", "wordlist": ""}
	for key, value := range values {
		placeholders[key], err = paramValue(m.Params[key], value)
		if err != nil {
			result.ErrorCode = "plugin_config"
			result.Error = "插件参数无效"
			return result
		}
	}
	if path := placeholders["wordlist"]; path != "" {
		real, err := filepath.EvalSymlinks(path)
		if err != nil || !strings.HasPrefix(real, "/opt/scopedesk-tools/wordlists/") {
			result.ErrorCode = "plugin_config"
			result.Error = "字典路径不在白名单目录"
			return result
		}
		info, err := os.Stat(real)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 16*1024*1024 {
			result.ErrorCode = "plugin_config"
			result.Error = "字典大小或类型无效"
			return result
		}
		raw, err := os.ReadFile(real)
		if err != nil {
			result.ErrorCode = "plugin_io"
			result.Error = "字典不可读取"
			return result
		}
		path = filepath.Join(dir, "wordlist")
		if os.WriteFile(path, raw, 0400) != nil {
			result.ErrorCode = "plugin_io"
			result.Error = "字典复制失败"
			return result
		}
		placeholders["wordlist"] = path
	}
	args := []string{}
	usesFile := false
	for _, arg := range m.Exec.Args {
		for _, match := range placeholderPattern.FindAllStringSubmatch(arg, -1) {
			if placeholders[match[1]] == "" {
				result.ErrorCode = "plugin_config"
				result.Error = "插件占位符缺少值"
				return result
			}
			if match[1] == "out_file" {
				usesFile = true
			}
		}
		args = append(args, placeholderPattern.ReplaceAllStringFunc(arg, func(token string) string { return placeholders[token[2:len(token)-2]] }))
	}
	fresh, err := check(ctx)
	if err != nil || fresh.Scope.executionRPS() != g.Scope.executionRPS() {
		result.ErrorCode = "scope_denied"
		if err != nil {
			result.setFailure(classifyExecutionError(err, "scope_denied"))
		}
		result.Error = "执行前授权已变更"
		return result
	}
	if p.Budget != nil {
		if err = p.Budget.Take(); err != nil {
			result.setFailure(executionFailure("budget_exhausted", err.Error(), false))
			return result
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	tasks, err := newPluginTaskGroup(pluginTaskLimit(m))
	if err != nil {
		result.ErrorCode, result.Error = "plugin_config", err.Error()
		return result
	}
	defer func() {
		if err := tasks.close(); err != nil {
			result.ErrorCode, result.Error, result.Retryable = "resource_cleanup", err.Error(), false
		}
	}()
	limits := []string{}
	keys := []string{}
	for key := range m.Exec.Limits {
		if key != "nproc" {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	for _, key := range keys {
		limits = append(limits, "--"+key+"="+strconv.FormatUint(m.Exec.Limits[key], 10))
	}
	limits = append(limits, "--", bin)
	limits = append(limits, args...)
	cmd := exec.CommandContext(runCtx, "/usr/bin/prlimit", limits...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "XDG_CONFIG_HOME=" + filepath.Join(dir, "config"), "TMPDIR=" + dir, "LANG=C.UTF-8"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, UseCgroupFD: true, CgroupFD: int(tasks.fd.Fd())}
	cmd.Cancel = func() error {
		return tasks.kill()
	}
	cmd.WaitDelay = 3 * time.Second
	reader, writer := io.Pipe()
	output := &pluginOutput{writer: writer, limit: m.Exec.MaxOutput, cancel: cancel}
	stderr := &pluginStderr{}
	cmd.Stdout = output
	cmd.Stderr = stderr
	parseDone := make(chan error, 1)
	go func() {
		parseErr := parsePluginStream(runCtx, reader, m, p.Guard, &result)
		if parseErr != nil {
			cancel()
		}
		reader.Close()
		parseDone <- parseErr
	}()
	watchDone := make(chan struct{})
	var watchWG sync.WaitGroup
	if usesFile {
		watchWG.Add(1)
		go func() {
			defer watchWG.Done()
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-watchDone:
					return
				case <-runCtx.Done():
					return
				case <-ticker.C:
					if info, err := os.Lstat(outFile); err == nil && (!info.Mode().IsRegular() || info.Size() > m.Exec.MaxOutput) {
						output.mu.Lock()
						output.exceeded = true
						output.mu.Unlock()
						cancel()
						return
					}
				}
			}
		}()
	}
	execErr := cmd.Run()
	// cgroup.kill also reaches descendants that escaped the original process group.
	killErr := tasks.kill()
	close(watchDone)
	watchWG.Wait()
	writer.Close()
	parseErr := <-parseDone
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if usesFile && execErr == nil && parseErr == nil && runCtx.Err() == nil {
		info, err := os.Lstat(outFile)
		if err != nil || !info.Mode().IsRegular() {
			parseErr = errors.New("插件输出文件无效")
		} else if info.Size()+output.used > m.Exec.MaxOutput {
			output.exceeded = true
		} else {
			file, err := os.Open(outFile)
			if err != nil {
				parseErr = errors.New("插件输出文件不可读取")
			} else {
				parseErr = parsePluginStream(runCtx, io.LimitReader(file, m.Exec.MaxOutput+1), m, p.Guard, &result)
				file.Close()
			}
		}
	}
	if parseErr == nil && m.Output.Format == "jsonl" {
		parseErr = validatePluginJSONL(&result)
	}
	result.Stderr = redactPluginStderr(stderr.data, secrets)
	switch {
	case killErr != nil:
		result.ErrorCode, result.Error = "resource_cleanup", "插件后代进程清理失败"
	case output.exceeded:
		result.ErrorCode = "output_limit"
		result.Error = "插件输出超过上限"
	case ctx.Err() != nil:
		result.ErrorCode = "cancelled"
		result.Error = "插件任务已取消"
	case parseErr != nil && !errors.Is(runCtx.Err(), context.DeadlineExceeded):
		result.setFailure(classifyExecutionError(parseErr, "invalid_output"))
	case runCtx.Err() != nil:
		result.ErrorCode = "plugin_timeout"
		result.Error = "插件超时或解析中止"
	case parseErr != nil:
		result.setFailure(classifyExecutionError(parseErr, "invalid_output"))
	case tasks.limitHit():
		result.ErrorCode, result.Error = "resource_limit", "插件独立任务数达到上限"
	case execErr != nil:
		result.ErrorCode = "exit_nonzero"
		result.Error = "插件非零退出或资源限制终止"
		if cmd.ProcessState == nil {
			result.setFailure(classifyExecutionError(execErr, "process_start"))
		} else if result.ExitCode < 0 {
			result.ErrorCode = "resource_limit"
		} else if slices.Contains(m.Exec.RetryExitCodes, result.ExitCode) {
			result.ErrorCode = "exit_retryable"
			result.Retryable = true
		}
	}

	return result
}
