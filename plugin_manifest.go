package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type PluginParam struct {
	Type    string  `yaml:"type" json:"type"`
	Max     float64 `yaml:"max" json:"max"`
	Enum    []any   `yaml:"enum" json:"enum,omitempty"`
	Default any     `yaml:"default" json:"default,omitempty"`
}
type PluginManifest struct {
	Name        string             `yaml:"name" json:"name"`
	Version     string             `yaml:"version" json:"version"`
	Kind        string             `yaml:"kind" json:"kind"`
	Mode        string             `yaml:"mode" json:"mode"`
	Active      bool               `yaml:"active" json:"active"`
	DNSOnly     bool               `yaml:"dns_only" json:"dns_only"`
	ScopeModes  []string           `yaml:"scope_modes" json:"scope_modes,omitempty"`
	ConfigFiles []PluginConfigFile `yaml:"config_files" json:"-"`
	Requires    struct {
		Caps   []string `yaml:"caps" json:"caps"`
		Labels []string `yaml:"worker_label" json:"worker_label"`
	} `yaml:"requires" json:"requires"`
	Exec struct {
		Bin            string            `yaml:"bin"`
		Args           []string          `yaml:"args"`
		Timeout        string            `yaml:"timeout"`
		MaxOutput      int64             `yaml:"max_output"`
		Limits         map[string]uint64 `yaml:"limits"`
		RetryExitCodes []int             `yaml:"retry_exit_codes"`
		RateFormat     string            `yaml:"rate_format"`
		TaskLimit      uint64            `yaml:"task_limit"`
	} `yaml:"exec" json:"-"`
	Input  string `yaml:"input" json:"input"`
	Output struct {
		Format       string            `yaml:"format" json:"format"`
		Mapping      map[string]string `yaml:"mapping" json:"mapping"`
		MaxLineBytes int64             `yaml:"max_line_bytes" json:"max_line_bytes,omitempty"`
	} `yaml:"output" json:"output"`
	Params  map[string]PluginParam `yaml:"params" json:"params"`
	Post    []string               `yaml:"post" json:"post"`
	timeout time.Duration
}

var placeholderPattern = regexp.MustCompile(`\{\{([a-zA-Z][a-zA-Z0-9_]*)\}\}`)
var pluginNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var paramNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)
var labelPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$`)
var reservedPlaceholders = []string{"domain", "targets_file", "wordlist", "out_file", "bandwidth", "rate", "ports"}

func trustedPluginBin(bin string, mustExist bool) (string, error) {
	root := "/opt/scopedesk-tools"
	if slices.Contains([]string{"sh", "bash", "dash", "zsh", "fish", "cmd", "powershell", "pwsh"}, filepath.Base(bin)) {
		return "", errors.New("不能将 shell 注册为插件")
	}
	if !filepath.IsAbs(bin) || filepath.Clean(bin) != bin || !strings.HasPrefix(bin, root+string(os.PathSeparator)) {
		return "", errors.New("插件路径不在白名单目录")
	}
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil {
		if !mustExist && os.IsNotExist(err) {
			return bin, nil
		}
		return "", errors.New("插件程序未安装或不可访问")
	}
	if !strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
		return "", errors.New("插件符号链接越出白名单目录")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("插件程序不可执行")
	}
	return resolved, nil
}
func parseManifest(raw []byte) (PluginManifest, error) {
	var m PluginManifest
	if len(raw) > 262144 {
		return m, errors.New("manifest 超过 256 KB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&m); err != nil {
		return m, errors.New("manifest YAML 字段或类型无效")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return m, errors.New("manifest 只允许一个文档")
	}
	if !pluginNamePattern.MatchString(m.Name) || slices.Contains([]string{"crtsh", "certspotter", "fofa", "hunter", "builtin-dns", "builtin-http"}, m.Name) {
		return m, errors.New("插件名称无效或保留")
	}
	if m.Mode != "external" || !slices.Contains([]string{"collector", "observer"}, m.Kind) {
		return m, errors.New("插件 mode/kind 不支持")
	}
	if m.Input != "domain" && m.Input != "targets_file" {
		return m, errors.New("插件 input 不支持")
	}
	if _, err := trustedPluginBin(m.Exec.Bin, false); err != nil {
		return m, err
	}
	if len(m.Exec.Args) == 0 || len(m.Exec.Args) > 128 {
		return m, errors.New("插件 args 须为非空数组，最多 128 项")
	}
	timeout, err := time.ParseDuration(m.Exec.Timeout)
	if err != nil || timeout <= 0 || timeout > 15*time.Minute {
		return m, errors.New("timeout 必填且不超过 15 分钟")
	}
	m.timeout = timeout
	if len(m.Exec.RetryExitCodes) > 32 {
		return m, errors.New("retry_exit_codes 最多 32 项")
	}
	seenExit := map[int]bool{}
	for _, code := range m.Exec.RetryExitCodes {
		if code < 1 || code > 255 || seenExit[code] {
			return m, errors.New("retry_exit_codes 必须为不重复的 1–255 退出码")
		}
		seenExit[code] = true
	}
	if m.Exec.MaxOutput <= 0 || m.Exec.MaxOutput > 64*1024*1024 {
		return m, errors.New("max_output 必填且不超过 64 MB")
	}
	for key, value := range m.Exec.Limits {
		if !slices.Contains([]string{"cpu", "as", "nproc", "fsize", "nofile"}, key) || value == 0 {
			return m, errors.New("资源限制名称或数值无效")
		}
	}
	if !slices.Contains([]string{"jsonl", "lines", "json"}, m.Output.Format) || m.Output.Mapping["host"] == "" {
		return m, errors.New("输出格式无效或缺少 host 映射")
	}
	for field, path := range m.Output.Mapping {
		if !slices.Contains([]string{"host", "ip", "port", "protocol", "service", "banner", "scheme", "status_code", "title", "server", "tls_subject", "favicon_sha256"}, field) || len(path) > 128 || path == "" {
			return m, errors.New("输出映射字段无效")
		}
	}
	for _, post := range m.Post {
		if !slices.Contains([]string{"normalize", "deduplicate", "scope_guard"}, post) {
			return m, errors.New("不支持脚本或未知 post 操作")
		}
	}
	for _, label := range append(slices.Clone(m.Requires.Labels), m.Requires.Caps...) {
		if !labelPattern.MatchString(label) {
			return m, errors.New("能力或 worker 标签无效")
		}
	}
	for _, cap := range m.Requires.Caps {
		if !slices.Contains([]string{"net_raw", "net_admin"}, cap) {
			return m, errors.New("未支持的 Linux capability")
		}
	}
	for name, param := range m.Params {
		if !paramNamePattern.MatchString(name) || slices.Contains([]string{"domain", "targets_file", "out_file", "rate"}, name) {
			return m, errors.New("参数名称无效或覆盖保留占位符")
		}
		if !slices.Contains([]string{"string", "integer", "number", "boolean", "string_array"}, param.Type) || param.Max < 0 || math.IsNaN(param.Max) || math.IsInf(param.Max, 0) {
			return m, errors.New("参数 type/max 无效")
		}
		if (param.Type == "string" || param.Type == "string_array") && param.Max <= 0 && len(param.Enum) == 0 {
			return m, errors.New("字符串参数须限制 max 或 enum")
		}
		if param.Default != nil {
			if _, err := paramValue(param, param.Default); err != nil {
				return m, fmt.Errorf("参数 %s 默认值无效", name)
			}
		}
		for _, value := range param.Enum {
			check := param
			check.Enum = nil
			if _, err := paramValue(check, value); err != nil {
				return m, fmt.Errorf("参数 %s 枚举值无效", name)
			}
		}
	}
	for _, arg := range m.Exec.Args {
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
			return m, errors.New("参数过长或包含空字符")
		}
		for _, match := range placeholderPattern.FindAllStringSubmatch(arg, -1) {
			if _, ok := m.Params[match[1]]; !ok && !slices.Contains(reservedPlaceholders, match[1]) {
				return m, errors.New("未知占位符")
			}
		}
		rest := placeholderPattern.ReplaceAllString(arg, "")
		if strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
			return m, errors.New("占位符格式无效")
		}
	}
	if m.Params == nil {
		m.Params = map[string]PluginParam{}
	}
	if err := validatePluginPolicy(m); err != nil {
		return m, err
	}
	return m, nil
}
func paramValue(p PluginParam, value any) (string, error) {
	invalid := errors.New("插件参数不符合 type/max/enum")
	text := ""
	switch p.Type {
	case "string":
		v, ok := value.(string)
		if !ok || strings.ContainsRune(v, 0) || (p.Max > 0 && float64(len([]rune(v))) > p.Max) {
			return "", invalid
		}
		text = v
	case "integer", "number":
		switch value.(type) {
		case int, int32, int64, uint, uint32, uint64, float32, float64, json.Number:
		default:
			return "", invalid
		}
		v, err := strconv.ParseFloat(fmt.Sprint(value), 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || (p.Type == "integer" && math.Trunc(v) != v) || (p.Max > 0 && v > p.Max) || v < 0 {
			return "", invalid
		}
		text = strconv.FormatFloat(v, 'f', -1, 64)
	case "boolean":
		v, ok := value.(bool)
		if !ok {
			return "", invalid
		}
		text = strconv.FormatBool(v)
	case "string_array":
		raw, err := jsonStrings(value)
		if err != nil || (p.Max > 0 && float64(len(raw)) > p.Max) {
			return "", invalid
		}
		text = strings.Join(raw, ",")
	default:
		return "", invalid
	}
	if len(p.Enum) > 0 {
		found := false
		for _, v := range p.Enum {
			if fmt.Sprint(v) == fmt.Sprint(value) {
				found = true
			}
		}
		if !found {
			return "", invalid
		}
	}
	if len(p.Enum) == 0 && strings.HasPrefix(text, "-") {
		return "", invalid
	}
	return text, nil
}
func jsonStrings(v any) ([]string, error) {
	if values, ok := v.([]string); ok {
		return values, nil
	}
	values, ok := v.([]any)
	if !ok {
		return nil, errors.New("须为字符串数组")
	}
	out := []string{}
	for _, v := range values {
		s, ok := v.(string)
		if !ok || len(s) > 4096 || strings.ContainsRune(s, 0) {
			return nil, errors.New("须为字符串数组")
		}
		out = append(out, s)
	}
	return out, nil
}
func effectiveParams(m PluginManifest, override map[string]any) (map[string]any, error) {
	values := map[string]any{}
	for key, p := range m.Params {
		if p.Default != nil {
			values[key] = p.Default
		}
	}
	for key, value := range override {
		if _, ok := m.Params[key]; !ok {
			return nil, errors.New("参数未声明")
		}
		values[key] = value
	}
	for key, value := range values {
		if _, err := paramValue(m.Params[key], value); err != nil {
			return nil, fmt.Errorf("参数 %s 无效", key)
		}
	}
	return values, nil
}
