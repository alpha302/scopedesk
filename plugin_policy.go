package main

import (
	"errors"
	"math"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type PluginConfigFile struct {
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
	Optional    bool   `yaml:"optional"`
}

func safePluginRelativePath(path string) bool {
	return path != "" && len(path) <= 256 && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != "." && path != ".." && !strings.HasPrefix(path, "../") && !strings.ContainsAny(path, "\\\x00:")
}

func validatePluginPolicy(m PluginManifest) error {
	if !slices.Contains([]string{"", "number", "integer"}, m.Exec.RateFormat) {
		return errors.New("rate_format 仅支持 number 或 integer")
	}
	seen := map[string]bool{}
	for _, mode := range m.ScopeModes {
		if !slices.Contains([]string{"exact", "subdomains", "descendants", "cidr"}, mode) || seen[mode] {
			return errors.New("scope_modes 无效或重复")
		}
		seen[mode] = true
	}
	if m.Exec.TaskLimit > 65536 || m.Exec.Limits["nproc"] > 65536 {
		return errors.New("插件任务数上限不超过 65536")
	}
	if m.Output.MaxLineBytes < 0 || m.Output.MaxLineBytes > min(m.Exec.MaxOutput, int64(4*1024*1024)) {
		return errors.New("max_line_bytes 不得超过 max_output 或 4 MB")
	}
	if len(m.ConfigFiles) > 16 {
		return errors.New("配置文件映射不超过 16 项")
	}
	seen = map[string]bool{}
	for _, file := range m.ConfigFiles {
		if !safePluginRelativePath(file.Source) || !safePluginRelativePath(file.Destination) || !strings.HasPrefix(file.Destination, "config/") || seen[file.Destination] {
			return errors.New("配置文件路径无效、目标重复或不在 config 目录")
		}
		seen[file.Destination] = true
	}
	return nil
}

func pluginRate(m PluginManifest, rps float64) (string, error) {
	if rps <= 0 || math.IsNaN(rps) || math.IsInf(rps, 0) {
		return "", errors.New("插件速率必须为有限正数")
	}
	if m.Exec.RateFormat == "integer" {
		if rps < 1 {
			return "", errors.New("插件声明整数速率，当前范围低于 1 RPS")
		}
		rps = math.Floor(rps)
	}
	return strconv.FormatFloat(rps, 'f', -1, 64), nil
}

func pluginTaskLimit(m PluginManifest) uint64 {
	limit := m.Exec.TaskLimit
	if limit == 0 {
		limit = 512
	}
	// Legacy nproc remains accepted, but now limits just this invocation's cgroup.
	if legacy := m.Exec.Limits["nproc"]; legacy > 0 && (m.Exec.TaskLimit == 0 || legacy < limit) {
		limit = legacy
	}
	return limit
}

func pluginMaxLineBytes(m PluginManifest) int64 {
	limit := min(m.Exec.MaxOutput, int64(4*1024*1024))
	if m.Output.MaxLineBytes > 0 {
		limit = min(limit, m.Output.MaxLineBytes)
	}
	return limit
}
