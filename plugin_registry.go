package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

//go:embed plugins/*.yaml
var defaultPluginFiles embed.FS

type PluginRegistry struct{ Manifests map[string]PluginManifest }

func loadPluginRegistry(dir string) (*PluginRegistry, error) {
	registry := &PluginRegistry{Manifests: map[string]PluginManifest{}}
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, errors.New("插件目录无效")
	}
	rawFiles := map[string][]byte{}
	if _, err = os.Stat(dir); os.IsNotExist(err) {
		raw, _ := defaultPluginFiles.ReadFile("plugins/subfinder.yaml")
		rawFiles["subfinder.yaml"] = raw
	} else {
		for _, path := range paths {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 262144 {
				return nil, errors.New("插件配置须为普通文件且不超过 256 KB")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, errors.New("无法读取插件配置")
			}
			rawFiles[filepath.Base(path)] = raw
		}
	}
	for filename, raw := range rawFiles {
		m, err := parseManifest(raw)
		if err != nil {
			return nil, errors.New(filename + ": " + err.Error())
		}
		if _, ok := registry.Manifests[m.Name]; ok {
			return nil, errors.New("插件名称重复")
		}
		registry.Manifests[m.Name] = m
	}
	return registry, nil
}
func (r *PluginRegistry) names() []string {
	names := []string{}
	if r != nil {
		for name := range r.Manifests {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}
func (s *Store) pluginConfig(ctx context.Context, name string) (PluginManifest, map[string]any, bool, error) {
	if s.Plugins == nil {
		return PluginManifest{}, nil, false, errors.New("插件注册表未加载")
	}
	m, ok := s.Plugins.Manifests[name]
	if !ok {
		return m, nil, false, errors.New("插件未注册")
	}
	var enabled bool
	var raw []byte
	if err := s.DB.QueryRow(ctx, "SELECT enabled,params FROM plugin_settings WHERE name=$1", name).Scan(&enabled, &raw); err != nil {
		return m, nil, false, errors.New("插件设置不可用")
	}
	var overrides map[string]any
	if json.Unmarshal(raw, &overrides) != nil {
		return m, nil, false, errors.New("插件设置格式无效")
	}
	values, err := effectiveParams(m, overrides)
	return m, values, enabled, err
}
func (s *Store) initializePlugins(ctx context.Context, r *PluginRegistry) error {
	s.Plugins = r
	for _, name := range r.names() {
		if _, err := s.DB.Exec(ctx, "INSERT INTO plugin_settings(name)VALUES($1)ON CONFLICT DO NOTHING", name); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) requiredPluginLabels(ctx context.Context, sources []string) ([]string, error) {
	labels := []string{}
	for _, name := range sources {
		if builtinPassive(name) {
			continue
		}
		if s.Plugins == nil {
			if name == "subfinder" {
				continue
			}
			return nil, errors.New("插件未注册")
		}
		m, _, enabled, err := s.pluginConfig(ctx, name)
		if err != nil {
			return nil, err
		}
		if !enabled {
			return nil, errors.New("所选插件已停用")
		}
		if m.Active {
			return nil, errors.New("主动插件尚无受控出口，不允许启用")
		}
		labels = append(labels, m.Requires.Labels...)
		for _, cap := range m.Requires.Caps {
			labels = append(labels, "cap:"+cap)
		}
	}
	slices.Sort(labels)
	return slices.Compact(labels), nil
}
func workerLabels(args []string) ([]string, error) {
	labels := []string{"default"}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--labels=") {
			labels = nil
			for _, label := range strings.Split(strings.TrimPrefix(arg, "--labels="), ",") {
				if label == "" {
					continue
				}
				if !labelPattern.MatchString(label) || strings.HasPrefix(label, "cap:") {
					return nil, errors.New("worker 标签无效")
				}
				labels = append(labels, label)
			}
		}
	}
	slices.Sort(labels)
	return slices.Compact(labels), nil
}
func actualCapabilities() []string {
	raw, _ := os.ReadFile("/proc/self/status")
	var effective uint64
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			effective, _ = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		}
	}
	out := []string{}
	if effective&(1<<13) != 0 {
		out = append(out, "net_raw")
	}
	if effective&(1<<12) != 0 {
		out = append(out, "net_admin")
	}
	return out
}
func routingLabels(labels, caps []string) []string {
	out := slices.Clone(labels)
	for _, cap := range caps {
		out = append(out, "cap:"+cap)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
