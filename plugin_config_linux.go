package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

const pluginConfigRoot = "/var/lib/scopedesk-go/plugins"
const pluginConfigMaxBytes = 1024 * 1024

// Open each component relative to a pinned directory FD, refusing symlinks.
// NONBLOCK prevents a substituted FIFO from blocking configuration loading.
func openPluginConfig(root, relative string) (*os.File, error) {
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(relative, "/")
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(fd, part, flags, 0)
		syscall.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), relative), nil
}

func copyPluginConfigs(root, dir string, files []PluginConfigFile) ([]string, error) {
	// Check again for callers constructing manifests in memory.
	if err := validatePluginPolicy(PluginManifest{ConfigFiles: files}); err != nil {
		return nil, err
	}
	secrets := []string{}
	for _, mapping := range files {
		file, err := openPluginConfig(root, mapping.Source)
		if errors.Is(err, syscall.ENOENT) && mapping.Optional {
			continue
		}
		if err != nil {
			return nil, errors.New("插件配置不可读取或包含符号链接")
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() > pluginConfigMaxBytes {
			file.Close()
			return nil, errors.New("插件配置类型或大小无效")
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, pluginConfigMaxBytes+1))
		file.Close()
		if readErr != nil || len(raw) > pluginConfigMaxBytes {
			return nil, errors.New("插件配置读取失败或超过 1 MB")
		}
		destination := filepath.Join(dir, mapping.Destination)
		if os.MkdirAll(filepath.Dir(destination), 0700) != nil || os.WriteFile(destination, raw, 0600) != nil {
			return nil, errors.New("插件配置复制失败")
		}
		var value any
		if yaml.Unmarshal(raw, &value) == nil {
			var visit func(any)
			visit = func(v any) {
				switch x := v.(type) {
				case string:
					secrets = append(secrets, x)
				case []any:
					for _, n := range x {
						visit(n)
					}
				case map[string]any:
					for _, n := range x {
						visit(n)
					}
				}
			}
			visit(value)
		}
	}
	return secrets, nil
}
