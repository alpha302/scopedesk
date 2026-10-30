package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const pluginCgroupUnavailable = "插件需要 cgroup v2 pids 委派；请配置 Delegate=pids 和 DelegateSubgroup=supervisor"

type pluginTaskGroup struct {
	dir string
	fd  *os.File
}

func pluginCgroupParent() (string, error) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", errors.New(pluginCgroupUnavailable)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		relative := strings.TrimPrefix(line, "0::")
		if filepath.Clean(relative) != relative || filepath.Base(relative) != "supervisor" {
			break
		}
		parent := filepath.Dir(filepath.Join("/sys/fs/cgroup", relative))
		if !strings.HasPrefix(parent, "/sys/fs/cgroup/") {
			break
		}
		controllers, err := os.ReadFile(filepath.Join(parent, "cgroup.controllers"))
		if err != nil || !slices.Contains(strings.Fields(string(controllers)), "pids") || syscall.Access(parent, 2) != nil {
			break
		}
		return parent, nil
	}
	return "", errors.New(pluginCgroupUnavailable)
}

func newPluginTaskGroup(limit uint64) (*pluginTaskGroup, error) {
	if limit == 0 || limit > 65536 {
		return nil, errors.New("插件任务数限制无效")
	}
	parent, err := pluginCgroupParent()
	if err != nil {
		return nil, err
	}
	// The supervisor subgroup keeps processes out of this delegated inner node.
	if err = os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+pids"), 0); err != nil {
		return nil, errors.New(pluginCgroupUnavailable)
	}
	dir := filepath.Join(parent, "plugin-"+random()[:24])
	if err = os.Mkdir(dir, 0700); err != nil {
		return nil, errors.New("插件独立 cgroup 创建失败")
	}
	if err = os.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.FormatUint(limit, 10)), 0); err != nil {
		os.Remove(dir)
		return nil, errors.New("插件任务数限制设置失败")
	}
	// Require atomic subtree termination before any plugin is launched.
	killer, err := os.OpenFile(filepath.Join(dir, "cgroup.kill"), os.O_WRONLY, 0)
	if err != nil {
		os.Remove(dir)
		return nil, errors.New("插件需要可写的 cgroup.kill，当前内核或委派配置不支持")
	}
	killer.Close()
	fd, err := os.Open(dir)
	if err != nil {
		os.Remove(dir)
		return nil, errors.New("插件 cgroup 不可打开")
	}
	return &pluginTaskGroup{dir: dir, fd: fd}, nil
}

func (g *pluginTaskGroup) kill() error {
	return os.WriteFile(filepath.Join(g.dir, "cgroup.kill"), []byte("1"), 0)
}

func (g *pluginTaskGroup) limitHit() bool {
	raw, err := os.ReadFile(filepath.Join(g.dir, "pids.events"))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(raw))
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i] == "max" {
			n, _ := strconv.ParseUint(fields[i+1], 10, 64)
			return n > 0
		}
	}
	return false
}

func (g *pluginTaskGroup) close() error {
	err := g.kill()
	g.fd.Close()
	if err != nil {
		return errors.New("插件后代进程清理失败")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err = os.Remove(g.dir); err == nil || os.IsNotExist(err) {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("插件 cgroup 未能完成清理")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
