package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

type PluginPlanReference struct {
	ScopeID int64      `json:"scope_id"`
	Domain  string     `json:"domain"`
	Owner   int        `json:"owner"`
	Enabled bool       `json:"enabled"`
	Next    *time.Time `json:"next_run_at"`
}

func (s *Store) pluginPlanReferences(ctx context.Context) (map[string][]PluginPlanReference, error) {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT collector.name,p.scope_id,s.domain,s.owner,p.enabled,p.next_run_at
 FROM monitor_plans p JOIN scopes s ON s.id=p.scope_id
 CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(p.collectors)='array' THEN p.collectors ELSE '[]'::jsonb END) AS collector(name)
 ORDER BY p.scope_id,collector.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]PluginPlanReference{}
	for rows.Next() {
		var name string
		var ref PluginPlanReference
		if err = rows.Scan(&name, &ref.ScopeID, &ref.Domain, &ref.Owner, &ref.Enabled, &ref.Next); err != nil {
			return nil, err
		}
		out[name] = append(out[name], ref)
	}
	return out, rows.Err()
}

func (e *Engine) collectorOptions(ctx context.Context) []string {
	out := []string{"crtsh", "certspotter", "fofa", "hunter"}
	if e.Store.Plugins == nil {
		return append(out, "subfinder")
	}
	for _, name := range e.Store.Plugins.names() {
		m, _, enabled, err := e.Store.pluginConfig(ctx, name)
		if err == nil && enabled && !m.Active {
			out = append(out, name)
		}
	}
	return out
}

func (e *Engine) validSources(sources []string) error {
	if e.Store.Plugins == nil {
		return validSources(sources)
	}
	if len(sources) == 0 || len(sources) > 32 {
		return errors.New("请选择 1–32 个来源")
	}
	seen := map[string]bool{}
	for _, source := range sources {
		if seen[source] {
			return errors.New("来源重复")
		}
		seen[source] = true
		if !builtinPassive(source) {
			if _, ok := e.Store.Plugins.Manifests[source]; !ok {
				return errors.New("来源未注册")
			}
		}
	}
	return nil
}
func (e *Engine) workerHeartbeat(ctx context.Context) {
	labels := routingLabels(e.Labels, e.Capabilities)
	if labels == nil {
		labels = []string{}
	}
	caps := e.Capabilities
	if caps == nil {
		caps = []string{}
	}
	e.Store.DB.Exec(ctx, `INSERT INTO workers(id,version,host,heartbeat_at,concurrency,active_jobs,labels,capabilities)VALUES($1,'0.3',$2,now(),$3,$4,$5,$6)
 ON CONFLICT(id)DO UPDATE SET heartbeat_at=now(),active_jobs=excluded.active_jobs,labels=excluded.labels,capabilities=excluded.capabilities,version=excluded.version`, e.WorkerID, strings.Split(e.WorkerID, "-")[0], e.workers, e.activeCount(), labels, caps)
}
func (e *Engine) servePlugins(w http.ResponseWriter, r *http.Request, u User) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/api/plugins")
	if path == "" && r.Method == "GET" {
		references, err := e.Store.pluginPlanReferences(ctx)
		if err != nil {
			fail(w, 500, "读取插件计划引用失败")
			return
		}
		health := pluginHealth()
		out := []map[string]any{}
		for _, item := range health {
			if item["name"] != "subfinder" || e.Store.Plugins == nil {
				item["enabled"] = true
				item["version"] = "builtin"
				out = append(out, item)
			}
		}
		if e.Store.Plugins != nil {
			for _, name := range e.Store.Plugins.names() {
				m, params, enabled, err := e.Store.pluginConfig(ctx, name)
				reason := ""
				_, binErr := trustedPluginBin(m.Exec.Bin, true)
				_, resourceErr := pluginCgroupParent()
				if binErr != nil {
					reason = binErr.Error()
				}
				if err != nil {
					reason = "插件配置无效"
				}
				if m.Active {
					reason = "主动插件缺少受控出口适配器"
				}
				if reason == "" && resourceErr != nil {
					reason = resourceErr.Error()
				}
				labels := slices.Clone(m.Requires.Labels)
				for _, cap := range m.Requires.Caps {
					labels = append(labels, "cap:"+cap)
				}
				out = append(out, map[string]any{"name": name, "kind": m.Kind, "mode": m.Mode, "path": m.Exec.Bin, "available": reason == "", "health": reason, "version": m.Version, "enabled": enabled, "params": m.Params, "defaults": params, "active": m.Active, "dns_only": m.DNSOnly, "required_labels": labels, "note": "manifest 插件；内部网络请求由可信工具控制，不计入平台精确请求数"})
				out[len(out)-1]["retry_exit_codes"] = append([]int{}, m.Exec.RetryExitCodes...)
				out[len(out)-1]["resource_control"] = map[string]any{"kind": "cgroup_v2_pids", "available": resourceErr == nil, "task_limit": pluginTaskLimit(m)}
			}
		}
		for _, item := range out {
			refs := references[item["name"].(string)]
			if refs == nil {
				refs = []PluginPlanReference{}
			}
			enabled := 0
			for _, ref := range refs {
				if ref.Enabled {
					enabled++
				}
			}
			item["plan_references"], item["plan_count"], item["enabled_plan_count"] = refs, len(refs), enabled
		}
		respond(w, 200, out)
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || e.Store.Plugins == nil {
		fail(w, 404, "插件不存在")
		return
	}
	name := parts[0]
	m, params, enabled, err := e.Store.pluginConfig(ctx, name)
	if err != nil {
		apiError(w, err)
		return
	}
	if len(parts) == 1 && r.Method == "PUT" {
		var body struct {
			Enabled bool           `json:"enabled"`
			Params  map[string]any `json:"params"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.Enabled {
			if m.Active {
				fail(w, 400, "主动插件尚无受控出口，不允许启用")
				return
			}
			if _, err = trustedPluginBin(m.Exec.Bin, true); err != nil {
				apiError(w, err)
				return
			}
		}
		values, err := effectiveParams(m, body.Params)
		if err != nil {
			apiError(w, err)
			return
		}
		raw, _ := json.Marshal(values)
		_, err = e.Store.DB.Exec(ctx, "UPDATE plugin_settings SET enabled=$2,params=$3,updated_at=now()WHERE name=$1", name, body.Enabled, raw)
		if err != nil {
			fail(w, 500, "插件设置保存失败")
			return
		}
		e.Store.operation(ctx, u.ID, "plugin.configure", name)
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	if len(parts) == 2 && parts[1] == "test" && r.Method == "POST" {
		var body struct {
			ScopeID int64          `json:"scope_id"`
			Target  string         `json:"target"`
			Params  map[string]any `json:"params"`
		}
		if !decode(w, r, &body) {
			return
		}
		g, err := e.Store.guard(ctx, body.ScopeID)
		if err != nil || g.Scope.Owner != u.ID {
			fail(w, 403, "测试范围必须属于当前管理员")
			return
		}
		target, err := g.AllowHost(body.Target)
		if err != nil {
			fail(w, 400, "测试目标不在有效授权范围内")
			return
		}
		if !enabled || m.Active {
			fail(w, 400, "插件未启用或不允许主动执行")
			return
		}
		if _, err = trustedPluginBin(m.Exec.Bin, true); err != nil {
			apiError(w, err)
			return
		}
		for key, value := range body.Params {
			params[key] = value
		}
		params, err = effectiveParams(m, params)
		if err != nil {
			apiError(w, err)
			return
		}
		labels, err := e.Store.requiredPluginLabels(ctx, []string{name})
		if err != nil {
			apiError(w, err)
			return
		}
		payload, _ := json.Marshal(map[string]any{"sources": []string{name}, "target": target, "params": params})
		budget, budgetErr := jobExecutionBudget([]string{name}, "plugin_test", e.Store.Plugins)
		if budgetErr != nil {
			apiError(w, budgetErr)
			return
		}
		tx, err := e.Store.DB.Begin(ctx)
		if err != nil {
			apiError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		fresh, err := lockScopeProject(ctx, tx, body.ScopeID, false)
		if err != nil {
			apiError(w, err)
			return
		}
		if fresh.Scope.Owner != u.ID {
			fail(w, 403, "测试范围必须属于当前管理员")
			return
		}
		if _, err = fresh.AllowHost(target); err != nil {
			apiError(w, err)
			return
		}
		var job int64
		err = tx.QueryRow(ctx, "INSERT INTO jobs(scope_id,owner,trigger,payload,required_labels,execution_timeout_seconds)VALUES($1,$2,'plugin_test',$3,$4,$5)RETURNING id", body.ScopeID, u.ID, payload, labels, int((budget+time.Second-1)/time.Second)).Scan(&job)
		if err != nil {
			fail(w, 409, "该范围已有未结束的插件测试，或测试任务写入失败")
			return
		}
		if err = tx.Commit(ctx); err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(ctx, u.ID, "plugin.test", name)
		respond(w, 202, map[string]any{"job": job, "message": "测试已独立入队，按 worker 标签运行；排队超过 10 分钟自动取消，结果可在插件页查看"})
		return
	}
	if len(parts) == 2 && parts[1] == "runs" && r.Method == "GET" {
		list, err := queryJSON(ctx, e.Store.DB, `SELECT to_jsonb(v)FROM(SELECT p.* FROM plugin_runs p JOIN jobs j ON j.id=p.job_id WHERE p.plugin=$1 ORDER BY p.id DESC LIMIT 20)v`, name)
		if err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, list)
		return
	}
	fail(w, 405, "不支持的插件操作")
}
func (e *Engine) executePluginTest(ctx context.Context, run Run, g ScopeGuard) {
	if len(run.Sources) != 1 || run.Owner != g.Scope.Owner {
		e.finish(run, "failed", "插件测试范围所有权不匹配", nil)
		return
	}
	m, _, enabled, err := e.Store.pluginConfig(ctx, run.Sources[0])
	if err != nil || !enabled {
		e.finish(run, "failed", "插件未注册或已停用", nil)
		return
	}
	// Recheck on the worker as well as at enqueue time. A queued scope may change.
	if _, err = g.AllowHost(run.Target); err != nil {
		e.finish(run, "failed", "测试目标不在有效范围", nil)
		return
	}
	required, err := e.Store.requiredPluginLabels(ctx, run.Sources)
	if err != nil || !labelsContain(routingLabels(e.Labels, e.Capabilities), required) {
		e.finish(run, "failed", "worker 能力不满足插件要求", nil)
		return
	}
	plugin := ExternalPlugin{Manifest: m, Params: run.Params, Store: e.Store, JobID: run.ID, Budget: &Budget{Limit: g.Scope.RequestLimit}, Guard: func(c context.Context) (ScopeGuard, error) { return e.Store.guard(c, run.ScopeID) }}
	result := plugin.Run(ctx, run.Target)
	status := "done"
	if result.Error != "" {
		status = "failed"
	}
	stats := []SourceStats{{Source: m.Name, Returned: result.Returned, InScope: result.InScope, Discarded: result.Returned - result.InScope, Attempts: 1, Error: result.Error, ErrorCode: result.ErrorCode, Retryable: result.Retryable, RejectedFields: result.RejectedFields}}
	if ctx.Err() != nil {
		e.finishStopped(ctx, run, stats)
		return
	}
	if result.ErrorCode == "cancelled" {
		status = "cancelled"
	}
	e.finish(run, status, result.Error, stats, map[string]any{"plugin_test": true, "plugin_run": result.RunID, "returned": result.Returned, "in_scope": result.InScope, "results": result.Records[:min(50, len(result.Records))], "sources": stats, "error_code": result.ErrorCode, "retryable": result.Retryable})
}
func labelsContain(worker, required []string) bool {
	for _, label := range required {
		if !slices.Contains(worker, label) {
			return false
		}
	}
	return true
}
func (e *Engine) updatePluginNewCounts(ctx context.Context, run Run, results []PluginResult) {
	// Attribute each asset once per plugin, to its latest successful/partial invocation.
	credited := map[string]bool{}
	for i := len(results) - 1; i >= 0; i-- {
		result := results[i]
		if result.RunID == 0 || result.Error != "" {
			continue
		}
		hosts := []string{}
		for _, record := range result.Records {
			key := record.Candidate.Source + ":" + record.Candidate.Host
			if !credited[key] {
				hosts = append(hosts, record.Candidate.Host)
				credited[key] = true
			}
		}
		e.Store.DB.Exec(ctx, `UPDATE plugin_runs SET new_count=(SELECT count(*)FROM assets a WHERE a.scope_id=$2 AND a.host=ANY($3::text[])AND EXISTS(SELECT 1 FROM asset_events ev WHERE ev.asset_id=a.id AND ev.job_id=$4 AND ev.type='NEW_ASSET'))WHERE id=$1`, result.RunID, run.ScopeID, hosts, run.ID)
	}
}
