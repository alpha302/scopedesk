package main

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func (e *Engine) handles(path string) bool {
	for _, p := range []string{"/api/explorations", "/api/projects", "/api/workspaces", "/api/scopes", "/api/assets", "/api/jobs", "/api/events", "/api/settings/", "/api/digest/", "/api/dashboard/", "/api/plugins", "/api/blacklist", "/api/security-rules"} {
		if path == p || strings.HasPrefix(path, p+"/") || strings.HasSuffix(p, "/") && strings.HasPrefix(path, p) {
			return true
		}
	}
	return slices.Contains([]string{"/api/state", "/api/collect", "/api/import", "/api/export"}, path)
}
func apiError(w http.ResponseWriter, e error) {
	if errors.Is(e, pgx.ErrNoRows) {
		fail(w, 404, "记录不存在或没有访问权限")
		return
	}
	fail(w, 400, safeError(e))
}
func (e *Engine) access(ctx context.Context, id int64, u User, writing ...bool) (ScopeV2, error) {
	v, err := e.Store.scopesByID(ctx, id)
	if err != nil {
		return v, err
	}
	write := len(writing) > 0 && writing[0]
	if u.Role == "readonly" && write {
		return v, pgx.ErrNoRows
	}
	if err = e.Store.projectPermission(ctx, v.ProjectID, u, write, false); err != nil {
		return v, err
	}
	return v, nil
}
func (e *Engine) serve(w http.ResponseWriter, r *http.Request, u User) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	path := r.URL.Path
	write := r.Method != "GET"
	if write && u.Role == "readonly" {
		fail(w, 403, "只读用户不能修改或执行任务")
		return
	}
	if strings.HasPrefix(path, "/api/settings/") || strings.HasPrefix(path, "/api/digest/") || strings.HasPrefix(path, "/api/plugins") || strings.HasPrefix(path, "/api/blacklist") || path == "/api/security-rules" {
		if u.Role != "admin" {
			fail(w, 403, "需要管理员权限")
			return
		}
	}
	switch {
	case path == "/api/settings/passive-accounts" || path == "/api/settings/passive-accounts/batch" || path == "/api/settings/passive-accounts/check" || path == "/api/settings/passive-budgets" || path == "/api/settings/passive-queries":
		e.servePassive(w, r.WithContext(ctx), u)
		return
	case path == "/api/explorations" || strings.HasPrefix(path, "/api/explorations/"):
		e.serveEnterprise(w, r.WithContext(ctx), u)
		return
	case path == "/api/projects" || strings.HasPrefix(path, "/api/projects/") || path == "/api/workspaces" || strings.HasPrefix(path, "/api/workspaces/"):
		e.serveProjects(w, r.WithContext(ctx), u)
		return
	case path == "/api/settings/source-credentials" && r.Method == "GET":
		credentials, err := e.Store.sourceCredentialList(ctx)
		if err != nil {
			fail(w, 500, "读取来源配置失败")
			return
		}
		respond(w, 200, credentials)
		return
	case path == "/api/security-rules":
		e.serveSecurityRules(w, r, u)
		return
	case strings.HasPrefix(path, "/api/assets/") && path != "/api/assets/batch" && r.Method == "PATCH":
		e.patchAsset(w, r, u)
		return
	case path == "/api/state" && r.Method == "GET":
		scopes, err := e.Store.scopes(ctx, u, r.URL.Query())
		if err != nil {
			apiError(w, err)
			return
		}
		jobs, err := e.jobList(ctx, u, r.URL.Query())
		if err != nil {
			apiError(w, err)
			return
		}
		projects, err := e.Store.visibleProjects(ctx, u, 0)
		if err != nil {
			apiError(w, err)
			return
		}
		workspaces, err := e.Store.visibleWorkspaces(ctx, u)
		if err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, map[string]any{"projects": projects, "workspaces": workspaces, "scopes": scopes, "assets": []any{}, "jobs": jobs, "src": programs, "version": "0.3", "storage": "PostgreSQL", "source_options": e.collectorOptions(ctx), "passive_provider_options": passiveProviderMetadata()})
		return
	case path == "/api/scopes" && r.Method == "GET":
		scopes, err := e.Store.scopes(ctx, u, r.URL.Query())
		if err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, scopes)
		return
	case path == "/api/scopes" && r.Method == "POST":
		e.saveScope(w, r, u, 0)
		return
	case strings.HasPrefix(path, "/api/scopes/"):
		parts := strings.Split(strings.TrimPrefix(path, "/api/scopes/"), "/")
		id, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			fail(w, 400, "范围 ID 无效")
			return
		}
		scope, err := e.access(ctx, id, u, write)
		if err != nil {
			apiError(w, err)
			return
		}
		if len(parts) == 1 && r.Method == "PUT" {
			e.saveScope(w, r, u, id)
			return
		}
		if len(parts) == 1 && r.Method == "DELETE" {
			var busy bool
			e.Store.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM jobs WHERE scope_id=$1 AND status IN('queued','running','retrying'))", id).Scan(&busy)
			if busy {
				fail(w, 409, "请先取消该范围任务")
				return
			}
			_, err = e.Store.DB.Exec(ctx, "UPDATE scopes SET confirmed=false WHERE id=$1", id)
			if err == nil {
				e.Store.DB.Exec(ctx, "UPDATE monitor_plans SET enabled=false WHERE scope_id=$1", id)
				e.Store.operation(ctx, u.ID, "scope.archive", strconv.FormatInt(id, 10))
			}
			if err != nil {
				apiError(w, err)
				return
			}
			respond(w, 200, map[string]bool{"ok": true})
			return
		}
		if len(parts) == 2 && parts[1] == "plan" {
			if r.Method == "GET" {
				p, err := e.Store.plan(ctx, id)
				if err != nil {
					apiError(w, err)
					return
				}
				respond(w, 200, p)
				return
			}
			if r.Method == "PUT" {
				var p Plan
				if !decode(w, r, &p) {
					return
				}
				if err = e.validSources(p.Collectors); err != nil {
					apiError(w, err)
					return
				}
				next, err := nextPlan(p, time.Now())
				if err != nil {
					apiError(w, err)
					return
				}
				if p.Enabled {
					if err = (ScopeGuard{Scope: scope}).Valid(); err != nil {
						apiError(w, err)
						return
					}
				}
				p.CollectionMode, err = validateCollectionMode(p.CollectionMode, p.Collectors)
				if err != nil {
					apiError(w, err)
					return
				}
				raw, _ := json.Marshal(p.Collectors)
				_, err = e.Store.DB.Exec(ctx, "INSERT INTO monitor_plans(scope_id,enabled,interval_hours,cron,collectors,next_run_at,collection_mode)VALUES($1,$2,$3,$4,$5,$6,$7)ON CONFLICT(scope_id)DO UPDATE SET enabled=excluded.enabled,interval_hours=excluded.interval_hours,cron=excluded.cron,collectors=excluded.collectors,collection_mode=excluded.collection_mode,next_run_at=excluded.next_run_at,schedule_error='',retry_at=NULL", id, p.Enabled, p.Interval, p.Cron, raw, next, p.CollectionMode)
				if err != nil {
					apiError(w, err)
					return
				}
				e.Store.operation(ctx, u.ID, "plan.update", scope.Domain)
				respond(w, 200, map[string]any{"ok": true, "next_run_at": next})
				return
			}
		}
		if len(parts) == 2 && parts[1] == "run" && r.Method == "POST" {
			var body struct {
				Sources        []string `json:"sources"`
				PluginStrategy string   `json:"plugin_strategy"`
				CollectionMode string   `json:"collection_mode"`
			}
			if !decode(w, r, &body) {
				return
			}
			e.enqueue(w, r, u, scope, body.Sources, body.PluginStrategy, body.CollectionMode)
			return
		}
	case path == "/api/collect" && r.Method == "POST":
		var body struct {
			ScopeID        int64    `json:"scope_id"`
			Sources        []string `json:"sources"`
			PluginStrategy string   `json:"plugin_strategy"`
			CollectionMode string   `json:"collection_mode"`
		}
		if !decode(w, r, &body) {
			return
		}
		scope, err := e.access(ctx, body.ScopeID, u, true)
		if err != nil {
			apiError(w, err)
			return
		}
		e.enqueue(w, r, u, scope, body.Sources, body.PluginStrategy, body.CollectionMode)
		return
	case path == "/api/import" && r.Method == "POST":
		e.importTargetsV2(w, r, u)
		return
	case path == "/api/assets" && r.Method == "GET":
		e.assets(w, r, u, false)
		return
	case (path == "/api/assets/export" || path == "/api/export") && r.Method == "GET":
		e.assets(w, r, u, true)
		return
	case path == "/api/assets/batch" && (r.Method == "PATCH" || r.Method == "POST"):
		e.batchAssets(w, r, u)
		return
	case strings.HasPrefix(path, "/api/assets/") && r.Method == "GET":
		id, err := strconv.ParseInt(strings.TrimPrefix(path, "/api/assets/"), 10, 64)
		if err != nil {
			apiError(w, err)
			return
		}
		list, err := queryJSON(ctx, e.Store.DB, "SELECT to_jsonb(a) FROM assets a JOIN scopes s ON s.id=a.scope_id WHERE a.id=$1 AND ($2='admin' OR scope_access(s.id,$3))", id, u.Role, u.ID)
		if err != nil || len(list) == 0 {
			apiError(w, pgx.ErrNoRows)
			return
		}
		history, err := queryJSON(ctx, e.Store.DB, "SELECT to_jsonb(v) FROM(SELECT id,job_id,payload,created_at FROM asset_snapshots WHERE asset_id=$1 ORDER BY created_at DESC LIMIT 30)v", id)
		if err != nil {
			apiError(w, err)
			return
		}
		events, err := queryJSON(ctx, e.Store.DB, "SELECT to_jsonb(v)FROM(SELECT * FROM asset_events WHERE asset_id=$1 ORDER BY created_at DESC LIMIT 50)v", id)
		if err != nil {
			apiError(w, err)
			return
		}
		services, err := queryJSON(ctx, e.Store.DB, assetServicesSQL, id)
		if err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, map[string]any{"asset": list[0], "snapshots": history, "events": events, "services": services})
		return
	case path == "/api/jobs" && r.Method == "GET":
		list, err := e.jobList(ctx, u, r.URL.Query())
		if err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, list)
		return
	case strings.HasPrefix(path, "/api/jobs/") && strings.HasSuffix(path, "/cancel") && r.Method == "POST":
		id, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(path, "/api/jobs/"), "/cancel"), 10, 64)
		if err != nil {
			apiError(w, err)
			return
		}
		tag, err := e.Store.DB.Exec(ctx, "UPDATE jobs SET cancel_requested=true,error_code='cancelled',retryable=false,error='用户请求取消',finished_at=CASE WHEN status IN('queued','retrying')THEN now()ELSE finished_at END,status=CASE WHEN status IN('queued','retrying')THEN 'cancelled'ELSE status END WHERE id=$1 AND ($2='admin' OR scope_access(jobs.scope_id,$3,true)) AND status IN('queued','running','retrying')", id, u.Role, u.ID)
		if err != nil {
			apiError(w, err)
			return
		}
		if tag.RowsAffected() == 0 {
			apiError(w, pgx.ErrNoRows)
			return
		}
		if cancel, ok := e.active.Load(id); ok {
			cancel.(context.CancelFunc)()
		}
		e.Store.operation(ctx, u.ID, "job.cancel", strconv.FormatInt(id, 10))
		respond(w, 200, map[string]bool{"ok": true})
		return
	case path == "/api/events" && r.Method == "GET":
		list, err := queryJSON(ctx, e.Store.DB, `SELECT to_jsonb(v) FROM(SELECT ev.*,a.host,s.domain,s.project_id FROM asset_events ev JOIN scopes s ON s.id=ev.scope_id LEFT JOIN assets a ON a.id=ev.asset_id WHERE ($1='admin' OR scope_access(s.id,$2))AND ($3='' OR ev.type=$3) AND ($4=0 OR s.project_id=$4)ORDER BY ev.created_at DESC LIMIT 200)v`, u.Role, u.ID, r.URL.Query().Get("type"), projectFilter(r.URL.Query()))
		if err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, list)
		return
	case path == "/api/dashboard/summary" && r.Method == "GET":
		e.dashboard(w, r, u)
		return
	case path == "/api/plugins" || strings.HasPrefix(path, "/api/plugins/"):
		e.servePlugins(w, r, u)
		return
	case path == "/api/blacklist" && r.Method == "GET":
		list, err := queryJSON(ctx, e.Store.DB, "SELECT to_jsonb(b)FROM global_blacklist b ORDER BY id")
		if err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, list)
		return
	case path == "/api/blacklist" && r.Method == "POST":
		var b struct {
			Pattern string `json:"pattern"`
			Note    string `json:"note"`
		}
		if !decode(w, r, &b) {
			return
		}
		pattern, err := normalizePattern(b.Pattern)
		if err != nil {
			apiError(w, err)
			return
		}
		_, err = e.Store.DB.Exec(ctx, "INSERT INTO global_blacklist(pattern,note)VALUES($1,$2)ON CONFLICT(pattern)DO UPDATE SET note=excluded.note", pattern, b.Note)
		if err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(ctx, u.ID, "blacklist.add", pattern)
		respond(w, 200, map[string]bool{"ok": true})
		return
	case strings.HasPrefix(path, "/api/blacklist/") && r.Method == "DELETE":
		id, err := strconv.ParseInt(strings.TrimPrefix(path, "/api/blacklist/"), 10, 64)
		if err != nil {
			apiError(w, err)
			return
		}
		_, err = e.Store.DB.Exec(ctx, "DELETE FROM global_blacklist WHERE id=$1", id)
		if err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(ctx, u.ID, "blacklist.remove", strconv.FormatInt(id, 10))
		respond(w, 200, map[string]bool{"ok": true})
		return
	case path == "/api/settings/smtp":
		c := defaultSMTP()
		if err := e.Store.setting(ctx, "smtp", &c); err != nil {
			apiError(w, err)
			return
		}
		if r.Method == "GET" {
			c.PasswordSet = c.Password != ""
			c.Password = ""
			respond(w, 200, c)
			return
		}
		if r.Method == "PUT" {
			old := c
			var incoming SMTPConfig
			if !decode(w, r, &incoming) {
				return
			}
			c = incoming
			if c.Password == "" {
				c.Password = old.Password
			}
			if err := c.validate(); err != nil {
				apiError(w, err)
				return
			}
			slices.Sort(c.ScopeIDs)
			slices.Sort(c.Recipients)
			c.PasswordSet = false
			if err := e.Store.putSetting(ctx, "smtp", c); err != nil {
				apiError(w, err)
				return
			}
			e.Store.operation(ctx, u.ID, "smtp.update", "masked configuration")
			respond(w, 200, map[string]bool{"ok": true})
			return
		}
	case path == "/api/settings/smtp/test" && r.Method == "POST":
		c := defaultSMTP()
		if err := e.Store.setting(ctx, "smtp", &c); err != nil {
			apiError(w, err)
			return
		}
		if err := sendSMTP(c, "ScopeDesk 测试邮件", "<h2>ScopeDesk SMTP 测试</h2><p>你显式触发了这封测试邮件。未包含资产和凭据。</p>"); err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(ctx, u.ID, "smtp.test", "configured recipients")
		respond(w, 200, map[string]bool{"ok": true})
		return
	case path == "/api/digest/preview" && r.Method == "POST":
		c := defaultSMTP()
		e.Store.setting(ctx, "smtp", &c)
		d, err := e.digest(ctx, c)
		if err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, map[string]any{"html": d.HTML, "date": d.Date, "new": d.New, "down": d.Down, "changed": d.Changed})
		return
	case path == "/api/digest/send" && r.Method == "POST":
		c := defaultSMTP()
		if err := e.Store.setting(ctx, "smtp", &c); err != nil {
			apiError(w, err)
			return
		}
		result, err := e.sendDigest(ctx, c, true)
		if err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(ctx, u.ID, "digest.send", "configured recipients")
		respond(w, 200, result)
		return
	case path == "/api/settings/mail-logs" && r.Method == "GET":
		list, err := queryJSON(ctx, e.Store.DB, "SELECT to_jsonb(l)FROM(SELECT * FROM digest_logs ORDER BY id DESC LIMIT 100)l")
		if err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, list)
		return
	}
	fail(w, 405, "接口不存在或请求方法不支持")
}
func normalizePattern(pattern string) (string, error) {
	pattern = strings.TrimSpace(pattern)
	if p, err := netip.ParsePrefix(pattern); err == nil {
		return p.Masked().String(), nil
	}
	wildcard := strings.HasPrefix(pattern, "*.")
	h, err := normalizeHost(pattern)
	if err != nil {
		return "", err
	}
	if wildcard {
		return "*." + h, nil
	}
	return h, nil
}
func validSources(sources []string) error {
	if len(sources) == 0 || len(sources) > 5 {
		return errors.New("请选择 1–5 个数据源")
	}
	seen := map[string]bool{}
	for _, s := range sources {
		if seen[s] {
			return errors.New("来源重复")
		}
		seen[s] = true
		if !slices.Contains([]string{"crtsh", "certspotter", "subfinder", "fofa", "hunter"}, s) {
			return errors.New("数据源未注册")
		}
	}
	return nil
}
func (e *Engine) enqueue(w http.ResponseWriter, r *http.Request, u User, s ScopeV2, sources []string, strategy ...string) {
	if len(sources) == 0 {
		p, err := e.Store.plan(r.Context(), s.ID)
		if err != nil {
			apiError(w, err)
			return
		}
		sources = p.Collectors
	}
	if err := e.validSources(sources); err != nil {
		apiError(w, err)
		return
	}
	g, err := e.Store.guard(r.Context(), s.ID)
	if err != nil {
		apiError(w, err)
		return
	}
	if _, err = g.AllowHost(s.Domain); err != nil && s.Mode != "subdomains" {
		apiError(w, err)
		return
	}
	chosen := "all"
	if len(strategy) > 0 && strategy[0] != "" {
		chosen = strategy[0]
	}
	mode := "profile"
	if len(strategy) > 1 {
		mode = strategy[1]
	}
	mode, err = validateCollectionMode(mode, sources)
	if err != nil {
		apiError(w, err)
		return
	}
	var id int64
	if q, ok := e.Queue.(interface {
		EnqueuePassiveMode(context.Context, ScopeV2, []string, string, string, string) (int64, error)
	}); ok {
		id, err = q.EnqueuePassiveMode(r.Context(), s, sources, "manual", chosen, mode)
	} else if mode == "evidence_only" {
		fail(w, 400, "当前队列不支持仅证据模式")
		return
	} else if q, ok := e.Queue.(interface {
		EnqueueStrategy(context.Context, ScopeV2, []string, string, string) (int64, error)
	}); ok {
		id, err = q.EnqueueStrategy(r.Context(), s, sources, "manual", chosen)
	} else {
		id, err = e.Queue.Enqueue(r.Context(), s, sources, "manual")
	}
	if err != nil {
		apiError(w, err)
		return
	}
	e.Store.operation(r.Context(), u.ID, "job.enqueue", s.Domain)
	respond(w, 202, map[string]any{"job": id})
}
func (e *Engine) saveScope(w http.ResponseWriter, r *http.Request, u User, id int64) {
	var body struct {
		ScopeV2
		Policy *string `json:"policy"`
	}
	if !decode(w, r, &body) {
		return
	}
	s := body.ScopeV2
	if body.Policy != nil {
		s.Policy = *body.Policy
	}
	// Retained for old clients, but scope expiry is no longer configurable.
	s.Expires = nil
	if id > 0 {
		old, err := e.access(r.Context(), id, u, true)
		if err != nil {
			apiError(w, err)
			return
		}
		s.Owner = old.Owner
		if s.ProjectID == 0 {
			s.ProjectID = old.ProjectID
		}
		if body.Policy == nil {
			s.Policy = old.Policy
		}
	} else {
		s.Owner = u.ID
	}
	if s.ProjectID == 0 {
		if err := e.Store.DB.QueryRow(r.Context(), "SELECT ensure_private_project($1)", s.Owner).Scan(&s.ProjectID); err != nil {
			apiError(w, err)
			return
		}
	}
	if err := e.Store.projectPermission(r.Context(), s.ProjectID, u, true, false); err != nil {
		apiError(w, err)
		return
	}
	if s.Active {
		var allowed bool
		if err := e.Store.DB.QueryRow(r.Context(), "SELECT allow_active FROM projects WHERE id=$1", s.ProjectID).Scan(&allowed); err != nil {
			apiError(w, err)
			return
		}
		if !allowed {
			fail(w, 400, "项目禁止主动探测，请关闭范围主动探测或由项目管理员调整策略")
			return
		}
	}
	if id > 0 {
		old, err := e.Store.scopesByID(r.Context(), id)
		if err != nil {
			apiError(w, err)
			return
		}
		if old.ProjectID != s.ProjectID {
			fail(w, 400, "已有范围不能直接跨项目移动；请单独登记以保留资产归属")
			return
		}
	}
	wildcard := strings.HasPrefix(strings.TrimSpace(s.Domain), "*.")
	domain, err := normalizeHost(s.Domain)
	if err != nil {
		apiError(w, err)
		return
	}
	if _, err = netip.ParseAddr(domain); err == nil {
		fail(w, 400, "范围登记仅接受域名；IP/CIDR 可用于排除及黑名单")
		return
	}
	s.Domain = domain
	if err := (ScopeGuard{Scope: ScopeV2{Domain: domain, Mode: "exact", Confirmed: true}}).Valid(); err != nil {
		apiError(w, err)
		return
	}
	if wildcard {
		s.Mode = "subdomains"
	}
	if !slices.Contains([]string{"exact", "descendants", "subdomains"}, s.Mode) {
		fail(w, 400, "请明确选择仅域名、域名及子域或仅子域")
		return
	}
	if !s.Confirmed {
		fail(w, 400, "请确认已获授权的范围及排除项")
		return
	}
	if len(s.Policy) > 2000 {
		fail(w, 400, "范围备注过长")
		return
	}
	if s.RPS < 0.1 || s.RPS > 5 || s.Concurrency < 1 || s.Concurrency > 4 || s.RequestLimit < 10 || s.RequestLimit > 10000 || s.WindowStart < 0 || s.WindowStart > 23 || s.WindowEnd < 0 || s.WindowEnd > 24 {
		fail(w, 400, "速率 0.1–5 RPS，并发 1–4，请求预算 10–10000，时间窗口 0–24 时")
		return
	}
	if len(s.Exclusions) > 1000 {
		fail(w, 400, "排除项不能超过 1000 条")
		return
	}
	for i, p := range s.Exclusions {
		normalized, err := normalizePattern(p)
		if err != nil {
			apiError(w, err)
			return
		}
		s.Exclusions[i] = normalized
	}
	raw, _ := json.Marshal(s.Exclusions)
	ctx := r.Context()
	tx, err := e.Store.DB.Begin(ctx)
	if err != nil {
		apiError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	if id == 0 {
		err = tx.QueryRow(ctx, "INSERT INTO scopes(owner,domain,mode,policy,confirmed,active,exclusions,expires_at,rps,concurrency,request_limit,window_start,window_end,project_id)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)RETURNING id", s.Owner, s.Domain, s.Mode, s.Policy, s.Confirmed, s.Active, raw, s.Expires, s.RPS, s.Concurrency, s.RequestLimit, s.WindowStart, s.WindowEnd, s.ProjectID).Scan(&id)
	} else {
		_, err = tx.Exec(ctx, "UPDATE scopes SET domain=$2,mode=$3,policy=$4,confirmed=$5,active=$6,exclusions=$7,expires_at=$8,rps=$9,concurrency=$10,request_limit=$11,window_start=$12,window_end=$13,updated_at=now()WHERE id=$1", id, s.Domain, s.Mode, s.Policy, s.Confirmed, s.Active, raw, s.Expires, s.RPS, s.Concurrency, s.RequestLimit, s.WindowStart, s.WindowEnd)
	}
	if err != nil {
		fail(w, 400, "范围保存失败：请检查是否已有相同范围")
		return
	}
	if _, err = tx.Exec(ctx, "INSERT INTO monitor_plans(scope_id)VALUES($1)ON CONFLICT DO NOTHING", id); err != nil {
		apiError(w, err)
		return
	}
	if err = tx.Commit(ctx); err != nil {
		apiError(w, err)
		return
	}
	e.Store.operation(ctx, u.ID, "scope.save", s.Domain)
	respond(w, 200, map[string]any{"id": id, "ok": true})
}
func (e *Engine) jobList(ctx context.Context, u User, filters ...urlQuery) ([]json.RawMessage, error) {
	return queryJSON(ctx, e.Store.DB, `SELECT to_jsonb(v)FROM(SELECT j.*,s.domain,s.project_id,(j.status IN('queued','retrying') AND j.created_at<now()-interval '5 minutes' AND NOT EXISTS(SELECT 1 FROM workers w WHERE w.heartbeat_at>now()-interval '2 minutes' AND j.required_labels <@ w.labels)) AS waiting_for_worker,coalesce((SELECT jsonb_agg(to_jsonb(ss))FROM job_source_stats ss WHERE ss.job_id=j.id),'[]')AS source_stats FROM jobs j JOIN scopes s ON s.id=j.scope_id WHERE($1='admin' OR scope_access(s.id,$2)) AND($3=0 OR s.project_id=$3)ORDER BY j.id DESC LIMIT 100)v`, u.Role, u.ID, projectFilter(filters...))
}
func (e *Engine) assets(w http.ResponseWriter, r *http.Request, u User, export bool) {
	if err := validateFaviconQuery(r.URL.Query()); err != nil {
		fail(w, 400, err.Error())
		return
	}
	ctx := r.Context()
	where, args := assetWhere(u, r.URL.Query())
	from := " FROM assets a JOIN scopes s ON s.id=a.scope_id"
	order := " ORDER BY a.id DESC"
	if r.URL.Query().Get("sort") == "score" {
		order = " ORDER BY a.score DESC,a.id DESC"
	}
	if export {
		e.Store.operation(ctx, u.ID, "assets.export", "filtered")
		rows, err := e.Store.DB.Query(ctx, "SELECT a.host,a.ips,a.port,a.status_code,a.title,a.fingerprints,a.category,a.score,a.status,a.sources,a.first_seen,a.last_seen,a.note,a.assignee"+from+where+order, args...)
		if err != nil {
			apiError(w, err)
			return
		}
		defer rows.Close()
		headers := []string{"域名", "IP", "端口", "状态码", "标题", "指纹", "分类", "评分", "工作状态", "来源", "首次发现", "最近发现", "备注", "负责人"}
		if r.URL.Query().Get("format") == "xlsx" {
			w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			w.Header().Set("Content-Disposition", "attachment; filename=assets.xlsx")
			writeXLSX(w, headers, rows)
		} else {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename=assets.csv")
			io.WriteString(w, "\ufeff")
			csvWriter := csv.NewWriter(w)
			csvWriter.Write(headers)
			for rows.Next() {
				values, err := rows.Values()
				if err != nil {
					break
				}
				csvWriter.Write(exportValues(values, true))
			}
			csvWriter.Flush()
		}
		return
	}
	var total int64
	if err := e.Store.DB.QueryRow(ctx, "SELECT count(*)"+from+where, args...).Scan(&total); err != nil {
		apiError(w, err)
		return
	}
	page := intParam(r.URL.Query().Get("page"), 1, 1, 10000000)
	size := intParam(r.URL.Query().Get("page_size"), 50, 1, 200)
	args = append(args, size, (page-1)*size)
	sql := "SELECT to_jsonb(a)||jsonb_build_object('domain',s.domain,'services_count',(SELECT count(*)FROM asset_services svc WHERE svc.asset_id=a.id),'ports_count',(SELECT count(DISTINCT port)FROM asset_services svc WHERE svc.asset_id=a.id))" + from + where + order + fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	items, err := queryJSON(ctx, e.Store.DB, sql, args...)
	if err != nil {
		apiError(w, err)
		return
	}
	respond(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}
func exportValues(values []any, csvSafe bool) []string {
	out := make([]string, len(values))
	for i, v := range values {
		switch val := v.(type) {
		case []string:
			out[i] = strings.Join(val, ", ")
		case []any:
			items := []string{}
			for _, x := range val {
				items = append(items, fmt.Sprint(x))
			}
			out[i] = strings.Join(items, ", ")
		case time.Time:
			out[i] = val.In(shanghai).Format("2006-01-02 15:04:05")
		default:
			if v != nil {
				out[i] = fmt.Sprint(v)
			}
		}
		if csvSafe && strings.ContainsAny(strings.TrimSpace(out[i])[:min(1, len(strings.TrimSpace(out[i])))], "=+-@\t\r") {
			out[i] = "'" + out[i]
		}
	}
	return out
}
func writeXLSX(w io.Writer, headers []string, rows pgx.Rows) {
	z := zip.NewWriter(w)
	defer z.Close()
	files := map[string]string{"[Content_Types].xml": `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`, "_rels/.rels": `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`, "xl/workbook.xml": `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Assets" sheetId="1" r:id="rId1"/></sheets></workbook>`, "xl/_rels/workbook.xml.rels": `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`}
	for name, body := range files {
		f, err := z.Create(name)
		if err != nil {
			return
		}
		io.WriteString(f, body)
	}
	sheet, err := z.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		return
	}
	io.WriteString(sheet, `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	writeRow := func(data []string) {
		io.WriteString(sheet, "<row>")
		for _, v := range data {
			io.WriteString(sheet, `<c t="inlineStr"><is><t xml:space="preserve">`)
			xml.EscapeText(sheet, []byte(v))
			io.WriteString(sheet, "</t></is></c>")
		}
		io.WriteString(sheet, "</row>")
	}
	writeRow(headers)
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return
		}
		writeRow(exportValues(values, false))
	}
	io.WriteString(sheet, "</sheetData></worksheet>")
}
func (e *Engine) importTargets(w http.ResponseWriter, r *http.Request, u User) {
	var body struct {
		ScopeID int64  `json:"scope_id"`
		Hosts   string `json:"hosts"`
		Preview bool   `json:"preview"`
	}
	if !decode(w, r, &body) {
		return
	}
	if _, err := e.access(r.Context(), body.ScopeID, u, true); err != nil {
		apiError(w, err)
		return
	}
	guard, err := e.Store.guard(r.Context(), body.ScopeID)
	if err != nil {
		apiError(w, err)
		return
	}
	inside := []string{}
	outside := []map[string]string{}
	seen := map[string]bool{}
	for _, raw := range strings.Split(body.Hosts, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		host, err := guard.AllowHost(raw)
		if err != nil {
			outside = append(outside, map[string]string{"input": raw, "reason": err.Error()})
			continue
		}
		if !seen[host] {
			inside = append(inside, host)
			seen[host] = true
		}
	}
	if len(inside) > 5000 {
		fail(w, 400, "单次导入不超过 5000 个目标")
		return
	}
	count := 0
	if !body.Preview {
		tx, err := e.Store.DB.Begin(r.Context())
		if err != nil {
			apiError(w, err)
			return
		}
		defer tx.Rollback(r.Context())
		for _, h := range inside {
			tag, err := tx.Exec(r.Context(), "INSERT INTO assets(scope_id,host,sources)VALUES($1,$2,ARRAY['manual'])ON CONFLICT(scope_id,host)DO UPDATE SET last_seen=now(),sources=(SELECT ARRAY(SELECT DISTINCT unnest(assets.sources||ARRAY['manual'])))", body.ScopeID, h)
			if err != nil {
				apiError(w, err)
				return
			}
			count += int(tag.RowsAffected())
		}
		if err = tx.Commit(r.Context()); err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(r.Context(), u.ID, "targets.import", fmt.Sprintf("scope=%d in=%d rejected=%d", body.ScopeID, len(inside), len(outside)))
	}
	respond(w, 200, map[string]any{"count": count, "in_scope": inside, "out_of_scope": outside, "preview": body.Preview})
}
func (e *Engine) dashboard(w http.ResponseWriter, r *http.Request, u User) {
	ctx := r.Context()
	var total, newCount, alive, active int64
	err := e.Store.DB.QueryRow(ctx, `SELECT count(*),count(*)FILTER(WHERE a.first_seen>=date_trunc('day',now() AT TIME ZONE 'Asia/Shanghai')AT TIME ZONE 'Asia/Shanghai'),count(*)FILTER(WHERE a.is_alive=true) FROM assets a JOIN scopes s ON s.id=a.scope_id WHERE ($1='admin'OR scope_access(s.id,$2)) AND ($3=0 OR s.project_id=$3)`, u.Role, u.ID, projectFilter(r.URL.Query())).Scan(&total, &newCount, &alive)
	if err != nil {
		apiError(w, err)
		return
	}
	e.Store.DB.QueryRow(ctx, "SELECT count(*)FROM jobs j JOIN scopes s ON s.id=j.scope_id WHERE j.status IN('running','queued','retrying')AND($1='admin'OR scope_access(s.id,$2)) AND ($3=0 OR s.project_id=$3)", u.Role, u.ID, projectFilter(r.URL.Query())).Scan(&active)
	trend, err := queryJSON(ctx, e.Store.DB, `SELECT jsonb_build_object('day',d::date,'count',count(a.id))FROM generate_series((now()AT TIME ZONE 'Asia/Shanghai')::date-6,(now()AT TIME ZONE 'Asia/Shanghai')::date,interval '1 day')d LEFT JOIN(assets a JOIN scopes s ON s.id=a.scope_id AND($1='admin'OR scope_access(s.id,$2)) AND ($3=0 OR s.project_id=$3))ON(a.first_seen AT TIME ZONE 'Asia/Shanghai')::date=d::date GROUP BY d ORDER BY d`, u.Role, u.ID, projectFilter(r.URL.Query()))
	if err != nil {
		apiError(w, err)
		return
	}
	respond(w, 200, map[string]any{"total": total, "today_new": newCount, "alive": alive, "active_jobs": active, "trend": trend})
}

var _ = html.EscapeString
