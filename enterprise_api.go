package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func (e *Engine) serveEnterprise(w http.ResponseWriter, r *http.Request, u User) {
	ctx := r.Context()
	suffix := strings.TrimPrefix(r.URL.Path, "/api/explorations")
	switch {
	case suffix == "/sources" && r.Method == "GET":
		sources := []map[string]any{}
		for _, name := range []string{"manual", "enscan", "commercial"} {
			available := name == "manual" || e.EnterpriseSources[name] != nil
			sources = append(sources, map[string]any{"name": name, "available": available, "status": map[bool]string{true: "ready", false: "not_configured"}[available]})
		}
		respond(w, 200, sources)
	case (suffix == "" || suffix == "/candidates") && r.Method == "GET":
		project := projectFilter(r.URL.Query())
		table := "enterprise_exploration_runs"
		if suffix == "/candidates" {
			table = "enterprise_candidates"
		}
		page := intParam(r.URL.Query().Get("page"), 1, 1, 100000)
		size := intParam(r.URL.Query().Get("page_size"), 50, 1, 100)
		where := " WHERE ($1='admin' OR project_access(project_id,$2)) AND ($3=0 OR project_id=$3)"
		var count int
		if err := e.Store.DB.QueryRow(ctx, "SELECT count(*) FROM "+table+where, u.Role, u.ID, project).Scan(&count); err != nil {
			apiError(w, err)
			return
		}
		rows, err := e.Store.DB.Query(ctx, "SELECT to_jsonb(t) FROM "+table+" t"+where+" ORDER BY id DESC LIMIT $4 OFFSET $5", u.Role, u.ID, project, size, (page-1)*size)
		if err != nil {
			apiError(w, err)
			return
		}
		defer rows.Close()
		items := []json.RawMessage{}
		for rows.Next() {
			var raw json.RawMessage
			if err = rows.Scan(&raw); err != nil {
				apiError(w, err)
				return
			}
			items = append(items, raw)
		}
		if err = rows.Err(); err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, map[string]any{"items": items, "total": count, "page": page, "page_size": size})
	case suffix == "" && r.Method == "POST":
		q := EnterpriseQuery{Source: "manual", MaxDepth: 2, MaxCompanies: 100, MaxCandidates: 1000, RequestLimit: 100}
		if !decode(w, r, &q) {
			return
		}
		if err := validateEnterpriseQuery(&q); err != nil {
			apiError(w, err)
			return
		}
		if err := e.Store.projectPermission(ctx, q.ProjectID, u, true, false); err != nil {
			apiError(w, err)
			return
		}
		if err := e.enterpriseProjectValid(ctx, q.ProjectID); err != nil {
			apiError(w, err)
			return
		}
		budget := newEnterpriseBudget(q)
		result := EnterpriseSourceResult{Status: "unavailable", ErrorCode: "not_configured"}
		if q.Source == "manual" {
			result = manualEnterpriseResult(q)
		} else if source := e.EnterpriseSources[q.Source]; source != nil {
			sourceCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			result = source.Explore(sourceCtx, q, budget)
			cancel()
		}
		result = normalizeEnterpriseResult(q, result, budget)
		id, err := e.Store.saveEnterpriseResult(ctx, q, result, budget, u)
		if err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(ctx, u.ID, "enterprise.explore", fmt.Sprint(id))
		respond(w, 201, map[string]any{"id": id, "status": result.Status, "complete": result.Complete, "error_code": result.ErrorCode, "saved_candidates": len(result.Candidates)})
	case strings.HasPrefix(suffix, "/candidates/"):
		parts := strings.Split(strings.TrimPrefix(suffix, "/candidates/"), "/")
		id, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || id < 1 {
			fail(w, 400, "候选编号无效")
			return
		}
		if len(parts) == 1 && r.Method == "PATCH" {
			e.reviewEnterpriseCandidate(w, r, u, id)
			return
		}
		if len(parts) == 2 && parts[1] == "import-scope" && r.Method == "POST" {
			e.importEnterpriseScope(w, r, u, id)
			return
		}
		fail(w, 404, "接口不存在")
	default:
		fail(w, 404, "接口不存在")
	}
}
func (e *Engine) enterpriseProjectValid(ctx context.Context, id int64) error {
	var enabled bool
	var expires *time.Time
	if err := e.Store.DB.QueryRow(ctx, "SELECT enabled,expires_at FROM projects WHERE id=$1", id).Scan(&enabled, &expires); err != nil {
		return err
	}
	if !enabled || expires != nil && !time.Now().Before(*expires) {
		return errors.New("项目已停用或授权到期")
	}
	return nil
}
func enterpriseProjectLock(ctx context.Context, tx pgx.Tx, id int64, u User) error {
	var enabled bool
	var expires *time.Time
	err := tx.QueryRow(ctx, "SELECT enabled,expires_at FROM projects WHERE id=$1 AND ($2='admin' OR project_access(id,$3,true)) FOR SHARE", id, u.Role, u.ID).Scan(&enabled, &expires)
	if err != nil {
		return err
	}
	if !enabled || expires != nil && !time.Now().Before(*expires) {
		return errors.New("项目已停用或授权到期")
	}
	return nil
}
func (s *Store) saveEnterpriseResult(ctx context.Context, q EnterpriseQuery, result EnterpriseSourceResult, b *EnterpriseBudget, u User) (int64, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if err = enterpriseProjectLock(ctx, tx, q.ProjectID, u); err != nil {
		return 0, err
	}
	requests, companies := b.Used()
	var count *int
	if result.Complete || slices.Contains([]string{"partial", "budget_exhausted"}, result.Status) && len(result.Candidates) > 0 {
		count = ptr(len(result.Candidates))
	}
	// Manually supplied lists cannot establish absence of a company-domain relation.
	absenceUsable := result.Complete && q.Source != "manual"
	var run int64
	err = tx.QueryRow(ctx, `INSERT INTO enterprise_exploration_runs(project_id,owner,company,source,status,error_code,complete,absence_usable,result_count,max_depth,max_companies,max_candidates,request_limit,requests_used,companies_seen)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)RETURNING id`, q.ProjectID, u.ID, q.Company, q.Source, result.Status, result.ErrorCode, result.Complete, absenceUsable, count, q.MaxDepth, q.MaxCompanies, q.MaxCandidates, q.RequestLimit, requests, companies).Scan(&run)
	if err != nil {
		return 0, err
	}
	for _, candidate := range result.Candidates {
		var old json.RawMessage
		var id int64
		err = tx.QueryRow(ctx, `INSERT INTO enterprise_candidates(project_id,domain,company)VALUES($1,$2,$3)ON CONFLICT(project_id,domain,company)DO UPDATE SET updated_at=now() RETURNING id,evidence`, q.ProjectID, candidate.Domain, candidate.Company).Scan(&id, &old)
		if err != nil {
			return 0, err
		}
		var evidence []json.RawMessage
		if err = json.Unmarshal(old, &evidence); err != nil {
			return 0, err
		}
		evidence = append(evidence, enterpriseEvidenceJSON(candidate, run, q.Source))
		// Keep recent provenance within the same evidence-size limits as plugin data.
		var raw []byte
		for {
			raw, _ = json.Marshal(evidence)
			if len(raw) <= 48<<10 || len(evidence) <= 1 {
				break
			}
			evidence = evidence[1:]
		}
		_, err = tx.Exec(ctx, "UPDATE enterprise_candidates SET evidence=$2::jsonb,updated_at=now() WHERE id=$1", id, raw)
		if err != nil {
			return 0, err
		}
	}
	return run, tx.Commit(ctx)
}
func (e *Engine) reviewEnterpriseCandidate(w http.ResponseWriter, r *http.Request, u User, id int64) {
	var body struct {
		Status string `json:"status"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !slices.Contains([]string{"pending", "confirmed", "rejected"}, body.Status) {
		fail(w, 400, "候选状态无效")
		return
	}
	tx, err := e.Store.DB.Begin(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	var project int64
	if err = tx.QueryRow(r.Context(), "SELECT project_id FROM enterprise_candidates WHERE id=$1", id).Scan(&project); err != nil {
		apiError(w, err)
		return
	}
	if err = enterpriseProjectLock(r.Context(), tx, project, u); err != nil {
		apiError(w, err)
		return
	}
	if _, err = tx.Exec(r.Context(), "UPDATE enterprise_candidates SET status=$2,reviewed_by=$3,reviewed_at=now(),updated_at=now() WHERE id=$1", id, body.Status, u.ID); err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		apiError(w, err)
		return
	}
	e.Store.operation(r.Context(), u.ID, "enterprise.review", fmt.Sprint(id))
	respond(w, 200, map[string]any{"ok": true})
}
func (e *Engine) importEnterpriseScope(w http.ResponseWriter, r *http.Request, u User, id int64) {
	var body struct {
		Confirmed bool   `json:"confirmed"`
		Mode      string `json:"mode"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !body.Confirmed || body.Mode != "exact" {
		fail(w, 400, "请明确确认授权；本阶段只支持精确域名，扩大粒度请在范围表单单独登记")
		return
	}
	ctx := r.Context()
	tx, err := e.Store.DB.Begin(ctx)
	if err != nil {
		apiError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var project int64
	if err = tx.QueryRow(ctx, "SELECT project_id FROM enterprise_candidates WHERE id=$1", id).Scan(&project); err != nil {
		apiError(w, err)
		return
	}
	if err = enterpriseProjectLock(ctx, tx, project, u); err != nil {
		apiError(w, err)
		return
	}
	var domain, status string
	var imported *int64
	if err = tx.QueryRow(ctx, "SELECT domain,status,imported_scope_id FROM enterprise_candidates WHERE id=$1 FOR UPDATE", id).Scan(&domain, &status, &imported); err != nil {
		apiError(w, err)
		return
	}
	if status != "confirmed" {
		fail(w, 400, "候选尚未人工确认")
		return
	}
	if imported != nil {
		respond(w, 200, map[string]any{"id": *imported, "existing": true})
		return
	}
	if _, err = normalizeEnterpriseDomain(domain); err != nil {
		apiError(w, err)
		return
	}
	// Reuse ScopeGuard's full boundary-aware blacklist matching without DNS/HTTP.
	if _, err = tx.Exec(ctx, "LOCK TABLE global_blacklist IN SHARE MODE"); err != nil {
		apiError(w, err)
		return
	}
	rows, err := tx.Query(ctx, "SELECT pattern FROM global_blacklist")
	if err != nil {
		apiError(w, err)
		return
	}
	guard := ScopeGuard{Scope: ScopeV2{Domain: domain, Mode: "exact", Confirmed: true}}
	for rows.Next() {
		var pattern string
		if err = rows.Scan(&pattern); err != nil {
			rows.Close()
			apiError(w, err)
			return
		}
		guard.Blacklist = append(guard.Blacklist, pattern)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		apiError(w, err)
		return
	}
	if _, err = guard.AllowHost(domain); err != nil {
		apiError(w, err)
		return
	}
	var scope int64
	err = tx.QueryRow(ctx, `INSERT INTO scopes(owner,project_id,domain,mode,confirmed,active,rps,concurrency,request_limit,window_start,window_end)VALUES($1,$2,$3,'exact',true,false,1,1,1000,0,24)ON CONFLICT(project_id,domain,mode)DO NOTHING RETURNING id`, u.ID, project, domain).Scan(&scope)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 409, "项目已有相同精确范围，请在授权范围页核对，未修改已有设置")
		return
	}
	if err == nil {
		_, err = tx.Exec(ctx, "INSERT INTO monitor_plans(scope_id,enabled)VALUES($1,false)ON CONFLICT DO NOTHING", scope)
	}
	if err == nil {
		_, err = tx.Exec(ctx, "UPDATE enterprise_candidates SET imported_scope_id=$2,updated_at=now() WHERE id=$1", id, scope)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		apiError(w, err)
		return
	}
	e.Store.operation(ctx, u.ID, "enterprise.import_scope", fmt.Sprint(id))
	respond(w, 201, map[string]any{"id": scope, "active": false, "plan_enabled": false})
}
