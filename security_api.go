package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (e *Engine) serveSecurityRules(w http.ResponseWriter, r *http.Request, u User) {
	ctx := r.Context()
	switch r.Method {
	case "GET":
		rules, err := e.Store.securityRules(ctx)
		if err != nil {
			apiError(w, err)
			return
		}
		respond(w, 200, rules)
		return
	case "POST", "PUT", "DELETE":
	default:
		fail(w, 405, "不支持的方法")
		return
	}
	tx, err := e.Store.DB.Begin(ctx)
	if err != nil {
		apiError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var id int64
	if r.Method == "DELETE" {
		id, err = strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if err != nil || id <= 0 {
			fail(w, 400, "规则 ID 无效")
			return
		}
		tag, err := tx.Exec(ctx, "DELETE FROM security_rules WHERE id=$1", id)
		if err != nil {
			apiError(w, err)
			return
		}
		if tag.RowsAffected() == 0 {
			apiError(w, pgx.ErrNoRows)
			return
		}
	} else {
		// builtin is server-managed provenance; clients cannot change it.
		body := SecurityRule{Enabled: true}
		if !decode(w, r, &body) {
			return
		}
		rule, err := compileSecurityRule(body)
		if err != nil {
			apiError(w, err)
			return
		}
		id = rule.ID
		if r.Method == "POST" {
			err = tx.QueryRow(ctx, "INSERT INTO security_rules(keyword,match,fields,enabled,builtin)VALUES($1,$2,$3,$4,false)RETURNING id", rule.Keyword, rule.Match, rule.Fields, rule.Enabled).Scan(&id)
		} else {
			if id <= 0 {
				fail(w, 400, "规则 ID 无效")
				return
			}
			tag, updateErr := tx.Exec(ctx, "UPDATE security_rules SET keyword=$2,match=$3,fields=$4,enabled=$5 WHERE id=$1", id, rule.Keyword, rule.Match, rule.Fields, rule.Enabled)
			err = updateErr
			if err == nil && tag.RowsAffected() == 0 {
				err = pgx.ErrNoRows
			}
		}
		if err != nil {
			apiError(w, err)
			return
		}
	}
	if _, err = tx.Exec(ctx, "INSERT INTO operation_logs(user_id,action,target)VALUES($1,$2,$3)", u.ID, "security_rules."+strings.ToLower(r.Method), fmt.Sprint(id)); err != nil {
		apiError(w, err)
		return
	}
	if err = tx.Commit(ctx); err != nil {
		apiError(w, err)
		return
	}
	if e.Pipeline != nil && e.Pipeline.Rules != nil {
		e.Pipeline.Rules.refresh(ctx, true)
	}
	respond(w, 200, map[string]any{"ok": true, "id": id})
}

type assetPatch struct {
	IDs              []int64         `json:"ids"`
	Status           string          `json:"status"`
	Note             *string         `json:"note"`
	Tags             *[]string       `json:"tags"`
	Assignee         *string         `json:"assignee"`
	SecurityOverride json.RawMessage `json:"security_device_override"`
}

func (e *Engine) patchAsset(w http.ResponseWriter, r *http.Request, u User) {
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/assets/"), 10, 64)
	if err != nil || id <= 0 {
		fail(w, 400, "资产 ID 无效")
		return
	}
	var body assetPatch
	if !decode(w, r, &body) {
		return
	}
	body.IDs = []int64{id}
	e.saveAssetPatch(w, r, u, body)
}
func (e *Engine) batchAssets(w http.ResponseWriter, r *http.Request, u User) {
	var body assetPatch
	if !decode(w, r, &body) {
		return
	}
	e.saveAssetPatch(w, r, u, body)
}
func (e *Engine) saveAssetPatch(w http.ResponseWriter, r *http.Request, u User, body assetPatch) {
	if len(body.IDs) == 0 || len(body.IDs) > 1000 {
		fail(w, 400, "请选择 1–1000 个资产")
		return
	}
	if body.Status != "" && !slices.Contains([]string{"new", "pending", "testing", "tested", "ignored"}, body.Status) {
		fail(w, 400, "工作状态无效")
		return
	}
	if body.Note != nil && len(*body.Note) > 4000 {
		fail(w, 400, "备注过长")
		return
	}
	overrideSet := len(body.SecurityOverride) > 0
	var override *bool
	if overrideSet {
		if err := json.Unmarshal(body.SecurityOverride, &override); err != nil || (override != nil && *override) {
			fail(w, 400, "人工标记仅允许 false 或 null")
			return
		}
	}
	ids := slices.Clone(body.IDs)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	ctx := r.Context()
	tx, err := e.Store.DB.Begin(ctx)
	if err != nil {
		apiError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT a.id FROM assets a JOIN scopes s ON s.id=a.scope_id WHERE a.id=ANY($1::bigint[])AND($2='admin'OR scope_access(s.id,$3,true)) ORDER BY a.id FOR UPDATE OF a", ids, u.Role, u.ID)
	if err != nil {
		apiError(w, err)
		return
	}
	count := 0
	for rows.Next() {
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		apiError(w, err)
		return
	}
	if count != len(ids) {
		apiError(w, pgx.ErrNoRows)
		return
	}
	_, err = tx.Exec(ctx, `UPDATE assets SET status=CASE WHEN $2=''THEN status ELSE $2 END,note=coalesce($3,note),tags=coalesce($4,tags),assignee=coalesce($5,assignee) WHERE id=ANY($1::bigint[])`, ids, body.Status, body.Note, body.Tags, body.Assignee)
	if err != nil {
		apiError(w, err)
		return
	}
	if overrideSet {
		// Match evidence is retained; null restores the last automatic observation.
		_, err = tx.Exec(ctx, `WITH changed AS (
   UPDATE assets SET security_device_override=$2,is_security_device=CASE WHEN $2::boolean IS NULL THEN jsonb_array_length(security_matches)>0 OR security_rule<>'' ELSE false END
   WHERE id=ANY($1::bigint[]) AND security_device_override IS DISTINCT FROM $2::boolean RETURNING *
  ) INSERT INTO asset_snapshots(asset_id,scope_id,job_id,payload)SELECT id,scope_id,NULL,to_jsonb(changed)FROM changed`, ids, override)
		if err != nil {
			apiError(w, err)
			return
		}
	}
	action := "assets.batch"
	if overrideSet {
		action = "assets.security_override"
	}
	target, _ := json.Marshal(map[string]any{"ids": ids, "security_device_override": body.SecurityOverride})
	if _, err = tx.Exec(ctx, "INSERT INTO operation_logs(user_id,action,target)VALUES($1,$2,$3)", u.ID, action, string(target)); err != nil {
		apiError(w, err)
		return
	}
	if err = tx.Commit(ctx); err != nil {
		apiError(w, err)
		return
	}
	respond(w, 200, map[string]any{"ok": true, "updated": len(ids)})
}
