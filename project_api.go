package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

func (e *Engine) serveProjects(w http.ResponseWriter, r *http.Request, u User) {
	ctx := r.Context()
	workspace := strings.HasPrefix(r.URL.Path, "/api/workspaces")
	root := "/api/projects"
	if workspace {
		root = "/api/workspaces"
	}
	suffix := strings.TrimPrefix(r.URL.Path, root)
	if suffix == "" {
		if r.Method == "GET" {
			var data []json.RawMessage
			var err error
			if workspace {
				data, err = e.Store.visibleWorkspaces(ctx, u)
			} else {
				data, err = e.Store.visibleProjects(ctx, u, workspaceFilter(r))
			}
			if err != nil {
				apiError(w, err)
				return
			}
			respond(w, 200, data)
			return
		}
		if r.Method == "POST" {
			if workspace {
				var body struct {
					Name string `json:"name"`
				}
				if !decode(w, r, &body) {
					return
				}
				body.Name = strings.TrimSpace(body.Name)
				if body.Name == "" || utf8.RuneCountInString(body.Name) > 100 {
					fail(w, 400, "工作空间名称须为 1–100 个字符")
					return
				}
				var id int64
				err := e.Store.DB.QueryRow(ctx, "INSERT INTO workspaces(owner,name)VALUES($1,$2)RETURNING id", u.ID, body.Name).Scan(&id)
				if err != nil {
					apiError(w, err)
					return
				}
				e.Store.operation(ctx, u.ID, "workspace.create", fmt.Sprint(id))
				respond(w, 201, map[string]any{"id": id})
				return
			}
			p := Project{ProjectPolicy: ProjectPolicy{Enabled: true, RPSLimit: 5}}
			if !decode(w, r, &p) {
				return
			}
			if err := validateProject(p); err != nil {
				apiError(w, err)
				return
			}
			if p.WorkspaceID == 0 {
				if err := e.Store.DB.QueryRow(ctx, "SELECT ensure_private_project($1)", u.ID).Scan(new(int64)); err != nil {
					apiError(w, err)
					return
				}
				if err := e.Store.DB.QueryRow(ctx, "SELECT id FROM workspaces WHERE owner=$1 AND is_default", u.ID).Scan(&p.WorkspaceID); err != nil {
					apiError(w, err)
					return
				}
			}
			if err := e.Store.workspacePermission(ctx, p.WorkspaceID, u, true); err != nil {
				apiError(w, err)
				return
			}
			err := e.Store.DB.QueryRow(ctx, "INSERT INTO projects(workspace_id,owner,name,rules_url,expires_at,allow_active,rps_limit,enabled)VALUES($1,$2,$3,$4,$5,$6,$7,$8)RETURNING id", p.WorkspaceID, u.ID, strings.TrimSpace(p.Name), p.RulesURL, p.Expires, p.AllowActive, p.RPSLimit, p.Enabled).Scan(&p.ID)
			if err != nil {
				apiError(w, err)
				return
			}
			e.Store.operation(ctx, u.ID, "project.create", fmt.Sprint(p.ID))
			respond(w, 201, map[string]any{"id": p.ID})
			return
		}
		fail(w, 405, "不支持的操作")
		return
	}
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id < 1 {
		fail(w, 400, "ID 无效")
		return
	}
	managing := r.Method != "GET" || len(parts) > 1
	if workspace {
		err = e.Store.workspacePermission(ctx, id, u, managing)
	} else {
		err = e.Store.projectPermission(ctx, id, u, managing, managing)
	}
	if err != nil {
		apiError(w, err)
		return
	}
	if len(parts) == 1 {
		if r.Method == "GET" {
			table := "projects"
			if workspace {
				table = "workspaces"
			}
			data, err := queryJSON(ctx, e.Store.DB, "SELECT to_jsonb(v) FROM "+table+" v WHERE id=$1", id)
			if err != nil {
				apiError(w, err)
				return
			}
			respond(w, 200, data[0])
			return
		}
		if r.Method == "PUT" {
			var cancelled int64
			if workspace {
				var body struct {
					Name string `json:"name"`
				}
				if !decode(w, r, &body) {
					return
				}
				body.Name = strings.TrimSpace(body.Name)
				if body.Name == "" || utf8.RuneCountInString(body.Name) > 100 {
					fail(w, 400, "名称无效")
					return
				}
				_, err = e.Store.DB.Exec(ctx, "UPDATE workspaces SET name=$2 WHERE id=$1", id, body.Name)
			} else {
				var p Project
				if !decode(w, r, &p) {
					return
				}
				if err = validateProject(p); err != nil {
					apiError(w, err)
					return
				}
				cancelled, err = e.Store.updateProjectPolicy(ctx, id, p)
			}
			if err != nil {
				apiError(w, err)
				return
			}
			e.Store.operation(ctx, u.ID, strings.TrimPrefix(root, "/api/")+".update", fmt.Sprintf("%d cancelled_jobs=%d", id, cancelled))
			respond(w, 200, map[string]any{"ok": true, "cancelled_jobs": cancelled})
			return
		}
	}
	if len(parts) >= 2 && parts[1] == "members" {
		table, key := "project_members", "project_id"
		if workspace {
			table, key = "workspace_members", "workspace_id"
		}
		if len(parts) == 2 && r.Method == "GET" {
			data, err := queryJSON(ctx, e.Store.DB, "SELECT to_jsonb(m) FROM "+table+" m WHERE "+key+"=$1 ORDER BY user_id", id)
			if err != nil {
				apiError(w, err)
				return
			}
			respond(w, 200, data)
			return
		}
		if len(parts) == 2 && r.Method == "PUT" {
			var body struct {
				UserID int    `json:"user_id"`
				Role   string `json:"role"`
			}
			if !decode(w, r, &body) {
				return
			}
			valid := body.Role == "admin" || body.Role == "viewer" || (!workspace && body.Role == "operator") || (workspace && body.Role == "member")
			if !valid || body.UserID < 1 {
				fail(w, 400, "成员或角色无效")
				return
			}
			tx, err := e.Store.DB.Begin(ctx)
			if err != nil {
				apiError(w, err)
				return
			}
			defer tx.Rollback(ctx)
			var enabled bool
			err = tx.QueryRow(ctx, "SELECT NOT coalesce((payload->>'disabled')::boolean,false) FROM platform_users WHERE id=$1 FOR SHARE", body.UserID).Scan(&enabled)
			if err != nil || !enabled {
				fail(w, 400, "成员不存在或已禁用")
				return
			}
			if !workspace {
				var belongs bool
				err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects p JOIN workspaces w ON w.id=p.workspace_id WHERE p.id=$1 AND(w.owner=$2 OR EXISTS(SELECT 1 FROM workspace_members wm WHERE wm.workspace_id=w.id AND wm.user_id=$2)))`, id, body.UserID).Scan(&belongs)
				if err != nil || !belongs {
					fail(w, 400, "请先将成员加入工作空间")
					return
				}
			}
			_, err = tx.Exec(ctx, "INSERT INTO "+table+"("+key+",user_id,role)VALUES($1,$2,$3)ON CONFLICT("+key+",user_id)DO UPDATE SET role=excluded.role", id, body.UserID, body.Role)
			if err == nil {
				err = tx.Commit(ctx)
			}
			if err != nil {
				apiError(w, err)
				return
			}
			e.Store.operation(ctx, u.ID, "membership.update", fmt.Sprintf("%s=%d user=%d role=%s", key, id, body.UserID, body.Role))
			respond(w, 200, map[string]bool{"ok": true})
			return
		}
		if len(parts) == 3 && r.Method == "DELETE" {
			uid, err := strconv.Atoi(parts[2])
			if err != nil || uid < 1 {
				fail(w, 400, "成员 ID 无效")
				return
			}
			_, err = e.Store.DB.Exec(ctx, "DELETE FROM "+table+" WHERE "+key+"=$1 AND user_id=$2", id, uid)
			if err != nil {
				apiError(w, err)
				return
			}
			e.Store.operation(ctx, u.ID, "membership.remove", fmt.Sprintf("%s=%d user=%d", key, id, uid))
			respond(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	apiError(w, pgx.ErrNoRows)
}
func workspaceFilter(r *http.Request) int64 {
	raw := r.URL.Query().Get("workspace_id")
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 {
		return -1
	}
	return n
}

func (s *Store) visibleWorkspaces(ctx context.Context, u User) ([]json.RawMessage, error) {
	return queryJSON(ctx, s.DB, `SELECT to_jsonb(v) FROM(SELECT w.*,($1!='readonly' AND ($1='admin' OR w.owner=$2 OR EXISTS(SELECT 1 FROM workspace_members wm WHERE wm.workspace_id=w.id AND wm.user_id=$2 AND wm.role='admin'))) AS can_manage FROM workspaces w WHERE $1='admin' OR w.owner=$2 OR EXISTS(SELECT 1 FROM workspace_members wm WHERE wm.workspace_id=w.id AND wm.user_id=$2) ORDER BY w.id)v`, u.Role, u.ID)
}
func (s *Store) visibleProjects(ctx context.Context, u User, wid int64) ([]json.RawMessage, error) {
	return queryJSON(ctx, s.DB, `SELECT to_jsonb(v) FROM(SELECT p.*,w.name AS workspace_name,($1!='readonly' AND ($1='admin' OR project_access(p.id,$2,true))) AS can_write,($1!='readonly' AND ($1='admin' OR project_access(p.id,$2,true,true))) AS can_manage FROM projects p JOIN workspaces w ON w.id=p.workspace_id WHERE ($1='admin' OR project_access(p.id,$2)) AND ($3=0 OR p.workspace_id=$3) ORDER BY p.id)v`, u.Role, u.ID, wid)
}
