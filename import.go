package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (e *Engine) importTargetsV2(w http.ResponseWriter, r *http.Request, u User) {
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
	newCount := 0
	if !body.Preview {
		ctx := r.Context()
		tx, err := e.Store.DB.Begin(ctx)
		if err != nil {
			apiError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT id FROM scopes WHERE id=$1 FOR SHARE", body.ScopeID); err != nil {
			apiError(w, err)
			return
		}
		if _, err = tx.Exec(ctx, "LOCK TABLE global_blacklist IN SHARE MODE"); err != nil {
			apiError(w, err)
			return
		}
		guard, err = e.Store.guard(ctx, body.ScopeID)
		if err != nil {
			apiError(w, err)
			return
		}
		for _, h := range inside {
			if _, err = guard.AllowHost(h); err != nil {
				apiError(w, err)
				return
			}
			var id int64
			var inserted bool
			err = tx.QueryRow(ctx, `INSERT INTO assets(scope_id,host,sources)VALUES($1,$2,ARRAY['manual'])ON CONFLICT(scope_id,host)DO UPDATE SET last_seen=now(),sources=(SELECT ARRAY(SELECT DISTINCT unnest(assets.sources||ARRAY['manual'])))RETURNING id,(xmax=0)`, body.ScopeID, h).Scan(&id, &inserted)
			if err != nil {
				apiError(w, err)
				return
			}
			if inserted {
				newCount++
				if err = addEvent(ctx, tx, body.ScopeID, id, 0, "NEW_ASSET", map[string]any{"host": h, "sources": []string{"manual"}}); err != nil {
					apiError(w, err)
					return
				}
				var raw []byte
				if err = tx.QueryRow(ctx, "SELECT to_jsonb(a)FROM assets a WHERE id=$1", id).Scan(&raw); err != nil {
					apiError(w, err)
					return
				}
				if _, err = tx.Exec(ctx, "INSERT INTO asset_snapshots(asset_id,scope_id,payload)VALUES($1,$2,$3)", id, body.ScopeID, json.RawMessage(raw)); err != nil {
					apiError(w, err)
					return
				}
			}
		}
		if err = tx.Commit(ctx); err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(ctx, u.ID, "targets.import", fmt.Sprintf("scope=%d in=%d new=%d rejected=%d", body.ScopeID, len(inside), newCount, len(outside)))
	}
	respond(w, 200, map[string]any{"count": len(inside), "new_count": newCount, "in_scope": inside, "out_of_scope": outside, "preview": body.Preview})
}
