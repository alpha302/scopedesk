package main

import (
	"fmt"
	"net/http"
	"strings"
)

// Import configuration only. Accounts receive no budget or selection, and no
// provider request is made. Keys never appear in returned metadata or audit text.
func (e *Engine) servePassiveBatch(w http.ResponseWriter, r *http.Request, u User) {
	var b struct {
		ProjectID int64    `json:"project_id"`
		Prefix    string   `json:"prefix"`
		Keys      []string `json:"keys"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 512*1024)
	if !decode(w, r, &b) {
		return
	}
	defer func() { clear(b.Keys) }()
	b.Prefix = strings.TrimSpace(b.Prefix)
	if b.Prefix == "" {
		b.Prefix = "Hunter"
	}
	if b.ProjectID <= 0 || len(b.Prefix) > 80 || len(b.Keys) < 1 || len(b.Keys) > 50 {
		fail(w, 400, "请选择项目；每批支持 1–50 个 Hunter 密钥，名称前缀最多 80 字节")
		return
	}
	// Validate the whole batch before opening a transaction. Do not quote a bad key.
	for i, key := range b.Keys {
		key = strings.TrimSpace(key)
		if len(key) < 1 || len(key) > 8192 || strings.IndexFunc(key, func(c rune) bool {
			return c <= ' ' || c == 127
		}) >= 0 {
			fail(w, 400, fmt.Sprintf("第 %d 行密钥格式无效，整批未保存", i+1))
			return
		}
		b.Keys[i] = key
	}
	ctx := r.Context()
	if err := e.Store.projectPermission(ctx, b.ProjectID, u, true, true); err != nil {
		apiError(w, err)
		return
	}
	tx, err := e.Store.DB.Begin(ctx)
	if err != nil {
		fail(w, 500, "批量保存失败")
		return
	}
	defer tx.Rollback(ctx)
	// Match single-account saves' project lock; concurrent imports cannot create
	// another budget identity for the same key in this project.
	if _, err = tx.Exec(ctx, `SELECT id FROM projects WHERE id=$1 FOR UPDATE`, b.ProjectID); err != nil {
		fail(w, 500, "批量保存失败")
		return
	}
	rows, err := tx.Query(ctx, `SELECT id,key_encrypted FROM passive_source_accounts WHERE project_id=$1 AND source='hunter'`, b.ProjectID)
	if err != nil {
		fail(w, 500, "账户去重失败")
		return
	}
	seen := make(map[string]bool)
	defer clear(seen)
	for rows.Next() {
		var id int64
		var encrypted []byte
		if err = rows.Scan(&id, &encrypted); err != nil {
			break
		}
		var key []byte
		key, err = e.Store.decrypt(passiveKeyContext(id), encrypted)
		if err != nil {
			break
		}
		seen[string(key)] = true
		clear(key)
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil || rowErr != nil {
		fail(w, 500, "账户去重失败，整批未保存")
		return
	}
	ids := []int64{}
	skipped := 0
	for i, key := range b.Keys {
		if seen[key] {
			skipped++
			continue
		}
		seen[key] = true
		var id int64
		if err = tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('passive_source_accounts','id'))`).Scan(&id); err != nil {
			break
		}
		var encrypted []byte
		encrypted, err = e.Store.encrypt(passiveKeyContext(id), []byte(key))
		if err != nil {
			break
		}
		_, err = tx.Exec(ctx, `INSERT INTO passive_source_accounts(id,project_id,source,name,key_encrypted,billing_policy,page_size,enabled,selected) VALUES($1,$2,'hunter',$3,$4,'credits_only',10,false,false)`, id, b.ProjectID, fmt.Sprintf("%s %02d", b.Prefix, i+1), encrypted)
		if err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		fail(w, 500, "批量保存失败，整批未保存")
		return
	}
	e.Store.operation(ctx, u.ID, "passive.account.batch", "Hunter 批量加密保存；默认停用且未选定；未请求供应商")
	respond(w, 200, map[string]any{"ids": ids, "created": len(ids), "skipped": skipped})
}
