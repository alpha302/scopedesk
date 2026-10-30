package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (e *Engine) servePassive(w http.ResponseWriter, r *http.Request, u User) {
	ctx := r.Context()
	// All passive management endpoints are platform-admin only in Engine.serve.
	path := strings.TrimPrefix(r.URL.Path, "/api/settings/")
	switch {
	case path == "passive-accounts/batch" && r.Method == "POST":
		e.servePassiveBatch(w, r, u)
	case path == "passive-accounts/check" && r.Method == "POST":
		var b struct {
			ID int64 `json:"id"`
		}
		if !decode(w, r, &b) {
			return
		}
		var rsv passiveReservation
		var encrypted []byte
		if err := e.Store.DB.QueryRow(ctx, `SELECT id,source,key_encrypted FROM passive_source_accounts WHERE id=$1`, b.ID).Scan(&rsv.AccountID, &rsv.Source, &encrypted); err != nil {
			apiError(w, err)
			return
		}
		key, err := e.Store.decrypt(passiveKeyContext(rsv.AccountID), encrypted)
		if err != nil {
			fail(w, 400, "账户凭据无法读取")
			return
		}
		rsv.Key = key
		client, cleanup := passiveClient(e.PassiveHTTPClient)
		defer cleanup()
		snapshot, err := e.Store.checkPassiveCredits(ctx, rsv, 0, 0, client)
		if err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(ctx, u.ID, "passive.account.check", "只检查积分余额；未查询资产")
		respond(w, 200, snapshot)
	case path == "passive-accounts" && r.Method == "GET":
		rows, err := e.Store.DB.Query(ctx, `SELECT id,project_id,source,name,enabled,selected,state,cooldown_until,provider_time_enabled,billing_policy,page_size,credit_snapshot,octet_length(key_encrypted)>0 FROM passive_source_accounts ORDER BY id`)
		if err != nil {
			apiError(w, errors.New("账户读取失败"))
			return
		}
		defer rows.Close()
		items := []PassiveAccount{}
		for rows.Next() {
			var a PassiveAccount
			var snapshotRaw []byte
			if err = rows.Scan(&a.ID, &a.ProjectID, &a.Source, &a.Name, &a.Enabled, &a.Selected, &a.State, &a.CooldownUntil, &a.ProviderTimeEnabled, &a.BillingPolicy, &a.PageSize, &snapshotRaw, &a.KeySet); err != nil {
				apiError(w, errors.New("账户读取失败"))
				return
			}
			var snapshot PassiveCredits
			if json.Unmarshal(snapshotRaw, &snapshot) == nil && !snapshot.CheckedAt.IsZero() {
				a.CreditSnapshot = &snapshot
			}
			items = append(items, a)
		}
		if rows.Err() != nil {
			apiError(w, errors.New("账户读取失败"))
			return
		}
		respond(w, 200, map[string]any{"items": items, "providers": passiveProviderMetadata()})
	case path == "passive-accounts" && (r.Method == "POST" || r.Method == "PUT"):
		var b struct {
			BillingPolicy       string `json:"billing_policy"`
			PageSize            int    `json:"page_size"`
			ProviderTimeEnabled bool   `json:"provider_time_enabled"`
			ID                  int64  `json:"id"`
			ProjectID           int64  `json:"project_id"`
			Source              string `json:"source"`
			Name                string `json:"name"`
			Key                 string `json:"key"`
			Enabled             bool   `json:"enabled"`
			Selected            bool   `json:"selected"`
		}
		if !decode(w, r, &b) {
			return
		}
		if b.BillingPolicy == "" {
			b.BillingPolicy = "credits_only"
		}
		if b.PageSize == 0 {
			b.PageSize = 10
		}
		if b.BillingPolicy != "credits_only" || b.PageSize < 1 || b.PageSize > 100 || b.Source == "hunter" && (b.PageSize != 10 && b.PageSize != 20 && b.PageSize != 50 && b.PageSize != 100) {
			fail(w, 400, "仅支持积分模式；Hunter 每页可选 10/20/50/100")
			return
		}
		if b.ID < 0 || !paidPassive(b.Source) || len(b.Name) < 1 || len(b.Name) > 100 || len(b.Key) > 8192 || b.Selected && !b.Enabled {
			fail(w, 400, "来源、账户名称或选择状态无效")
			return
		}
		if b.Enabled && !passiveProviderVerified(b.Source) {
			fail(w, 400, "该来源官方接口资料尚未核实，暂不能启用")
			return
		}
		tx, err := e.Store.DB.Begin(ctx)
		if err != nil {
			apiError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		if err = e.Store.projectPermission(ctx, b.ProjectID, u, true, true); err != nil {
			apiError(w, err)
			return
		}
		// Serialize explicit selection changes for a project; no automatic account swaps.
		if _, err = tx.Exec(ctx, `SELECT id FROM projects WHERE id=$1 FOR UPDATE`, b.ProjectID); err != nil {
			apiError(w, err)
			return
		}
		if b.ID == 0 {
			if b.Key == "" {
				fail(w, 400, "新账户需要在此表单填写密钥")
				return
			}
			if err = tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('passive_source_accounts','id'))`).Scan(&b.ID); err != nil {
				apiError(w, err)
				return
			}
			encrypted, encErr := e.Store.encrypt(passiveKeyContext(b.ID), []byte(b.Key))
			b.Key = ""
			if encErr != nil {
				fail(w, 500, "账户加密失败")
				return
			}
			if b.Selected {
				if _, err = tx.Exec(ctx, `UPDATE passive_source_accounts SET selected=false WHERE project_id=$1 AND source=$2`, b.ProjectID, b.Source); err != nil {
					apiError(w, err)
					return
				}
			}
			_, err = tx.Exec(ctx, `INSERT INTO passive_source_accounts(id,project_id,source,name,key_encrypted,enabled,selected,provider_time_enabled,billing_policy,page_size) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, b.ID, b.ProjectID, b.Source, b.Name, encrypted, b.Enabled, b.Selected, b.ProviderTimeEnabled, b.BillingPolicy, b.PageSize)
		} else {
			var project int64
			var source string
			if err = tx.QueryRow(ctx, `SELECT project_id,source FROM passive_source_accounts WHERE id=$1 FOR UPDATE`, b.ID).Scan(&project, &source); err != nil {
				apiError(w, err)
				return
			}
			if project != b.ProjectID || source != b.Source {
				fail(w, 400, "既有账户不能更换项目或供应商")
				return
			}
			// Updating configuration must not unblock a charge awaiting reconciliation.
			var pending bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM passive_source_queries WHERE account_id=$1 AND state='pending_reconciliation')`, b.ID).Scan(&pending); err != nil {
				apiError(w, err)
				return
			}
			if pending && (b.Selected || b.Key != "") {
				fail(w, 409, "先核对该账户未结算的请求；可以停用账户")
				return
			}
			if b.Selected {
				if _, err = tx.Exec(ctx, `UPDATE passive_source_accounts SET selected=false WHERE project_id=$1 AND source=$2`, project, source); err != nil {
					apiError(w, err)
					return
				}
			}
			_, err = tx.Exec(ctx, `UPDATE passive_source_accounts SET name=$2,enabled=$3,selected=$4,provider_time_enabled=$5,billing_policy=$6,page_size=$7,updated_at=now() WHERE id=$1`, b.ID, b.Name, b.Enabled, b.Selected, b.ProviderTimeEnabled, b.BillingPolicy, b.PageSize)
			if err == nil && b.Key != "" {
				encrypted, encErr := e.Store.encrypt(passiveKeyContext(b.ID), []byte(b.Key))
				b.Key = ""
				if encErr != nil {
					fail(w, 500, "账户加密失败")
					return
				}
				_, err = tx.Exec(ctx, `UPDATE passive_source_accounts SET key_encrypted=$2,credit_snapshot='{}'::jsonb,state=CASE WHEN state='auth_expired' THEN 'ready' ELSE state END,updated_at=now() WHERE id=$1`, b.ID, encrypted)
			}
		}
		if err == nil {
			err = tx.Commit(ctx)
		}
		if err != nil {
			fail(w, 400, "账户保存失败，请检查项目、选择冲突或存储状态")
			return
		}
		e.Store.operation(ctx, u.ID, "passive.account.save", "只写凭据；不执行供应商请求")
		respond(w, 200, map[string]any{"id": b.ID, "key_set": true})
	case path == "passive-accounts" && r.Method == "PATCH":
		var b struct {
			ID      int64 `json:"id"`
			Recover bool  `json:"recover"`
		}
		if !decode(w, r, &b) {
			return
		}
		if !b.Recover {
			fail(w, 400, "需要明确恢复账户状态")
			return
		}
		tx, err := e.Store.DB.Begin(ctx)
		if err != nil {
			apiError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		var state string
		var cooldown *time.Time
		if err = tx.QueryRow(ctx, `SELECT state,cooldown_until FROM passive_source_accounts WHERE id=$1 FOR UPDATE`, b.ID).Scan(&state, &cooldown); err != nil {
			apiError(w, err)
			return
		}
		if state != "unavailable" && !(state == "rate_limited" && cooldown != nil && !cooldown.After(time.Now())) {
			fail(w, 409, "仅可恢复不可用或冷却已结束的账户；认证失效请更新密钥")
			return
		}
		var pending bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM passive_source_queries WHERE account_id=$1 AND state='pending_reconciliation')`, b.ID).Scan(&pending); err != nil {
			apiError(w, err)
			return
		}
		if pending {
			fail(w, 409, "先结算账户待核对请求")
			return
		}
		if _, err = tx.Exec(ctx, `UPDATE passive_source_accounts SET state='ready',updated_at=now() WHERE id=$1`, b.ID); err == nil {
			err = tx.Commit(ctx)
		}
		if err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(ctx, u.ID, "passive.account.recover", "显式恢复状态；未发送查询")
		respond(w, 200, map[string]bool{"ok": true})
	case path == "passive-budgets" && r.Method == "GET":
		rows, err := e.Store.DB.Query(ctx, `SELECT account_id,window_start,window_end,timezone,reset_policy,request_limit,record_limit,unit_limit,reserve_units_per_page,charge_unit,requests_used,requests_reserved,records_returned,records_reserved,units_used,units_reserved,balance_as_of,policy_reference FROM passive_source_budgets ORDER BY account_id`)
		if err != nil {
			fail(w, 500, "预算读取失败")
			return
		}
		defer rows.Close()
		items := []PassiveBudget{}
		for rows.Next() {
			var b PassiveBudget
			if err = rows.Scan(&b.AccountID, &b.WindowStart, &b.WindowEnd, &b.Timezone, &b.ResetPolicy, &b.RequestLimit, &b.RecordLimit, &b.UnitLimit, &b.ReserveUnits, &b.ChargeUnit, &b.RequestsUsed, &b.RequestsReserved, &b.RecordsReturned, &b.RecordsReserved, &b.UnitsUsed, &b.UnitsReserved, &b.BalanceAsOf, &b.PolicyReference); err != nil {
				fail(w, 500, "预算读取失败")
				return
			}
			items = append(items, b)
		}
		if rows.Err() != nil {
			fail(w, 500, "预算读取失败")
			return
		}
		respond(w, 200, items)
	case path == "passive-budgets" && r.Method == "PUT":
		var b PassiveBudget
		if !decode(w, r, &b) {
			return
		}
		if b.AccountID <= 0 || !b.WindowEnd.After(b.WindowStart) || !b.WindowEnd.After(time.Now()) || b.WindowStart.After(time.Now()) || b.WindowEnd.Sub(b.WindowStart) > 32*24*time.Hour || b.BalanceAsOf.IsZero() || b.BalanceAsOf.After(time.Now().Add(time.Minute)) || b.BalanceAsOf.Before(b.WindowStart) || b.RequestLimit < 1 || b.RequestLimit > 1000000 || b.RecordLimit < 1 || b.RecordLimit > 10000000 || b.UnitLimit < 1 || b.UnitLimit > 1000000000 || b.ReserveUnits < 1 || b.ReserveUnits > b.UnitLimit || b.ChargeUnit != "points" || b.ResetPolicy != "manual_confirmed" || len(b.PolicyReference) < 1 || len(b.PolicyReference) > 1000 || !sourceNamePattern.MatchString(b.Timezone) && b.Timezone != "Asia/Shanghai" && b.Timezone != "Etc/UTC" {
			fail(w, 400, "预算窗口、单位或核实信息无效；不会自动重置额度")
			return
		}
		tx, err := e.Store.DB.Begin(ctx)
		if err != nil {
			apiError(w, err)
			return
		}
		defer tx.Rollback(ctx)
		var id int64
		if err = tx.QueryRow(ctx, `SELECT id FROM passive_source_accounts WHERE id=$1 FOR UPDATE`, b.AccountID).Scan(&id); err != nil {
			apiError(w, err)
			return
		}
		var pending bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM passive_source_queries WHERE account_id=$1 AND state='pending_reconciliation')`, b.AccountID).Scan(&pending); err != nil {
			apiError(w, err)
			return
		}
		if pending {
			fail(w, 409, "账户有待核对请求，不能改写或重置预算")
			return
		}
		// Same window keeps cumulative consumption. A new, nonoverlapping confirmed
		// window may start fresh; no assumed timezone or daily allowance is generated.
		var oldStart, oldEnd time.Time
		var oldUnit string
		var oldUsed, oldHeld int64
		err = tx.QueryRow(ctx, `SELECT window_start,window_end,charge_unit,units_used,units_reserved FROM passive_source_budgets WHERE account_id=$1`, id).Scan(&oldStart, &oldEnd, &oldUnit, &oldUsed, &oldHeld)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			apiError(w, err)
			return
		}
		fresh := err == pgx.ErrNoRows || !b.WindowStart.Before(oldEnd)
		if !fresh && oldUnit != b.ChargeUnit && (oldUsed > 0 || oldHeld > 0) {
			fail(w, 409, "同一预算窗口不能更换已记账的收费单位")
			return
		}
		if !fresh && (!b.WindowStart.Equal(oldStart) || !b.WindowEnd.Equal(oldEnd)) {
			fail(w, 409, "预算窗口不可重叠或挪动；同一窗口保留已用量")
			return
		}
		_, err = tx.Exec(ctx, `INSERT INTO passive_source_budgets(account_id,window_start,window_end,timezone,reset_policy,request_limit,record_limit,unit_limit,reserve_units_per_page,charge_unit,balance_as_of,policy_reference) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
 ON CONFLICT(account_id) DO UPDATE SET window_start=excluded.window_start,window_end=excluded.window_end,timezone=excluded.timezone,request_limit=excluded.request_limit,record_limit=excluded.record_limit,unit_limit=excluded.unit_limit,reserve_units_per_page=excluded.reserve_units_per_page,charge_unit=excluded.charge_unit,balance_as_of=excluded.balance_as_of,policy_reference=excluded.policy_reference,requests_used=CASE WHEN $13 THEN 0 ELSE passive_source_budgets.requests_used END,requests_reserved=0,records_returned=CASE WHEN $13 THEN 0 ELSE passive_source_budgets.records_returned END,units_used=CASE WHEN $13 THEN 0 ELSE passive_source_budgets.units_used END,updated_at=now()`, id, b.WindowStart, b.WindowEnd, b.Timezone, b.ResetPolicy, b.RequestLimit, b.RecordLimit, b.UnitLimit, b.ReserveUnits, b.ChargeUnit, b.BalanceAsOf, b.PolicyReference, fresh)
		if err == nil {
			err = tx.Commit(ctx)
		}
		if err != nil {
			fail(w, 400, "预算保存失败")
			return
		}
		e.Store.operation(ctx, u.ID, "passive.budget.save", "人工确认窗口；未联网查询")
		respond(w, 200, map[string]bool{"ok": true})
	case path == "passive-queries" && r.Method == "GET":
		page := passivePage(r)
		limit := 50
		rows, err := e.Store.DB.Query(ctx, `SELECT jsonb_build_object('id',id,'account_id',account_id,'project_id',project_id,'source',source,'job_id',job_id,'query',query,'page',page,'page_size',page_size,'request_count',request_count,'returned_count',returned_count,'reserved_units',reserved_units,'budget_window_start',budget_window_start,'budget_window_end',budget_window_end,'actual_units',actual_units,'charge_unit',charge_unit,'state',state,'status',status,'error_code',error_code,'page_complete',page_complete,'query_complete',query_complete,'provider_remaining',provider_remaining,'created_at',created_at,'sent_at',sent_at,'received_at',received_at,'reconciled_at',reconciled_at) FROM passive_source_queries ORDER BY id DESC LIMIT $1 OFFSET $2`, limit, (page-1)*limit)
		if err != nil {
			fail(w, 500, "账本读取失败")
			return
		}
		defer rows.Close()
		items := []any{}
		for rows.Next() {
			var raw []byte
			if err = rows.Scan(&raw); err != nil {
				fail(w, 500, "账本读取失败")
				return
			}
			items = append(items, json.RawMessage(raw))
		}
		if rows.Err() != nil {
			fail(w, 500, "账本读取失败")
			return
		}
		respond(w, 200, map[string]any{"items": items, "page": page, "page_size": limit})
	case path == "passive-queries" && r.Method == "PATCH":
		var b struct {
			ID            int64  `json:"id"`
			ActualUnits   *int64 `json:"actual_units"`
			ReturnedCount *int   `json:"returned_count"`
			Confirmed     bool   `json:"confirmed"`
		}
		if !decode(w, r, &b) {
			return
		}
		if !b.Confirmed || b.ActualUnits == nil || *b.ActualUnits < 0 || *b.ActualUnits > 1000000000 || b.ReturnedCount == nil || *b.ReturnedCount < 0 || *b.ReturnedCount > 10000 {
			fail(w, 400, "须人工核实实际收费及返回条数，并明确确认")
			return
		}
		if err := e.Store.reconcilePassive(ctx, b.ID, *b.ActualUnits, *b.ReturnedCount, u.ID); err != nil {
			apiError(w, err)
			return
		}
		e.Store.operation(ctx, u.ID, "passive.query.reconcile", "已人工核对；不自动重新查询")
		respond(w, 200, map[string]bool{"ok": true})
	default:
		fail(w, 405, "不支持的被动来源管理操作")
	}
}

func (s *Store) reconcilePassive(ctx context.Context, id, actual int64, count, user int) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var account int64
	if err = tx.QueryRow(ctx, `SELECT account_id FROM passive_source_queries WHERE id=$1`, id).Scan(&account); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT id FROM passive_source_accounts WHERE id=$1 FOR UPDATE`, account); err != nil {
		return err
	}
	var r passiveReservation
	var state, status string
	var returned *int
	var requests int
	if err = tx.QueryRow(ctx, `SELECT state,status,page_size,reserved_units,returned_count,request_count FROM passive_source_queries WHERE id=$1 FOR UPDATE`, id).Scan(&state, &status, &r.PageSize, &r.Units, &returned, &requests); err != nil {
		return err
	}
	if state == "settled" {
		return errors.New("该请求已经结算，禁止重复结算")
	}
	var running bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs j JOIN passive_source_queries q ON q.job_id=j.id WHERE q.id=$1 AND j.status IN ('running','queued','retrying'))`, id).Scan(&running); err != nil {
		return err
	}
	if running {
		return errors.New("须等待原任务终止后核对，避免与运行中请求重复结算")
	}
	if returned != nil && *returned != count {
		return errors.New("返回条数与已取得响应不一致")
	}
	if returned == nil {
		if _, err = tx.Exec(ctx, `UPDATE passive_source_budgets SET records_reserved=records_reserved-$2,records_returned=records_returned+$3 WHERE account_id=$1`, account, r.PageSize, count); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE passive_source_budgets SET units_reserved=units_reserved-$2,units_used=units_used+$3,requests_reserved=requests_reserved-$4,updated_at=now() WHERE account_id=$1`, account, r.Units, actual, 1-requests)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE passive_source_queries SET state='settled',actual_units=$2,returned_count=$3,reconciled_at=now(),reconciled_by=$4,reconciliation_note='administrator_confirmed' WHERE id=$1`, id, actual, count, user)
	if err != nil {
		return err
	}
	next := "ready"
	if status == "auth_expired" || status == "rate_limited" || status == "unavailable" {
		next = status
	}
	_, err = tx.Exec(ctx, `UPDATE passive_source_accounts SET state=$2,updated_at=now() WHERE id=$1`, account, next)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func passivePage(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("page"))
	return min(100000, max(1, n))
}
