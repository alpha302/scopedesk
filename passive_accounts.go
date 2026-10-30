package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type PassiveAccount struct {
	BillingPolicy       string          `json:"billing_policy"`
	PageSize            int             `json:"page_size"`
	CreditSnapshot      *PassiveCredits `json:"credit_snapshot"`
	ProviderTimeEnabled bool            `json:"provider_time_enabled"`
	ID                  int64           `json:"id"`
	ProjectID           int64           `json:"project_id"`
	Source              string          `json:"source"`
	Name                string          `json:"name"`
	Enabled             bool            `json:"enabled"`
	Selected            bool            `json:"selected"`
	State               string          `json:"state"`
	CooldownUntil       *time.Time      `json:"cooldown_until"`
	KeySet              bool            `json:"key_set"`
}
type PassiveBudget struct {
	AccountID        int64     `json:"account_id"`
	WindowStart      time.Time `json:"window_start"`
	WindowEnd        time.Time `json:"window_end"`
	Timezone         string    `json:"timezone"`
	ResetPolicy      string    `json:"reset_policy"`
	RequestLimit     int64     `json:"request_limit"`
	RecordLimit      int64     `json:"record_limit"`
	UnitLimit        int64     `json:"unit_limit"`
	ReserveUnits     int64     `json:"reserve_units_per_page"`
	ChargeUnit       string    `json:"charge_unit"`
	RequestsUsed     int64     `json:"requests_used"`
	RequestsReserved int64     `json:"requests_reserved"`
	RecordsReturned  int64     `json:"records_returned"`
	RecordsReserved  int64     `json:"records_reserved"`
	UnitsUsed        int64     `json:"units_used"`
	UnitsReserved    int64     `json:"units_reserved"`
	BalanceAsOf      time.Time `json:"balance_as_of"`
	PolicyReference  string    `json:"policy_reference"`
}
type passiveReservation struct {
	BillingPolicy       string
	ProviderTimeEnabled bool
	ID                  int64
	AccountID           int64
	Source              string
	Key                 []byte
	Units               int64
	PageSize            int
}

func passiveKeyContext(id int64) string { return fmt.Sprintf("passive_source_accounts:%d", id) }

// A selected account is an explicit project binding. No fallback or rotation.
// The account lock serializes reservation, settlement and administrator updates.
func (s *Store) reservePassive(ctx context.Context, run Run, source, query string, page, size int) (r passiveReservation, err error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer tx.Rollback(ctx)
	guard, err := lockScopeProject(ctx, tx, run.ScopeID, false)
	if err != nil {
		return r, err
	}
	var validJob int64
	if err = tx.QueryRow(ctx, `SELECT id FROM jobs WHERE id=$1 AND scope_id=$2 AND worker_id=$3 AND status='running' AND NOT cancel_requested AND lease_until>clock_timestamp() FOR SHARE`, run.ID, run.ScopeID, run.Worker).Scan(&validJob); err != nil {
		return r, passiveFailure("lease_lost", "请求预约前任务已取消或租约失效")
	}
	var encrypted []byte
	var state string
	var cooldown *time.Time
	var configuredSize int
	err = tx.QueryRow(ctx, `SELECT id,key_encrypted,state,cooldown_until,provider_time_enabled,billing_policy,page_size FROM passive_source_accounts WHERE project_id=$1 AND source=$2 AND enabled AND selected FOR UPDATE`, guard.Scope.ProjectID, source).Scan(&r.AccountID, &encrypted, &state, &cooldown, &r.ProviderTimeEnabled, &r.BillingPolicy, &configuredSize)
	if err != nil {
		return r, passiveFailure("not_configured", "项目未绑定可用的被动来源账户")
	}
	if state != "ready" && !(state == "rate_limited" && cooldown != nil && !cooldown.After(time.Now())) {
		return r, passiveFailure(state, "来源账户需要处理或仍在冷却；不会自动换号")
	}
	if r.BillingPolicy != "credits_only" {
		return r, passiveFailure("billing_policy", "仅支持积分方式")
	}
	size = min(size, configuredSize)
	var pending bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM passive_source_queries WHERE account_id=$1 AND state='pending_reconciliation')`, r.AccountID).Scan(&pending); err != nil {
		return r, err
	}
	if pending {
		return r, passiveFailure("reconciliation_required", "账户存在未结算请求，须先核对实际收费")
	}
	var bound int64
	err = tx.QueryRow(ctx, `UPDATE passive_source_budgets SET requests_reserved=requests_reserved+1,records_reserved=records_reserved+$2,units_reserved=units_reserved+reserve_units_per_page,updated_at=now()
 WHERE account_id=$1 AND charge_unit='points' AND reserve_units_per_page>0 AND unit_limit>0 AND window_start<=clock_timestamp() AND window_end>clock_timestamp() AND requests_used+requests_reserved<request_limit AND records_returned+records_reserved+$2<=record_limit AND units_used+units_reserved+reserve_units_per_page<=unit_limit
 RETURNING reserve_units_per_page`, r.AccountID, size).Scan(&bound)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, passiveFailure("budget_exhausted", "独立来源预算不足、未配置或窗口已到期；不推测每日重置")
	}
	if err != nil {
		return r, err
	}
	// Uniqueness also blocks automatic replay after worker lease recovery.
	err = tx.QueryRow(ctx, `INSERT INTO passive_source_queries(account_id,project_id,source,job_id,query,page,page_size,reserved_units,charge_unit,budget_window_start,budget_window_end) SELECT $1,$2,$3,$4,$5,$6,$7,$8,charge_unit,window_start,window_end FROM passive_source_budgets WHERE account_id=$1 RETURNING id`, r.AccountID, guard.Scope.ProjectID, source, run.ID, query, page, size, bound).Scan(&r.ID)
	if err != nil {
		return r, passiveFailure("reconciliation_required", "同一任务分页已预约或提交状态不明；禁止自动重查")
	}
	r.Key, err = s.decrypt(passiveKeyContext(r.AccountID), encrypted)
	if err != nil {
		return r, passiveFailure("auth_expired", "来源凭据无法读取")
	}
	r.Source = source
	r.Units = bound
	r.PageSize = size
	if err = tx.Commit(ctx); err != nil {
		return passiveReservation{}, passiveFailure("reconciliation_required", "请求预约提交状态不明；请核对账本")
	}
	return r, nil
}

// No network failure causes a refund. Unknown charge keeps the reservation and
// blocks new requests until an administrator supplies a confirmed settlement.
func (s *Store) recordPassiveResponse(r passiveReservation, count *int, actual *int64, remaining *int64, status, code string, pageComplete, queryComplete bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM passive_source_accounts WHERE id=$1 FOR UPDATE`, r.AccountID); err != nil {
		return err
	}
	var state string
	var oldCount *int
	if err = tx.QueryRow(ctx, `SELECT state,returned_count FROM passive_source_queries WHERE id=$1 FOR UPDATE`, r.ID).Scan(&state, &oldCount); err != nil {
		return err
	}
	if state == "settled" || oldCount != nil {
		return tx.Commit(ctx)
	}
	next := "pending_reconciliation"
	if actual != nil {
		next = "settled"
	}
	_, err = tx.Exec(ctx, `UPDATE passive_source_queries SET returned_count=$2,actual_units=$3,provider_remaining=$4,status=$5,error_code=$6,page_complete=$7,query_complete=$8,state=$9,received_at=CASE WHEN $2::integer IS NOT NULL THEN now() ELSE NULL END WHERE id=$1`, r.ID, count, actual, remaining, status, code, pageComplete, queryComplete, next)
	if err != nil {
		return err
	}
	if count != nil {
		if _, err = tx.Exec(ctx, `UPDATE passive_source_budgets SET records_reserved=records_reserved-$2,records_returned=records_returned+$3,updated_at=now() WHERE account_id=$1`, r.AccountID, r.PageSize, *count); err != nil {
			return err
		}
	}
	if actual != nil {
		if count == nil {
			return errors.New("收费结算需要已知返回条数")
		}
		_, err = tx.Exec(ctx, `UPDATE passive_source_budgets SET units_reserved=units_reserved-$2,units_used=units_used+$3,updated_at=now() WHERE account_id=$1`, r.AccountID, r.Units, *actual)
	}
	if err != nil {
		return err
	}
	accountState := "ready"
	if actual == nil {
		accountState = "reconciliation_required"
	} else if status == "auth_expired" || status == "rate_limited" || status == "unavailable" {
		accountState = status
	}
	_, err = tx.Exec(ctx, `UPDATE passive_source_accounts SET state=$2,cooldown_until=CASE WHEN $3='rate_limited' THEN now()+interval '15 minutes' ELSE cooldown_until END,updated_at=now() WHERE id=$1`, r.AccountID, accountState, status)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Persist the send boundary separately from reservation. A crash in the narrow
// boundary remains pending; recovery must never infer that the request was free.
func (s *Store) markPassiveSent(ctx context.Context, r passiveReservation) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM passive_source_accounts WHERE id=$1 FOR UPDATE`, r.AccountID); err != nil {
		return err
	}
	var enabled, selected bool
	if err = tx.QueryRow(ctx, `SELECT enabled,selected FROM passive_source_accounts WHERE id=$1`, r.AccountID).Scan(&enabled, &selected); err != nil {
		return err
	}
	if !enabled || !selected {
		return errors.New("账户已停用或不再被项目选定；预约保留待核对")
	}
	tag, err := tx.Exec(ctx, `UPDATE passive_source_queries SET status='sent',sent_at=now(),request_count=1 WHERE id=$1 AND state='pending_reconciliation' AND status='reserved' AND request_count=0`, r.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("请求发送边界已处理或待核对")
	}
	if _, err = tx.Exec(ctx, `UPDATE passive_source_budgets SET requests_reserved=requests_reserved-1,requests_used=requests_used+1 WHERE account_id=$1`, r.AccountID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
