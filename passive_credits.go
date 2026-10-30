package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

type PassiveCredits struct {
	CheckedAt    time.Time `json:"checked_at"`
	Credits      *int64    `json:"credits"`
	DailyCredits *int64    `json:"daily_credits"`
	PaidBalance  *int64    `json:"paid_balance"`
	APIQueries   *int64    `json:"api_queries"`
	APIData      *int64    `json:"api_data"`
	Policy       string    `json:"billing_policy"`
}

func creditsOnlyAllowed(c PassiveCredits, reserve int64) error {
	if c.Policy != "credits_only" || c.PaidBalance == nil || *c.PaidBalance != 0 {
		return passiveFailure("paid_balance_blocked", "仅积分模式：付费余额非零或未知，无法排除上游回退扣费，停止查询")
	}
	if c.Credits == nil || *c.Credits < reserve {
		return passiveFailure("budget_exhausted", "可用积分不足或未知，停止查询；不会使用付费余额")
	}
	return nil
}
func parsePassiveCredits(source string, raw []byte) (snapshot PassiveCredits, err error) {
	snapshot.Policy = "credits_only"
	snapshot.CheckedAt = time.Now().UTC()
	if source == "hunter" {
		var body struct {
			Code json.RawMessage `json:"code"`
			Data *struct {
				Free   *int64 `json:"rest_free_point"`
				Daily  *int64 `json:"day_free_point"`
				Equity *int64 `json:"rest_equity_point"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &body) != nil || providerCode(body.Code) != "200" || body.Data == nil {
			return snapshot, passiveFailure("source_unavailable", "Hunter 账户接口未返回可核实的积分信息")
		}
		snapshot.Credits = body.Data.Free
		snapshot.DailyCredits = body.Data.Daily
		snapshot.PaidBalance = body.Data.Equity
	} else if source == "fofa" {
		var body struct {
			Error   *bool  `json:"error"`
			Coin    *int64 `json:"fcoin"`
			Points  *int64 `json:"fofa_point"`
			Queries *int64 `json:"remain_api_query"`
			Data    *int64 `json:"remain_api_data"`
		}
		if json.Unmarshal(raw, &body) != nil || body.Error == nil || *body.Error {
			return snapshot, passiveFailure("source_unavailable", "FOFA 账户接口未返回可核实的积分信息")
		}
		snapshot.PaidBalance = body.Coin
		snapshot.Credits = body.Points
		snapshot.APIQueries = body.Queries
		snapshot.APIData = body.Data
	} else {
		return snapshot, passiveFailure("source_config", "未知积分来源")
	}
	for _, n := range []*int64{snapshot.Credits, snapshot.DailyCredits, snapshot.PaidBalance} {
		if n != nil && *n < 0 {
			return snapshot, passiveFailure("invalid_output", "来源积分字段无效")
		}
	}
	return snapshot, nil
}
func providerCode(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}
func passiveClient(base *http.Client) (*http.Client, func()) {
	c := &http.Client{Timeout: 25 * time.Second}
	cleanup := func() {}
	if base != nil {
		*c = *base
		if c.Timeout <= 0 || c.Timeout > 25*time.Second {
			c.Timeout = 25 * time.Second
		}
	} else {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DisableKeepAlives = true
		c.Transport = transport
		cleanup = transport.CloseIdleConnections
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c, cleanup
}
func passiveAccountRequest(ctx context.Context, source string, key []byte) (*http.Request, error) {
	endpoint := "https://fofa.info/api/v1/info/my"
	parameter := "key"
	if source == "hunter" {
		endpoint = "https://hunter.qianxin.com/openApi/userInfo"
		parameter = "api-key"
	} else if source != "fofa" {
		return nil, errors.New("未知来源")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+url.Values{parameter: {string(key)}}.Encode(), nil)
	if err == nil {
		req.Header.Set("User-Agent", "ScopeDesk/0.3")
	}
	return req, err
}

// Account checks have their own audit rows. For job preflight they consume a
// separate API request from the same budget; they are never hidden search retries.
func (s *Store) checkPassiveCredits(ctx context.Context, r passiveReservation, jobID, scopeID int64, client *http.Client) (snapshot PassiveCredits, err error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return snapshot, err
	}
	defer tx.Rollback(ctx)
	var cooling bool
	if err = tx.QueryRow(ctx, `SELECT state='rate_limited' AND COALESCE(cooldown_until>clock_timestamp(),false) FROM passive_source_accounts WHERE id=$1 FOR UPDATE`, r.AccountID).Scan(&cooling); err != nil {
		return snapshot, err
	}
	if cooling {
		return snapshot, passiveFailure("rate_limited", "账户尚在冷却，未请求供应商")
	}
	if jobID != 0 {
		tag, e := tx.Exec(ctx, `UPDATE passive_source_budgets SET requests_used=requests_used+1 WHERE account_id=$1 AND window_start<=clock_timestamp() AND window_end>clock_timestamp() AND requests_used+requests_reserved<request_limit`, r.AccountID)
		if e != nil {
			return snapshot, e
		}
		if tag.RowsAffected() != 1 {
			return snapshot, passiveFailure("budget_exhausted", "账户检查请求预算不足")
		}
	}
	var checkID int64
	var job *int64
	if jobID != 0 {
		job = &jobID
	}
	if err = tx.QueryRow(ctx, `INSERT INTO passive_source_account_checks(account_id,job_id) VALUES($1,$2) RETURNING id`, r.AccountID, job).Scan(&checkID); err != nil {
		return snapshot, err
	}
	if err = tx.Commit(ctx); err != nil {
		return snapshot, passiveFailure("commit_uncertain", "账户检查预约状态不明，未自动重试")
	}
	finish := func(status, code string, snapshot PassiveCredits) error {
		saveCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		tx, e := s.DB.Begin(saveCtx)
		if e != nil {
			return e
		}
		defer tx.Rollback(saveCtx)
		raw, _ := json.Marshal(snapshot)
		if _, e = tx.Exec(saveCtx, `UPDATE passive_source_account_checks SET status=$2,error_code=$3,snapshot=$4,finished_at=now() WHERE id=$1`, checkID, status, code, raw); e != nil {
			return e
		}
		if status != "complete" {
			if _, e = tx.Exec(saveCtx, `UPDATE passive_source_accounts SET state=$2,cooldown_until=CASE WHEN $2='rate_limited' THEN now()+interval '15 minutes' ELSE cooldown_until END,updated_at=now() WHERE id=$1`, r.AccountID, status); e != nil {
				return e
			}
		}
		if status == "complete" {
			if _, e = tx.Exec(saveCtx, `UPDATE passive_source_accounts SET credit_snapshot=$2,updated_at=now() WHERE id=$1`, r.AccountID, raw); e != nil {
				return e
			}
		}
		return tx.Commit(saveCtx)
	}
	if scopeID != 0 {
		g, e := s.guard(ctx, scopeID)
		if e != nil || g.Valid() != nil {
			finish("unavailable", "scope_denied", snapshot)
			return snapshot, passiveFailure("scope_denied", "账户检查前授权失效")
		}
	}
	req, e := passiveAccountRequest(ctx, r.Source, r.Key)
	if e != nil {
		finish("unavailable", "source_config", snapshot)
		return snapshot, passiveFailure("source_config", "账户请求配置失败")
	}
	response, e := client.Do(req)
	if e != nil {
		finish("unavailable", "source_connection", snapshot)
		return snapshot, passiveFailure("source_connection", "账户接口连接失败或超时；未发送资产查询")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 1_000_001))
	response.Body.Close()
	status, code := passiveHTTPStatus(PassiveProvider{ErrorCodes: map[string]string{"http:401": "auth_expired", "http:403": "auth_expired", "http:429": "rate_limited"}}, response.StatusCode)
	if status != "complete" {
		finish(status, code, snapshot)
		return snapshot, passiveFailure(code, "账户接口认证失效、限流或不可用")
	}
	if e != nil || len(raw) > 1_000_000 {
		finish("unavailable", "invalid_output", snapshot)
		return snapshot, passiveFailure("invalid_output", "账户接口响应无效")
	}
	snapshot, e = parsePassiveCredits(r.Source, raw)
	if e != nil {
		finish("unavailable", "invalid_output", snapshot)
		return snapshot, e
	}
	if e = finish("complete", "", snapshot); e != nil {
		return snapshot, passiveFailure("source_storage", "账户检查保存失败，停止资产查询")
	}
	return snapshot, nil
}

// Only a provably unsent search may release its reservation automatically.
// Network-uncertain searches still use the existing pending-reconciliation path.
func (s *Store) cancelUnsentPassive(r passiveReservation, code string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM passive_source_accounts WHERE id=$1 FOR UPDATE`, r.AccountID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE passive_source_queries SET state='settled',status='failed',error_code=$2,actual_units=0,returned_count=0 WHERE id=$1 AND request_count=0 AND status='reserved' AND state='pending_reconciliation'`, r.ID, code)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("查询可能已发送，禁止释放预约")
	}
	_, err = tx.Exec(ctx, `UPDATE passive_source_budgets SET requests_reserved=requests_reserved-1,records_reserved=records_reserved-$2,units_reserved=units_reserved-$3 WHERE account_id=$1`, r.AccountID, r.PageSize, r.Units)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
