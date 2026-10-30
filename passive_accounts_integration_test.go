package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// All operations below stay in integrationStore's isolated schema. No provider
// HTTP, account-info call or target request is used, even when later executed.
func passiveAccountFixture(t *testing.T, s *Store, scope ScopeV2) (int64, Run) {
	t.Helper()
	ctx := context.Background()
	fresh, err := s.scopesByID(ctx, scope.ID)
	if err != nil {
		t.Fatal(err)
	}
	run := claimedRun(t, s, fresh)
	var account int64
	if err = s.DB.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('passive_source_accounts','id'))`).Scan(&account); err != nil {
		t.Fatal(err)
	}
	encrypted, err := s.encrypt(passiveKeyContext(account), []byte("offline-fixture-key"))
	if err != nil {
		t.Fatal(err)
	}
	projectExec(t, s, `INSERT INTO passive_source_accounts(id,project_id,source,name,key_encrypted,enabled,selected) VALUES($1,$2,'fofa','offline fixture',$3,true,true)`, account, fresh.ProjectID, encrypted)
	projectExec(t, s, `INSERT INTO passive_source_budgets(account_id,window_start,window_end,request_limit,record_limit,unit_limit,reserve_units_per_page,charge_unit,balance_as_of,policy_reference) VALUES($1,now()-interval '1 hour',now()+interval '1 hour',10,1000,100,20,'points',now(),'offline fixture')`, account)
	return account, run
}
func TestPostgresPassiveReservationUnknownChargeAndSettlement(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	account, run := passiveAccountFixture(t, s, scope)
	r, err := s.reservePassive(ctx, run, "fofa", `domain="example.com"`, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	var requests, reserved, units int64
	if err = s.DB.QueryRow(ctx, `SELECT requests_used,requests_reserved,units_reserved FROM passive_source_budgets WHERE account_id=$1`, account).Scan(&requests, &reserved, &units); err != nil || requests != 0 || reserved != 1 || units != 20 {
		t.Fatal("reservation counted as actual consumption", err, requests, reserved, units)
	}
	if err = s.markPassiveSent(ctx, r); err != nil {
		t.Fatal(err)
	}
	count := 3
	if err = s.recordPassiveResponse(r, &count, nil, nil, "complete", "reconciliation_required", true, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.reservePassive(ctx, run, "fofa", `domain="example.com"`, 2, 100); err == nil {
		t.Fatal("unknown charge did not stop automatic continuation")
	}
	if err = s.DB.QueryRow(ctx, `SELECT requests_used,requests_reserved,units_reserved FROM passive_source_budgets WHERE account_id=$1`, account).Scan(&requests, &reserved, &units); err != nil || requests != 1 || reserved != 0 || units != 20 {
		t.Fatal("unknown charge refunded or converted to one point", err, requests, reserved, units)
	}
	if err = s.reconcilePassive(ctx, r.ID, 7, count, 1); err == nil {
		t.Fatal("reconciled while original job still running")
	}
	projectExec(t, s, `UPDATE jobs SET status='done' WHERE id=$1`, run.ID)
	if err = s.reconcilePassive(ctx, r.ID, 7, count, 1); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcilePassive(ctx, r.ID, 7, count, 1); err == nil {
		t.Fatal("double settlement permitted")
	}
	var returned int64
	if err = s.DB.QueryRow(ctx, `SELECT records_returned,units_used,units_reserved FROM passive_source_budgets WHERE account_id=$1`, account).Scan(&returned, &units, &reserved); err != nil || returned != 3 || units != 7 || reserved != 0 {
		t.Fatal("settlement lost actual units or double counted returned rows", err, returned, units, reserved)
	}
	if _, err = s.reservePassive(ctx, run, "fofa", `domain="example.com"`, 1, 100); err == nil {
		t.Fatal("same task page replayed after reconciliation")
	}
	e := &Engine{Store: s}
	response := projectCall(e, User{ID: 1, Role: "admin"}, "GET", "/api/settings/passive-accounts", "")
	if response.Code != 200 || strings.Contains(response.Body.String(), "offline-fixture-key") || strings.Contains(response.Body.String(), "encrypted") {
		t.Fatal("account secret exposed", response.Code)
	}
}
func TestPostgresPassiveConcurrentReserveAndExpiry(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	account, run := passiveAccountFixture(t, s, scope)
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.reservePassive(ctx, run, "fofa", `domain="example.com"`, 1, 100); err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("concurrent duplicate reservation", success)
	}
	var n int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM passive_source_queries WHERE account_id=$1`, account).Scan(&n); err != nil || n != 1 {
		t.Fatal("duplicate ledger rows", err, n)
	}
	projectExec(t, s, `UPDATE passive_source_budgets SET window_start=now()-interval '2 hour',window_end=now()-interval '1 hour' WHERE account_id=$1`, account)
	if _, err := s.reservePassive(ctx, run, "fofa", "other", 2, 100); err == nil {
		t.Fatal("expired window reused")
	}
	// Read-only callers cannot access admin credential/budget/query management.
	for _, path := range []string{"passive-accounts", "passive-budgets", "passive-queries"} {
		w := projectCall(&Engine{Store: s}, User{ID: 1, Role: "readonly"}, "GET", "/api/settings/"+path, "")
		if w.Code != 403 {
			t.Fatal("management permission", path, w.Code)
		}
	}
}

func TestPostgresPassiveCollectorEvidenceOnlyOffline(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	account, run := passiveAccountFixture(t, s, scope)
	calls := 0
	collector := &PassiveAPICollector{Source: "fofa", Store: s, Run: run, Budget: &Budget{Limit: 10}, Client: &http.Client{Transport: policyTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/v1/info/my" {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"error":false,"fcoin":0,"fofa_point":1000}`))}, nil
		}
		calls++
		if !officialPassiveEndpoint(req.URL.String()) {
			t.Fatal("request escaped official origin")
		}
		if strings.Contains(req.URL.Query().Get("fields"), "lastupdatetime") {
			t.Fatal("default request assumed privileged time capability")
		}
		if req.URL.Query().Get("page") != "1" {
			t.Fatal("unknown charge triggered another billable page")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"error":false,"results":[["api.example.com","8.8.8.8","443","Historical","server","https"]],"size":1,"page":1,"query":"domain=\"example.com\""}`))}, nil
	})}}
	stream, err := collector.Collect(ctx, scope)
	if err == nil || calls != 1 || collector.Result.Complete || collector.Result.AbsenceUsable {
		t.Fatal("unknown charge was treated as complete or retried", err, calls)
	}
	if len(stream) != 1 || len(collector.Result.Records) != 1 {
		t.Fatal("unknown charge lost verified data")
	}
	ev := collector.Result.Records[0].Observation.PluginEvidence[0]
	if ev.AccountID == nil || *ev.AccountID != account || ev.ProviderTime != nil {
		t.Fatal("historical account or missing time misrepresented")
	}
	var state string
	var used, held, returned int64
	if err = s.DB.QueryRow(ctx, `SELECT a.state,b.requests_used,b.units_reserved,b.records_returned FROM passive_source_accounts a JOIN passive_source_budgets b ON b.account_id=a.id WHERE a.id=$1`, account).Scan(&state, &used, &held, &returned); err != nil || state != "reconciliation_required" || used != 2 || held != 20 || returned != 1 {
		t.Fatal("response accounting", err, state, used, held, returned)
	}
}

func TestPostgresPassiveCreditsOnlyPreflightStopsPaidBalance(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	account, run := passiveAccountFixture(t, s, scope)
	searches := 0
	client := &http.Client{Transport: policyTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/api/v1/info/my" {
			searches++
			t.Fatal("search issued with paid balance")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"error":false,"fcoin":1,"fofa_point":1000}`))}, nil
	})}
	c := &PassiveAPICollector{Source: "fofa", Store: s, Run: run, Budget: &Budget{Limit: 10}, Client: client}
	result := c.CollectPassive(ctx, scope)
	if result.Err == nil || classifyExecutionError(result.Err, "").Code != "paid_balance_blocked" || searches != 0 {
		t.Fatal("credits-only guard", result.Err, searches)
	}
	var pending, actual, used, reserved int64
	if err := s.DB.QueryRow(ctx, `SELECT (SELECT count(*) FROM passive_source_queries WHERE account_id=$1 AND state='pending_reconciliation'),units_used,requests_used,requests_reserved FROM passive_source_budgets WHERE account_id=$1`, account).Scan(&pending, &actual, &used, &reserved); err != nil || pending != 0 || actual != 0 || used != 1 || reserved != 0 {
		t.Fatal("known-unsent search accounting", err, pending, actual, used, reserved)
	}
}
func TestPostgresPassiveHunterKnownQuotaSettlesAndPreservesHistory(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	account, run := passiveAccountFixture(t, s, scope)
	projectExec(t, s, `UPDATE passive_source_accounts SET source='hunter' WHERE id=$1`, account)
	client := &http.Client{Transport: policyTransport(func(req *http.Request) (*http.Response, error) {
		body := `{"code":200,"data":{"rest_free_point":500,"day_free_point":500,"rest_equity_point":0}}`
		if req.URL.Path == "/openApi/search" {
			body = `{"code":200,"data":{"total":2,"arr":[{"domain":"api.example.com","ip":"8.8.8.8","port":443,"status_code":200},{"domain":"outside.invalid","ip":"8.8.4.4","port":80}],"consume_quota":"消耗积分：2","rest_quota":"今日剩余积分：498"}}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	c := &PassiveAPICollector{Source: "hunter", Store: s, Run: run, Budget: &Budget{Limit: 10}, Client: client}
	result := c.CollectPassive(ctx, scope)
	if result.Err != nil || !result.Complete || result.AbsenceUsable || len(result.Records) != 1 || !result.Records[0].Observation.EvidenceOnly {
		t.Fatal("Hunter evidence/coverage", result.Err, result.Complete, len(result.Records))
	}
	var units, used, held int64
	if err := s.DB.QueryRow(ctx, `SELECT units_used,requests_used,units_reserved FROM passive_source_budgets WHERE account_id=$1`, account).Scan(&units, &used, &held); err != nil || units != 2 || used != 2 || held != 0 {
		t.Fatal("actual quota was confused with calls", err, units, used, held)
	}
}
func TestPostgresPassiveFrontConfigurationAPI(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	fresh, err := s.scopesByID(ctx, scope.ID)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Store: s, PassiveHTTPClient: &http.Client{Transport: policyTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":200,"data":{"rest_free_point":500,"day_free_point":500,"rest_equity_point":0,"personal_info":{"email":"private@example.invalid"}}}`))}, nil
	})}}
	u := User{ID: 1, Role: "admin"}
	body := fmt.Sprintf(`{"project_id":%d,"source":"hunter","name":"offline account","key":"offline-frontend-secret","enabled":true,"selected":true,"billing_policy":"credits_only","page_size":10}`, fresh.ProjectID)
	w := projectCall(e, u, "POST", "/api/settings/passive-accounts", body)
	if w.Code != 200 {
		t.Fatal("save account", w.Code, w.Body.String())
	}
	var saved struct {
		ID int64 `json:"id"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	w = projectCall(e, u, "POST", "/api/settings/passive-accounts/check", fmt.Sprintf(`{"id":%d}`, saved.ID))
	if w.Code != 200 || strings.Contains(w.Body.String(), "private@example.invalid") {
		t.Fatal("typed account check", w.Code)
	}
	w = projectCall(e, u, "GET", "/api/settings/passive-accounts", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "offline-frontend-secret") || strings.Contains(w.Body.String(), "key_encrypted") || !strings.Contains(w.Body.String(), `"credits":500`) {
		t.Fatal("front configuration secret/metadata", w.Code)
	}
	var checks int
	if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM passive_source_account_checks WHERE account_id=$1 AND status='complete'`, saved.ID).Scan(&checks); err != nil || checks != 1 {
		t.Fatal("account-check request absent from audit", err, checks)
	}
	w = projectCall(e, User{ID: 1, Role: "readonly"}, "POST", "/api/settings/passive-accounts/check", fmt.Sprintf(`{"id":%d}`, saved.ID))
	if w.Code != 403 {
		t.Fatal("non-admin account check allowed")
	}
}

func TestPostgresPassiveHunterPagingCompleteness(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(fmt.Sprintf("short=%t", short), func(t *testing.T) {
			s := integrationStore(t)
			ctx := context.Background()
			scope := insertScope(t, s, 1)
			account, run := passiveAccountFixture(t, s, scope)
			projectExec(t, s, `UPDATE passive_source_accounts SET source='hunter' WHERE id=$1`, account)
			searches := 0
			client := &http.Client{Transport: policyTransport(func(req *http.Request) (*http.Response, error) {
				body := `{"code":200,"data":{"rest_free_point":500,"rest_equity_point":0}}`
				if req.URL.Path == "/openApi/search" {
					searches++
					n := 10
					if short || searches == 2 {
						n = 1
					}
					rows := []map[string]any{}
					for i := 0; i < n; i++ {
						rows = append(rows, map[string]any{"domain": "api.example.com", "ip": "8.8.8.8", "port": 4000 + searches*100 + i})
					}
					raw, _ := json.Marshal(map[string]any{"code": 200, "data": map[string]any{"total": 11, "arr": rows, "consume_quota": fmt.Sprintf("消耗积分：%d", n), "rest_quota": "今日剩余积分：480"}})
					body = string(raw)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			result := (&PassiveAPICollector{Source: "hunter", Store: s, Run: run, Budget: &Budget{Limit: 10}, Client: client}).CollectPassive(ctx, scope)
			if short {
				if result.Err == nil || result.Complete || searches != 1 || len(result.Records) != 1 {
					t.Fatal("short nonterminal page falsely completed or skipped rows")
				}
			} else {
				if result.Err != nil || !result.Complete || result.AbsenceUsable || searches != 2 || len(result.Records) != 11 {
					t.Fatal("numbered paging", result.Err, result.Complete, searches, len(result.Records))
				}
			}
		})
	}
}

func TestPostgresPassiveBatchAccounts(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	_, project := projectFixture(t, s, 1)
	calls := 0
	e := &Engine{Store: s, PassiveHTTPClient: &http.Client{Transport: policyTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":200,"data":{"rest_free_point":500,"rest_equity_point":0}}`))}, nil
	})}}
	u := User{ID: 1, Role: "admin"}
	endpoint := "/api/settings/passive-accounts/batch"
	body := fmt.Sprintf(`{"project_id":%d,"prefix":"fixture","keys":["offline-batch-a","offline-batch-b","offline-batch-a"]}`, project)
	if w := projectCall(e, User{ID: 1, Role: "readonly"}, "POST", endpoint, body); w.Code != 403 {
		t.Fatal("batch management permission", w.Code)
	}
	w := projectCall(e, u, "POST", endpoint, body)
	var result struct {
		Created int     `json:"created"`
		Skipped int     `json:"skipped"`
		IDs     []int64 `json:"ids"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Created != 2 || result.Skipped != 1 || strings.Contains(w.Body.String(), "offline-batch") {
		t.Fatal("batch result/secret", w.Code)
	}
	for i, id := range result.IDs {
		var encrypted []byte
		var selected, enabled bool
		var policy string
		var size int
		if err := s.DB.QueryRow(ctx, `SELECT key_encrypted,selected,enabled,billing_policy,page_size FROM passive_source_accounts WHERE id=$1`, id).Scan(&encrypted, &selected, &enabled, &policy, &size); err != nil {
			t.Fatal(err)
		}
		key, err := s.decrypt(passiveKeyContext(id), encrypted)
		if err != nil || string(key) != []string{"offline-batch-a", "offline-batch-b"}[i] || selected || enabled || policy != "credits_only" || size != 10 {
			t.Fatal("batch encrypted configuration", err)
		}
	}
	w = projectCall(e, u, "POST", endpoint, body)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Created != 0 || result.Skipped != 3 {
		t.Fatal("existing account deduplication", w.Code)
	}
	invalid := fmt.Sprintf(`{"project_id":%d,"keys":["offline-new","invalid key"]}`, project)
	if w = projectCall(e, u, "POST", endpoint, invalid); w.Code != 400 || strings.Contains(w.Body.String(), "invalid key") {
		t.Fatal("batch validation", w.Code)
	}
	var count int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM passive_source_accounts WHERE project_id=$1`, project).Scan(&count); err != nil || count != 2 || calls != 0 {
		t.Fatal("batch atomicity or unwanted provider request", err, count, calls)
	}
	// Concurrent imports of identical keys must share the existing identities.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := projectCall(e, u, "POST", endpoint, body)
			if w.Code != 200 {
				t.Error("concurrent batch", w.Code)
			}
		}()
	}
	wg.Wait()
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM passive_source_accounts WHERE project_id=$1`, project).Scan(&count); err != nil || count != 2 {
		t.Fatal("concurrent batch duplicated accounts", err, count)
	}
	var account int64
	if err := s.DB.QueryRow(ctx, `SELECT min(id) FROM passive_source_accounts WHERE project_id=$1`, project).Scan(&account); err != nil {
		t.Fatal(err)
	}
	projectExec(t, s, `UPDATE passive_source_accounts SET state='rate_limited',cooldown_until=now()+interval '10 minutes' WHERE id=$1`, account)
	w = projectCall(e, u, "POST", "/api/settings/passive-accounts/check", fmt.Sprintf(`{"id":%d}`, account))
	if w.Code == 200 || calls != 0 {
		t.Fatal("account check bypassed cooldown", w.Code, calls)
	}
}
