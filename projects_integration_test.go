package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func projectExec(t *testing.T, s *Store, sql string, args ...any) {
	t.Helper()
	if _, err := s.DB.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}
func projectCall(e *Engine, u User, method, path, body string) *httptest.ResponseRecorder {
	w := apiRecorder()
	e.serve(w, apiRequest(method, path, body), u)
	return w
}
func projectFixture(t *testing.T, s *Store, owner int) (ScopeV2, int64) {
	t.Helper()
	scope := insertScope(t, s, owner)
	scope, err := s.scopesByID(context.Background(), scope.ID)
	if err != nil {
		t.Fatal(err)
	}
	return scope, scope.ProjectID
}
func TestPostgresProjectMigrationPreservesPrivateScopes(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.DB)
	defer db.Close()
	if err := goose.DownToContext(ctx, db, "migrations", 9); err != nil {
		t.Fatal(err)
	}
	a := insertScope(t, s, 1)
	b := insertScope(t, s, 2)
	projectExec(t, s, "UPDATE scopes SET active=true WHERE id=$1", a.ID)
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatal(err)
	}
	first, err := s.scopesByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.scopesByID(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.ProjectID == 0 || first.ProjectID == second.ProjectID || first.WorkspaceID == second.WorkspaceID || !first.Active || !first.ProjectPolicy.AllowActive {
		t.Fatal("migration changed legacy authorization", first, second)
	}
	e := &Engine{Store: s}
	if _, err = e.access(ctx, b.ID, User{ID: 1, Role: "user"}); err == nil {
		t.Fatal("legacy private permissions expanded")
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownToContext(ctx, db, "migrations", 9); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM scopes WHERE id=ANY($1::bigint[])", []int64{a.ID, b.ID}).Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
}
func TestPostgresProjectMembershipAndRevocation(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	e := &Engine{Store: s}
	u := User{ID: 2, Role: "user"}
	ctx := context.Background()
	projectExec(t, s, "INSERT INTO workspace_members(workspace_id,user_id,role)VALUES($1,2,'member')", scope.WorkspaceID)
	if _, err := e.access(ctx, scope.ID, u); err == nil {
		t.Fatal("workspace membership leaked project")
	}
	projectExec(t, s, "INSERT INTO project_members(project_id,user_id,role)VALUES($1,2,'viewer')", pid)
	var assetID, jobID int64
	if err := s.DB.QueryRow(ctx, "INSERT INTO assets(scope_id,host)VALUES($1,'shared.example.com')RETURNING id", scope.ID).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, "INSERT INTO jobs(scope_id,owner,status)VALUES($1,1,'queued')RETURNING id", scope.ID).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/api/scopes", "/api/assets", fmt.Sprintf("/api/assets/%d", assetID), "/api/jobs", "/api/assets/export?format=csv"} {
		w := projectCall(e, u, "GET", route, "")
		if w.Code != 200 {
			t.Fatal("viewer could not read shared project", route, w.Code, w.Body.String())
		}
	}
	for _, tc := range []struct{ method, path, body string }{{"PATCH", fmt.Sprintf("/api/assets/%d", assetID), `{"note":"denied"}`}, {"POST", fmt.Sprintf("/api/jobs/%d/cancel", jobID), `{}`}} {
		w := projectCall(e, u, tc.method, tc.path, tc.body)
		if w.Code == 200 {
			t.Fatal("viewer changed shared asset/job", tc, w.Body.String())
		}
	}

	if _, err := e.access(ctx, scope.ID, u); err != nil {
		t.Fatal(err)
	}
	if _, err := e.access(ctx, scope.ID, u, true); err == nil {
		t.Fatal("viewer wrote scope")
	}
	for _, tc := range []struct{ method, path, body string }{{"POST", fmt.Sprintf("/api/scopes/%d/run", scope.ID), `{"sources":["crtsh"]}`}, {"PUT", fmt.Sprintf("/api/scopes/%d/plan", scope.ID), `{"enabled":false}`}, {"POST", "/api/import", fmt.Sprintf(`{"scope_id":%d,"hosts":"api.example.com","preview":true}`, scope.ID)}, {"PUT", fmt.Sprintf("/api/projects/%d", pid), `{"name":"hijack","rps_limit":1,"enabled":true}`}} {
		if w := projectCall(e, u, tc.method, tc.path, tc.body); w.Code == 200 || w.Code == 201 {
			t.Fatal("viewer mutation accepted", tc, w.Body.String())
		}
	}
	projectExec(t, s, "UPDATE project_members SET role='operator' WHERE project_id=$1", pid)
	for _, tc := range []struct{ method, path, body string }{{"PATCH", fmt.Sprintf("/api/assets/%d", assetID), `{"note":"operator update"}`}, {"POST", fmt.Sprintf("/api/jobs/%d/cancel", jobID), `{}`}} {
		w := projectCall(e, u, tc.method, tc.path, tc.body)
		if w.Code != 200 {
			t.Fatal("operator could not manage shared asset/job", tc, w.Code, w.Body.String())
		}
	}

	if _, err := e.access(ctx, scope.ID, u, true); err != nil {
		t.Fatal(err)
	}
	if err := s.projectPermission(ctx, pid, u, true, true); err == nil {
		t.Fatal("operator managed project")
	}
	if _, err := e.access(ctx, scope.ID, User{ID: 2, Role: "readonly"}, true); err == nil {
		t.Fatal("global readonly bypass")
	}
	projectExec(t, s, "DELETE FROM workspace_members WHERE workspace_id=$1 AND user_id=2", scope.WorkspaceID)
	if _, err := e.access(ctx, scope.ID, u); err == nil {
		t.Fatal("removed workspace member retained stale project grant")
	}
	projectExec(t, s, "INSERT INTO workspace_members(workspace_id,user_id,role)VALUES($1,2,'viewer')", scope.WorkspaceID)
	if _, err := e.access(ctx, scope.ID, u, true); err == nil {
		t.Fatal("workspace viewer elevated by project operator")
	}
	// Scope.owner is historical attribution, not an access bypass after project transfer.
	projectExec(t, s, "UPDATE scopes SET owner=2 WHERE id=$1", scope.ID)
	projectExec(t, s, "DELETE FROM project_members WHERE project_id=$1", pid)
	if _, err := e.access(ctx, scope.ID, u); err == nil {
		t.Fatal("scope owner bypassed project ACL")
	}
}
func TestPostgresProjectPolicyRevokesRequestsQueueAndCommit(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	ctx := context.Background()
	projectExec(t, s, "UPDATE scopes SET active=true WHERE id=$1", scope.ID)
	projectExec(t, s, "UPDATE projects SET allow_active=false WHERE id=$1", pid)
	g, err := s.guard(ctx, scope.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g.ActiveAllowed() == nil {
		t.Fatal("project active prohibition ignored")
	}
	projectExec(t, s, "UPDATE projects SET allow_active=true WHERE id=$1", pid)
	scope, _ = s.scopesByID(ctx, scope.ID)
	requests := 0
	p := &Pipeline{Guard: s.guard, Limit: &faviconLimit{}, httpTransport: faviconRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		projectExec(t, s, "UPDATE projects SET enabled=false WHERE id=$1", pid)
		w := httptest.NewRecorder()
		http.Redirect(w, r, "/after", 302)
		res := w.Result()
		res.Request = r
		return res, nil
	})}
	if _, err = p.http(ctx, scope, "/", "https", "api.example.com", &Budget{Limit: 10}); err == nil || requests != 1 {
		t.Fatal("revoked project followed redirect", requests, err)
	}
	if _, err := (&PGQueue{s}).Enqueue(ctx, scope, []string{"crtsh"}, "manual"); err == nil {
		t.Fatal("stale scope enqueued disabled project")
	}
	projectExec(t, s, "UPDATE projects SET enabled=true WHERE id=$1", pid)
	run := claimedRun(t, s, scope)
	projectExec(t, s, "UPDATE projects SET enabled=false WHERE id=$1", pid)
	if _, err = s.WriteResults(ctx, run, []Observation{{Host: "api.example.com"}}, false); err == nil {
		t.Fatal("disabled project committed observations")
	}
	closeRun(t, s, run)
	projectExec(t, s, "UPDATE projects SET enabled=true,expires_at=now()-interval '1 second' WHERE id=$1", pid)
	g, err = s.guard(ctx, scope.ID)
	if err != nil || g.Valid() == nil {
		t.Fatal("project expiry ignored", err)
	}
	projectExec(t, s, "INSERT INTO monitor_plans(scope_id,enabled,next_run_at)VALUES($1,true,now()-interval '1 hour')", scope.ID)
	e := &Engine{Store: s, root: ctx}
	e.scheduleTick()
	var problem string
	if err = s.DB.QueryRow(ctx, "SELECT schedule_error FROM monitor_plans WHERE scope_id=$1", scope.ID).Scan(&problem); err != nil || problem == "" {
		t.Fatal("scheduler did not explain expired project", problem, err)
	}
}
func TestPostgresProjectSharedRateLimit(t *testing.T) {
	s := integrationStore(t)
	a, pid := projectFixture(t, s, 1)
	ctx := context.Background()
	var second int64
	if err := s.DB.QueryRow(ctx, "INSERT INTO scopes(owner,project_id,domain,mode,policy)VALUES(1,$1,'other.com','exact','')RETURNING id", pid).Scan(&second); err != nil {
		t.Fatal(err)
	}
	projectExec(t, s, "UPDATE projects SET rps_limit=0.5 WHERE id=$1", pid)
	start := time.Now()
	var wg sync.WaitGroup
	for _, id := range []int64{a.ID, second} {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			if err := (&PGRateLimiter{s}).Wait(ctx, id, 5); err != nil {
				t.Error(err)
			}
		}(id)
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed < 1800*time.Millisecond || elapsed > 5*time.Second {
		t.Fatal("project rate not shared between scopes", elapsed)
	}
}
func TestPostgresProjectCRUDAndMemberBoundaries(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	e := &Engine{Store: s}
	owner := User{ID: 1, Role: "user"}
	stranger := User{ID: 2, Role: "user"}
	projectExec(t, s, `INSERT INTO platform_users(id,payload)VALUES(2,'{"disabled":false}'),(3,'{"disabled":true}')`)
	call := func(u User, method, path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := projectCall(e, u, method, path, body)
		if w.Code != want {
			t.Fatal(method, path, w.Code, w.Body.String())
		}
		return w
	}
	call(stranger, "PUT", fmt.Sprintf("/api/projects/%d/members", pid), `{"user_id":2,"role":"admin"}`, 404)
	call(owner, "PUT", fmt.Sprintf("/api/projects/%d/members", pid), `{"user_id":2,"role":"operator"}`, 400)
	call(owner, "PUT", fmt.Sprintf("/api/workspaces/%d/members", scope.WorkspaceID), `{"user_id":2,"role":"member"}`, 200)
	call(owner, "PUT", fmt.Sprintf("/api/projects/%d/members", pid), `{"user_id":2,"role":"operator"}`, 200)
	call(owner, "PUT", fmt.Sprintf("/api/projects/%d/members", pid), `{"user_id":3,"role":"viewer"}`, 400)
	w := call(owner, "POST", "/api/projects", fmt.Sprintf(`{"workspace_id":%d,"name":"B SRC","rps_limit":1}`, scope.WorkspaceID), 201)
	var created struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &created)
	var active bool
	if err := s.DB.QueryRow(context.Background(), "SELECT allow_active FROM projects WHERE id=$1", created.ID).Scan(&active); err != nil || active {
		t.Fatal("new project enabled active probing", err)
	}
	call(owner, "PUT", fmt.Sprintf("/api/projects/%d", created.ID), `{"name":"B SRC","rps_limit":1,"rules_url":"javascript:alert(1)"}`, 400)
	call(owner, "PUT", fmt.Sprintf("/api/projects/%d", created.ID), `{"name":"B SRC","rps_limit":1,"enabled":true,"workspace_id":999}`, 400)
	call(stranger, "GET", fmt.Sprintf("/api/projects/%d", created.ID), "", 404)
	call(owner, "DELETE", fmt.Sprintf("/api/projects/%d/members/2", pid), "{}", 200)
	if _, err := e.access(context.Background(), scope.ID, stranger); err == nil {
		t.Fatal("project membership revocation failed")
	}
}
func TestPostgresProjectFiltersCoverAssetsJobsEventsAndExports(t *testing.T) {
	s := integrationStore(t)
	a, pid := projectFixture(t, s, 1)
	ctx := context.Background()
	var other, scopeB int64
	if err := s.DB.QueryRow(ctx, "INSERT INTO projects(workspace_id,owner,name)VALUES($1,1,'B')RETURNING id", a.WorkspaceID).Scan(&other); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, "INSERT INTO scopes(owner,project_id,domain,mode,policy)VALUES(1,$1,'example.com','exact','')RETURNING id", other).Scan(&scopeB); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		id   int64
		host string
	}{{a.ID, "a.example.com"}, {scopeB, "b.example.com"}} {
		projectExec(t, s, "INSERT INTO assets(scope_id,host)VALUES($1,$2)", v.id, v.host)
		projectExec(t, s, "INSERT INTO jobs(scope_id,owner,status)VALUES($1,1,'done')", v.id)
		projectExec(t, s, "INSERT INTO asset_events(scope_id,asset_id,job_id,type,detail,dedupe_key)SELECT $1,a.id,j.id,'NEW_ASSET','{}',$2 FROM assets a JOIN jobs j ON j.scope_id=a.scope_id WHERE a.scope_id=$1", v.id, v.host)
	}
	e := &Engine{Store: s}
	u := User{ID: 1, Role: "user"}
	for _, route := range []string{"/api/state", "/api/scopes", "/api/assets", "/api/jobs", "/api/events", "/api/assets/export?format=csv"} {
		sep := "?"
		if strings.Contains(route, "?") {
			sep = "&"
		}
		w := projectCall(e, u, "GET", route+sep+fmt.Sprintf("project_id=%d", pid), "")
		if w.Code != 200 || strings.Contains(w.Body.String(), "b.example.com") {
			t.Fatal("project filter failed", route, w.Code, w.Body.String())
		}
	}
	w := projectCall(e, u, "GET", fmt.Sprintf("/api/dashboard/summary?project_id=%d", pid), "")
	var summary struct {
		Total int `json:"total"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &summary) != nil || summary.Total != 1 {
		t.Fatal("dashboard filter", w.Body.String())
	}
	w = projectCall(e, u, "GET", "/api/assets?project_id=bad", "")
	var result struct {
		Total int `json:"total"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Total != 0 {
		t.Fatal("invalid project filter broadened access", w.Body.String())
	}
}

func TestPostgresProjectScopeCreationAndPrivateDefault(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	ctx := context.Background()
	e := &Engine{Store: s}
	u := User{ID: 2, Role: "user"}
	projectExec(t, s, "INSERT INTO workspace_members(workspace_id,user_id,role)VALUES($1,2,'member')", scope.WorkspaceID)
	projectExec(t, s, "INSERT INTO project_members(project_id,user_id,role)VALUES($1,2,'operator')", pid)
	input := sampleScope()
	input.ID = 0
	input.Owner = 999
	input.Domain = "other.example.com"
	input.ProjectID = pid
	input.Active = false
	raw, _ := json.Marshal(input)
	w := projectCall(e, u, "POST", "/api/scopes", string(raw))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	created, err := s.scopesByID(ctx, result.ID)
	if err != nil || created.Owner != 2 || created.ProjectID != pid {
		t.Fatal("scope attribution or caller identity lost", created, err)
	}
	projectExec(t, s, "DELETE FROM project_members WHERE project_id=$1 AND user_id=2", pid)
	if _, err = e.access(ctx, created.ID, u); err == nil {
		t.Fatal("historical owner bypassed project removal")
	}
	input.Domain = "forbidden.example.com"
	raw, _ = json.Marshal(input)
	w = projectCall(e, u, "POST", "/api/scopes", string(raw))
	if w.Code != 404 {
		t.Fatal("unauthorized scope destination", w.Code, w.Body.String())
	}
	input.ProjectID = 0
	input.Active = true
	raw, _ = json.Marshal(input)
	w = projectCall(e, u, "POST", "/api/scopes", string(raw))
	if w.Code != 400 {
		t.Fatal("new private default allowed active probing", w.Code, w.Body.String())
	}
	input.Active = false
	raw, _ = json.Marshal(input)
	w = projectCall(e, u, "POST", "/api/scopes", string(raw))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var allowed bool
	if err = s.DB.QueryRow(ctx, "SELECT p.allow_active FROM projects p JOIN workspaces ws ON ws.id=p.workspace_id WHERE ws.owner=2 AND ws.is_default AND p.is_default").Scan(&allowed); err != nil || allowed {
		t.Fatal("new private project default is not passive", err)
	}
}

func TestPostgresProjectSharedPermissionPagination100k(t *testing.T) {
	s := integrationStore(t)
	scope, pid := projectFixture(t, s, 1)
	projectExec(t, s, "INSERT INTO workspace_members(workspace_id,user_id,role)VALUES($1,2,'member')", scope.WorkspaceID)
	projectExec(t, s, "INSERT INTO project_members(project_id,user_id,role)VALUES($1,2,'viewer')", pid)
	projectExec(t, s, "INSERT INTO assets(scope_id,host)SELECT $1,'shared-'||n||'.example.com' FROM generate_series(1,100000)n", scope.ID)
	projectExec(t, s, "ANALYZE assets")
	e := &Engine{Store: s}
	for _, uid := range []int{1, 2} {
		start := time.Now()
		w := projectCall(e, User{ID: uid, Role: "user"}, "GET", "/api/assets?page=100&page_size=50", "")
		elapsed := time.Since(start)
		var result struct {
			Total int               `json:"total"`
			Items []json.RawMessage `json:"items"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Total != 100000 || len(result.Items) != 50 {
			t.Fatal("shared pagination failed", uid, w.Code, w.Body.String())
		}
		t.Logf("100k ACL pagination user=%d: %s", uid, elapsed)
		if elapsed > 2*time.Second {
			t.Fatal("project ACL pagination exceeds 2 seconds", elapsed)
		}
	}
}
