package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) *Server {
	t.Helper()
	s, e := newServer(filepath.Join(t.TempDir(), "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	for i, name := range []string{"admin", "alice", "bob"} {
		role := "user"
		if i == 0 {
			role = "admin"
		}
		salt := random()
		s.data.Users = append(s.data.Users, User{i + 1, name, role, false, salt, password("test-password-2026", salt), time.Now().Unix()})
	}
	if e = s.save(); e != nil {
		t.Fatal(e)
	}
	return s
}
func call(s *Server, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:18765"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:4444"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func signin(t *testing.T, s *Server, name string) (*http.Cookie, string) {
	t.Helper()
	r := call(s, "POST", "/api/login", `{"name":"`+name+`","password":"test-password-2026"}`, nil, "")
	if r.Code != 200 {
		t.Fatalf("login: %d %s", r.Code, r.Body.String())
	}
	var out struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(r.Body.Bytes(), &out)
	return r.Result().Cookies()[0], out.CSRF
}
func TestIsolationAndPermissions(t *testing.T) {
	s := fixture(t)
	a, csrf := signin(t, s, "alice")
	b, bcsrf := signin(t, s, "bob")
	if r := call(s, "POST", "/api/scopes", `{"domain":"example.com","policy":"test authorization","authorized":true}`, a, csrf); r.Code != 201 {
		t.Fatal(r.Body.String())
	}
	r := call(s, "POST", "/api/import", `{"scope_id":1,"hosts":"api.example.com\napi.example.com\nevil-example.com\nexample.com.evil.org"}`, a, csrf)
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if len(s.data.Assets) != 1 {
		t.Fatal("scope filtering or dedup failed")
	}
	for _, path := range []string{"/api/users", "/api/status", "/api/logs"} {
		if r := call(s, "GET", path, "", a, ""); r.Code != 403 {
			t.Fatalf("admin path %s leaked", path)
		}
	}
	if r := call(s, "GET", "/api/state", "", b, ""); strings.Contains(r.Body.String(), "example.com") {
		t.Fatal("cross-user state leak")
	}
	if r := call(s, "GET", "/api/export", "", b, ""); strings.Contains(r.Body.String(), "example.com") {
		t.Fatal("cross-user export leak")
	}
	if r := call(s, "POST", "/api/import", `{"scope_id":1,"hosts":"api.example.com"}`, b, bcsrf); r.Code != 404 {
		t.Fatal("cross-user modification allowed")
	}
	if r := call(s, "POST", "/api/scopes", `{"domain":"bad.com"}`, a, ""); r.Code != 403 {
		t.Fatal("CSRF bypass")
	}
	for _, path := range []string{"/api/state", "/api/export", "/api/users"} {
		if r := call(s, "GET", path, "", nil, ""); r.Code != 401 {
			t.Fatal("anonymous data access")
		}
	}
}
func TestDisableRevokesSessionAndPersists(t *testing.T) {
	s := fixture(t)
	a, csrf := signin(t, s, "admin")
	b, _ := signin(t, s, "bob")
	r := call(s, "POST", "/api/user/update", `{"id":3,"role":"user","disabled":true,"password":""}`, a, csrf)
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := call(s, "GET", "/api/me", "", b, ""); r.Code != 401 {
		t.Fatal("disabled user session remains valid")
	}
	reopened, e := newServer(s.path)
	if e != nil || !reopened.data.Users[2].Disabled {
		t.Fatal("state did not persist")
	}
	r = call(s, "POST", "/api/user/update", `{"id":1,"role":"user","disabled":true,"password":""}`, a, csrf)
	if r.Code != 400 {
		t.Fatal("self-disable allowed")
	}
	if strings.Contains(call(s, "GET", "/api/users", "", a, "").Body.String(), "hash") {
		t.Fatal("password hash exposed")
	}
}
func TestPasswordChangeAndAudit(t *testing.T) {
	s := fixture(t)
	a, csrf := signin(t, s, "alice")
	if r := call(s, "POST", "/api/page", `{"page":"assets"}`, a, csrf); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := call(s, "POST", "/api/password", `{"current":"test-password-2026","password":"changed-password-2026"}`, a, csrf); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := call(s, "GET", "/api/me", "", a, ""); r.Code != 401 {
		t.Fatal("old session valid after password change")
	}
	raw, _ := json.Marshal(s.logs)
	if strings.Contains(string(raw), "test-password") || strings.Contains(string(raw), "changed-password") {
		t.Fatal("audit contains password")
	}
	if !strings.Contains(string(raw), "/page/assets") {
		t.Fatal("page navigation not logged")
	}
}
func TestLoginLimitsAndHostValidation(t *testing.T) {
	s := fixture(t)
	for range 8 {
		r := call(s, "POST", "/api/login", `{"name":"unknown","password":"incorrect-password"}`, nil, "")
		if r.Code != 401 {
			t.Fatal(r.Code)
		}
	}
	if r := call(s, "POST", "/api/login", `{"name":"admin","password":"test-password-2026"}`, nil, ""); r.Code != 429 {
		t.Fatal("login not limited")
	}
	r := httptest.NewRequest("GET", "http://attacker.invalid/api/state", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("host validation missing")
	}
}
func TestDomains(t *testing.T) {
	for _, d := range []string{"127.0.0.1", "https://example.com", "*.example.com", "bad..com", "-bad.com"} {
		if _, e := domainName(d); e == nil {
			t.Fatalf("accepted %s", d)
		}
	}
	if inScope("evil-example.com", "example.com") || inScope("example.com.evil.org", "example.com") {
		t.Fatal("domain boundary error")
	}
}

func TestHTTPSProxyTransportAndCookies(t *testing.T) {
	s := fixture(t)
	s.publicHost = "ali.howtime.top"
	request := func(remote, origin string, proxy bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://ali.howtime.top/api/login", strings.NewReader(`{"name":"admin","password":"test-password-2026"}`))
		r.RemoteAddr = remote
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if proxy {
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Prefix", "/scopedesk")
			r.Header.Set("X-Real-IP", "203.0.113.10")
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if r := request("198.51.100.5:4000", "https://ali.howtime.top", true); r.Code != 403 {
		t.Fatal("untrusted proxy headers accepted")
	}
	if r := request("127.0.0.1:4000", "https://ali.howtime.top", false); r.Code != 403 {
		t.Fatal("public host accepted without HTTPS proxy")
	}
	if r := request("127.0.0.1:4000", "http://ali.howtime.top", true); r.Code != 403 {
		t.Fatal("insecure public origin accepted")
	}
	r := request("127.0.0.1:4000", "https://ali.howtime.top", true)
	if r.Code != 200 {
		t.Fatalf("HTTPS proxy login failed: %s", r.Body.String())
	}
	c := r.Result().Cookies()[0]
	if !c.Secure || !c.HttpOnly || c.Path != "/scopedesk/" || c.SameSite != http.SameSiteStrictMode {
		t.Fatal("public cookie attributes incorrect")
	}
	if s.logs[len(s.logs)-1].IP != "203.0.113.10" {
		t.Fatal("proxy client IP not audited")
	}
}

func TestExplicitHTTPProxy(t *testing.T) {
	s := fixture(t)
	s.httpHost = "47.103.214.77:8080"
	r := httptest.NewRequest("POST", "http://47.103.214.77:8080/api/login", strings.NewReader(`{"name":"admin","password":"test-password-2026"}`))
	r.RemoteAddr = "127.0.0.1:4000"
	r.Header.Set("Origin", "http://47.103.214.77:8080")
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-Prefix", "/")
	r.Header.Set("X-Real-IP", "203.0.113.20")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("HTTP proxy login failed: %s", w.Body.String())
	}
	c := w.Result().Cookies()[0]
	if c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteStrictMode {
		t.Fatal("explicit HTTP cookie attributes incorrect")
	}
	if s.logs[len(s.logs)-1].IP != "203.0.113.20" {
		t.Fatal("HTTP proxy client IP missing")
	}
	if s.publicProxy(&http.Request{Host: s.httpHost, RemoteAddr: "198.51.100.5:1234", Header: r.Header}) {
		t.Fatal("untrusted public proxy accepted")
	}
}
