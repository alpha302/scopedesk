package main

import (
	"bufio"
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/*
var files embed.FS

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
	Salt     string `json:"salt,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Created  int64  `json:"created"`
}
type Scope struct {
	ID      int    `json:"id"`
	Owner   int    `json:"owner"`
	Domain  string `json:"domain"`
	Policy  string `json:"policy"`
	Created int64  `json:"created"`
}
type Asset struct {
	Scope  int    `json:"scope_id"`
	Host   string `json:"host"`
	Source string `json:"source"`
	First  int64  `json:"first_seen"`
	Last   int64  `json:"last_seen"`
}
type Job struct {
	ID       int    `json:"id"`
	Scope    int    `json:"scope_id"`
	Owner    int    `json:"owner"`
	Domain   string `json:"domain"`
	State    string `json:"state"`
	Message  string `json:"message"`
	Created  int64  `json:"created"`
	Finished int64  `json:"finished"`
}
type State struct {
	Users  []User  `json:"users"`
	Scopes []Scope `json:"scopes"`
	Assets []Asset `json:"assets"`
	Jobs   []Job   `json:"jobs"`
}
type Session struct {
	User    int
	CSRF    string
	Expires time.Time
}
type Attempt struct {
	Count int
	Until time.Time
}
type Access struct {
	Time   string `json:"time"`
	User   string `json:"user"`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Millis int64  `json:"ms"`
	Agent  string `json:"agent"`
}
type Server struct {
	engine     *Engine
	httpHost   string
	publicHost string
	mu         sync.Mutex
	data       State
	path       string
	sessions   map[string]Session
	attempts   map[string]Attempt
	logs       []Access
	started    time.Time
	jobs       chan struct{}
	logMu      sync.Mutex
}

var programs = []map[string]string{
	{"name": "腾讯 TSRC", "url": "https://security.tencent.com/index.php/report/add", "note": "官方提交入口，先核对安全测试规范与当期范围。"},
	{"name": "阿里巴巴 ASRC", "url": "https://security.alibaba.com/report.htm", "note": "官方漏洞报告入口，第三方业务须单独核对。"},
	{"name": "百度 BSRC", "url": "https://bsrc.baidu.com/", "note": "官方漏洞收集平台，查看当前接收规则。"},
	{"name": "360 SRC", "url": "https://src.360.cn/Index/faq", "note": "官方 FAQ 提供处理和奖励规则。"},
	{"name": "挖财 SRC", "url": "https://sec.wacai.com/", "note": "官方平台提供测试范围与评分标准。"},
}

func random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func password(value, salt string) string {
	key, e := pbkdf2.Key(sha256.New, value, []byte(salt), 600000, 32)
	if e != nil {
		panic(e)
	}
	return hex.EncodeToString(key)
}
func public(u User) User          { u.Salt = ""; u.Hash = ""; return u }
func validPassword(p string) bool { return len(p) >= 12 && len(p) <= 128 }
func nextUser(list []User) int {
	n := 0
	for _, v := range list {
		if v.ID > n {
			n = v.ID
		}
	}
	return n + 1
}
func newServer(path string) (*Server, error) {
	s := &Server{httpHost: os.Getenv("RECON_HTTP_HOST"), publicHost: os.Getenv("RECON_PUBLIC_HOST"), path: path, sessions: map[string]Session{}, attempts: map[string]Attempt{}, started: time.Now(), jobs: make(chan struct{}, 2)}
	raw, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(raw, &s.data); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	for i := range s.data.Jobs {
		if s.data.Jobs[i].State == "running" || s.data.Jobs[i].State == "queued" {
			s.data.Jobs[i].State = "interrupted"
			s.data.Jobs[i].Message = "服务重启，任务中断，请重新采集"
			s.data.Jobs[i].Finished = time.Now().Unix()
		}
	}
	if e = s.save(); e != nil {
		return nil, e
	}
	f, e := os.Open(filepath.Join(filepath.Dir(path), "access.jsonl"))
	if e == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var a Access
			if json.Unmarshal(scanner.Bytes(), &a) == nil {
				s.logs = append(s.logs, a)
			}
			if len(s.logs) > 500 {
				s.logs = s.logs[1:]
			}
		}
	}
	return s, nil
}

// All state mutations call save under mu. Atomic rename keeps the previous state intact on write failure.
func (s *Server) save() error {
	if s.engine != nil {
		return s.engine.Store.saveUsers(s.data.Users)
	}
	raw, e := json.Marshal(s.data)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(s.path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(s.path+".tmp", s.path)
}
func (s *Server) transaction(fn func() error) error {
	backup, _ := json.Marshal(s.data)
	if e := fn(); e != nil {
		json.Unmarshal(backup, &s.data)
		return e
	}
	if e := s.save(); e != nil {
		json.Unmarshal(backup, &s.data)
		return errors.New("保存失败，请检查磁盘与服务日志")
	}
	return nil
}
func respond(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
func fail(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 200000)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		fail(w, 400, "请求格式错误或内容过大")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		fail(w, 400, "请求格式错误")
		return false
	}
	return true
}
func (s *Server) identity(r *http.Request) (User, Session, string) {
	c, e := r.Cookie("scopedesk")
	if e != nil {
		return User{}, Session{}, ""
	}
	h := sha256.Sum256([]byte(c.Value))
	key := hex.EncodeToString(h[:])
	ss, ok := s.sessions[key]
	if !ok || time.Now().After(ss.Expires) {
		delete(s.sessions, key)
		return User{}, Session{}, ""
	}
	for _, u := range s.data.Users {
		if u.ID == ss.User && !u.Disabled {
			return u, ss, key
		}
	}
	return User{}, Session{}, ""
}
func (s *Server) invalidate(id int) {
	for key, v := range s.sessions {
		if v.User == id {
			delete(s.sessions, key)
		}
	}
}

// Only local proxies for explicitly configured hosts may supply client metadata.
func (s *Server) publicProxy(r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	addr, parseErr := netip.ParseAddr(ip)
	if err != nil || parseErr != nil || !addr.IsLoopback() {
		return false
	}
	httpsProxy := s.publicHost != "" && r.Host == s.publicHost && r.Header.Get("X-Forwarded-Proto") == "https" && r.Header.Get("X-Forwarded-Prefix") == "/scopedesk"
	httpProxy := s.httpHost != "" && r.Host == s.httpHost && r.Header.Get("X-Forwarded-Proto") == "http" && r.Header.Get("X-Forwarded-Prefix") == "/"
	return httpsProxy || httpProxy
}
func (s *Server) secureRequest(r *http.Request) bool {
	return r.TLS != nil || (s.publicProxy(r) && r.Header.Get("X-Forwarded-Proto") == "https")
}
func (s *Server) clientIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if s.publicProxy(r) {
		if addr, err := netip.ParseAddr(r.Header.Get("X-Real-IP")); err == nil {
			return addr.String()
		}
	}
	return ip
}
func (s *Server) cookiePath(r *http.Request) string {
	if s.publicProxy(r) && r.Host == s.publicHost {
		return "/scopedesk/"
	}
	return "/"
}

type capture struct {
	http.ResponseWriter
	status int
}

func (c *capture) WriteHeader(n int) { c.status = n; c.ResponseWriter.WriteHeader(n) }
func (s *Server) audit(r *http.Request, status int, username string, start time.Time) {
	// Background polling is excluded; browser navigation, user actions, login and API reads are retained.
	if r.URL.Path == "/api/state" || r.URL.Path == "/api/status" || r.URL.Path == "/api/logs" || strings.HasSuffix(r.URL.Path, ".js") || strings.HasSuffix(r.URL.Path, ".css") {
		return
	}
	ip := s.clientIP(r)
	a := Access{time.Now().Format(time.RFC3339), username, ip, r.Method, r.URL.Path, status, time.Since(start).Milliseconds(), r.UserAgent()}
	if len(a.Agent) > 200 {
		a.Agent = a.Agent[:200]
	}
	if len(a.Path) > 200 {
		a.Path = a.Path[:200]
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	s.logs = append(s.logs, a)
	if len(s.logs) > 500 {
		s.logs = s.logs[1:]
	}
	path := filepath.Join(filepath.Dir(s.path), "access.jsonl")
	if st, e := os.Stat(path); e == nil && st.Size() > 10<<20 {
		os.Rename(path, path+".1")
	}
	f, e := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if e == nil {
		json.NewEncoder(f).Encode(a)
		f.Close()
	} else {
		log.Printf("audit write: %v", e)
	}
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	cw := &capture{w, 200}
	w = cw
	username := "未登录"
	defer func() { s.audit(r, cw.status, username, start) }()
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.Host != "127.0.0.1:18765" && r.Host != "localhost:18765" && !s.publicProxy(r) {
		fail(w, 403, "访问地址未配置")
		return
	}
	scheme := "http"
	if s.secureRequest(r) {
		scheme = "https"
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != scheme+"://"+r.Host {
		fail(w, 403, "来源不允许")
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		fail(w, 403, "来源不允许")
		return
	}
	if !slices.Contains([]string{"GET", "POST", "PUT", "PATCH", "DELETE"}, r.Method) {
		fail(w, 405, "不支持的请求方法")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != "GET" {
			fail(w, 405, "不支持的请求方法")
			return
		}
		name := map[string]string{"/": "index.html", "/app.js": "app.js", "/style.css": "style.css", "/vue.global.prod.js": "vue.global.prod.js"}[r.URL.Path]
		if name == "" {
			fail(w, 404, "页面不存在")
			return
		}
		raw, e := files.ReadFile("web/" + name)
		if e != nil {
			fail(w, 500, "资源未构建")
			return
		}
		if strings.HasSuffix(name, ".js") {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		} else if strings.HasSuffix(name, ".css") {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		w.Write(raw)
		return
	}
	if r.URL.Path == "/api/login" && r.Method == "POST" {
		username = s.login(w, r)
		return
	}
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()
	u, ss, key := s.identity(r)
	if u.ID == 0 {
		fail(w, 401, "请先登录")
		return
	}
	username = u.Name
	if r.Method != "GET" && subtle.ConstantTimeCompare([]byte(ss.CSRF), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
		fail(w, 403, "会话验证失败，请刷新页面")
		return
	}
	if s.engine != nil && s.engine.handles(r.URL.Path) {
		locked = false
		s.mu.Unlock()
		s.engine.serve(w, r, u)
		return
	}
	switch r.URL.Path {
	case "/api/me":
		if r.Method != "GET" {
			break
		}
		respond(w, 200, map[string]any{"user": public(u), "csrf": ss.CSRF})
		return
	case "/api/logout":
		if r.Method != "POST" {
			break
		}
		delete(s.sessions, key)
		http.SetCookie(w, &http.Cookie{Name: "scopedesk", Value: "", Path: s.cookiePath(r), Secure: s.secureRequest(r), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		respond(w, 200, map[string]bool{"ok": true})
		return
	case "/api/password":
		if r.Method != "POST" {
			break
		}
		var body struct {
			Current  string `json:"current"`
			Password string `json:"password"`
		}
		if !decode(w, r, &body) {
			return
		}
		if !validPassword(body.Password) || subtle.ConstantTimeCompare([]byte(password(body.Current, u.Salt)), []byte(u.Hash)) != 1 {
			fail(w, 400, "原密码错误，或新密码长度不在 12–128 字节内")
			return
		}
		e := s.transaction(func() error {
			for i := range s.data.Users {
				if s.data.Users[i].ID == u.ID {
					salt := random()
					s.data.Users[i].Salt = salt
					s.data.Users[i].Hash = password(body.Password, salt)
				}
			}
			return nil
		})
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		s.invalidate(u.ID)
		respond(w, 200, map[string]bool{"ok": true})
		return
	case "/api/state":
		if r.Method != "GET" {
			break
		}
		scopes := []Scope{}
		assets := []Asset{}
		jobs := []Job{}
		ids := map[int]bool{}
		for _, v := range s.data.Scopes {
			if u.Role == "admin" || v.Owner == u.ID {
				scopes = append(scopes, v)
				ids[v.ID] = true
			}
		}
		for _, v := range s.data.Assets {
			if ids[v.Scope] {
				assets = append(assets, v)
			}
		}
		for _, v := range s.data.Jobs {
			if u.Role == "admin" || v.Owner == u.ID {
				jobs = append(jobs, v)
			}
		}
		slices.Reverse(jobs)
		if len(jobs) > 50 {
			jobs = jobs[:50]
		}
		respond(w, 200, map[string]any{"scopes": scopes, "assets": assets, "jobs": jobs, "src": programs})
		return
	case "/api/scopes":
		if r.Method != "POST" {
			break
		}
		s.scope(w, r, u)
		return
	case "/api/collect", "/api/import":
		if r.Method != "POST" {
			break
		}
		s.collectRequest(w, r, u)
		return
	case "/api/export":
		if r.Method != "GET" {
			break
		}
		ids := map[int]string{}
		for _, v := range s.data.Scopes {
			if u.Role == "admin" || v.Owner == u.ID {
				ids[v.ID] = v.Domain
			}
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=assets.csv")
		io.WriteString(w, "\ufeff")
		writer := csv.NewWriter(w)
		writer.Write([]string{"scope", "host", "source", "first_seen", "last_seen"})
		for _, v := range s.data.Assets {
			if root, ok := ids[v.Scope]; ok {
				writer.Write([]string{root, v.Host, v.Source, strconv.FormatInt(v.First, 10), strconv.FormatInt(v.Last, 10)})
			}
		}
		writer.Flush()
		return
	case "/api/page":
		if r.Method != "POST" {
			break
		}
		var body struct {
			Page string `json:"page"`
		}
		if !decode(w, r, &body) {
			return
		}
		allowed := []string{"passive", "exploration", "projects", "assets", "scope", "programs", "jobs", "users", "logs", "status", "account", "events", "mail", "plugins", "blacklist", "overview", "security-rules"}
		if !slices.Contains(allowed, body.Page) {
			fail(w, 400, "无效页面")
			return
		}
		if slices.Contains([]string{"passive", "users", "logs", "status", "mail", "plugins", "blacklist", "security-rules"}, body.Page) && u.Role != "admin" {
			fail(w, 403, "需要管理员权限")
			return
		}
		r.URL.Path = "/page/" + body.Page
		respond(w, 200, map[string]bool{"ok": true})
		return
	case "/api/users", "/api/user/update", "/api/user/create", "/api/logs", "/api/status":
		if u.Role != "admin" {
			fail(w, 403, "需要管理员权限")
			return
		}
		s.admin(w, r, u)
		return
	}
	fail(w, 405, "接口不存在或请求方法错误")
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) string {
	var body struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return "未登录"
	}
	ip := s.clientIP(r)
	key := ip
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, a := range s.attempts {
		if now.After(a.Until) {
			delete(s.attempts, k)
		}
	}
	a := s.attempts[key]
	if a.Count >= 8 && now.Before(a.Until) {
		fail(w, 429, "登录尝试过多，请 15 分钟后重试")
		return "未登录"
	}
	var found User
	for _, u := range s.data.Users {
		if u.Name == body.Name {
			found = u
		}
	}
	hash := password(body.Password, found.Salt)
	if found.ID == 0 || found.Disabled || subtle.ConstantTimeCompare([]byte(hash), []byte(found.Hash)) != 1 {
		a.Count++
		if a.Until.IsZero() {
			a.Until = now.Add(15 * time.Minute)
		}
		s.attempts[key] = a
		fail(w, 401, "用户名或密码错误，或账户已停用")
		return "未登录"
	}
	delete(s.attempts, key)
	for k, v := range s.sessions {
		if now.After(v.Expires) {
			delete(s.sessions, k)
		}
	}
	token := random()
	digest := sha256.Sum256([]byte(token))
	csrf := random()
	s.sessions[hex.EncodeToString(digest[:])] = Session{found.ID, csrf, now.Add(12 * time.Hour)}
	http.SetCookie(w, &http.Cookie{Name: "scopedesk", Value: token, Path: s.cookiePath(r), HttpOnly: true, Secure: s.secureRequest(r), SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	respond(w, 200, map[string]any{"user": public(found), "csrf": csrf})
	return found.Name
}

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func domainName(raw string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if len(d) > 253 || !strings.Contains(d, ".") {
		return "", errors.New("请填写完整 ASCII 域名（国际域名使用 punycode），不要填写 URL 或 IP")
	}
	if _, e := netip.ParseAddr(d); e == nil {
		return "", errors.New("此版本仅接受域名")
	}
	for _, v := range strings.Split(d, ".") {
		if !domainPattern.MatchString(v) {
			return "", errors.New("域名格式错误")
		}
	}
	return d, nil
}
func inScope(host, root string) bool { return host == root || strings.HasSuffix(host, "."+root) }
func (s *Server) scope(w http.ResponseWriter, r *http.Request, u User) {
	var body struct {
		Domain     string `json:"domain"`
		Policy     string `json:"policy"`
		Authorized bool   `json:"authorized"`
	}
	if !decode(w, r, &body) {
		return
	}
	domain, e := domainName(body.Domain)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	if !body.Authorized || len(body.Policy) > 2000 {
		fail(w, 400, "请确认范围")
		return
	}
	e = s.transaction(func() error {
		id := 0
		for _, v := range s.data.Scopes {
			if v.ID > id {
				id = v.ID
			}
			if v.Owner == u.ID && v.Domain == domain {
				return errors.New("该授权范围已存在")
			}
		}
		s.data.Scopes = append(s.data.Scopes, Scope{id + 1, u.ID, domain, body.Policy, time.Now().Unix()})
		return nil
	})
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	respond(w, 201, map[string]bool{"ok": true})
}
func (s *Server) merge(scope Scope, hosts []string, source string) int {
	valid := map[string]bool{}
	for _, h := range hosts {
		d, e := domainName(strings.TrimPrefix(h, "*."))
		if e == nil && inScope(d, scope.Domain) {
			valid[d] = true
		}
	}
	now := time.Now().Unix()
	for i := range s.data.Assets {
		a := &s.data.Assets[i]
		if a.Scope == scope.ID && a.Source == source && valid[a.Host] {
			a.Last = now
			delete(valid, a.Host)
		}
	}
	n := len(valid)
	for h := range valid {
		s.data.Assets = append(s.data.Assets, Asset{scope.ID, h, source, now, now})
	}
	return n
}
func (s *Server) collectRequest(w http.ResponseWriter, r *http.Request, u User) {
	var body struct {
		Scope int    `json:"scope_id"`
		Hosts string `json:"hosts"`
	}
	if !decode(w, r, &body) {
		return
	}
	var scope Scope
	for _, v := range s.data.Scopes {
		if v.ID == body.Scope && (v.Owner == u.ID || u.Role == "admin") {
			scope = v
		}
	}
	if scope.ID == 0 {
		fail(w, 404, "授权范围不存在")
		return
	}
	if r.URL.Path == "/api/import" {
		n := 0
		e := s.transaction(func() error { n = s.merge(scope, strings.Split(body.Hosts, "\n"), "manual"); return nil })
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		respond(w, 200, map[string]int{"count": n})
		return
	}
	id := 0
	for _, j := range s.data.Jobs {
		if j.ID > id {
			id = j.ID
		}
		if j.Scope == scope.ID && (j.State == "running" || j.State == "queued") {
			fail(w, 409, "该范围已有采集任务")
			return
		}
	}
	select {
	case s.jobs <- struct{}{}:
	default:
		fail(w, 429, "最多同时运行两个采集任务")
		return
	}
	id++
	e := s.transaction(func() error {
		s.data.Jobs = append(s.data.Jobs, Job{id, scope.ID, u.ID, scope.Domain, "running", "查询 crt.sh 证书透明度记录", time.Now().Unix(), 0})
		return nil
	})
	if e != nil {
		<-s.jobs
		fail(w, 500, e.Error())
		return
	}
	go s.runJob(id, scope)
	respond(w, 202, map[string]int{"job": id})
}
func (s *Server) runJob(id int, scope Scope) {
	defer func() { <-s.jobs }()
	client := &http.Client{Timeout: 50 * time.Second}
	q := url.Values{"q": {"%." + scope.Domain}, "output": {"json"}}
	req, _ := http.NewRequest("GET", "https://crt.sh/?"+q.Encode(), nil)
	req.Header.Set("User-Agent", "ScopeDesk/0.2")
	res, e := client.Do(req)
	var hosts []string
	if e == nil {
		defer res.Body.Close()
		if res.StatusCode != 200 {
			e = fmt.Errorf("crt.sh 返回 HTTP %d", res.StatusCode)
		} else {
			raw, err := io.ReadAll(io.LimitReader(res.Body, 8000001))
			e = err
			if e == nil && len(raw) > 8000000 {
				e = errors.New("响应超过 8 MB，请缩小范围")
			}
			if e == nil {
				var rows []struct {
					Name string `json:"name_value"`
				}
				e = json.Unmarshal(raw, &rows)
				if e == nil {
					for _, row := range rows {
						hosts = append(hosts, strings.Split(row.Name, "\n")...)
					}
				}
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	saveErr := s.transaction(func() error {
		message := ""
		state := "done"
		if e != nil {
			state = "failed"
			message = "采集失败：" + e.Error()
		} else {
			n := s.merge(scope, hosts, "crt.sh")
			message = fmt.Sprintf("新增 %d 条线索；已有记录已更新时间。证书记录不代表存活。", n)
		}
		for i := range s.data.Jobs {
			if s.data.Jobs[i].ID == id {
				s.data.Jobs[i].State = state
				s.data.Jobs[i].Message = message
				s.data.Jobs[i].Finished = time.Now().Unix()
			}
		}
		return nil
	})
	if saveErr != nil {
		log.Printf("job persist: %v", saveErr)
	}
}
func (s *Server) admin(w http.ResponseWriter, r *http.Request, u User) {
	switch r.URL.Path {
	case "/api/users":
		if r.Method != "GET" {
			break
		}
		users := []User{}
		for _, v := range s.data.Users {
			users = append(users, public(v))
		}
		respond(w, 200, users)
		return
	case "/api/user/create":
		if r.Method != "POST" {
			break
		}
		var body struct {
			Name     string `json:"name"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if !decode(w, r, &body) {
			return
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]{3,32}$`).MatchString(body.Name) || !validPassword(body.Password) || !slices.Contains([]string{"admin", "user", "readonly"}, body.Role) {
			fail(w, 400, "用户名须为 3–32 位字母数字、下划线或短横线；密码须为 12–128 字节")
			return
		}
		e := s.transaction(func() error {
			for _, v := range s.data.Users {
				if strings.EqualFold(v.Name, body.Name) {
					return errors.New("用户名已存在")
				}
			}
			salt := random()
			s.data.Users = append(s.data.Users, User{nextUser(s.data.Users), body.Name, body.Role, false, salt, password(body.Password, salt), time.Now().Unix()})
			return nil
		})
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		respond(w, 201, map[string]bool{"ok": true})
		return
	case "/api/user/update":
		if r.Method != "POST" {
			break
		}
		var body struct {
			ID       int    `json:"id"`
			Role     string `json:"role"`
			Disabled bool   `json:"disabled"`
			Password string `json:"password"`
		}
		if !decode(w, r, &body) {
			return
		}
		if !slices.Contains([]string{"admin", "user", "readonly"}, body.Role) {
			fail(w, 400, "角色无效")
			return
		}
		if body.Password != "" && !validPassword(body.Password) {
			fail(w, 400, "密码须为 12–128 字节")
			return
		}
		if body.ID == u.ID && (body.Disabled || body.Role != "admin") {
			fail(w, 400, "不能停用或降级当前管理员")
			return
		}
		e := s.transaction(func() error {
			found := false
			for i := range s.data.Users {
				v := &s.data.Users[i]
				if v.ID == body.ID {
					found = true
					v.Role = body.Role
					v.Disabled = body.Disabled
					if body.Password != "" {
						v.Salt = random()
						v.Hash = password(body.Password, v.Salt)
					}
				}
			}
			if !found {
				return errors.New("用户不存在")
			}
			n := 0
			for _, v := range s.data.Users {
				if v.Role == "admin" && !v.Disabled {
					n++
				}
			}
			if n == 0 {
				return errors.New("须保留至少一名启用的管理员")
			}
			return nil
		})
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		s.invalidate(body.ID)
		respond(w, 200, map[string]bool{"ok": true})
		return
	case "/api/logs":
		if r.Method != "GET" {
			break
		}
		s.logMu.Lock()
		logs := append([]Access{}, s.logs...)
		s.logMu.Unlock()
		slices.Reverse(logs)
		respond(w, 200, logs)
		return
	case "/api/status":
		if r.Method != "GET" {
			break
		}
		status := s.status()
		if s.engine != nil {
			status["storage"] = "PostgreSQL 16 · pgx + goose"
			workers, err := queryJSON(r.Context(), s.engine.Store.DB, "SELECT to_jsonb(w)FROM workers w WHERE heartbeat_at>now()-interval '2 minutes' ORDER BY id")
			if err == nil {
				status["workers"] = workers
			}
			status["active_jobs"] = s.engine.activeCount()
		}
		respond(w, 200, status)
		return
	}
	fail(w, 405, "请求方法错误")
}
func (s *Server) status() map[string]any {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	host, _ := os.Hostname()
	load, _ := os.ReadFile("/proc/loadavg")
	mem, _ := os.ReadFile("/proc/meminfo")
	uptime, _ := os.ReadFile("/proc/uptime")
	values := map[string]uint64{}
	for _, line := range strings.Split(string(mem), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			n, _ := strconv.ParseUint(fields[1], 10, 64)
			values[strings.TrimSuffix(fields[0], ":")] = n * 1024
		}
	}
	var stat syscall.Statfs_t
	syscall.Statfs(filepath.Dir(s.path), &stat)
	sessions := 0
	for _, v := range s.sessions {
		if time.Now().Before(v.Expires) {
			sessions++
		}
	}
	return map[string]any{"hostname": host, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(), "load": strings.TrimSpace(string(load)), "memory_total": values["MemTotal"], "memory_available": values["MemAvailable"], "disk_total": stat.Blocks * uint64(stat.Bsize), "disk_available": stat.Bavail * uint64(stat.Bsize), "process_memory": m.Alloc, "goroutines": runtime.NumGoroutine(), "service_uptime": int64(time.Since(s.started).Seconds()), "host_uptime": strings.Fields(string(uptime)), "active_jobs": len(s.jobs), "sessions": sessions, "storage": "JSON 原子持久化", "time": time.Now().Format(time.RFC3339)}
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "fingerprints-convert" {
		if err := runFingerprintConvert(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		engine, err := newEngine(ctx, os.Getenv("DATABASE_URL"))
		cancel()
		if err != nil {
			log.Fatal("worker initialization failed: ", safeError(err))
		}
		engine.Start()
		select {}
	}
	path := os.Getenv("RECON_DATA")
	if path == "" {
		path = "data/state.json"
	}
	s, e := newServer(path)
	if e != nil {
		log.Fatal(e)
	}
	if len(os.Args) > 1 && os.Args[1] == "init-admin" {
		if len(s.data.Users) > 0 {
			log.Fatal("admin already initialized")
		}
		raw, e := io.ReadAll(io.LimitReader(os.Stdin, 256))
		if e != nil {
			log.Fatal(e)
		}
		p := strings.TrimSpace(string(raw))
		if !validPassword(p) {
			log.Fatal("password must contain 12-128 bytes")
		}
		salt := random()
		s.data.Users = append(s.data.Users, User{1, "admin", "admin", false, salt, password(p, salt), time.Now().Unix()})
		if e = s.save(); e != nil {
			log.Fatal(e)
		}
		fmt.Println("Administrator initialized")
		return
	}
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		engine, err := newEngine(ctx, dsn)
		if err == nil {
			err = engine.Store.importLegacy(ctx, s.data)
		}
		if err != nil {
			cancel()
			log.Fatal("database initialization failed: ", safeError(err))
		}
		users, err := engine.Store.loadUsers(ctx)
		cancel()
		if err != nil {
			log.Fatal("cannot load database users")
		}
		s.engine = engine
		s.data.Users = users
		s.data.Scopes = nil
		s.data.Assets = nil
		s.data.Jobs = nil
		if len(os.Args) > 1 && os.Args[1] == "migrate" {
			log.Println("Database migration and legacy import complete")
			return
		}
		engine.Start()
		if len(os.Args) > 1 && os.Args[1] == "worker" {
			select {}
		}
	}
	listen := os.Getenv("RECON_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:18765"
	}
	srv := &http.Server{Addr: listen, Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Println("ScopeDesk Go listening on http://127.0.0.1:18765")
	log.Fatal(srv.ListenAndServe())
}
