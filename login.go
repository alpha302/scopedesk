package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"time"
)

// Conservative single-instance limits: one password hash and at most two
// waiting login requests. These do not replace the existing per-IP attempt cap.
const loginHashConcurrency = 1
const loginAdmissionLimit = 3

func (s *Server) initLoginStateLocked() {
	if s.loginHashSlots == nil {
		s.loginHashSlots = make(chan struct{}, loginHashConcurrency)
	}
	if s.loginAdmissions == nil {
		s.loginAdmissions = make(chan struct{}, loginAdmissionLimit)
	}
	if s.loginPending == nil {
		s.loginPending = map[string]int{}
	}
	if s.authVersions == nil {
		s.authVersions = map[int]uint64{}
	}
}

func (s *Server) finishLoginAttemptLocked(key string, failed bool) {
	s.loginPending[key]--
	if s.loginPending[key] == 0 {
		delete(s.loginPending, key)
	}
	a := s.attempts[key]
	if failed {
		// The 15-minute failure window starts at the first failed verification,
		// never earlier because a request spent time in the bounded queue.
		if a.Count == 0 {
			a.Until = time.Now().Add(15 * time.Minute)
		}
		a.Count++
	}
	if a.Count == 0 && s.loginPending[key] == 0 {
		delete(s.attempts, key)
	} else {
		s.attempts[key] = a
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) string {
	var body struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return "未登录"
	}
	key := s.clientIP(r)
	s.mu.Lock()
	s.initLoginStateLocked()
	now := time.Now()
	for ip, a := range s.attempts {
		if now.After(a.Until) && s.loginPending[ip] == 0 {
			delete(s.attempts, ip)
		}
	}
	a := s.attempts[key]
	if a.Count+s.loginPending[key] >= 8 {
		s.mu.Unlock()
		fail(w, 429, "登录尝试过多，请 15 分钟后重试")
		return "未登录"
	}
	admissions, compute := s.loginAdmissions, s.loginHashSlots
	select {
	case admissions <- struct{}{}:
	default:
		s.mu.Unlock()
		fail(w, 503, "登录处理繁忙，请稍后重试")
		return "未登录"
	}
	if a.Until.IsZero() {
		a.Until = now.Add(15 * time.Minute)
	}
	s.attempts[key] = a
	s.loginPending[key]++
	var found User
	for _, u := range s.data.Users {
		if u.Name == body.Name {
			found = u
		}
	}
	version := s.authVersions[found.ID]
	hasher := s.loginHash
	if hasher == nil {
		hasher = password
	}
	s.mu.Unlock()

	finished := false
	defer func() {
		if !finished {
			s.mu.Lock()
			s.finishLoginAttemptLocked(key, false)
			s.mu.Unlock()
		}
		<-admissions
	}()
	reservation, limited, err := s.accountLimits.reserve(body.Name)
	if err != nil {
		fail(w, 503, "登录处理繁忙，请稍后重试")
		return "未登录"
	}
	if limited {
		fail(w, 429, "登录尝试过多，请 15 分钟后重试")
		return "未登录"
	}
	accountFinished := false
	defer func() {
		if !accountFinished {
			_ = s.accountLimits.finish(reservation, false, false)
		}
	}()
	select {
	case compute <- struct{}{}:
	case <-r.Context().Done():
		fail(w, 408, "登录请求已取消")
		return "未登录"
	}
	if r.Context().Err() != nil {
		<-compute
		fail(w, 408, "登录请求已取消")
		return "未登录"
	}
	var hash string
	func() { defer func() { <-compute }(); hash = hasher(body.Password, found.Salt) }()
	matched := subtle.ConstantTimeCompare([]byte(hash), []byte(found.Hash)) == 1

	s.mu.Lock()
	var current User
	for _, u := range s.data.Users {
		if u.ID == found.ID {
			current = u
		}
	}
	valid := found.ID != 0 && !found.Disabled && matched && current.ID == found.ID && !current.Disabled &&
		current.Hash == found.Hash && current.Salt == found.Salt && current.Name == found.Name && current.Role == found.Role && s.authVersions[found.ID] == version
	s.mu.Unlock()
	err = s.accountLimits.finish(reservation, !valid, valid && r.Context().Err() == nil)
	accountFinished = true
	if err != nil {
		fail(w, 503, "登录处理繁忙，请稍后重试")
		return "未登录"
	}
	s.mu.Lock()
	// Persistence is outside the global mutex. Revalidate after that I/O too.
	valid = false
	for _, u := range s.data.Users {
		if found.ID != 0 && u.ID == found.ID && !found.Disabled && !u.Disabled && matched && u.Hash == found.Hash && u.Salt == found.Salt && u.Name == found.Name && u.Role == found.Role && s.authVersions[found.ID] == version {
			current = u
			valid = true
		}
	}
	s.finishLoginAttemptLocked(key, !valid)
	finished = true
	if !valid {
		s.mu.Unlock()
		fail(w, 401, "用户名或密码错误，或账户已停用")
		return "未登录"
	}
	if r.Context().Err() != nil {
		s.mu.Unlock()
		fail(w, 408, "登录请求已取消")
		return "未登录"
	}
	// Reset completed failures on success, while preserving reservations owned
	// by other admitted requests so they cannot bypass the eight-attempt cap.
	a = s.attempts[key]
	a.Count = 0
	if s.loginPending[key] == 0 {
		delete(s.attempts, key)
	} else {
		s.attempts[key] = a
	}
	now = time.Now()
	for k, ss := range s.sessions {
		if now.After(ss.Expires) {
			delete(s.sessions, k)
		}
	}
	token := random()
	digest := sha256.Sum256([]byte(token))
	csrf := random()
	s.sessions[hex.EncodeToString(digest[:])] = Session{current.ID, csrf, now.Add(12 * time.Hour)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "scopedesk", Value: token, Path: s.cookiePath(r), HttpOnly: true, Secure: s.secureRequest(r), SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	respond(w, 200, map[string]any{"user": public(current), "csrf": csrf})
	return current.Name
}
