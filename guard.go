package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

type ScopeV2 struct {
	ID            int64          `json:"id"`
	ProjectID     int64          `json:"project_id"`
	ProjectName   string         `json:"project_name"`
	WorkspaceID   int64          `json:"workspace_id"`
	ProjectPolicy *ProjectPolicy `json:"project_policy,omitempty"`
	Owner         int            `json:"owner"`
	Domain        string         `json:"domain"`
	Mode          string         `json:"mode"`
	Policy        string         `json:"policy"`
	Confirmed     bool           `json:"confirmed"`
	Active        bool           `json:"active"`
	Exclusions    []string       `json:"exclusions"`
	Expires       *time.Time     `json:"expires_at"`
	RPS           float64        `json:"rps"`
	Concurrency   int            `json:"concurrency"`
	RequestLimit  int            `json:"request_limit"`
	WindowStart   int            `json:"window_start"`
	WindowEnd     int            `json:"window_end"`
	Created       time.Time      `json:"created_at"`
	Plan          *Plan          `json:"plan,omitempty"`
	AssetCount    int64          `json:"asset_count"`
}
type Plan struct {
	CollectionMode string     `json:"collection_mode"`
	ScheduleError  string     `json:"schedule_error"`
	RetryAt        *time.Time `json:"retry_at"`
	Enabled        bool       `json:"enabled"`
	Interval       int        `json:"interval_hours"`
	Cron           string     `json:"cron"`
	Collectors     []string   `json:"collectors"`
	Next           *time.Time `json:"next_run_at"`
	Last           *time.Time `json:"last_run_at"`
}
type Candidate struct {
	Host   string `json:"host"`
	Source string `json:"source"`
}
type ScopeGuard struct {
	Scope     ScopeV2
	Blacklist []string
	Now       func() time.Time
}

var shanghai = time.FixedZone("Asia/Shanghai", 8*3600)
var hostLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func normalizeHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "-") || strings.ContainsAny(raw, "\r\n\t ;|&`$\\") {
		return "", errors.New("目标格式错误")
	}
	if strings.Contains(raw, "://") {
		u, e := url.Parse(raw)
		if e != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return "", errors.New("只接受 HTTP(S) URL 或域名")
		}
		raw = u.Hostname()
	} else {
		raw = strings.SplitN(raw, "/", 2)[0]
		if h, _, e := net.SplitHostPort(raw); e == nil {
			raw = h
		} else if strings.Count(raw, ":") == 1 {
			u, e := url.Parse("http://" + raw)
			if e != nil {
				return "", e
			}
			raw = u.Hostname()
		}
	}
	raw = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(raw), "*."), ".")
	if ip, e := netip.ParseAddr(raw); e == nil {
		return ip.Unmap().String(), nil
	}
	ascii, e := idna.Lookup.ToASCII(raw)
	if e != nil || len(ascii) > 253 || !strings.Contains(ascii, ".") {
		return "", errors.New("目标必须为有效完整域名或 IP")
	}
	for _, part := range strings.Split(ascii, ".") {
		if !hostLabel.MatchString(part) {
			return "", errors.New("域名格式错误")
		}
	}
	return ascii, nil
}
func matchPattern(host, pattern string, children bool) bool {
	p := strings.TrimSpace(pattern)
	if prefix, e := netip.ParsePrefix(p); e == nil {
		ip, e := netip.ParseAddr(host)
		return e == nil && prefix.Contains(ip.Unmap())
	}
	wildcard := strings.HasPrefix(p, "*.")
	p, e := normalizeHost(p)
	if e != nil {
		return false
	}
	if wildcard {
		return strings.HasSuffix(host, "."+p)
	}
	return host == p || (children && strings.HasSuffix(host, "."+p))
}
func (g ScopeGuard) Valid() error {
	now := time.Now()
	if g.Now != nil {
		now = g.Now()
	}
	if g.Scope.ProjectPolicy != nil {
		if !g.Scope.ProjectPolicy.Enabled {
			return errors.New("项目已停用")
		}
		if g.Scope.ProjectPolicy.Expires != nil && !now.Before(*g.Scope.ProjectPolicy.Expires) {
			return errors.New("项目授权已到期")
		}
	}
	if !g.Scope.Confirmed {
		return errors.New("范围尚未确认授权")
	}
	if g.Scope.Mode != "cidr" {
		if _, err := publicsuffix.EffectiveTLDPlusOne(g.Scope.Domain); err != nil {
			return errors.New("授权范围不能是公共后缀或顶级域")
		}
	}
	if g.Scope.Expires != nil && !now.Before(*g.Scope.Expires) {
		return errors.New("授权已到期")
	}
	return nil
}
func (g ScopeGuard) AllowHost(raw string) (string, error) {
	if e := g.Valid(); e != nil {
		return "", e
	}
	h, e := normalizeHost(raw)
	if e != nil {
		return "", e
	}
	for _, p := range g.Blacklist {
		if matchPattern(h, p, true) {
			return "", errors.New("命中全局黑名单")
		}
	}
	for _, p := range g.Scope.Exclusions {
		if matchPattern(h, p, false) {
			return "", errors.New("命中范围排除列表")
		}
	}
	allowed := false
	switch g.Scope.Mode {
	case "exact":
		allowed = h == g.Scope.Domain
	case "subdomains":
		allowed = strings.HasSuffix(h, "."+g.Scope.Domain)
	case "descendants":
		allowed = inScope(h, g.Scope.Domain)
	case "cidr":
		allowed = matchPattern(h, g.Scope.Domain, false)
	}
	if !allowed {
		return "", errors.New("目标不属于明确授权范围")
	}
	return h, nil
}
func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001:db8::/32"} {
		p := netip.MustParsePrefix(cidr)
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
func (g ScopeGuard) AllowIP(raw string) error {
	if e := g.Valid(); e != nil {
		return e
	}
	ip, e := netip.ParseAddr(raw)
	if e != nil || !publicIP(ip) {
		return errors.New("拒绝内网、保留或无效 IP")
	}
	for _, p := range append(append([]string{}, g.Blacklist...), g.Scope.Exclusions...) {
		if matchPattern(ip.Unmap().String(), p, false) {
			return errors.New("IP 命中黑名单或范围排除")
		}
	}
	if g.Scope.Mode == "cidr" && !matchPattern(ip.String(), g.Scope.Domain, false) {
		return errors.New("IP 不在授权网段")
	}
	return nil
}
func (g ScopeGuard) ActiveAllowed() error {
	if g.Scope.ProjectPolicy != nil && !g.Scope.ProjectPolicy.AllowActive {
		return errors.New("项目禁止主动探测")
	}
	if e := g.Valid(); e != nil {
		return e
	}
	if !g.Scope.Active {
		return errors.New("主动探测未开启")
	}
	now := time.Now()
	if g.Now != nil {
		now = g.Now()
	}
	hour := now.In(shanghai).Hour()
	a, b := g.Scope.WindowStart, g.Scope.WindowEnd
	allowed := a == b || (a < b && hour >= a && hour < b) || (a > b && (hour >= a || hour < b))
	if !allowed {
		return errors.New("当前不在允许探测时间窗口")
	}
	return nil
}

type RateLimiter interface {
	Wait(context.Context, int64, float64) error
}
type LocalRateLimiter struct {
	mu     sync.Mutex
	scopes map[int64]*rate.Limiter
	global *rate.Limiter
}

func NewRateLimiter() *LocalRateLimiter {
	return &LocalRateLimiter{scopes: map[int64]*rate.Limiter{}, global: rate.NewLimiter(5, 1)}
}
func (l *LocalRateLimiter) Wait(ctx context.Context, id int64, rps float64) error {
	if rps <= 0 {
		return errors.New("速率必须大于零")
	}
	l.mu.Lock()
	lim := l.scopes[id]
	if lim == nil {
		lim = rate.NewLimiter(rate.Limit(rps), 1)
		l.scopes[id] = lim
	} else {
		lim.SetLimit(rate.Limit(rps))
	}
	l.mu.Unlock()
	if e := l.global.Wait(ctx); e != nil {
		return e
	}
	return lim.Wait(ctx)
}

type Budget struct {
	mu          sync.Mutex
	Used, Limit int
}

func (b *Budget) Take() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Used >= b.Limit {
		return fmt.Errorf("达到任务请求预算 %d", b.Limit)
	}
	b.Used++
	return nil
}

// PostgreSQL slots keep the same total scope rate even if independent worker processes are started.
type PGRateLimiter struct{ Store *Store }

func (l *PGRateLimiter) Wait(ctx context.Context, id int64, rps float64) error {
	if rps <= 0 {
		return errors.New("速率必须大于零")
	}
	g, err := l.Store.guard(ctx, id)
	if err != nil {
		return err
	}
	if err = g.Valid(); err != nil {
		return err
	}
	slots := []struct {
		id      int64
		rps     float64
		project bool
	}{{0, 5, false}, {id, rps, false}}
	if g.Scope.ProjectID > 0 && g.Scope.ProjectPolicy != nil {
		slots = append(slots, struct {
			id      int64
			rps     float64
			project bool
		}{g.Scope.ProjectID, g.Scope.ProjectPolicy.RPSLimit, true})
	}
	for _, slot := range slots {
		tx, err := l.Store.DB.Begin(ctx)
		if err != nil {
			return err
		}
		table, key := "rate_slots", "scope_id"
		if slot.project {
			table, key = "project_rate_slots", "project_id"
		}
		_, err = tx.Exec(ctx, "INSERT INTO "+table+"("+key+",next_at)VALUES($1,now())ON CONFLICT DO NOTHING", slot.id)
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
		var at time.Time
		err = tx.QueryRow(ctx, "UPDATE "+table+" SET next_at=greatest(next_at,clock_timestamp())+$2*interval '1 second' WHERE "+key+"=$1 RETURNING next_at-$2*interval '1 second'", slot.id, 1/slot.rps).Scan(&at)
		if err == nil {
			err = tx.Commit(ctx)
		} else {
			tx.Rollback(ctx)
		}
		if err != nil {
			return err
		}
		if delay := time.Until(at); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return nil
}
