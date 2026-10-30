package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	Plugins *PluginRegistry
	DB      *pgxpool.Pool
	AEAD    cipher.AEAD
}

func openStore(ctx context.Context, dsn string) (*Store, error) {
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		return nil, errors.New("数据库连接配置无效")
	}
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	db, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		return nil, e
	}
	if e = db.Ping(ctx); e != nil {
		db.Close()
		return nil, errors.New("无法连接 PostgreSQL")
	}
	key, e := base64.StdEncoding.DecodeString(os.Getenv("RECON_MASTER_KEY"))
	if e != nil || len(key) != 32 {
		db.Close()
		return nil, errors.New("RECON_MASTER_KEY 必须是 32 字节密钥的 Base64")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	sqlDB := stdlib.OpenDBFromPool(db)
	defer sqlDB.Close()
	goose.SetBaseFS(migrations)
	if e = goose.SetDialect("postgres"); e != nil {
		return nil, e
	}
	if e = goose.UpContext(ctx, sqlDB, "migrations"); e != nil {
		db.Close()
		return nil, e
	}
	s := &Store{DB: db, AEAD: aead}
	if e = s.ensurePartitions(ctx); e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) ensurePartitions(ctx context.Context) error {
	// Identifiers and dates are generated locally, never derived from request text.
	now := time.Now().UTC()
	for offset := -1; offset <= 2; offset++ {
		start := time.Date(now.Year(), now.Month()+time.Month(offset), 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(0, 1, 0)
		for _, table := range []string{"asset_events", "asset_snapshots"} {
			q := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s_%s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')", table, start.Format("200601"), table, start.Format("2006-01-02"), end.Format("2006-01-02"))
			if _, e := s.DB.Exec(ctx, q); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Store) encrypt(key string, data []byte) ([]byte, error) {
	nonce := make([]byte, s.AEAD.NonceSize())
	if _, e := io.ReadFull(rand.Reader, nonce); e != nil {
		return nil, e
	}
	return s.AEAD.Seal(nonce, nonce, data, []byte(key)), nil
}
func (s *Store) decrypt(key string, data []byte) ([]byte, error) {
	n := s.AEAD.NonceSize()
	if len(data) < n {
		return nil, errors.New("密文无效")
	}
	return s.AEAD.Open(nil, data[:n], data[n:], []byte(key))
}
func (s *Store) setting(ctx context.Context, key string, out any) error {
	var raw []byte
	e := s.DB.QueryRow(ctx, "SELECT payload FROM encrypted_settings WHERE key=$1", key).Scan(&raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	plain, e := s.decrypt(key, raw)
	if e != nil {
		return e
	}
	return json.Unmarshal(plain, out)
}
func (s *Store) putSetting(ctx context.Context, key string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	raw, e = s.encrypt(key, raw)
	if e != nil {
		return e
	}
	_, e = s.DB.Exec(ctx, "INSERT INTO encrypted_settings(key,payload)VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET payload=excluded.payload,updated_at=now()", key, raw)
	return e
}
func (s *Store) saveUsers(users []User) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	for _, u := range users {
		raw, _ := json.Marshal(u)
		if _, e = tx.Exec(ctx, "INSERT INTO platform_users(id,payload)VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", u.ID, raw); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) loadUsers(ctx context.Context) ([]User, error) {
	rows, e := s.DB.Query(ctx, "SELECT payload FROM platform_users ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var raw []byte
		var u User
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, &u); e != nil {
			return nil, e
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (s *Store) importLegacy(ctx context.Context, old State) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(2700101)")
	if e != nil {
		return e
	}
	var exists bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM migration_markers WHERE key='legacy-json')").Scan(&exists); e != nil {
		return e
	}
	if exists {
		return nil
	}
	for _, u := range old.Users {
		raw, _ := json.Marshal(u)
		if _, e = tx.Exec(ctx, "INSERT INTO platform_users(id,payload)VALUES($1,$2) ON CONFLICT DO NOTHING", u.ID, raw); e != nil {
			return e
		}
	}
	for _, v := range old.Scopes {
		if _, e = tx.Exec(ctx, "INSERT INTO scopes(id,owner,domain,mode,policy,created_at)VALUES($1,$2,$3,'descendants',$4,to_timestamp($5)) ON CONFLICT DO NOTHING", v.ID, v.Owner, v.Domain, v.Policy, v.Created); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO monitor_plans(scope_id)VALUES($1) ON CONFLICT DO NOTHING", v.ID); e != nil {
			return e
		}
	}
	for _, a := range old.Assets {
		if _, e = tx.Exec(ctx, `INSERT INTO assets(scope_id,host,sources,first_seen,last_seen)VALUES($1,$2,ARRAY[$3],to_timestamp($4),to_timestamp($5)) ON CONFLICT(scope_id,host)DO UPDATE SET sources=(SELECT ARRAY(SELECT DISTINCT unnest(assets.sources||excluded.sources))),last_seen=greatest(assets.last_seen,excluded.last_seen)`, a.Scope, a.Host, a.Source, a.First, a.Last); e != nil {
			return e
		}
	}
	for _, j := range old.Jobs {
		status := j.State
		if !slices.Contains([]string{"done", "failed", "cancelled"}, status) {
			status = "cancelled"
		}
		var finished any
		if j.Finished > 0 {
			finished = time.Unix(j.Finished, 0)
		}
		if _, e = tx.Exec(ctx, "INSERT INTO jobs(id,scope_id,owner,trigger,status,created_at,finished_at,error,progress)VALUES($1,$2,$3,'legacy',$4,to_timestamp($5),$6,$7,100)ON CONFLICT DO NOTHING", j.ID, j.Scope, j.Owner, status, j.Created, finished, j.Message); e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, "SELECT setval('scopes_id_seq',coalesce((SELECT max(id) FROM scopes),0)+1,false),setval('jobs_id_seq',coalesce((SELECT max(id)FROM jobs),0)+1,false)")
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO migration_markers(key)VALUES('legacy-json')")
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) scopes(ctx context.Context, u User, filters ...urlQuery) ([]ScopeV2, error) {
	rows, e := s.DB.Query(ctx, `SELECT s.id,s.owner,s.domain,s.mode,s.policy,s.confirmed,s.active,s.exclusions,s.expires_at,s.rps,s.concurrency,s.request_limit,s.window_start,s.window_end,s.created_at,(SELECT count(*) FROM assets a WHERE a.scope_id=s.id),s.project_id,p.name,p.workspace_id,jsonb_build_object('enabled',p.enabled,'allow_active',p.allow_active,'expires_at',p.expires_at,'rps_limit',p.rps_limit) FROM scopes s JOIN projects p ON p.id=s.project_id WHERE ($1='admin' OR scope_access(s.id,$2)) AND ($3=0 OR s.project_id=$3) ORDER BY s.id DESC`, u.Role, u.ID, projectFilter(filters...))
	if e != nil {
		return nil, e
	}
	out := []ScopeV2{}
	for rows.Next() {
		var v ScopeV2
		var exclusions, projectPolicy []byte
		if e = rows.Scan(&v.ID, &v.Owner, &v.Domain, &v.Mode, &v.Policy, &v.Confirmed, &v.Active, &exclusions, &v.Expires, &v.RPS, &v.Concurrency, &v.RequestLimit, &v.WindowStart, &v.WindowEnd, &v.Created, &v.AssetCount, &v.ProjectID, &v.ProjectName, &v.WorkspaceID, &projectPolicy); e != nil {
			rows.Close()
			return nil, e
		}
		json.Unmarshal(exclusions, &v.Exclusions)
		json.Unmarshal(projectPolicy, &v.ProjectPolicy)
		out = append(out, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for i := range out {
		p, e := s.plan(ctx, out[i].ID)
		if e != nil {
			return nil, e
		}
		out[i].Plan = &p
	}
	return out, nil
}
func (s *Store) guard(ctx context.Context, id int64) (ScopeGuard, error) {
	return readScopeGuard(ctx, s.DB, id)
}

// One statement gives the scope and blacklist the same PostgreSQL snapshot.
const scopeGuardSQL = `SELECT s.id,s.owner,s.domain,s.mode,s.policy,s.confirmed,s.active,s.exclusions,s.expires_at,s.rps,s.concurrency,s.request_limit,s.window_start,s.window_end,s.created_at,
 COALESCE((SELECT array_agg(pattern ORDER BY id) FROM global_blacklist),'{}'::text[]),s.project_id,p.name,p.workspace_id,jsonb_build_object('enabled',p.enabled,'allow_active',p.allow_active,'expires_at',p.expires_at,'rps_limit',p.rps_limit) FROM scopes s JOIN projects p ON p.id=s.project_id WHERE s.id=$1`

func readScopeGuard(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id int64) (ScopeGuard, error) {
	var g ScopeGuard
	var raw, policy []byte
	v := &g.Scope
	if err := db.QueryRow(ctx, scopeGuardSQL, id).Scan(&v.ID, &v.Owner, &v.Domain, &v.Mode, &v.Policy, &v.Confirmed, &v.Active, &raw, &v.Expires, &v.RPS, &v.Concurrency, &v.RequestLimit, &v.WindowStart, &v.WindowEnd, &v.Created, &g.Blacklist, &v.ProjectID, &v.ProjectName, &v.WorkspaceID, &policy); err != nil {
		return ScopeGuard{}, err
	}
	if err := json.Unmarshal(raw, &v.Exclusions); err != nil {
		return ScopeGuard{}, err
	}
	if err := json.Unmarshal(policy, &v.ProjectPolicy); err != nil {
		return ScopeGuard{}, err
	}
	return g, nil
}
func (s *Store) scopesByID(ctx context.Context, id int64) (ScopeV2, error) {
	g, err := s.guard(ctx, id)
	return g.Scope, err
}

func (s *Store) plan(ctx context.Context, id int64) (Plan, error) {
	p := Plan{Interval: 24, Collectors: []string{"crtsh", "certspotter"}}
	var raw []byte
	e := s.DB.QueryRow(ctx, "SELECT enabled,interval_hours,cron,collectors,next_run_at,last_run_at,schedule_error,retry_at,collection_mode FROM monitor_plans WHERE scope_id=$1", id).Scan(&p.Enabled, &p.Interval, &p.Cron, &raw, &p.Next, &p.Last, &p.ScheduleError, &p.RetryAt, &p.CollectionMode)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, nil
	}
	if e == nil {
		e = json.Unmarshal(raw, &p.Collectors)
	}
	return p, e
}
func (s *Store) operation(ctx context.Context, user int, action, target string) {
	s.DB.Exec(ctx, "INSERT INTO operation_logs(user_id,action,target)VALUES($1,$2,$3)", user, action, target)
}
func queryJSON(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) ([]json.RawMessage, error) {
	rows, e := db.Query(ctx, sql, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}
func assetWhere(u User, q urlQuery) (string, []any) {
	args := []any{u.Role, u.ID}
	where := " WHERE ($1='admin' OR scope_access(s.id,$2))"
	add := func(expr string, value any) {
		args = append(args, value)
		where += " AND " + strings.ReplaceAll(expr, "?", "$"+strconv.Itoa(len(args)))
	}
	if id := q.Get("project_id"); id != "" {
		parsed, err := strconv.ParseInt(id, 10, 64)
		if err != nil || parsed < 1 {
			parsed = -1
		}
		add("s.project_id=?::bigint", parsed)
	}
	if id := q.Get("scope_id"); id != "" {
		parsed, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			parsed = -1
		}
		add("a.scope_id=?::bigint", parsed)
	}
	for _, name := range []string{"status", "category", "assignee"} {
		if value := q.Get(name); value != "" {
			add("a."+name+"=?", value)
		}
	}
	if value := q.Get("q"); value != "" {
		value = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "%", "\\%"), "_", "\\_")
		add("(a.host ILIKE ? OR a.title ILIKE ? OR array_to_string(a.fingerprints,',') ILIKE ?)", "%"+value+"%")
	}
	if value := q.Get("status_code"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			parsed = -1
		}
		add("a.status_code=?::int", parsed)
	}
	if value := q.Get("ip"); value != "" {
		add("?=ANY(a.ips)", value)
	}
	if value := q.Get("source"); value != "" {
		add("?=ANY(a.sources)", value)
	}

	// Both predicates belong to one service, so port=443&service=ssh cannot
	// accidentally match two unrelated services of the same asset.
	serviceConditions := []string{"svc.asset_id=a.id"}
	if value := q.Get("port"); value != "" {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			port = -1
		}
		args = append(args, port)
		serviceConditions = append(serviceConditions, fmt.Sprintf("svc.port=$%d", len(args)))
	}
	if value := q.Get("service"); value != "" {
		args = append(args, value)
		serviceConditions = append(serviceConditions, fmt.Sprintf("svc.service=$%d", len(args)))
	}
	if err := validateFaviconQuery(q); err != nil {
		where += " AND FALSE"
	} else {
		if value := q.Get("favicon_mmh3"); value != "" {
			n, _ := strconv.ParseInt(value, 10, 32)
			args = append(args, n)
			serviceConditions = append(serviceConditions, fmt.Sprintf("NOT svc.evidence_only AND svc.favicon_mmh3 IS NOT NULL AND svc.favicon_mmh3=$%d::integer", len(args)))
		}
		if value := q.Get("favicon_sha256"); value != "" {
			args = append(args, strings.ToLower(value))
			serviceConditions = append(serviceConditions, fmt.Sprintf("NOT svc.evidence_only AND svc.favicon_sha256 IS NOT NULL AND svc.favicon_sha256=$%d", len(args)))
		}
	}
	if len(serviceConditions) > 1 {
		where += " AND EXISTS(SELECT 1 FROM asset_services svc WHERE " + strings.Join(serviceConditions, " AND ") + ")"
	}
	if q.Get("alive") == "true" {
		where += " AND a.is_alive=true"
	}
	if kind := q.Get("network_category"); slices.Contains([]string{"cdn", "waf", "cloud"}, kind) {
		filter, _ := json.Marshal([]map[string]string{{"category": kind}})
		add("a.network_evidence @> ?::jsonb", string(filter))
	}
	if q.Get("cdn") == "false" {
		where += " AND NOT a.is_cdn"
	}
	if q.Get("security") == "true" {
		where += " AND a.is_security_device"
	}
	return where, args
}

type urlQuery interface{ Get(string) string }
