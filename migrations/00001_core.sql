-- +goose Up
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;
CREATE TABLE platform_users(id integer PRIMARY KEY, payload jsonb NOT NULL);
CREATE TABLE scopes (
 id bigserial PRIMARY KEY, owner integer NOT NULL, domain text NOT NULL, mode text NOT NULL DEFAULT 'exact',
 policy text NOT NULL, confirmed boolean NOT NULL DEFAULT true, active boolean NOT NULL DEFAULT false,
 exclusions jsonb NOT NULL DEFAULT '[]', expires_at timestamptz, rps double precision NOT NULL DEFAULT 1,
 concurrency integer NOT NULL DEFAULT 2, request_limit integer NOT NULL DEFAULT 1000,
 window_start integer NOT NULL DEFAULT 0, window_end integer NOT NULL DEFAULT 24,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(owner,domain,mode)
);
CREATE TABLE monitor_plans(scope_id bigint PRIMARY KEY REFERENCES scopes(id) ON DELETE CASCADE,
 enabled boolean NOT NULL DEFAULT false, interval_hours integer NOT NULL DEFAULT 24, cron text NOT NULL DEFAULT '',
 collectors jsonb NOT NULL DEFAULT '["crtsh","certspotter"]', next_run_at timestamptz, last_run_at timestamptz);
CREATE TABLE jobs(id bigserial PRIMARY KEY, scope_id bigint REFERENCES scopes(id), owner integer NOT NULL,
 trigger text NOT NULL DEFAULT 'manual', status text NOT NULL DEFAULT 'queued', payload jsonb NOT NULL DEFAULT '{}',
 worker_id text, lease_until timestamptz, heartbeat_at timestamptz, attempts integer NOT NULL DEFAULT 0,
 max_attempts integer NOT NULL DEFAULT 3, available_at timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, finished_at timestamptz,
 progress integer NOT NULL DEFAULT 0, error text NOT NULL DEFAULT '', stats jsonb NOT NULL DEFAULT '{}', cancel_requested boolean NOT NULL DEFAULT false);
CREATE UNIQUE INDEX jobs_one_scope ON jobs(scope_id) WHERE status IN ('queued','running','retrying');
CREATE INDEX jobs_claim ON jobs(available_at,id) WHERE status IN ('queued','retrying');
CREATE TABLE job_source_stats(job_id bigint REFERENCES jobs(id) ON DELETE CASCADE, source text NOT NULL,
 returned integer NOT NULL DEFAULT 0, in_scope integer NOT NULL DEFAULT 0, discarded integer NOT NULL DEFAULT 0,
 new_count integer NOT NULL DEFAULT 0, attempts integer NOT NULL DEFAULT 0, error text NOT NULL DEFAULT '', PRIMARY KEY(job_id,source));
CREATE TABLE assets(id bigserial PRIMARY KEY, scope_id bigint NOT NULL REFERENCES scopes(id), host text NOT NULL,
 ips text[] NOT NULL DEFAULT '{}', cnames text[] NOT NULL DEFAULT '{}', sources text[] NOT NULL DEFAULT '{}',
 port integer NOT NULL DEFAULT 0, status_code integer NOT NULL DEFAULT 0, title text NOT NULL DEFAULT '', server text NOT NULL DEFAULT '',
 response_length bigint NOT NULL DEFAULT 0, redirects jsonb NOT NULL DEFAULT '[]', fingerprints text[] NOT NULL DEFAULT '{}',
 tls_subject text NOT NULL DEFAULT '', tls_not_after timestamptz, favicon_hash text NOT NULL DEFAULT '',
 category text NOT NULL DEFAULT '未分类', score integer NOT NULL DEFAULT 0, status text NOT NULL DEFAULT 'new',
 tags text[] NOT NULL DEFAULT '{}', note text NOT NULL DEFAULT '', assignee text NOT NULL DEFAULT '',
 is_cdn boolean NOT NULL DEFAULT false, is_security_device boolean NOT NULL DEFAULT false, security_rule text NOT NULL DEFAULT '',
 is_alive boolean, miss_count integer NOT NULL DEFAULT 0, first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
 dns_at timestamptz, observed_run bigint REFERENCES jobs(id), UNIQUE(scope_id,host));
CREATE INDEX assets_scope_id ON assets(scope_id,id DESC);
CREATE INDEX assets_status ON assets(scope_id,status,id DESC);
CREATE INDEX assets_seen ON assets(last_seen DESC);
CREATE INDEX assets_host_trgm ON assets USING gin(host gin_trgm_ops);
CREATE INDEX assets_title_trgm ON assets USING gin(title gin_trgm_ops);
CREATE TABLE asset_snapshots(id bigserial, asset_id bigint NOT NULL, scope_id bigint NOT NULL, job_id bigint,
 payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(id,created_at)) PARTITION BY RANGE(created_at);
CREATE TABLE asset_events(id bigserial, asset_id bigint NOT NULL, scope_id bigint NOT NULL REFERENCES scopes(id), job_id bigint,
 type text NOT NULL, detail jsonb NOT NULL DEFAULT '{}', dedupe_key text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(id,created_at)) PARTITION BY RANGE(created_at);
CREATE INDEX events_scope_time ON asset_events(scope_id,created_at DESC);
CREATE TABLE event_dedupes(key text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE encrypted_settings(key text PRIMARY KEY, payload bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE digest_logs(id bigserial PRIMARY KEY, idempotency_key text UNIQUE NOT NULL, status text NOT NULL,
 recipient_count integer NOT NULL DEFAULT 0, attempts integer NOT NULL DEFAULT 0, error text NOT NULL DEFAULT '',
 next_attempt_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE workers(id text PRIMARY KEY, version text NOT NULL, host text NOT NULL, heartbeat_at timestamptz NOT NULL,
 concurrency integer NOT NULL, active_jobs integer NOT NULL DEFAULT 0);
CREATE TABLE global_blacklist(id bigserial PRIMARY KEY, pattern text UNIQUE NOT NULL, note text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE operation_logs(id bigserial PRIMARY KEY, user_id integer NOT NULL, action text NOT NULL, target text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE migration_markers(key text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE rate_slots(scope_id bigint PRIMARY KEY, next_at timestamptz NOT NULL);

-- +goose Down
DROP TABLE IF EXISTS rate_slots,migration_markers,operation_logs,global_blacklist,workers,digest_logs,encrypted_settings,event_dedupes,asset_events,asset_snapshots,assets,job_source_stats,jobs,monitor_plans,scopes,platform_users CASCADE;
