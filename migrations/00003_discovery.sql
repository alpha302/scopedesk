-- +goose Up
CREATE TABLE candidates (
 id bigserial PRIMARY KEY, scope_id bigint NOT NULL REFERENCES scopes(id), host text NOT NULL,
 sources text[] NOT NULL DEFAULT '{}', first_round integer NOT NULL DEFAULT 1 CHECK(first_round>=0),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','out_of_scope','wildcard','invalid','blacklisted')),
 reason text NOT NULL DEFAULT '', first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
 UNIQUE(scope_id,host)
);
CREATE INDEX candidates_scope_status ON candidates(scope_id,status);
CREATE TABLE discovery_rounds (
 id bigserial PRIMARY KEY, job_id bigint NOT NULL REFERENCES jobs(id), round integer NOT NULL CHECK(round>=1),
 started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
 new_candidates integer NOT NULL DEFAULT 0 CHECK(new_candidates>=0), new_assets integer NOT NULL DEFAULT 0 CHECK(new_assets>=0),
 stage_stats jsonb NOT NULL DEFAULT '{}', UNIQUE(job_id,round)
);
CREATE TABLE dns_records (
 id bigserial PRIMARY KEY, scope_id bigint NOT NULL REFERENCES scopes(id), host text NOT NULL,
 rtype text NOT NULL, value text NOT NULL, first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
 UNIQUE(scope_id,host,rtype,value)
);
CREATE INDEX dns_records_scope_host ON dns_records(scope_id,host);
CREATE TABLE ip_assets (
 id bigserial PRIMARY KEY, scope_id bigint NOT NULL REFERENCES scopes(id), ip inet NOT NULL CHECK(masklen(ip)=CASE WHEN family(ip)=4 THEN 32 ELSE 128 END),
 is_cdn boolean NOT NULL DEFAULT false, cdn_provider text NOT NULL DEFAULT '',
 first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(), UNIQUE(scope_id,ip)
);
CREATE TABLE asset_ips (
 asset_id bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 ip_asset_id bigint NOT NULL REFERENCES ip_assets(id) ON DELETE CASCADE, PRIMARY KEY(asset_id,ip_asset_id)
);
CREATE INDEX asset_ips_ip ON asset_ips(ip_asset_id);
CREATE TABLE asset_services (
 id bigserial PRIMARY KEY, asset_id bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 ip inet CHECK(ip IS NULL OR masklen(ip)=CASE WHEN family(ip)=4 THEN 32 ELSE 128 END), port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),
 protocol text NOT NULL DEFAULT 'tcp' CHECK(protocol IN ('tcp','udp')),
 service text NOT NULL DEFAULT '', banner text NOT NULL DEFAULT '', scheme text NOT NULL DEFAULT '',
 status_code integer NOT NULL DEFAULT 0, title text NOT NULL DEFAULT '', server text NOT NULL DEFAULT '',
 favicon_mmh3 integer, favicon_sha256 text NOT NULL DEFAULT '', fingerprints jsonb NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(fingerprints)='array'),
 tls_subject text NOT NULL DEFAULT '', tls_not_after timestamptz, screenshot_ref text NOT NULL DEFAULT '',
 first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(), miss_count integer NOT NULL DEFAULT 0 CHECK(miss_count>=0),
 UNIQUE(asset_id,ip,port,protocol)
);
-- Partial unique index also makes unknown-IP services idempotent on PostgreSQL 14.
CREATE UNIQUE INDEX asset_services_unknown_ip ON asset_services(asset_id,port,protocol) WHERE ip IS NULL;
CREATE INDEX asset_services_asset ON asset_services(asset_id);
CREATE INDEX asset_services_port ON asset_services(port,asset_id);
CREATE INDEX asset_services_service ON asset_services(service,asset_id);
CREATE TABLE source_credentials (
 source text PRIMARY KEY, key_encrypted bytea NOT NULL, enabled boolean NOT NULL DEFAULT false,
 quota jsonb NOT NULL DEFAULT '{}', last_error text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE plugin_runs (
 id bigserial PRIMARY KEY, job_id bigint NOT NULL REFERENCES jobs(id), plugin text NOT NULL, version text NOT NULL DEFAULT '',
 params_digest text NOT NULL DEFAULT '', started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
 exit_code integer, returned integer NOT NULL DEFAULT 0, in_scope integer NOT NULL DEFAULT 0, new_count integer NOT NULL DEFAULT 0,
 stderr_excerpt text NOT NULL DEFAULT ''
);
CREATE INDEX plugin_runs_job ON plugin_runs(job_id,started_at);
CREATE TABLE wordlists (
 id bigserial PRIMARY KEY, name text NOT NULL, tier text NOT NULL DEFAULT 'standard', entries bigint NOT NULL DEFAULT 0 CHECK(entries>=0),
 sha256 text NOT NULL DEFAULT '', path text NOT NULL
);
CREATE TABLE resolvers (
 id bigserial PRIMARY KEY, addr text UNIQUE NOT NULL, enabled boolean NOT NULL DEFAULT true,
 failure_rate double precision NOT NULL DEFAULT 0 CHECK(failure_rate>=0 AND failure_rate<=1), updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose StatementBegin
CREATE FUNCTION pg_temp.scopedesk_legacy_ip(input text) RETURNS inet LANGUAGE plpgsql AS $$
BEGIN
 RETURN host(input::inet)::inet;
EXCEPTION WHEN invalid_text_representation THEN
 RETURN NULL;
END;
$$;
-- +goose StatementEnd

INSERT INTO asset_services(asset_id,ip,port,protocol,service,scheme,status_code,title,server,favicon_sha256,fingerprints,tls_subject,tls_not_after,first_seen,last_seen,miss_count)
SELECT id,pg_temp.scopedesk_legacy_ip(ips[1]),
 CASE WHEN port BETWEEN 1 AND 65535 THEN port WHEN tls_subject<>'' OR tls_not_after IS NOT NULL THEN 443 ELSE 80 END,
 'tcp',CASE WHEN port=443 OR tls_subject<>'' OR tls_not_after IS NOT NULL THEN 'https' ELSE 'http' END,
 CASE WHEN port=443 OR tls_subject<>'' OR tls_not_after IS NOT NULL THEN 'https' ELSE 'http' END,
 status_code,title,server,favicon_hash,to_jsonb(fingerprints),tls_subject,tls_not_after,first_seen,last_seen,miss_count
FROM assets WHERE status_code>0 OR port>0 OR title<>'' OR server<>'' OR tls_subject<>'' OR tls_not_after IS NOT NULL OR favicon_hash<>''
ON CONFLICT DO NOTHING;

INSERT INTO ip_assets(scope_id,ip,first_seen,last_seen)
SELECT scope_id,pg_temp.scopedesk_legacy_ip(v),min(first_seen),max(last_seen)
FROM assets CROSS JOIN LATERAL unnest(ips) v WHERE pg_temp.scopedesk_legacy_ip(v) IS NOT NULL
GROUP BY scope_id,pg_temp.scopedesk_legacy_ip(v)
ON CONFLICT(scope_id,ip) DO UPDATE SET last_seen=GREATEST(ip_assets.last_seen,excluded.last_seen);
INSERT INTO asset_ips(asset_id,ip_asset_id)
SELECT DISTINCT a.id,i.id FROM assets a CROSS JOIN LATERAL unnest(a.ips) v
JOIN ip_assets i ON i.scope_id=a.scope_id AND i.ip=pg_temp.scopedesk_legacy_ip(v) ON CONFLICT DO NOTHING;
DROP FUNCTION pg_temp.scopedesk_legacy_ip(text);

-- +goose Down
DROP TABLE asset_ips,asset_services,ip_assets,dns_records,discovery_rounds,candidates,source_credentials,plugin_runs,wordlists,resolvers;
