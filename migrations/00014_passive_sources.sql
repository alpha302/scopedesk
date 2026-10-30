-- +goose Up
ALTER TABLE monitor_plans ADD COLUMN collection_mode text NOT NULL DEFAULT 'profile' CHECK(collection_mode IN ('profile','evidence_only'));
ALTER TABLE job_source_stats ADD COLUMN complete boolean NOT NULL DEFAULT false, ADD COLUMN absence_usable boolean NOT NULL DEFAULT false;
CREATE TABLE passive_source_accounts(
 id bigserial PRIMARY KEY,
 project_id bigint NOT NULL REFERENCES projects(id),
 source text NOT NULL CHECK(source IN ('hunter','fofa')),
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
 provider_time_enabled boolean NOT NULL DEFAULT false,
 key_encrypted bytea NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 selected boolean NOT NULL DEFAULT false,
 state text NOT NULL DEFAULT 'ready' CHECK(state IN ('ready','auth_expired','rate_limited','unavailable','reconciliation_required')),
 cooldown_until timestamptz,
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(id,project_id,source),
 CHECK(NOT selected OR enabled)
);
CREATE UNIQUE INDEX passive_selected_account ON passive_source_accounts(project_id,source) WHERE selected;
CREATE TABLE passive_source_budgets(
 account_id bigint PRIMARY KEY REFERENCES passive_source_accounts(id),
 window_start timestamptz NOT NULL,
 window_end timestamptz NOT NULL CHECK(window_end>window_start),
 timezone text NOT NULL DEFAULT 'unconfirmed',
 reset_policy text NOT NULL DEFAULT 'manual_confirmed' CHECK(reset_policy='manual_confirmed'),
 request_limit bigint NOT NULL CHECK(request_limit BETWEEN 1 AND 1000000),
 record_limit bigint NOT NULL CHECK(record_limit BETWEEN 1 AND 10000000),
 unit_limit bigint NOT NULL CHECK(unit_limit BETWEEN 0 AND 1000000000),
 reserve_units_per_page bigint NOT NULL CHECK(reserve_units_per_page BETWEEN 0 AND 1000000000),
 charge_unit text NOT NULL CHECK(charge_unit IN ('points','fcoin','unknown')),
 requests_used bigint NOT NULL DEFAULT 0 CHECK(requests_used>=0),
 requests_reserved bigint NOT NULL DEFAULT 0 CHECK(requests_reserved>=0),
 records_returned bigint NOT NULL DEFAULT 0 CHECK(records_returned>=0),
 records_reserved bigint NOT NULL DEFAULT 0 CHECK(records_reserved>=0),
 units_used bigint NOT NULL DEFAULT 0 CHECK(units_used>=0),
 units_reserved bigint NOT NULL DEFAULT 0 CHECK(units_reserved>=0),
 balance_as_of timestamptz NOT NULL,
 policy_reference text NOT NULL CHECK(length(policy_reference) BETWEEN 1 AND 1000),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE passive_source_queries(
 id bigserial PRIMARY KEY,
 account_id bigint NOT NULL,
 project_id bigint NOT NULL,
 source text NOT NULL,
 job_id bigint NOT NULL REFERENCES jobs(id),
 query text NOT NULL CHECK(length(query)<=2000),
 page integer NOT NULL CHECK(page BETWEEN 1 AND 100),
 page_size integer NOT NULL CHECK(page_size BETWEEN 1 AND 100),
 reserved_units bigint NOT NULL CHECK(reserved_units>=0),
 budget_window_start timestamptz NOT NULL,
 budget_window_end timestamptz NOT NULL,
 request_count integer NOT NULL DEFAULT 0 CHECK(request_count IN (0,1)),
 returned_count integer CHECK(returned_count>=0),
 actual_units bigint CHECK(actual_units>=0),
 charge_unit text NOT NULL,
 state text NOT NULL DEFAULT 'pending_reconciliation' CHECK(state IN ('pending_reconciliation','settled')),
 status text NOT NULL DEFAULT 'reserved' CHECK(status IN ('reserved','sent','complete','partial','auth_expired','rate_limited','unavailable','failed')),
 error_code text NOT NULL DEFAULT '',
 page_complete boolean NOT NULL DEFAULT false,
 query_complete boolean NOT NULL DEFAULT false,
 provider_remaining bigint CHECK(provider_remaining>=0),
 created_at timestamptz NOT NULL DEFAULT now(),
 sent_at timestamptz,
 received_at timestamptz,
 reconciled_at timestamptz,
 reconciled_by integer,
 reconciliation_note text,
 FOREIGN KEY(account_id,project_id,source) REFERENCES passive_source_accounts(id,project_id,source),
 UNIQUE(job_id,source,query,page),
 CHECK(state!='settled' OR actual_units IS NOT NULL),
 CHECK(NOT query_complete OR page_complete)
);
CREATE INDEX passive_queries_account ON passive_source_queries(account_id,id DESC);
CREATE INDEX passive_queries_project ON passive_source_queries(project_id,id DESC);
-- +goose Down
ALTER TABLE monitor_plans DROP COLUMN collection_mode;
ALTER TABLE job_source_stats DROP COLUMN complete, DROP COLUMN absence_usable;
DROP TABLE passive_source_queries,passive_source_budgets,passive_source_accounts;
