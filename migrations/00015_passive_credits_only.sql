-- +goose Up
ALTER TABLE passive_source_accounts
 ADD COLUMN billing_policy text NOT NULL DEFAULT 'credits_only' CHECK(billing_policy='credits_only'),
 ADD COLUMN page_size integer NOT NULL DEFAULT 10 CHECK(page_size BETWEEN 1 AND 100),
 ADD COLUMN credit_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(credit_snapshot)='object');
CREATE TABLE passive_source_account_checks(
 id bigserial PRIMARY KEY,
 account_id bigint NOT NULL REFERENCES passive_source_accounts(id),
 job_id bigint REFERENCES jobs(id),
 request_count integer NOT NULL DEFAULT 1 CHECK(request_count=1),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','complete','auth_expired','rate_limited','unavailable')),
 error_code text NOT NULL DEFAULT '',
 snapshot jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(snapshot)='object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz
);
CREATE INDEX passive_checks_account ON passive_source_account_checks(account_id,id DESC);
-- +goose Down
DROP TABLE passive_source_account_checks;
ALTER TABLE passive_source_accounts DROP COLUMN billing_policy,DROP COLUMN page_size,DROP COLUMN credit_snapshot;
