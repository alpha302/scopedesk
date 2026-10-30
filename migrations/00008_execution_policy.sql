-- +goose Up
ALTER TABLE jobs ADD COLUMN execution_timeout_seconds integer NOT NULL DEFAULT 0 CHECK(execution_timeout_seconds>=0);
ALTER TABLE jobs ADD COLUMN deadline_at timestamptz;
ALTER TABLE jobs ADD COLUMN error_code text NOT NULL DEFAULT '';
ALTER TABLE jobs ADD COLUMN retryable boolean NOT NULL DEFAULT false;
ALTER TABLE plugin_runs ADD COLUMN error_code text NOT NULL DEFAULT '';
ALTER TABLE plugin_runs ADD COLUMN retryable boolean NOT NULL DEFAULT false;
ALTER TABLE job_source_stats ADD COLUMN error_code text NOT NULL DEFAULT '';
ALTER TABLE job_source_stats ADD COLUMN retryable boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE job_source_stats DROP COLUMN retryable,DROP COLUMN error_code;
ALTER TABLE plugin_runs DROP COLUMN retryable,DROP COLUMN error_code;
ALTER TABLE jobs DROP COLUMN retryable,DROP COLUMN error_code,DROP COLUMN deadline_at,DROP COLUMN execution_timeout_seconds;
