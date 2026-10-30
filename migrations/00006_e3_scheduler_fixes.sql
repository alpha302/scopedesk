-- +goose Up
ALTER TABLE monitor_plans ADD COLUMN schedule_error text NOT NULL DEFAULT '';
ALTER TABLE monitor_plans ADD COLUMN retry_at timestamptz;
DROP INDEX jobs_one_scope;
CREATE UNIQUE INDEX jobs_one_scope ON jobs(scope_id)
 WHERE status IN ('queued','running','retrying') AND trigger <> 'plugin_test';
CREATE UNIQUE INDEX jobs_one_scope_plugin_test ON jobs(scope_id)
 WHERE status IN ('queued','running','retrying') AND trigger = 'plugin_test';

-- +goose Down
-- Refuse rollback when simultaneous test/monitor jobs exist; finish or cancel them first.
-- PostgreSQL rolls back this migration atomically if the original index cannot be restored.
DROP INDEX jobs_one_scope_plugin_test;
DROP INDEX jobs_one_scope;
CREATE UNIQUE INDEX jobs_one_scope ON jobs(scope_id) WHERE status IN ('queued','running','retrying');
ALTER TABLE monitor_plans DROP COLUMN retry_at;
ALTER TABLE monitor_plans DROP COLUMN schedule_error;
