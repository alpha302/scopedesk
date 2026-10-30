-- +goose Up
ALTER TABLE jobs ADD COLUMN required_labels text[] NOT NULL DEFAULT '{}';
ALTER TABLE workers ADD COLUMN labels text[] NOT NULL DEFAULT '{}', ADD COLUMN capabilities text[] NOT NULL DEFAULT '{}';
CREATE TABLE plugin_settings (
 name text PRIMARY KEY, enabled boolean NOT NULL DEFAULT false,
 params jsonb NOT NULL DEFAULT '{}', updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO plugin_settings(name,enabled)VALUES('subfinder',true);
ALTER TABLE plugin_runs ADD COLUMN error text NOT NULL DEFAULT '', ADD COLUMN output_sample jsonb NOT NULL DEFAULT '[]';
CREATE INDEX jobs_required_labels ON jobs USING gin(required_labels);
CREATE INDEX plugin_runs_job_plugin ON plugin_runs(job_id,plugin,id DESC);

-- +goose Down
DROP INDEX plugin_runs_job_plugin;
DROP INDEX jobs_required_labels;
ALTER TABLE plugin_runs DROP COLUMN output_sample, DROP COLUMN error;
DROP TABLE plugin_settings;
ALTER TABLE workers DROP COLUMN labels, DROP COLUMN capabilities;
ALTER TABLE jobs DROP COLUMN required_labels;
