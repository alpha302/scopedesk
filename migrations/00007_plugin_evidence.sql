-- +goose Up
ALTER TABLE assets ADD COLUMN plugin_evidence jsonb NOT NULL DEFAULT '[]'
 CHECK (jsonb_typeof(plugin_evidence) = 'array');
ALTER TABLE asset_services ADD COLUMN evidence_only boolean NOT NULL DEFAULT false;
ALTER TABLE asset_services ADD COLUMN source text NOT NULL DEFAULT '';
ALTER TABLE plugin_runs ADD COLUMN rejected_fields jsonb NOT NULL DEFAULT '{}'
 CHECK (jsonb_typeof(rejected_fields) = 'object');
ALTER TABLE job_source_stats ADD COLUMN rejected_fields jsonb NOT NULL DEFAULT '{}'
 CHECK (jsonb_typeof(rejected_fields) = 'object');

-- +goose Down
ALTER TABLE job_source_stats DROP COLUMN rejected_fields;
ALTER TABLE plugin_runs DROP COLUMN rejected_fields;
ALTER TABLE asset_services DROP COLUMN source;
ALTER TABLE asset_services DROP COLUMN evidence_only;
ALTER TABLE assets DROP COLUMN plugin_evidence;
