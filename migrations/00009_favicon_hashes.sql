-- +goose Up
ALTER TABLE assets ADD COLUMN favicon_mmh3 integer;
ALTER TABLE assets ADD COLUMN favicon_sha256 text;
ALTER TABLE asset_services ADD COLUMN favicon_legacy_sha256 text;
ALTER TABLE asset_services ADD COLUMN favicon_legacy_mmh3 integer;
ALTER TABLE asset_services ADD COLUMN favicon_first_verified_at timestamptz;
UPDATE asset_services SET favicon_legacy_sha256=NULLIF(favicon_sha256,''),favicon_legacy_mmh3=favicon_mmh3;
ALTER TABLE asset_services ALTER COLUMN favicon_sha256 DROP NOT NULL;
ALTER TABLE asset_services ALTER COLUMN favicon_sha256 DROP DEFAULT;
UPDATE asset_services SET favicon_sha256=NULL,favicon_mmh3=NULL;
CREATE INDEX asset_services_favicon_mmh3 ON asset_services(favicon_mmh3,asset_id) WHERE favicon_mmh3 IS NOT NULL AND NOT evidence_only;
CREATE INDEX asset_services_favicon_sha256 ON asset_services(favicon_sha256,asset_id) WHERE favicon_sha256 IS NOT NULL AND NOT evidence_only;

-- +goose Down
DROP INDEX asset_services_favicon_sha256;
DROP INDEX asset_services_favicon_mmh3;
UPDATE asset_services SET favicon_sha256=coalesce(favicon_sha256,favicon_legacy_sha256,''),favicon_mmh3=coalesce(favicon_mmh3,favicon_legacy_mmh3);
ALTER TABLE asset_services ALTER COLUMN favicon_sha256 SET DEFAULT '';
ALTER TABLE asset_services ALTER COLUMN favicon_sha256 SET NOT NULL;
ALTER TABLE asset_services DROP COLUMN favicon_legacy_mmh3;
ALTER TABLE asset_services DROP COLUMN favicon_first_verified_at;
ALTER TABLE asset_services DROP COLUMN favicon_legacy_sha256;
ALTER TABLE assets DROP COLUMN favicon_sha256;
ALTER TABLE assets DROP COLUMN favicon_mmh3;
