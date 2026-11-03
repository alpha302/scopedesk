-- +goose Up
ALTER TABLE assets ADD COLUMN dns_observation jsonb;
ALTER TABLE assets ADD CONSTRAINT assets_dns_observation_bounded CHECK
 (dns_observation IS NULL OR (jsonb_typeof(dns_observation)='object' AND octet_length(dns_observation::text)<=32768));
-- Historical DNS/HTTP facts stay unchanged; lack of evidence remains NULL.
-- +goose Down
ALTER TABLE assets DROP CONSTRAINT assets_dns_observation_bounded;
ALTER TABLE assets DROP COLUMN dns_observation;
