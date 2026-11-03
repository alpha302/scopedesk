-- +goose Up
-- Legacy keys and evidence remain unchanged. Only a lookup index is added for
-- compatibility with already-recorded events on the same Shanghai natural day.
CREATE INDEX event_dedupes_legacy_lookup ON event_dedupes
 ((split_part(key,':',1)),(split_part(key,':',2)),(split_part(key,':',3)));

-- +goose Down
DROP INDEX event_dedupes_legacy_lookup;
