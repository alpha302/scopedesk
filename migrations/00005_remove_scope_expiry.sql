-- +goose Up
-- Preserve historical values for an explicit rollback; API fields stay compatible.
CREATE TABLE scope_expiry_archive (
 scope_id bigint PRIMARY KEY REFERENCES scopes(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL
);
INSERT INTO scope_expiry_archive(scope_id,expires_at)
 SELECT id,expires_at FROM scopes WHERE expires_at IS NOT NULL;
UPDATE scopes SET expires_at=NULL,updated_at=now() WHERE expires_at IS NOT NULL;

-- +goose Down
UPDATE scopes s SET expires_at=a.expires_at,updated_at=now()
 FROM scope_expiry_archive a WHERE s.id=a.scope_id;
DROP TABLE scope_expiry_archive;
