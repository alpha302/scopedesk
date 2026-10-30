-- +goose Up
CREATE TABLE security_rules (
 id bigserial PRIMARY KEY,
 keyword text NOT NULL CHECK (length(btrim(keyword)) BETWEEN 1 AND 512),
 match text NOT NULL CHECK (match IN ('contains','regex')),
 fields text[] NOT NULL CHECK (cardinality(fields)>0 AND fields <@ ARRAY['title','server','tls','fingerprint']::text[] AND array_position(fields,NULL) IS NULL),
 enabled boolean NOT NULL DEFAULT true,
 builtin boolean NOT NULL DEFAULT false
);
INSERT INTO security_rules(keyword,match,fields,builtin)
SELECT keyword,'contains',ARRAY['title','server','tls'],true
FROM unnest(ARRAY['防火墙','vpn','waf','网关','路由器','摄像头','fortinet','fortigate','sangfor','pan-os','sonicwall']) keyword;
ALTER TABLE assets ADD COLUMN security_matches jsonb NOT NULL DEFAULT '[]',
 ADD COLUMN security_device_override boolean DEFAULT NULL CHECK (security_device_override IS NULL OR security_device_override=false);

-- +goose Down
ALTER TABLE assets DROP COLUMN security_device_override, DROP COLUMN security_matches;
DROP TABLE security_rules;
