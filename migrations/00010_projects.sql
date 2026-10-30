-- +goose Up
CREATE TABLE workspaces(id bigserial PRIMARY KEY,owner integer NOT NULL,name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100),is_default boolean NOT NULL DEFAULT false,created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX workspaces_private_owner ON workspaces(owner) WHERE is_default;
CREATE TABLE workspace_members(workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,user_id integer NOT NULL,role text NOT NULL CHECK(role IN ('admin','member','viewer')),PRIMARY KEY(workspace_id,user_id));
CREATE TABLE projects(id bigserial PRIMARY KEY,workspace_id bigint NOT NULL REFERENCES workspaces(id),owner integer NOT NULL,name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100),is_default boolean NOT NULL DEFAULT false,rules_url text NOT NULL DEFAULT '',expires_at timestamptz,allow_active boolean NOT NULL DEFAULT false,rps_limit double precision NOT NULL DEFAULT 5 CHECK(rps_limit BETWEEN 0.1 AND 5),enabled boolean NOT NULL DEFAULT true,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX projects_private_default ON projects(workspace_id) WHERE is_default;
CREATE TABLE project_members(project_id bigint NOT NULL REFERENCES projects(id) ON DELETE CASCADE,user_id integer NOT NULL,role text NOT NULL CHECK(role IN ('admin','operator','viewer')),PRIMARY KEY(project_id,user_id));
CREATE TABLE project_rate_slots(project_id bigint PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,next_at timestamptz NOT NULL);
-- +goose StatementBegin
CREATE FUNCTION ensure_private_project(who integer) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE wid bigint; pid bigint;
BEGIN
 INSERT INTO workspaces(owner,name,is_default) VALUES(who,'个人工作空间',true) ON CONFLICT(owner) WHERE is_default DO UPDATE SET owner=excluded.owner RETURNING id INTO wid;
 INSERT INTO projects(workspace_id,owner,name,is_default,allow_active) VALUES(wid,who,'默认项目',true,false) ON CONFLICT(workspace_id) WHERE is_default DO UPDATE SET owner=projects.owner RETURNING id INTO pid;
 RETURN pid;
END $$;
-- +goose StatementEnd
ALTER TABLE scopes ADD COLUMN project_id bigint REFERENCES projects(id);
UPDATE scopes SET project_id=ensure_private_project(owner);
-- Preserve existing scope active settings only for projects created by the legacy backfill.
UPDATE projects p SET allow_active=true WHERE EXISTS(SELECT 1 FROM scopes s WHERE s.project_id=p.id);
ALTER TABLE scopes ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE scopes DROP CONSTRAINT scopes_owner_domain_mode_key;
ALTER TABLE scopes ADD CONSTRAINT scopes_project_domain_mode_key UNIQUE(project_id,domain,mode);
CREATE INDEX scopes_project ON scopes(project_id,id);
-- +goose StatementBegin
CREATE FUNCTION scope_default_project() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.project_id IS NULL THEN NEW.project_id=ensure_private_project(NEW.owner); END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER scope_default_project BEFORE INSERT ON scopes FOR EACH ROW EXECUTE FUNCTION scope_default_project();
-- +goose StatementBegin
CREATE FUNCTION project_access(pid bigint,uid integer,writing boolean DEFAULT false,managing boolean DEFAULT false) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM projects p JOIN workspaces w ON w.id=p.workspace_id WHERE p.id=pid AND (
 w.owner=uid OR EXISTS(SELECT 1 FROM workspace_members wm WHERE wm.workspace_id=w.id AND wm.user_id=uid AND wm.role='admin') OR
 ((p.owner=uid OR EXISTS(SELECT 1 FROM project_members pm WHERE pm.project_id=p.id AND pm.user_id=uid AND (NOT writing OR pm.role IN ('admin','operator')) AND (NOT managing OR pm.role='admin')))
 AND EXISTS(SELECT 1 FROM workspace_members wm WHERE wm.workspace_id=w.id AND wm.user_id=uid AND (NOT writing OR wm.role!='viewer')))));
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION scope_access(sid bigint,uid integer,writing boolean DEFAULT false) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM scopes s WHERE s.id=sid AND project_access(s.project_id,uid,writing));
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION scope_access(bigint,integer,boolean);
DROP FUNCTION project_access(bigint,integer,boolean,boolean);
DROP TRIGGER scope_default_project ON scopes;
DROP FUNCTION scope_default_project();
ALTER TABLE scopes DROP CONSTRAINT scopes_project_domain_mode_key;
-- Rollback refuses cross-project duplicates instead of deleting or merging authorizations.
ALTER TABLE scopes ADD CONSTRAINT scopes_owner_domain_mode_key UNIQUE(owner,domain,mode);
ALTER TABLE scopes DROP COLUMN project_id;
DROP FUNCTION ensure_private_project(integer);
DROP TABLE project_rate_slots,project_members,projects,workspace_members,workspaces;
