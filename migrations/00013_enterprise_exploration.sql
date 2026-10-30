-- +goose Up
CREATE TABLE enterprise_exploration_runs(
 id bigserial PRIMARY KEY,
 project_id bigint NOT NULL REFERENCES projects(id),
 owner integer NOT NULL,
 company text NOT NULL CHECK(length(company) BETWEEN 1 AND 200),
 source text NOT NULL CHECK(source IN ('manual','enscan','commercial')),
 status text NOT NULL CHECK(status IN ('complete','partial','auth_expired','rate_limited','unavailable','budget_exhausted','cancelled','failed')),
 error_code text NOT NULL DEFAULT '',
 complete boolean NOT NULL DEFAULT false,
 absence_usable boolean NOT NULL DEFAULT false,
 result_count integer CHECK(result_count>=0),
 max_depth integer NOT NULL CHECK(max_depth BETWEEN 0 AND 5),
 max_companies integer NOT NULL CHECK(max_companies BETWEEN 1 AND 500),
 max_candidates integer NOT NULL CHECK(max_candidates BETWEEN 1 AND 5000),
 request_limit integer NOT NULL CHECK(request_limit BETWEEN 1 AND 1000),
 requests_used integer NOT NULL CHECK(requests_used>=0 AND requests_used<=request_limit),
 companies_seen integer NOT NULL CHECK(companies_seen>=0 AND companies_seen<=max_companies),
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK(NOT complete OR status='complete'),
 CHECK(NOT absence_usable OR (complete AND source!='manual')),
 CHECK(status IN ('complete','partial','budget_exhausted') OR result_count IS NULL),
 CHECK(NOT complete OR result_count IS NOT NULL)
);
CREATE INDEX enterprise_runs_project ON enterprise_exploration_runs(project_id,id DESC);
CREATE TABLE enterprise_candidates(
 id bigserial PRIMARY KEY,
 project_id bigint NOT NULL REFERENCES projects(id),
 domain text NOT NULL,
 company text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','confirmed','rejected')),
 attribution_score integer CHECK(attribution_score BETWEEN 0 AND 100),
 attribution_state text NOT NULL DEFAULT 'unassessed' CHECK(attribution_state IN ('unassessed','supported','conflicting')),
 evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(jsonb_typeof(evidence)='array' AND octet_length(evidence::text)<=65536),
 reviewed_by integer,
 reviewed_at timestamptz,
 imported_scope_id bigint REFERENCES scopes(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(project_id,domain,company)
);
CREATE INDEX enterprise_candidates_project ON enterprise_candidates(project_id,id DESC);
-- +goose Down
DROP TABLE enterprise_candidates;
DROP TABLE enterprise_exploration_runs;
