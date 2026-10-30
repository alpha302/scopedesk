package main

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

type ProjectPolicy struct {
	Enabled     bool       `json:"enabled"`
	AllowActive bool       `json:"allow_active"`
	Expires     *time.Time `json:"expires_at"`
	RPSLimit    float64    `json:"rps_limit"`
}
type Project struct {
	ID          int64  `json:"id"`
	WorkspaceID int64  `json:"workspace_id"`
	Owner       int    `json:"owner"`
	Name        string `json:"name"`
	RulesURL    string `json:"rules_url"`
	ProjectPolicy
}

func projectFilter(q ...urlQuery) int64 {
	if len(q) == 0 || q[0] == nil || q[0].Get("project_id") == "" {
		return 0
	}
	n, err := strconv.ParseInt(q[0].Get("project_id"), 10, 64)
	if err != nil || n < 1 {
		return -1
	}
	return n
}
func validateProject(p Project) error {
	if strings.TrimSpace(p.Name) == "" || utf8.RuneCountInString(p.Name) > 100 {
		return errors.New("项目名称须为 1–100 个字符")
	}
	if p.RPSLimit < 0.1 || p.RPSLimit > 5 {
		return errors.New("项目总速率须为 0.1–5 RPS")
	}
	if p.RulesURL != "" {
		u, err := url.Parse(p.RulesURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || len(p.RulesURL) > 2000 {
			return errors.New("规则链接须为不带凭据的 HTTP(S) URL")
		}
	}
	return nil
}
func (s *Store) projectPermission(ctx context.Context, id int64, u User, write, manage bool) error {
	var ok bool
	err := s.DB.QueryRow(ctx, "SELECT ($1='admin' OR project_access($2,$3,$4,$5)) AND EXISTS(SELECT 1 FROM projects WHERE id=$2)", u.Role, id, u.ID, write, manage).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return pgx.ErrNoRows
	}
	return nil
}
func (s *Store) workspacePermission(ctx context.Context, id int64, u User, manage bool) error {
	var ok bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM workspaces w WHERE w.id=$1 AND ($2='admin' OR w.owner=$3 OR EXISTS(SELECT 1 FROM workspace_members wm WHERE wm.workspace_id=w.id AND wm.user_id=$3 AND (NOT $4 OR wm.role='admin'))))`, id, u.Role, u.ID, manage).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return pgx.ErrNoRows
	}
	return nil
}

// This also bounds declared external-tool rate arguments; their internal calls
// remain outside the platform's exact per-request accounting.
func (s ScopeV2) executionRPS() float64 {
	if s.ProjectPolicy != nil {
		return min(s.RPS, s.ProjectPolicy.RPSLimit)
	}
	return s.RPS
}
