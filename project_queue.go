package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Every enqueue path holds a project share lock through its job insert.
// Revocation holds the conflicting project update lock through cancellation.
func lockScopeProject(ctx context.Context, tx pgx.Tx, scopeID int64, nowait bool) (ScopeGuard, error) {
	sql := "SELECT p.id FROM projects p JOIN scopes s ON s.project_id=p.id WHERE s.id=$1 FOR SHARE OF p,s"
	if nowait {
		sql += " NOWAIT"
	}
	var id int64
	if err := tx.QueryRow(ctx, sql, scopeID).Scan(&id); err != nil {
		return ScopeGuard{}, err
	}
	g, err := readScopeGuard(ctx, tx, scopeID)
	if err != nil {
		return g, err
	}
	if err = g.Valid(); err != nil {
		return g, executionFailure("scope_denied", err.Error(), false)
	}
	return g, nil
}
func projectLockBusy(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "55P03"
}

// Only waiting jobs change. Runtime statistics are historical facts and are
// never reset or refunded: this platform has no enqueue-time quota reservation.
func cancelRevokedProjectJobs(ctx context.Context, tx pgx.Tx, id int64) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE jobs j SET status='cancelled',cancel_requested=true,error_code='project_revoked',error='项目已停用或授权到期，等待任务已撤销',retryable=false,finished_at=clock_timestamp(),lease_until=NULL
 FROM scopes s,projects p WHERE j.scope_id=s.id AND s.project_id=p.id AND p.id=$1
 AND(NOT p.enabled OR p.expires_at<=clock_timestamp()) AND j.status IN('queued','retrying')`, id)
	return tag.RowsAffected(), err
}
func (s *Store) updateProjectPolicy(ctx context.Context, id int64, p Project) (int64, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var wid int64
	if err = tx.QueryRow(ctx, "SELECT workspace_id FROM projects WHERE id=$1 FOR UPDATE", id).Scan(&wid); err != nil {
		return 0, err
	}
	if p.WorkspaceID != 0 && p.WorkspaceID != wid {
		return 0, errors.New("项目不能跨工作空间移动")
	}
	_, err = tx.Exec(ctx, "UPDATE projects SET name=$2,rules_url=$3,expires_at=$4,allow_active=$5,rps_limit=$6,enabled=$7,updated_at=clock_timestamp()WHERE id=$1", id, strings.TrimSpace(p.Name), p.RulesURL, p.Expires, p.AllowActive, p.RPSLimit, p.Enabled)
	if err != nil {
		return 0, err
	}
	n, err := cancelRevokedProjectJobs(ctx, tx, id)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return n, nil
}

// Natural expiry has no HTTP update request. Poll it proactively, including
// projects whose plans are disabled or which have no monitor plan at all.
func (s *Store) sweepRevokedProjects(ctx context.Context) (int64, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT p.id FROM projects p WHERE(NOT p.enabled OR p.expires_at<=clock_timestamp()) AND EXISTS(SELECT 1 FROM scopes s JOIN jobs j ON j.scope_id=s.id WHERE s.project_id=p.id AND j.status IN('queued','retrying')) ORDER BY p.id FOR UPDATE OF p SKIP LOCKED`)
	if err != nil {
		return 0, err
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, id := range ids {
		n, err := cancelRevokedProjectJobs(ctx, tx, id)
		if err != nil {
			return 0, err
		}
		total += n
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return total, nil
}

func lockClaimProject(ctx context.Context, tx pgx.Tx, id int64, leaseRecovery bool) error {
	var enabled bool
	var expires *time.Time
	err := tx.QueryRow(ctx, "SELECT enabled,expires_at FROM projects WHERE id=$1 FOR SHARE NOWAIT", id).Scan(&enabled, &expires)
	if projectLockBusy(err) {
		return pgx.ErrNoRows
	}
	if err != nil {
		return err
	}
	if !leaseRecovery && (!enabled || (expires != nil && !time.Now().Before(*expires))) {
		return pgx.ErrNoRows
	}
	return nil
}
