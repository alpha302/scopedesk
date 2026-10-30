package main

import (
	"context"
	"testing"
)

func TestPostgresSchedulerLeaderAndExpiry(t *testing.T) {
	store := integrationStore(t)
	ctx := context.Background()
	scope := insertScope(t, store, 1)
	if _, err := store.DB.Exec(ctx, "INSERT INTO monitor_plans(scope_id,enabled,interval_hours,next_run_at)VALUES($1,true,6,now()-interval '1 minute')", scope.ID); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{Store: store, root: ctx, WorkerID: "fixture-node", workers: 2}
	engine.scheduleTick()
	engine.scheduleTick()
	var count int
	store.DB.QueryRow(ctx, "SELECT count(*)FROM jobs WHERE scope_id=$1", scope.ID).Scan(&count)
	if count != 1 {
		t.Fatal("scheduler duplicated or missed due task", count)
	}
	store.DB.Exec(ctx, "UPDATE scopes SET expires_at=now()-interval '1 second' WHERE id=$1", scope.ID)
	engine.scheduleTick()
	var enabled bool
	store.DB.QueryRow(ctx, "SELECT enabled FROM monitor_plans WHERE scope_id=$1", scope.ID).Scan(&enabled)
	if enabled {
		t.Fatal("expired authorization plan remains enabled")
	}
	tx, err := store.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(2700102)"); err != nil {
		t.Fatal(err)
	}
	engine.WorkerID = "nonleader-fixture-node"
	engine.scheduleTick()
	store.DB.QueryRow(ctx, "SELECT count(*)FROM workers WHERE id='nonleader-fixture-node'").Scan(&count)
	if count != 1 {
		t.Fatal("nonleader worker heartbeat missing")
	}
}
