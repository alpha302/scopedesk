package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// Explicit opt-in, synthetic PG only, no scheduler/worker or collector is started.
func TestBrowserW05Fixture(t *testing.T) {
	if os.Getenv("W05_BROWSER_FIXTURE") != "ephemeral-ci" {
		t.Skip("manual browser fixture only")
	}
	s, _ := p0Store(t)
	server := fixture(t)
	server.data.Users[1].Role = "readonly"
	server.engine = &Engine{Store: s, Queue: &PGQueue{s}, Pipeline: &Pipeline{}}
	if err := s.saveUsers(server.data.Users); err != nil {
		t.Fatal(err)
	}
	scope := insertScope(t, s, 1)
	p0Exec(t, s, `INSERT INTO workspace_members(workspace_id,user_id,role) SELECT p.workspace_id,2,'member' FROM scopes s JOIN projects p ON p.id=s.project_id WHERE s.id=$1 ON CONFLICT DO NOTHING`, scope.ID)
	p0Exec(t, s, `INSERT INTO project_members(project_id,user_id,role) SELECT project_id,2,'viewer' FROM scopes WHERE id=$1 ON CONFLICT DO NOTHING`, scope.ID)
	run := claimedRun(t, s, scope)
	if _, err := s.WriteResults(context.Background(), run, []Observation{{Host: "api2.example.com", Alive: ptr(true)}}, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, s, run)
	p0Exec(t, s, `INSERT INTO assets(scope_id,host,category,score)VALUES($1,'contest.example.com','旧分类',77)`, scope.ID)
	listener, err := net.Listen("tcp", "127.0.0.1:28765")
	if err != nil {
		t.Fatal(err)
	}
	h := &http.Server{Handler: server, ReadHeaderTimeout: 5 * time.Second}
	defer h.Close()
	go h.Serve(listener)
	t.Log("synthetic browser fixture ready on loopback; no workers/scheduler")
	deadline := time.NewTimer(10 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			return
		case <-tick.C:
			if _, err := os.Stat("/tmp/w05-browser-stop"); err == nil {
				return
			}
		}
	}
}
