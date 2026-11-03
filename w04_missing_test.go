package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestW04PassiveAbsenceNeverChangesLiveState(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	for _, source := range []string{"manual", "hunter", "certspotter", "crtsh"} {
		p0Exec(t, s, `INSERT INTO assets(scope_id,host,sources,is_alive,miss_count)VALUES($1,$2,$3,true,2)`, scope.ID, source+".example.com", []string{source})
	}
	for range 3 {
		run := claimedRun(t, s, scope)
		if _, err := s.WriteResults(ctx, run, nil, true); err != nil {
			t.Fatal("fixture write failed")
		}
		closeRun(t, s, run)
	}
	var affected, events int
	if err := s.DB.QueryRow(ctx, `SELECT count(*)FROM assets WHERE miss_count<>2 OR is_alive IS DISTINCT FROM true`).Scan(&affected); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, `SELECT count(*)FROM asset_events WHERE type IN('ASSET_DOWN','ASSET_BACK')`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if affected != 0 || events != 0 {
		t.Fatal("W04: passive index absence changes live state or emits live-state events")
	}
}

func TestW04PassiveDiscoveryCannotResetHTTPFailures(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		s, _ := p0Store(t)
		ctx := context.Background()
		scope := insertScope(t, s, 1)
		p0Exec(t, s, `INSERT INTO assets(scope_id,host,sources,is_alive,miss_count)VALUES($1,'api.example.com',ARRAY['manual'],false,3)`, scope.ID)
		ob := Observation{Host: "api.example.com", Sources: []string{"certspotter"}, DNSChecked: unknown, IPs: []string{}, CNames: []string{}}
		run := claimedRun(t, s, scope)
		if _, err := s.WriteResults(ctx, run, []Observation{ob}, false); err != nil {
			t.Fatal("fixture write failed")
		}
		closeRun(t, s, run)
		var miss, events int
		var alive *bool
		if err := s.DB.QueryRow(ctx, `SELECT miss_count,is_alive FROM assets WHERE host='api.example.com'`).Scan(&miss, &alive); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow(ctx, `SELECT count(*)FROM asset_events WHERE type='ASSET_BACK'`).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if miss != 3 || alive == nil || *alive || events != 0 {
			t.Fatal("W04: discovery/unknown DNS resets HTTP failure evidence")
		}
	}
}

func TestW04CertificatePaginationIsNotCoverage(t *testing.T) {
	c := &CertificateCollector{Source: "certspotter", Budget: &Budget{Limit: 10}, Client: &http.Client{Transport: policyTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("[]"))}, nil
	})}}
	r := c.CollectPassive(context.Background(), sampleScope())
	if !r.Complete {
		t.Fatal("terminal pagination completion lost")
	}
	if r.AbsenceUsable {
		t.Fatal("W04: pagination completion grants unproven absence coverage")
	}
}

func TestW04ActualHTTPFailureAndRecoveryRemain(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	p0Exec(t, s, `INSERT INTO assets(scope_id,host,sources,is_alive)VALUES($1,'api.example.com',ARRAY['manual'],true)`, scope.ID)
	for i := 1; i <= 3; i++ {
		run := claimedRun(t, s, scope)
		summary, err := s.WriteResults(ctx, run, []Observation{{Host: "api.example.com", Alive: ptr(false)}}, false)
		if err != nil {
			t.Fatal(err)
		}
		closeRun(t, s, run)
		if summary["absence_eligible"] != false || summary["coverage_complete"] != false || summary["absence_reason"] == "" {
			t.Fatal("missing explicit absence explanation")
		}
		var miss int
		if err = s.DB.QueryRow(ctx, `SELECT miss_count FROM assets WHERE host='api.example.com'`).Scan(&miss); err != nil || miss != i {
			t.Fatal("actual HTTP failure counter changed")
		}
	}
	run := claimedRun(t, s, scope)
	if _, err := s.WriteResults(ctx, run, []Observation{{Host: "api.example.com", Alive: ptr(true), EvidenceOnly: true}}, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, s, run)
	var miss int
	if err := s.DB.QueryRow(ctx, `SELECT miss_count FROM assets WHERE host='api.example.com'`).Scan(&miss); err != nil || miss != 3 {
		t.Fatal("third-party evidence reset actual failure")
	}
	run = claimedRun(t, s, scope)
	summary, err := s.WriteResults(ctx, run, []Observation{{Host: "api.example.com", Alive: ptr(true)}}, false)
	if err != nil || summary["back"] != 1 {
		t.Fatal("actual recovery suppressed")
	}
	closeRun(t, s, run)
	var down, back int
	if err = s.DB.QueryRow(ctx, `SELECT count(*)FILTER(WHERE type='ASSET_DOWN'),count(*)FILTER(WHERE type='ASSET_BACK')FROM asset_events`).Scan(&down, &back); err != nil || down != 1 || back != 1 {
		t.Fatal("actual HTTP transitions changed")
	}
}
