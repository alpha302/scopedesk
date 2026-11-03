package main

import (
	"context"
	"testing"
)

func TestW05NewAssetsAndLegacyClassification(t *testing.T) {
	s, _ := p0Store(t)
	ctx := context.Background()
	scope := insertScope(t, s, 1)
	p0Exec(t, s, `INSERT INTO assets(scope_id,host,category,score)VALUES($1,'test.example.com','人工分类',77),($1,'legacy.example.com','API',30)`, scope.ID)
	run := claimedRun(t, s, scope)
	obs := []Observation{}
	for _, host := range []string{"contest.example.com", "capital.example.com", "api2.example.com", "test.example.com", "legacy.example.com"} {
		obs = append(obs, Observation{Host: host, Sources: []string{"fixture"}})
	}
	if _, err := s.WriteResults(ctx, run, obs, false); err != nil {
		t.Fatal(err)
	}
	closeRun(t, s, run)
	for host, want := range map[string]struct {
		category string
		score    int
	}{
		"contest.example.com": {"未分类", 10}, "capital.example.com": {"未分类", 10},
		"api2.example.com": {"API", 30}, "test.example.com": {"人工分类", 77}, "legacy.example.com": {"API", 30},
	} {
		var category string
		var score int
		if err := s.DB.QueryRow(ctx, `SELECT category,score FROM assets WHERE scope_id=$1 AND host=$2`, scope.ID, host).Scan(&category, &score); err != nil {
			t.Fatal(err)
		}
		if category != want.category || score != want.score {
			t.Fatalf("%s: got %s/%d want %s/%d", host, category, score, want.category, want.score)
		}
	}
}

func TestW05CategoryBoundaries(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"contest.example.com", "未分类"}, {"capital.example.com", "未分类"},
		{"api.com", "未分类"}, {"www.test.com", "未分类"},
		{"API.Example.COM.", "API"}, {"api2.example.com", "API"},
		{"2api.example.com", "未分类"}, {"api-v2.example.com", "API"},
		{"my-api.example.com", "API"}, {"myapi.example.com", "未分类"},
		{"devops.example.com", "未分类"}, {"test123.example.com", "开发测试"},
		{"api.sso.example.co.uk", "API"}, {"sso.example.com", "认证 SSO"},
		{"admin.example.com", "支撑平台"}, {"uat.example.com", "开发测试"},
		{"api.例子.公司.cn", "API"}, {"127.0.0.1", "未分类"},
		{"bad..api.com", "未分类"}, {"xn--api-test.example.com", "未分类"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			for _, active := range []bool{false, true} {
				got, score := categoryScore(tc.host, active)
				wantScore := 10
				if tc.want != "未分类" {
					wantScore += 20
				}
				if active {
					wantScore += 10
				}
				if got != tc.want || score != wantScore {
					t.Fatalf("got %s/%d want %s/%d", got, score, tc.want, wantScore)
				}
			}
		})
	}
}

func TestW05ScopeRoot(t *testing.T) {
	for _, tc := range []struct{ host, root, want string }{
		{"admin.example.com", "admin.example.com", "未分类"},
		{"www.admin.example.com", "ADMIN.EXAMPLE.COM.", "未分类"},
		{"api.admin.example.com", "admin.example.com", "API"},
		{"api.example.com", "other.example.com", "API"},
		{"api.example.com", "ample.com", "API"},
		{"foo.api.github.io", "api.github.io", "未分类"},
	} {
		got, _ := categoryScore(tc.host, false, tc.root)
		if got != tc.want {
			t.Errorf("%s root %s: got %s want %s", tc.host, tc.root, got, tc.want)
		}
	}
}
