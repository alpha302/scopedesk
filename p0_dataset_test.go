package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Dataset hashes exclude explicitly listed wall-clock bookkeeping fields only.
// Each query has stable row ordering; no production data is imported.
func p0DatasetHashes(t *testing.T, s *Store) map[string]string {
	t.Helper()
	queries := map[string]string{
		"assets":       `SELECT to_jsonb(a) FROM assets a ORDER BY id`,
		"services":     `SELECT to_jsonb(a)-'first_seen'-'last_seen' FROM asset_services a ORDER BY id`,
		"scopes":       `SELECT to_jsonb(a)-'created_at'-'updated_at' FROM scopes a ORDER BY id`,
		"projects":     `SELECT to_jsonb(a)-'created_at'-'updated_at' FROM projects a ORDER BY id`,
		"candidates":   `SELECT to_jsonb(a)-'first_seen'-'last_seen' FROM candidates a ORDER BY id`,
		"jobs":         `SELECT to_jsonb(a)-'available_at' FROM jobs a ORDER BY id`,
		"source_stats": `SELECT to_jsonb(a) FROM job_source_stats a ORDER BY job_id,source`,
		"events":       `SELECT to_jsonb(a) FROM asset_events a ORDER BY id`,
		"snapshots":    `SELECT to_jsonb(a) FROM asset_snapshots a ORDER BY id`,
	}
	out := map[string]string{}
	for name, query := range queries {
		rows, err := s.DB.Query(context.Background(), query)
		if err != nil {
			t.Fatal("dataset fingerprint query failed")
		}
		hash := sha256.New()
		for rows.Next() {
			var raw json.RawMessage
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				t.Fatal("dataset fingerprint read failed")
			}
			hash.Write(raw)
			hash.Write([]byte{'\n'})
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal("dataset fingerprint iteration failed")
		}
		out[name] = hex.EncodeToString(hash.Sum(nil))
	}
	return out
}

func TestP0DatasetV1(t *testing.T) {
	for _, n := range []int{1000, 10000} {
		for _, skew := range []bool{false, true} {
			name := fmt.Sprintf("n%d-skew%t", n, skew)
			var first map[string]string
			for round := 1; round <= 3; round++ {
				t.Run(fmt.Sprintf("%s-round%d", name, round), func(t *testing.T) {
					s, _ := p0Store(t)
					p0Seed(t, s, n, skew)
					var dual, multi, title, wide, unprofiled, cdn, largest, events, snapshots, jobs int
					err := s.DB.QueryRow(context.Background(), `SELECT
 count(*)FILTER(WHERE '2001:db8::1'=ANY(ips)),
 count(*)FILTER(WHERE cardinality(ips)>1),count(*)FILTER(WHERE length(title)>100),
 count(*)FILTER(WHERE plugin_evidence<>'[]'::jsonb),count(*)FILTER(WHERE dns_at IS NULL),
 count(*)FILTER(WHERE is_cdn),
 (SELECT max(n)FROM(SELECT count(*)n FROM assets GROUP BY scope_id)x),
 (SELECT count(*)FROM asset_events),(SELECT count(*)FROM asset_snapshots),(SELECT count(*)FROM jobs) FROM assets`).Scan(&dual, &multi, &title, &wide, &unprofiled, &cdn, &largest, &events, &snapshots, &jobs)
					wantLargest := n / 20
					if skew {
						wantLargest = n * 9 / 10
					}
					if err != nil || dual != n/20 || multi != n/5 || title != n/10 || wide != n/100 || unprofiled != n/4 || cdn != n/5 || largest != wantLargest || events != n || snapshots != n || jobs != 600 {
						t.Fatal("synthetic distribution differs from fixture v1 contract")
					}
					hashes := p0DatasetHashes(t, s)
					if first == nil {
						first = hashes
					} else {
						for table, digest := range first {
							if hashes[table] != digest {
								t.Fatalf("dataset is not reproducible: %s", table)
							}
						}
					}
					p0Write(t, fmt.Sprintf("dataset-%s-round%d", name, round), map[string]any{"fixture_version": 1, "assets": n, "services": 2 * n, "projects": 4, "scopes": 20, "candidates": n, "history_days": 30, "jobs": jobs, "events": events, "snapshots": snapshots, "dual_stack": dual, "multiple_ip_including_dual": multi, "long_title": title, "wide_evidence": wide, "never_profiled": unprofiled, "cdn_marked": cdn, "largest_scope": largest, "sha256": hashes, "synthetic": true, "timings_or_performance_claims": false})
					t.Logf("PASS fixture v1: assets=%d services=%d skew90=%t round=%d; 9 table fingerprints match", n, 2*n, skew, round)
				})
			}
		}
	}
}

func TestP0PositiveDNSHTTPFixture(t *testing.T) {
	for round := 1; round <= 3; round++ {
		t.Run(fmt.Sprintf("round%d", round), func(t *testing.T) {
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal("DNS fixture unavailable")
			}
			defer conn.Close()
			go func() {
				buf := make([]byte, 4096)
				for {
					n, addr, err := conn.ReadFrom(buf)
					if err != nil {
						return
					}
					var q dnsmessage.Message
					if q.Unpack(buf[:n]) != nil {
						continue
					}
					res := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: q.Questions}
					for _, question := range q.Questions {
						h := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}
						switch question.Type {
						case dnsmessage.TypeA:
							res.Answers = append(res.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}})
						case dnsmessage.TypeAAAA:
							res.Answers = append(res.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}}})
						}
					}
					raw, err := res.Pack()
					if err == nil {
						conn.WriteTo(raw, addr)
					}
				}
			}()
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ips, err := resolver.LookupIPAddr(ctx, "h1.s1.example.test.")
			if err != nil || len(ips) != 2 {
				t.Fatal("positive dual-stack DNS fixture failed")
			}
			seen := map[string]bool{}
			for _, ip := range ips {
				seen[ip.IP.String()] = true
			}
			if !seen["192.0.2.1"] || !seen["2001:db8::1"] {
				t.Fatal("DNS fixture data changed")
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					io.WriteString(w, `<title>P0 synthetic</title><link rel="icon" href="/favicon.ico">`)
				case "/redirect":
					http.Redirect(w, r, "/", http.StatusFound)
				case "/favicon.ico":
					w.Header().Set("Content-Type", "image/png")
					w.Write(faviconPNG())
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			// Use the server's loopback URL, never the documentation addresses
			// returned by DNS. This is fixture readiness, not production dial testing.
			client := server.Client()
			client.Timeout = 5 * time.Second
			for _, path := range []string{"/", "/redirect", "/favicon.ico"} {
				resp, err := client.Get(server.URL + path)
				if err != nil {
					t.Fatal("HTTP fixture unavailable")
				}
				raw, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if readErr != nil || resp.StatusCode != 200 {
					t.Fatal("HTTP fixture response failed")
				}
				if path == "/favicon.ico" {
					if !validFavicon(raw) {
						t.Fatal("invalid fixture favicon")
					}
				} else if !strings.Contains(string(raw), "P0 synthetic") {
					t.Fatal("HTTP fixture content changed")
				}
			}
			t.Log("PASS controlled fixtures: dual-stack DNS, HTTP 200, same-origin redirect, favicon; loopback only; no product dial or performance claim")
		})
	}
}
