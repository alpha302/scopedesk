package main

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

type AssetDoc struct {
	SecurityDeviceOverride *bool `json:"security_device_override"`
	ID                     int64 `json:"id"`
	ScopeID                int64 `json:"scope_id"`
	Observation
	Category string     `json:"category"`
	Score    int        `json:"score"`
	Status   string     `json:"status"`
	Tags     []string   `json:"tags"`
	Note     string     `json:"note"`
	Assignee string     `json:"assignee"`
	Miss     int        `json:"miss_count"`
	First    time.Time  `json:"first_seen"`
	Last     time.Time  `json:"last_seen"`
	DNSAt    *time.Time `json:"dns_at"`
	RunID    int64      `json:"observed_run"`
}
type ResultWriter interface {
	WriteResults(context.Context, Run, []Observation, bool) (map[string]any, error)
}

func (s *Store) WriteResults(ctx context.Context, run Run, observations []Observation, complete bool) (map[string]any, error) {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	var allowed bool
	var cancelled bool
	if e = tx.QueryRow(ctx, "SELECT status='running' AND worker_id=$2 AND lease_until>now(),cancel_requested FROM jobs WHERE id=$1 FOR UPDATE", run.ID, run.Worker).Scan(&allowed, &cancelled); e != nil {
		if !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}
		return nil, executionFailure("lease_lost", "任务取消或租约不再属于当前 worker", false)
	}
	if cancelled {
		return nil, executionFailure("cancelled", "用户取消了任务", false)
	}
	if !allowed {
		return nil, executionFailure("lease_lost", "任务已取消或租约不再属于当前 worker", false)
	}
	if _, e = tx.Exec(ctx, "SELECT id FROM scopes WHERE id=$1 FOR SHARE", run.ScopeID); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, "LOCK TABLE global_blacklist IN SHARE MODE"); e != nil {
		return nil, e
	}
	guard, e := readScopeGuard(ctx, tx, run.ScopeID)
	if e != nil {
		return nil, e
	}
	if e = guard.Valid(); e != nil {
		return nil, executionFailure("scope_denied", e.Error(), false)
	}
	sourceNew := map[string]int{}
	summary := map[string]any{"new": 0, "updated": 0, "down": 0, "back": 0, "ip_changed": 0, "source_new_counts": sourceNew, "absence_eligible": false, "coverage_complete": false, "absence_reason": "被动索引和分页完成不证明实时覆盖；本轮仅保留发现证据，不判定被动缺失或站点下线"}
	freshCount := 0
	seen := []int64{}
	for _, ob := range groupObservations(observations) {
		if _, e = guard.AllowHost(ob.Host); e != nil {
			continue
		}
		var raw []byte
		var old AssetDoc
		exists := true
		e = tx.QueryRow(ctx, "SELECT to_jsonb(a) FROM assets a WHERE scope_id=$1 AND host=$2 FOR UPDATE", run.ScopeID, ob.Host).Scan(&raw)
		if errors.Is(e, pgx.ErrNoRows) {
			exists = false
		} else if e != nil {
			return nil, e
		}
		if exists {
			if e = json.Unmarshal(raw, &old); e != nil {
				return nil, e
			}
		}
		projectService(&ob, old.Observation)
		current := old
		current.ScopeID = run.ScopeID
		current.Host = ob.Host
		current.RunID = run.ID
		current.Last = time.Now().UTC()
		if !exists {
			current.First = current.Last
			current.Status = "new"
			current.Tags = []string{}
			current.Category, current.Score = categoryScore(ob.Host, ob.Alive != nil && *ob.Alive)
			current.IPs = []string{}
			current.CNames = []string{}
			current.Sources = []string{}
			current.Fingerprints = []string{}
			current.Redirects = []string{}
			current.SecurityMatches = []SecurityMatch{}
		}
		if current.FingerprintEvidence == nil {
			current.FingerprintEvidence = json.RawMessage("[]")
		}
		if current.NetworkEvidence == nil {
			current.NetworkEvidence = []NetworkEvidence{}
		}
		current.Sources = append(current.Sources, ob.Sources...)
		slices.Sort(current.Sources)
		current.Sources = slices.Compact(current.Sources)
		current.PluginEvidence = mergePluginEvidence(old.PluginEvidence, ob.PluginEvidence)
		if ob.DNSChecked {
			current.IPs = ob.IPs
			current.CNames = ob.CNames
			now := time.Now().UTC()
			current.DNSAt = &now
		}
		if len(ob.CNames) > 0 {
			current.CNames = ob.CNames
		}
		if !ob.EvidenceOnly {
			if ob.NetworkMeasured {
				current.IsCDN = ob.IsCDN
				current.NetworkEvidence = ob.NetworkEvidence
				classifiedAt := time.Now().UTC()
				current.NetworkClassifiedAt = &classifiedAt
			}
		}
		if ob.Alive != nil && !ob.EvidenceOnly {
			if *ob.Alive {
				current.Miss = 0
				current.Alive = ob.Alive
			} else {
				current.Miss = old.Miss + 1
				if current.Miss >= 3 {
					current.Alive = ob.Alive
				}
			}
		}
		if ob.StatusCode > 0 {
			current.Port = ob.Port
			current.StatusCode = ob.StatusCode
			current.Title = ob.Title
			current.Server = ob.Server
			current.Length = ob.Length
			current.Redirects = ob.Redirects
			current.TLSSubject = ob.TLSSubject
			current.TLSNotAfter = ob.TLSNotAfter
			current.Favicon = ob.Favicon
			current.Fingerprints = ob.Fingerprints
			if ob.FingerprintMeasured {
				current.FingerprintEvidence = ob.FingerprintEvidence
			}
			current.Security = ob.Security
			current.SecurityRule = ob.SecurityRule
			current.SecurityMatches = ob.SecurityMatches
			if current.SecurityMatches == nil {
				current.SecurityMatches = []SecurityMatch{}
			}
			if current.SecurityDeviceOverride != nil {
				current.Security = false
			}
		}
		if current.ID == 0 {
			e = tx.QueryRow(ctx, "INSERT INTO assets(scope_id,host)VALUES($1,$2)ON CONFLICT(scope_id,host)DO UPDATE SET host=excluded.host RETURNING id", run.ScopeID, current.Host).Scan(&current.ID)
			if e != nil {
				return nil, e
			}
		}
		// JSON is used only for parameter transport; all searchable fields remain indexed columns.
		if e = upsertServices(ctx, tx, current.ID, ob.Services, guard); e != nil {
			return nil, e
		}
		e = tx.QueryRow(ctx, `SELECT favicon_mmh3,favicon_sha256 FROM asset_services WHERE asset_id=$1 AND NOT evidence_only AND favicon_mmh3 IS NOT NULL AND favicon_sha256 IS NOT NULL ORDER BY (port=443) DESC,favicon_first_verified_at NULLS LAST,id LIMIT 1`, current.ID).Scan(&current.FaviconMMH3, &current.FaviconSHA256)
		if errors.Is(e, pgx.ErrNoRows) {
			current.FaviconMMH3, current.FaviconSHA256 = nil, nil
		} else if e != nil {
			return nil, e
		}
		payload, _ := json.Marshal(current)
		_, e = tx.Exec(ctx, `UPDATE assets a SET fingerprint_evidence=x.fingerprint_evidence,network_evidence=x.network_evidence,network_classified_at=x.network_classified_at,plugin_evidence=x.plugin_evidence,ips=x.ips,cnames=x.cnames,sources=x.sources,port=x.port,status_code=x.status_code,title=x.title,server=x.server,response_length=x.response_length,redirects=x.redirects,fingerprints=x.fingerprints,tls_subject=x.tls_subject,tls_not_after=x.tls_not_after,favicon_hash=x.favicon_hash,favicon_mmh3=x.favicon_mmh3,favicon_sha256=x.favicon_sha256,category=x.category,score=x.score,status=x.status,tags=x.tags,note=x.note,assignee=x.assignee,is_cdn=x.is_cdn,is_security_device=x.is_security_device,security_rule=x.security_rule,security_matches=x.security_matches,security_device_override=x.security_device_override,is_alive=x.is_alive,miss_count=x.miss_count,first_seen=x.first_seen,last_seen=x.last_seen,dns_at=x.dns_at,observed_run=x.observed_run FROM jsonb_populate_record(NULL::assets,$2::jsonb)x WHERE a.id=$1`, current.ID, payload)
		if e != nil {
			return nil, e
		}
		if e = writeDNSHistory(ctx, tx, current.ID, ob, guard); e != nil {
			return nil, e
		}
		seen = append(seen, current.ID)
		if !exists {
			freshCount++
			for _, source := range ob.Sources {
				sourceNew[source]++
			}
			if e = addEvent(ctx, tx, run.ScopeID, current.ID, run.ID, "NEW_ASSET", map[string]any{"host": current.Host, "sources": ob.Sources}); e != nil {
				return nil, e
			}
		}
		if exists && old.Miss >= 3 && current.Miss == 0 {
			summary["back"] = summary["back"].(int) + 1
			if e = addEvent(ctx, tx, run.ScopeID, current.ID, run.ID, "ASSET_BACK", map[string]any{"host": current.Host, "evidence": "实际 HTTP 探测响应恢复"}); e != nil {
				return nil, e
			}
		}
		if exists && old.Miss < 3 && current.Miss >= 3 {
			summary["down"] = summary["down"].(int) + 1
			if e = addEvent(ctx, tx, run.ScopeID, current.ID, run.ID, "ASSET_DOWN", map[string]any{"host": current.Host, "evidence": "连续 3 次 HTTP 探测未成功，不等于已确认服务关闭"}); e != nil {
				return nil, e
			}
		}
		if exists && ob.DNSChecked && !slices.Equal(old.IPs, current.IPs) {
			summary["ip_changed"] = summary["ip_changed"].(int) + 1
			if e = addEvent(ctx, tx, run.ScopeID, current.ID, run.ID, "IP_CHANGED", map[string]any{"before": old.IPs, "after": current.IPs}); e != nil {
				return nil, e
			}
		}
		if !exists || observationKey(old.Observation) != observationKey(current.Observation) {
			if _, e = tx.Exec(ctx, "INSERT INTO asset_snapshots(asset_id,scope_id,job_id,payload)VALUES($1,$2,$3,$4)", current.ID, run.ScopeID, run.ID, payload); e != nil {
				return nil, e
			}
		}
	}
	// Legacy complete reports processing completion, never authoritative absence
	// coverage. Preserve legacy mixed miss_count/is_alive; do not guess its origin.

	summary["new"] = freshCount
	summary["updated"] = len(seen) - freshCount
	if e = tx.Commit(ctx); e != nil {
		return nil, classifyCommitError(e)
	}
	return summary, nil
}
