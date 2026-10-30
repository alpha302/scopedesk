package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/robfig/cron/v3"
)

type Run struct {
	CollectionMode          string         `json:"collection_mode"`
	ExecutionTimeoutSeconds int            `json:"execution_timeout_seconds"`
	DeadlineAt              *time.Time     `json:"deadline_at"`
	Trigger                 string         `json:"trigger"`
	PluginStrategy          string         `json:"plugin_strategy"`
	Target                  string         `json:"target,omitempty"`
	Params                  map[string]any `json:"params,omitempty"`
	RequiredLabels          []string       `json:"required_labels"`
	ID                      int64          `json:"id"`
	ScopeID                 int64          `json:"scope_id"`
	Owner                   int            `json:"owner"`
	Sources                 []string       `json:"sources"`
	Worker                  string         `json:"worker_id"`
	Attempts                int            `json:"attempts"`
}
type SourceStats struct {
	Complete       bool           `json:"complete"`
	AbsenceUsable  bool           `json:"absence_usable"`
	ErrorCode      string         `json:"error_code"`
	Retryable      bool           `json:"retryable"`
	RejectedFields map[string]int `json:"rejected_fields"`
	Source         string         `json:"source"`
	Returned       int            `json:"returned"`
	InScope        int            `json:"in_scope"`
	Discarded      int            `json:"discarded"`
	New            int            `json:"new_count"`
	Attempts       int            `json:"attempts"`
	Error          string         `json:"error"`
}
type Queue interface {
	Enqueue(context.Context, ScopeV2, []string, string) (int64, error)
	Claim(context.Context, string) (Run, error)
	Heartbeat(context.Context, Run) (bool, error)
}
type PGQueue struct{ Store *Store }

func (q *PGQueue) Enqueue(ctx context.Context, s ScopeV2, sources []string, trigger string) (int64, error) {
	return q.EnqueueStrategy(ctx, s, sources, trigger, "all")
}
func (q *PGQueue) EnqueueStrategy(ctx context.Context, s ScopeV2, sources []string, trigger, strategy string) (int64, error) {
	return q.EnqueuePassiveMode(ctx, s, sources, trigger, strategy, "profile")
}
func (q *PGQueue) EnqueuePassiveMode(ctx context.Context, s ScopeV2, sources []string, trigger, strategy, mode string) (int64, error) {
	var modeErr error
	mode, modeErr = validateCollectionMode(mode, sources)
	if modeErr != nil {
		return 0, modeErr
	}

	fresh, err := q.Store.scopesByID(ctx, s.ID)
	if err != nil {
		return 0, err
	}
	s = fresh
	if !slices.Contains([]string{"all", "first_success", "fallback"}, strategy) {
		return 0, errors.New("插件合并策略无效")
	}
	if e := (ScopeGuard{Scope: s}).Valid(); e != nil {
		return 0, e
	}
	raw, _ := json.Marshal(map[string]any{"sources": sources, "plugin_strategy": strategy, "collection_mode": mode})
	labels, err := q.Store.requiredPluginLabels(ctx, sources)
	if err != nil {
		return 0, err
	}
	budget, err := jobExecutionBudget(sources, trigger, q.Store.Plugins)
	if err != nil {
		return 0, err
	}
	tx, err := q.Store.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	guard, err := lockScopeProject(ctx, tx, s.ID, false)
	if err != nil {
		return 0, err
	}
	s = guard.Scope
	var id int64
	e := tx.QueryRow(ctx, "INSERT INTO jobs(scope_id,owner,trigger,payload,required_labels,execution_timeout_seconds)VALUES($1,$2,$3,$4,$5,$6) RETURNING id", s.ID, s.Owner, trigger, raw, labels, int((budget+time.Second-1)/time.Second)).Scan(&id)
	if e != nil {
		return 0, errors.New("该范围已有未结束任务，或队列写入失败")
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return id, nil
}
func (q *PGQueue) Claim(ctx context.Context, worker string) (Run, error) {
	return q.ClaimWithLabels(ctx, worker, []string{})
}
func (q *PGQueue) ClaimWithLabels(ctx context.Context, worker string, labels []string) (Run, error) {
	if labels == nil {
		labels = []string{}
	}
	var r Run
	var raw []byte
	tx, e := q.Store.DB.Begin(ctx)
	if e != nil {
		return r, e
	}
	defer tx.Rollback(ctx)
	var jobID, projectID int64
	var leaseRecovery bool
	e = tx.QueryRow(ctx, `SELECT j.id,s.project_id,(j.status='running') FROM jobs j JOIN scopes s ON s.id=j.scope_id JOIN projects p ON p.id=s.project_id
 WHERE ((p.enabled AND(p.expires_at IS NULL OR p.expires_at>clock_timestamp())) OR (j.status='running' AND j.lease_until<now())) AND j.required_labels <@ $1::text[] AND NOT j.cancel_requested AND j.attempts<j.max_attempts AND(j.trigger<>'plugin_test' OR j.started_at IS NOT NULL OR j.created_at>now()-interval '10 minutes') AND((j.status IN('queued','retrying') AND j.available_at<=now())OR(j.status='running' AND j.lease_until<now())) ORDER BY j.id FOR UPDATE OF j SKIP LOCKED LIMIT 1`, labels).Scan(&jobID, &projectID, &leaseRecovery)
	if e != nil {
		return r, e
	}
	if e = lockClaimProject(ctx, tx, projectID, leaseRecovery); e != nil {
		return r, e
	}
	e = tx.QueryRow(ctx, `UPDATE jobs SET status='running',worker_id=$1,lease_until=now()+interval '45 seconds',heartbeat_at=now(),started_at=coalesce(started_at,now()),attempts=attempts+1 WHERE id=$2 RETURNING id,scope_id,owner,payload,attempts,trigger,required_labels,execution_timeout_seconds,deadline_at`, worker, jobID).Scan(&r.ID, &r.ScopeID, &r.Owner, &raw, &r.Attempts, &r.Trigger, &r.RequiredLabels, &r.ExecutionTimeoutSeconds, &r.DeadlineAt)
	if e != nil {
		return r, e
	}
	if e = tx.Commit(ctx); e != nil {
		return Run{}, e
	}
	var payload struct {
		CollectionMode string         `json:"collection_mode"`
		Sources        []string       `json:"sources"`
		Target         string         `json:"target"`
		PluginStrategy string         `json:"plugin_strategy"`
		Params         map[string]any `json:"params"`
	}
	if e = json.Unmarshal(raw, &payload); e != nil {
		return r, e
	}
	r.CollectionMode = payload.CollectionMode
	r.Sources = payload.Sources
	r.Target = payload.Target
	r.Params = payload.Params
	r.PluginStrategy = payload.PluginStrategy
	if r.PluginStrategy == "" {
		r.PluginStrategy = "all"
	}
	r.Worker = worker
	return r, nil
}
func (q *PGQueue) Heartbeat(ctx context.Context, r Run) (bool, error) {
	var cancelled bool
	e := q.Store.DB.QueryRow(ctx, "UPDATE jobs SET heartbeat_at=now(),lease_until=now()+interval '45 seconds' WHERE id=$1 AND worker_id=$2 AND status='running' RETURNING cancel_requested", r.ID, r.Worker).Scan(&cancelled)
	return cancelled, e
}

type Engine struct {
	PassiveHTTPClient *http.Client
	EnterpriseSources map[string]EnterpriseSource
	Labels            []string
	Capabilities      []string
	Store             *Store
	Queue             Queue
	Limiter           RateLimiter
	Pipeline          *Pipeline
	root              context.Context
	cancel            context.CancelFunc
	WorkerID          string
	workers           int
	active            sync.Map
	SendMail          func(SMTPConfig, string, string) error
}

func newEngine(ctx context.Context, dsn string) (*Engine, error) {
	if _, err := maxJobDuration(); err != nil {
		return nil, err
	}
	store, e := openStore(ctx, dsn)
	if e != nil {
		return nil, e
	}
	root, cancel := context.WithCancel(context.Background())
	host, _ := os.Hostname()
	engine := &Engine{Store: store, Queue: &PGQueue{store}, Limiter: &PGRateLimiter{store}, root: root, cancel: cancel, WorkerID: host + "-" + random()[:8], workers: 2}
	rules := &SecurityRuleCache{Load: store.securityRules}
	if _, err := rules.refresh(ctx, true); err != nil {
		cancel()
		store.DB.Close()
		return nil, err
	}
	networkRules, err := defaultNetworkRules()
	if err != nil {
		cancel()
		store.DB.Close()
		return nil, err
	}
	fingerprints, err := loadFingerprintEngine()
	if err != nil {
		cancel()
		store.DB.Close()
		return nil, err
	}
	log.Printf("passive fingerprint rules loaded: %d", len(fingerprints.Rules))
	engine.Pipeline = &Pipeline{Guard: store.guard, Limit: engine.Limiter, Rules: rules, NetworkRules: networkRules, Fingerprints: fingerprints}
	dir := os.Getenv("RECON_PLUGINS")
	if dir == "" {
		dir = "/opt/scopedesk-go/plugins"
	}
	registry, err := loadPluginRegistry(dir)
	if err != nil {
		cancel()
		store.DB.Close()
		return nil, err
	}
	if err = store.initializePlugins(ctx, registry); err != nil {
		cancel()
		store.DB.Close()
		return nil, err
	}
	engine.Labels, err = workerLabels(os.Args[1:])
	if err != nil {
		cancel()
		store.DB.Close()
		return nil, err
	}
	engine.Capabilities = actualCapabilities()
	if v, e := strconv.Atoi(os.Getenv("RECON_WORKERS")); e == nil {
		engine.workers = max(1, min(8, v))
	}
	return engine, nil
}
func (e *Engine) Start() {
	e.workerHeartbeat(e.root)
	if e.Pipeline != nil && e.Pipeline.Rules != nil {
		go e.Pipeline.Rules.run(e.root)
	}
	for i := 0; i < e.workers; i++ {
		go e.worker(e.WorkerID + "-" + strconv.Itoa(i))
	}
	go e.scheduler()
	go e.digestScheduler()
}
func (e *Engine) worker(id string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.root.Done():
			return
		case <-ticker.C:
			var run Run
			var err error
			if q, ok := e.Queue.(interface {
				ClaimWithLabels(context.Context, string, []string) (Run, error)
			}); ok {
				run, err = q.ClaimWithLabels(e.root, id, routingLabels(e.Labels, e.Capabilities))
			} else {
				run, err = e.Queue.Claim(e.root, id)
			}
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				log.Printf("queue claim failed")
				continue
			}
			e.execute(run)
		}
	}
}
func (e *Engine) execute(run Run) {
	if run.PluginStrategy == "" {
		run.PluginStrategy = "all"
	}
	deadlineCtx, cancelDeadline, startErr := e.beginExecution(&run)
	if startErr != nil {
		e.finishFailure(run, startErr, nil)
		return
	}
	defer cancelDeadline()
	ctx, cancelCause := context.WithCancelCause(deadlineCtx)
	defer cancelCause(nil)
	cancel := context.CancelFunc(func() { cancelCause(executionFailure("cancelled", "用户取消了任务", false)) })
	e.active.Store(run.ID, cancel)
	defer e.active.Delete(run.ID)
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				stop, err := e.Queue.Heartbeat(ctx, run)
				if err != nil || stop {
					if err != nil {
						cancelCause(executionFailure("lease_lost", "任务租约已失效或无法确认", false))
					} else {
						cancel()
					}
					return
				}
			}
		}
	}()
	guard, err := e.Store.guard(ctx, run.ScopeID)
	if err != nil {
		if ctx.Err() != nil {
			e.finishStopped(ctx, run, nil)
		} else {
			e.finishFailure(run, classifyExecutionError(err, "scope_check_failed"), nil)
		}
		return
	}
	if err = guard.Valid(); err != nil {
		e.finishFailure(run, executionFailure("scope_denied", err.Error(), false), nil)
		return
	}
	scope := guard.Scope
	run.CollectionMode, err = validateCollectionMode(run.CollectionMode, run.Sources)
	if err != nil {
		e.finishFailure(run, err, nil)
		return
	}
	if run.Trigger == "plugin_test" {
		e.executePluginTest(ctx, run, guard)
		return
	}
	b := &Budget{Limit: scope.RequestLimit}
	observed := map[string][]string{}
	stats := []SourceStats{}
	success := 0
	pluginResults := []PluginResult{}
	pluginObservations := []Observation{}
	failedPluginCandidates := false
	candidateCheckFailed := false
	stopPlugins := false
	pluginAttempted := false
	pluginSucceeded := false
	pluginFailed := false
	builtinFailed := false
	formatIncomplete := false
	collectionCtx, stopCollection := context.WithDeadline(ctx, run.DeadlineAt.Add(-profileBudget-commitBudget))
	defer stopCollection()
	candidateCtx := ctx
	{
		ctx := collectionCtx
		for _, source := range run.Sources {
			if ctx.Err() != nil {
				break
			}
			st := SourceStats{Source: source}
			var collector Collector
			switch source {
			case "fofa", "hunter":
				collector = &PassiveAPICollector{Client: e.PassiveHTTPClient, Source: source, Store: e.Store, Run: run, Limit: e.Limiter, Budget: b}
			case "crtsh", "certspotter":
				collector = &CertificateCollector{Source: source, Limit: e.Limiter, Budget: b, Guard: func(c context.Context) (ScopeGuard, error) { return e.Store.guard(c, run.ScopeID) }}
			default:
				if stopPlugins {
					continue
				}
				pluginAttempted = true
				m, params, enabled, configErr := e.Store.pluginConfig(ctx, source)
				if configErr != nil || !enabled {
					st.Error = "插件未注册或已停用"
					st.ErrorCode = "plugin_config"
					pluginFailed = true
					stats = append(stats, st)
					continue
				}
				required := slices.Clone(m.Requires.Labels)
				for _, cap := range m.Requires.Caps {
					required = append(required, "cap:"+cap)
				}
				if !labelsContain(routingLabels(e.Labels, e.Capabilities), required) {
					st.Error = "worker 能力不满足当前插件配置"
					st.ErrorCode = "worker_labels"
					pluginFailed = true
					stats = append(stats, st)
					continue
				}
				collector = &ManifestCollector{Plugin: ExternalPlugin{Manifest: m, Params: params, Budget: b, Store: e.Store, JobID: run.ID, QueryRoot: true, Guard: func(c context.Context) (ScopeGuard, error) { return e.Store.guard(c, run.ScopeID) }}}
			}
			var stream <-chan Candidate
			maxAttempts := sourceMaxAttempts
			if _, ok := collector.(PassiveSource); ok {
				maxAttempts = 1
			}
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				st.Attempts = attempt
				guard, err = e.Store.guard(ctx, run.ScopeID)
				if err == nil {
					if validErr := guard.Valid(); validErr != nil {
						err = executionFailure("scope_denied", validErr.Error(), false)
					}
				}
				if err != nil {
					break
				}
				sourceCtx, sourceCancel := collectorAttemptContext(ctx, collector)
				stream, err = collector.Collect(sourceCtx, guard.Scope)
				sourceCancel()
				if err == nil {
					break
				}
				failure := classifyExecutionError(err, "source_failed")
				if !failure.Retryable || attempt == maxAttempts {
					break
				}
				if err = waitForRetry(ctx, time.Duration(1<<attempt)*time.Second); err != nil {
					break
				}
			}
			if err != nil {
				failure := classifyExecutionError(err, "source_failed")
				st.Error, st.ErrorCode, st.Retryable = failure.Message, failure.Code, failure.Retryable
			} else {
				success++
			}
			st.Complete = err == nil
			st.AbsenceUsable = err == nil
			if builtinPassive(source) {
				builtinFailed = builtinFailed || err != nil
			} else {
				pluginSucceeded = pluginSucceeded || err == nil
				pluginFailed = pluginFailed || err != nil
				if err == nil && (run.PluginStrategy == "first_success" || (run.PluginStrategy == "fallback" && len(stream) > 0)) {
					stopPlugins = true
				}
			}
			if api, ok := collector.(*PassiveAPICollector); ok {
				st.Complete = api.Result.Complete
				st.AbsenceUsable = api.Result.AbsenceUsable
				for _, record := range api.Result.Records {
					if record.Observation != nil {
						pluginObservations = append(pluginObservations, *record.Observation)
					}
				}
				builtinFailed = builtinFailed || !api.Result.Complete || !api.Result.AbsenceUsable
			}
			if external, ok := collector.(*ManifestCollector); ok {
				candidates := PluginResult{}
				for _, result := range external.Results {
					// Keep hosts from every attempt, including attempts before a retry.
					candidates.Records = append(candidates.Records, result.Records...)
					pluginResults = append(pluginResults, result)
					if result.Error != "" {
						failedPluginCandidates = failedPluginCandidates || len(result.Records) > 0
						continue
					}
					for _, record := range result.Records {
						if record.Observation != nil {
							pluginObservations = append(pluginObservations, *record.Observation)
						}
					}
				}
				stream = pluginCandidates(candidates)
			}
			if stream != nil {
				counts, guardErr := consumeCandidates(candidateCtx, stream, func(c context.Context) (ScopeGuard, error) {
					return e.Store.guard(c, run.ScopeID)
				}, func(host string) {
					if !slices.Contains(observed[host], source) {
						observed[host] = append(observed[host], source)
					}
				})
				st.Returned, st.InScope, st.Discarded = counts.Returned, counts.InScope, counts.Discarded
				if guardErr != nil {
					candidateCheckFailed = true
					st.Complete = false
					st.AbsenceUsable = false
					failure := classifyExecutionError(guardErr, "scope_check_failed")
					st.Error, st.ErrorCode, st.Retryable = failure.Message, failure.Code, failure.Retryable
				}
			}
			if external, ok := collector.(*ManifestCollector); ok && len(external.Results) > 0 {
				last := external.Results[len(external.Results)-1]
				st.Returned = last.Returned
				st.InScope = last.InScope
				st.Discarded = last.Returned - last.InScope
				st.RejectedFields = last.RejectedFields
			}
			stats = append(stats, st)
			formatIncomplete = formatIncomplete || st.RejectedFields["malformed_jsonl"] > 0
			e.Store.DB.Exec(ctx, "UPDATE jobs SET progress=$3 WHERE id=$1 AND worker_id=$2", run.ID, run.Worker, min(30, len(stats)*30/max(1, len(run.Sources))))
		}
	}
	collectionTimedOut := collectionCtx.Err() != nil
	collectionIncomplete := collectionTimedOut || candidateCheckFailed
	stopCollection()
	if ctx.Err() != nil {
		e.finishStopped(ctx, run, stats)
		return
	}
	if success == 0 && len(observed) == 0 {
		failure := executionFailure("sources_failed", "全部数据源失败，未进行缺失判定", false)
		if len(stats) == 1 && stats[0].ErrorCode != "" {
			failure = executionFailure(stats[0].ErrorCode, stats[0].Error, false)
		}
		if collectionTimedOut {
			failure = executionFailure("collection_timeout", "采集阶段时限已耗尽，未进行缺失判定", false)
		}
		e.finishFailure(run, failure, stats)
		return
	}
	observations := []Observation{}
	profileCtx, stopProfile := context.WithTimeout(ctx, profileBudget)
	defer stopProfile()
	wildcard := ""
	if run.CollectionMode != "evidence_only" {
		wildcard = e.Pipeline.Wildcard(profileCtx, scope, b)
	}
	hosts := make([]string, 0, len(observed))
	for host := range observed {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	// A bounded pipeline; per-scope concurrency is an upper bound, conservative serial processing keeps request order auditable.
	discardedWildcard := 0
	discardedWildcardHosts := map[string]bool{}
	for i, host := range hosts {
		if profileCtx.Err() != nil {
			break
		}
		if run.CollectionMode == "evidence_only" {
			observations = append(observations, Observation{Host: host, Sources: observed[host], EvidenceOnly: true, PreserveReachability: true})
			continue
		}
		if b.Used >= b.Limit {
			break
		}
		e.Store.operation(ctx, run.Owner, "pipeline.observe", fmt.Sprintf("job=%d worker=%s host=%s active=%t", run.ID, run.Worker, host, scope.Active))
		o, probeErr := e.Pipeline.Probe(profileCtx, scope, host, observed[host], b)
		if probeErr != nil {
			e.Store.operation(ctx, run.Owner, "pipeline.rejected", fmt.Sprintf("job=%d host=%s reason=%s", run.ID, host, safeError(probeErr)))
			continue
		}
		o.PreserveReachability = o.Alive == nil && observerSourcesOnly(observed[host], e.Store.Plugins)
		if wildcard != "" && wildcardSignature(o.IPs) == wildcard {
			discardedWildcard++
			discardedWildcardHosts[host] = true
			continue
		}
		observations = append(observations, o)
		if i%10 == 0 {
			e.Store.DB.Exec(ctx, "UPDATE jobs SET progress=$3 WHERE id=$1 AND worker_id=$2", run.ID, run.Worker, 30+(i+1)*60/max(1, len(hosts)))
		}
	}
	if ctx.Err() != nil {
		e.finishStopped(ctx, run, stats)
		return
	}
	sourcesComplete := run.CollectionMode != "evidence_only" && !builtinFailed && (!pluginAttempted || pluginSucceeded) && (run.PluginStrategy != "all" || !pluginFailed)
	profileIncomplete := profileCtx.Err() != nil || len(observations)+discardedWildcard < len(hosts)
	// Retain authorized discoveries even when profiling cannot continue. They carry
	// no live measurements, and the writer rechecks the current authorization.
	retained := map[string]bool{}
	for _, ob := range observations {
		retained[ob.Host] = true
	}
	for _, host := range hosts {
		if !retained[host] && !discardedWildcardHosts[host] {
			observations = append(observations, Observation{Host: host, Sources: observed[host], EvidenceOnly: true, PreserveReachability: true})
		}
	}
	stopProfile()
	complete := !failedPluginCandidates && !collectionIncomplete && !profileIncomplete && !formatIncomplete && sourcesComplete && len(observations)+discardedWildcard == len(hosts)
	submitCtx, stopSubmit := context.WithTimeout(ctx, commitBudget)
	defer stopSubmit()
	for i := range pluginObservations {
		if pluginObservations[i].StatusCode > 0 {
			if err := retryStage(submitCtx, func() error { return e.Pipeline.classifySecurity(submitCtx, scope, &pluginObservations[i]) }); err != nil {
				if ctx.Err() != nil {
					e.finishStopped(ctx, run, stats)
				} else {
					e.finishFailure(run, err, stats)
				}
				return
			}
		}
	}
	observations = append(observations, pluginObservations...)
	var summary map[string]any
	err = retryStage(submitCtx, func() error {
		var writeErr error
		summary, writeErr = e.Store.WriteResults(submitCtx, run, observations, complete)
		return writeErr
	})
	if err != nil {
		if classifyExecutionError(err, "stage_failed").Code == "commit_uncertain" {
			e.finishFailure(run, err, stats)
		} else if ctx.Err() != nil {
			e.finishStopped(ctx, run, stats)
		} else {
			e.finishFailure(run, err, stats)
		}
		return
	}
	e.updatePluginNewCounts(ctx, run, pluginResults)
	if contributions, ok := summary["source_new_counts"].(map[string]int); ok {
		for i := range stats {
			stats[i].New = contributions[stats[i].Source]
		}
	}
	summary["collection_mode"] = run.CollectionMode
	summary["requests"] = b.Used
	summary["budget_limit"] = b.Limit
	summary["wildcard_filtered"] = discardedWildcard
	summary["complete"] = complete
	summary["format_incomplete"] = formatIncomplete
	summary["profile_incomplete"] = profileIncomplete
	summary["collection_incomplete"] = collectionIncomplete
	summary["sources"] = stats
	if !complete {
		summary["warning"] = "部分来源失败、存在格式错误行、预算耗尽或结果未完整处理；本次不判定连续未发现"
	}
	e.finish(run, "done", "", stats, summary)
}
func safeError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if strings.Contains(text, "postgres://") || strings.Contains(text, "password") {
		return "内部存储错误"
	}
	if len(text) > 250 {
		text = text[:250]
	}
	return text
}
func (e *Engine) saveStats(ctx context.Context, run Run, stats []SourceStats) {
	for _, s := range stats {
		e.Store.DB.Exec(ctx, `INSERT INTO job_source_stats(job_id,source,returned,in_scope,discarded,new_count,attempts,error,rejected_fields,error_code,retryable,complete,absence_usable)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)ON CONFLICT(job_id,source)DO UPDATE SET returned=excluded.returned,in_scope=excluded.in_scope,discarded=excluded.discarded,new_count=excluded.new_count,attempts=excluded.attempts,error=excluded.error,rejected_fields=excluded.rejected_fields,error_code=excluded.error_code,retryable=excluded.retryable,complete=excluded.complete,absence_usable=excluded.absence_usable`, run.ID, s.Source, s.Returned, s.InScope, s.Discarded, s.New, s.Attempts, s.Error, rejectedFieldsJSON(s.RejectedFields), s.ErrorCode, s.Retryable, s.Complete, s.AbsenceUsable)
	}
}
func (e *Engine) finish(run Run, status, message string, stats []SourceStats, summary ...map[string]any) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e.saveStats(ctx, run, stats)
	data := map[string]any{"sources": stats}
	if len(summary) > 0 {
		data = summary[0]
	}
	data["execution_timeout_seconds"] = run.ExecutionTimeoutSeconds
	data["deadline_at"] = run.DeadlineAt
	code, _ := data["error_code"].(string)
	retryable, _ := data["retryable"].(bool)
	if code == "" && status == "failed" {
		code = "job_failed"
	}
	if code == "" && status == "cancelled" {
		code = "cancelled"
	}
	data["error_code"], data["retryable"] = code, retryable
	raw, _ := json.Marshal(data)
	_ = retryStage(ctx, func() error {
		_, err := e.Store.DB.Exec(ctx, "UPDATE jobs SET status=$3,error=$4,stats=$5,progress=100,finished_at=now(),lease_until=NULL,error_code=$6,retryable=$7 WHERE id=$1 AND worker_id=$2 AND status='running'", run.ID, run.Worker, status, message, raw, code, retryable)
		return err
	})
}
func nextPlan(p Plan, now time.Time) (time.Time, error) {
	if p.Cron != "" {
		schedule, e := cron.ParseStandard("CRON_TZ=Asia/Shanghai " + p.Cron)
		if e != nil {
			return time.Time{}, e
		}
		next := schedule.Next(now)
		if next.IsZero() {
			return next, errors.New("cron 没有未来执行时间")
		}
		if schedule.Next(next).Sub(next) < 5*time.Minute {
			return next, errors.New("监控计划最小间隔 5 分钟")
		}
		return next, nil
	}
	if p.Interval != 6 && p.Interval != 12 && p.Interval != 24 {
		return time.Time{}, errors.New("固定周期仅支持 6/12/24 小时")
	}
	return now.Add(time.Duration(p.Interval) * time.Hour), nil
}
func (e *Engine) scheduler() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-e.root.Done():
			return
		case <-tick.C:
			e.scheduleTick()
		}
	}
}
func (e *Engine) scheduleTick() {
	ctx, cancel := context.WithTimeout(e.root, 8*time.Second)
	defer cancel()
	e.workerHeartbeat(ctx)
	if _, err := e.Store.sweepRevokedProjects(ctx); err != nil {
		return
	}
	tx, err := e.Store.DB.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	var leader bool
	if tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(2700102)").Scan(&leader) != nil || !leader {
		return
	}
	tx.Exec(ctx, "UPDATE monitor_plans p SET enabled=false FROM scopes s WHERE p.scope_id=s.id AND s.expires_at<=now()")
	tx.Exec(ctx, "UPDATE jobs SET status='cancelled',finished_at=now(),error='取消或租约重试次数耗尽',error_code=CASE WHEN cancel_requested THEN 'cancelled' ELSE 'lease_exhausted' END,retryable=false WHERE (cancel_requested AND status IN('queued','retrying')) OR(status='running' AND lease_until<now() AND attempts>=max_attempts)")
	if _, err = tx.Exec(ctx, "UPDATE jobs SET status='cancelled',finished_at=now(),error='插件测试排队超过 10 分钟，已自动取消',error_code='queue_timeout',retryable=false WHERE trigger='plugin_test' AND status IN('queued','retrying') AND started_at IS NULL AND created_at<=now()-interval '10 minutes'"); err != nil {
		return
	}
	rows, err := tx.Query(ctx, "SELECT p.scope_id,p.interval_hours,p.cron,p.collectors,p.collection_mode FROM monitor_plans p JOIN scopes s ON s.id=p.scope_id WHERE p.enabled AND p.next_run_at<=now() AND (p.retry_at IS NULL OR p.retry_at<=now()) AND s.confirmed AND (s.expires_at IS NULL OR s.expires_at>now()) FOR UPDATE OF p SKIP LOCKED")
	if err != nil {
		return
	}
	type due struct {
		id int64
		p  Plan
	}
	list := []due{}
	for rows.Next() {
		var d due
		var raw []byte
		if rows.Scan(&d.id, &d.p.Interval, &d.p.Cron, &raw, &d.p.CollectionMode) != nil {
			rows.Close()
			return
		}
		json.Unmarshal(raw, &d.p.Collectors)
		list = append(list, d)
	}
	rows.Close()
	for _, d := range list {
		guard, guardErr := lockScopeProject(ctx, tx, d.id, true)
		if guardErr == nil {
			guardErr = guard.Valid()
		}
		if guardErr != nil {
			if _, err := tx.Exec(ctx, "UPDATE monitor_plans SET schedule_error=$2,retry_at=now()+interval '5 minutes' WHERE scope_id=$1", d.id, guardErr.Error()); err != nil {
				return
			}
			continue
		}
		next, err := nextPlan(d.p, time.Now())
		if err != nil {
			if _, err = tx.Exec(ctx, "UPDATE monitor_plans SET schedule_error=$2,retry_at=now()+interval '5 minutes' WHERE scope_id=$1", d.id, err.Error()); err != nil {
				return
			}
			continue
		}
		if _, modeErr := validateCollectionMode(d.p.CollectionMode, d.p.Collectors); modeErr != nil {
			if _, err = tx.Exec(ctx, "UPDATE monitor_plans SET schedule_error=$2,retry_at=now()+interval '5 minutes' WHERE scope_id=$1", d.id, modeErr.Error()); err != nil {
				return
			}
			continue
		}
		payload, _ := json.Marshal(map[string]any{"sources": d.p.Collectors, "collection_mode": d.p.CollectionMode})
		labels, labelErr := e.Store.requiredPluginLabels(ctx, d.p.Collectors)
		if labelErr != nil {
			if _, err = tx.Exec(ctx, "UPDATE monitor_plans SET schedule_error=$2,retry_at=now()+interval '5 minutes' WHERE scope_id=$1", d.id, labelErr.Error()); err != nil {
				return
			}
			continue
		}
		budget, budgetErr := jobExecutionBudget(d.p.Collectors, "schedule", e.Store.Plugins)
		if budgetErr != nil {
			if _, err = tx.Exec(ctx, "UPDATE monitor_plans SET schedule_error=$2,retry_at=now()+interval '5 minutes' WHERE scope_id=$1", d.id, budgetErr.Error()); err != nil {
				return
			}
			continue
		}
		inserted, err := tx.Exec(ctx, "INSERT INTO jobs(scope_id,owner,trigger,payload,required_labels,execution_timeout_seconds)SELECT id,owner,'schedule',$2,$3,$4 FROM scopes WHERE id=$1 ON CONFLICT DO NOTHING", d.id, payload, labels, int((budget+time.Second-1)/time.Second))
		if err != nil {
			return
		}
		if inserted.RowsAffected() == 0 {
			_, err = tx.Exec(ctx, "UPDATE monitor_plans SET schedule_error='等待该范围的监控任务结束',retry_at=now()+interval '10 seconds' WHERE scope_id=$1", d.id)
		} else {
			_, err = tx.Exec(ctx, "UPDATE monitor_plans SET next_run_at=$2,last_run_at=now(),schedule_error='',retry_at=NULL WHERE scope_id=$1", d.id, next)
		}
		if err != nil {
			return
		}
	}
	if tx.Commit(ctx) != nil {
		return
	}
	e.Store.ensurePartitions(ctx)
}

// A plugin owns its manifest timeout. The parent still enforces the overall job deadline.
func collectorAttemptContext(ctx context.Context, collector Collector) (context.Context, context.CancelFunc) {
	timeout := 150 * time.Second
	if external, ok := collector.(*ManifestCollector); ok {
		timeout = external.Plugin.Manifest.timeout
	}
	return context.WithTimeout(ctx, timeout)
}
func (e *Engine) activeCount() int {
	n := 0
	e.active.Range(func(_, _ any) bool { n++; return true })
	return n
}

var _ = fmt.Sprintf
