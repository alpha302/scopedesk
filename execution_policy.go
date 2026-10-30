package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const sourceMaxAttempts = 3
const profileBudget = 15 * time.Minute
const commitBudget = 30 * time.Second

type ExecutionError struct {
	Code      string
	Message   string
	Retryable bool
}

func (e *ExecutionError) Error() string { return e.Message }

func (r *PluginResult) setFailure(err error) {
	failure := classifyExecutionError(err, "plugin_failed")
	r.Error, r.ErrorCode, r.Retryable = failure.Message, failure.Code, failure.Retryable
}
func executionFailure(code, message string, retryable bool) *ExecutionError {
	return &ExecutionError{code, message, retryable}
}

func classifyExecutionError(err error, fallback string) *ExecutionError {
	if err == nil {
		return nil
	}
	var policy *ExecutionError
	if errors.As(err, &policy) {
		return policy
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return executionFailure("timeout", "执行超时", false)
	}
	if errors.Is(err, context.Canceled) {
		return executionFailure("cancelled", "执行已取消", false)
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		retryable := pg.Code == "40001" || pg.Code == "40P01" || pg.Code == "55P03" || pg.Code == "53300" || pg.Code == "57P03" || strings.HasPrefix(pg.Code, "08")
		return executionFailure("database_"+pg.Code, "内部存储操作失败", retryable)
	}
	for _, cause := range []error{syscall.EAGAIN, syscall.ECONNRESET, syscall.ECONNREFUSED, syscall.EPIPE, io.ErrUnexpectedEOF, io.EOF} {
		if errors.Is(err, cause) {
			return executionFailure("temporary_io", "资源或连接暂时不可用", true)
		}
	}
	var network net.Error
	if errors.As(err, &network) {
		if network.Timeout() {
			return executionFailure("timeout", "请求超时", false)
		}
		if network.Temporary() {
			return executionFailure("network_temporary", "网络暂时不可用", true)
		}
	}
	return executionFailure(fallback, safeError(err), false)
}

func classifyCommitError(err error) *ExecutionError {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "40001" || pg.Code == "40P01") {
		return classifyExecutionError(err, "commit_failed")
	}
	return executionFailure("commit_uncertain", "结果提交状态不确定，请核对执行记录后再操作", false)
}

func maxJobDuration() (time.Duration, error) {
	raw := os.Getenv("RECON_MAX_JOB_DURATION")
	if raw == "" {
		return 2 * time.Hour, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < time.Second || d > 24*time.Hour {
		return 0, executionFailure("execution_policy", "RECON_MAX_JOB_DURATION 必须为 1 秒至 24 小时的时长", false)
	}
	return d, nil
}

func jobExecutionBudget(sources []string, trigger string, registry *PluginRegistry) (time.Duration, error) {
	if len(sources) == 0 || len(sources) > 32 {
		return 0, executionFailure("execution_policy", "任务需要 1–32 个来源", false)
	}
	budget := commitBudget
	if trigger != "plugin_test" {
		budget += profileBudget
	}
	if trigger == "plugin_test" && len(sources) != 1 {
		return 0, executionFailure("execution_policy", "插件测试只接受一个来源", false)
	}
	for _, source := range sources {
		timeout := 150 * time.Second
		external := !builtinPassive(source)
		if external {
			m, ok := PluginManifest{}, false
			if registry != nil {
				m, ok = registry.Manifests[source]
			}
			if !ok && registry == nil && source == "subfinder" {
				raw, _ := defaultPluginFiles.ReadFile("plugins/subfinder.yaml")
				var err error
				m, err = parseManifest(raw)
				ok = err == nil
			}
			if !ok || m.timeout <= 0 || m.timeout > 15*time.Minute {
				return 0, executionFailure("execution_policy", "插件未注册或超时配置无效："+source, false)
			}
			timeout = m.timeout
		}
		attempts := sourceMaxAttempts
		if trigger == "plugin_test" || builtinPassive(source) {
			attempts = 1
		}
		budget += time.Duration(attempts) * timeout
		if external {
			budget += time.Duration(attempts) * 5 * time.Second
		}
		if attempts > 1 {
			budget += 6 * time.Second
		}
	}
	budget = ((budget + time.Second - 1) / time.Second) * time.Second
	limit, err := maxJobDuration()
	if err != nil {
		return 0, err
	}
	if budget > limit {
		return 0, executionFailure("job_budget_exceeded", fmt.Sprintf("任务需要 %s，超过全局上限 %s，请减少来源或调整上限", budget, limit), false)
	}
	return budget, nil
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryStage(ctx context.Context, operation func() error) error {
	for attempt := 1; attempt <= 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := operation()
		if err == nil {
			return nil
		}
		failure := classifyExecutionError(err, "stage_failed")
		if !failure.Retryable || attempt == 3 {
			return failure
		}
		if err = waitForRetry(ctx, time.Duration(attempt)*200*time.Millisecond); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) finishFailure(run Run, err error, stats []SourceStats) {
	failure := classifyExecutionError(err, "job_failed")
	status := "failed"
	if failure.Code == "cancelled" || failure.Code == "lease_lost" || failure.Code == "scope_denied" {
		status = "cancelled"
	}
	e.finish(run, status, failure.Message, stats, map[string]any{"sources": stats, "error_code": failure.Code, "retryable": failure.Retryable})
}

func (e *Engine) finishStopped(ctx context.Context, run Run, stats []SourceStats) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		e.finishFailure(run, executionFailure("job_timeout", "作业总时限已耗尽，未完成结果不提交", false), stats)
		return
	}
	e.finishFailure(run, classifyExecutionError(context.Cause(ctx), "cancelled"), stats)
}

func (e *Engine) beginExecution(run *Run) (context.Context, context.CancelFunc, error) {
	budget, err := jobExecutionBudget(run.Sources, run.Trigger, e.Store.Plugins)
	if err != nil {
		return nil, nil, err
	}
	limit, err := maxJobDuration()
	if err != nil {
		return nil, nil, err
	}
	frozen := time.Duration(run.ExecutionTimeoutSeconds) * time.Second
	if frozen > limit {
		return nil, nil, executionFailure("job_budget_exceeded", "已排队任务的时限超过当前全局上限，请重新提交", false)
	}
	if run.DeadlineAt != nil && frozen > 0 && budget > frozen {
		return nil, nil, executionFailure("execution_policy_changed", "插件时间配置已变化，请重新提交任务", false)
	}
	budget = max(budget, frozen)
	run.ExecutionTimeoutSeconds = int((budget + time.Second - 1) / time.Second)
	setup, stop := context.WithTimeout(e.root, 10*time.Second)
	defer stop()
	err = e.Store.DB.QueryRow(setup, `UPDATE jobs SET execution_timeout_seconds=$3::integer,deadline_at=coalesce(deadline_at,now()+$3::integer*interval '1 second') WHERE id=$1 AND worker_id=$2 AND status='running' AND lease_until>now() RETURNING deadline_at`, run.ID, run.Worker, run.ExecutionTimeoutSeconds).Scan(&run.DeadlineAt)
	if err != nil {
		return nil, nil, classifyExecutionError(err, "execution_start_failed")
	}
	ctx, cancel := context.WithDeadline(e.root, *run.DeadlineAt)
	return ctx, cancel, nil
}
