package scribe

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Strategy selects bounded task scheduling order.
type Strategy string

const (
	// HostSpray spreads starts across hosts in the bounded lookahead window.
	HostSpray Strategy = "host-spray"
	// ScriptSpray keeps input order, typically all scripts for each endpoint.
	ScriptSpray Strategy = "script-spray"
)

type hostState struct {
	active, failures int
	starts           uint64
	next             time.Time
}
type scheduledTask struct {
	task Task
	host *hostState
}
type completion struct {
	result Result
	host   *hostState
}

func hostKey(t Target) string {
	host := t.IP
	if host == "" {
		host = t.Host
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}

// run is the sole owner of scheduling state. Workers only own their invocation.
// Producers execute synchronously and must honor context. Slice cancellation
// drains all submitted tasks; streaming cancellation drains accepted tasks only.
func (e *Engine) run(ctx context.Context, next func(context.Context) (Task, bool, error), sink func(Result) error, drain bool) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	hosts := map[string]*hostState{}
	type moduleKey struct {
		dialect Dialect
		id      string
	}
	modules := map[moduleKey]int{}
	keyFor := func(t Task) moduleKey { return moduleKey{t.Script.Dialect, t.Script.ID} }
	pending := make([]scheduledTask, 0, e.options.Window)
	done := make(chan completion, e.workers)
	active, failed := 0, 0
	var globalNext time.Time
	eof := false
	var inputErr, sinkErr error
	emit := func(r Result) {
		if r.Status == Failed {
			failed++
		}
		if sinkErr == nil {
			if e.options.OnEvent != nil {
				for _, event := range Events(r) {
					if sinkErr = e.options.OnEvent(event); sinkErr != nil {
						break
					}
				}
			}
			if sinkErr == nil {
				sinkErr = sink(r)
			}
			if sinkErr != nil {
				cancel()
			}
		}
	}
	terminal := func(t Task, status Status, reason string) Result {
		r := Result{SchemaVersion: 1, ScriptID: t.Script.ID, ScriptSHA256: fmt.Sprintf("%x", sha256.Sum256(t.Script.Source)), Dialect: t.Script.Dialect, Target: t.Target, Status: status, Verdict: Unknown}
		if status == Skipped {
			r.Output = Output{Skipped: true, SkipReason: reason}
		} else {
			r.Error = reason
		}
		return r
	}
	for !eof || len(pending) > 0 || active > 0 {
		if runCtx.Err() != nil && !drain {
			eof = true
		}
		for !eof && len(pending)+active < e.options.Window {
			if runCtx.Err() != nil && !drain {
				eof = true
				break
			}
			task, ok, err := next(runCtx)
			if err != nil {
				inputErr = err
				eof = true
				break
			}
			if !ok {
				eof = true
				break
			}
			if err = e.validate(task); err != nil {
				inputErr = err
				eof = true
				break
			}
			if runCtx.Err() != nil {
				emit(terminal(task, Cancelled, runCtx.Err().Error()))
				continue
			}
			if task.planSkip != "" {
				emit(terminal(task, Skipped, task.planSkip))
				continue
			}
			key := hostKey(task.Target)
			host := hosts[key]
			if host == nil {
				if len(hosts) >= e.options.MaxHosts {
					inputErr = errors.New("host accounting limit exceeded")
					eof = true
					emit(terminal(task, Failed, inputErr.Error()))
					break
				}
				host = &hostState{}
				hosts[key] = host
			}
			pending = append(pending, scheduledTask{task, host})
		}
		// Collect completed failures before admitting more work against a budget.
		collect := func(c completion) {
			active--
			c.host.active--
			k := moduleKey{c.result.Dialect, c.result.ScriptID}
			modules[k]--
			if modules[k] == 0 {
				delete(modules, k)
			}
			if c.result.Status == Failed {
				c.host.failures++
			}
			emit(c.result)
		}
	drainDone:
		for active > 0 {
			select {
			case c := <-done:
				collect(c)
			default:
				break drainDone
			}
		}
		for i := 0; i < len(pending); {
			p := pending[i]
			status, reason := Status(""), ""
			if runCtx.Err() != nil {
				status, reason = Cancelled, runCtx.Err().Error()
			} else if e.options.HostErrorBudget > 0 && p.host.failures >= e.options.HostErrorBudget {
				status, reason = Skipped, "host error budget exhausted"
			}
			if status != "" {
				emit(terminal(p.task, status, reason))
				pending = append(pending[:i], pending[i+1:]...)
				continue
			}
			i++
		}
		now := time.Now()
		var wake time.Time
		for active < e.workers && runCtx.Err() == nil {
			if now.Before(globalNext) {
				wake = globalNext
				break
			}
			chosen := -1
			for i, p := range pending {
				if modules[keyFor(p.task)] >= e.options.ModuleConcurrency {
					continue
				}
				if p.host.active >= e.options.HostConcurrency {
					continue
				}
				if now.Before(p.host.next) {
					if wake.IsZero() || p.host.next.Before(wake) {
						wake = p.host.next
					}
					continue
				}
				if chosen < 0 || e.options.Strategy == HostSpray && p.host.starts < pending[chosen].host.starts {
					chosen = i
					if e.options.Strategy == ScriptSpray {
						break
					}
				}
			}
			if chosen < 0 {
				break
			}
			p := pending[chosen]
			pending = append(pending[:chosen], pending[chosen+1:]...)
			globalNext = time.Now().Add(e.options.GlobalInterval)
			modules[keyFor(p.task)]++
			p.host.active++
			p.host.starts++
			p.host.next = time.Now().Add(e.options.HostInterval)
			active++
			go func(p scheduledTask) { done <- completion{e.execute(runCtx, p.task), p.host} }(p)
			now = time.Now()
		}
		if len(pending) == 0 && active == 0 {
			continue
		}
		// Refill lookahead before blocking if input remains and space is available.
		if !eof && len(pending)+active < e.options.Window && active < e.workers {
			continue
		}
		var timer *time.Timer
		var tick <-chan time.Time
		if active < e.workers && !wake.IsZero() {
			timer = time.NewTimer(time.Until(wake))
			tick = timer.C
		}
		cancelled := runCtx.Done()
		if runCtx.Err() != nil {
			cancelled = nil
		}
		select {
		case c := <-done:
			collect(c)
		case <-tick:
		case <-cancelled:
		}
		if timer != nil {
			timer.Stop()
		}
	}
	if sinkErr != nil {
		return sinkErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if inputErr != nil {
		return inputErr
	}
	if failed > 0 {
		return fmt.Errorf("%d script execution(s) failed", failed)
	}
	return nil
}
