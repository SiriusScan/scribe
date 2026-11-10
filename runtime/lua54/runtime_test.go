package lua54

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
)

func task(dialect scribe.Dialect, source string) scribe.Task {
	return scribe.Task{Script: scribe.Script{ID: "original-fixture", Dialect: dialect, Source: []byte(source)}, Target: scribe.Target{Host: "localhost", IP: "127.0.0.1", Port: 8080, Protocol: "tcp", Service: "http", State: "open"}}
}

func native(t *testing.T, options Options) scribe.Runtime {
	t.Helper()
	runtime, err := NewNative(options)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func TestNativeCapabilityAndFinding(t *testing.T) {
	functions := map[string]scribe.Function{"inspect": func(ctx context.Context, target scribe.Target, args []any) (any, error) {
		if target.IP != "127.0.0.1" || len(args) != 2 || args[0] != "hello" || args[1] != int64(42) {
			t.Errorf("unexpected capability inputs: %v %v", target, args)
		}
		return map[string]any{"status": 200, "headers": map[string]string{"server": "local-fixture"}}, nil
	}}
	runtime := native(t, Options{Functions: functions})
	delete(functions, "inspect") // Runtime owns its immutable registrations.
	input := task(scribe.Sirius, `local sirius = require "sirius"
return {api_version=1, rule=function(target,args) return target.service == "http" end,
action=function(target,args)
  local result=sirius.call("inspect",args.message,42)
  return {data=result,findings={{id="fixture.observation",title="Fixture response",severity="info",evidence=result.headers.server,references={"https://example.invalid"},metadata={status=result.status}}}}
end}`)
	input.Script.Args = map[string]any{"message": "hello"}
	output, err := runtime.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Findings) != 1 || output.Findings[0].Evidence != "local-fixture" || output.Findings[0].Metadata["status"] != int64(200) {
		t.Fatalf("unexpected output: %#v", output)
	}
}

func TestNativeFailures(t *testing.T) {
	runtime := native(t, Options{})
	for _, test := range []struct{ name, source, message string }{
		{"syntax", "return {", "load script"},
		{"initialization", `error("initialization failed")`, "initialize script"},
		{"top-level type", `return 1`, "must return a table"},
		{"version", `return {api_version=2}`, "api_version"},
		{"rule type", `return {api_version=1,rule=true}`, "rule must be a function"},
		{"rule value", `return {api_version=1,rule=function() return 1 end}`, "rule must return a boolean"},
		{"action type", `return {api_version=1}`, "action must be a function"},
		{"action error", `return {api_version=1,action=function() error("fixture failed") end}`, "fixture failed"},
		{"output type", `return {api_version=1,action=function() return "wrong" end}`, "output table"},
		{"unknown output", `return {api_version=1,action=function() return {finding=true} end}`, "unknown output field"},
		{"invalid severity", `return {api_version=1,action=function() return {findings={{id="x",title="x",severity="urgent"}}} end}`, "severity must be"},
		{"missing title", `return {api_version=1,action=function() return {findings={{id="x",severity="info"}}} end}`, "title must be"},
		{"function data", `return {api_version=1,action=function() return {data=function()end} end}`, "cannot be returned"},
		{"mixed keys", `return {api_version=1,action=function() return {data={"one",key="two"}} end}`, "mixed object"},
		{"sparse array", `return {api_version=1,action=function() return {data={[2]="two"}} end}`, "contiguous"},
		{"nonfinite", `return {api_version=1,action=function() return {data=0/0} end}`, "nonfinite"},
		{"binary string", `return {api_version=1,action=function() return {data=string.char(255)} end}`, "UTF-8"},
		{"cyclic output", `return {api_version=1,action=function() local t={};t.self=t;return {data=t} end}`, "cyclic Lua table"},
		{"deep output", `return {api_version=1,action=function() local root={};local t=root;for i=1,40 do t.next={};t=t.next end;return {data=root} end}`, "nested"},
		{"oversized output", `return {api_version=1,action=function() return {data=string.rep("a",1048577)} end}`, "conversion limit"},
		{"encoded size", `return {api_version=1,action=function() return {data=string.rep(string.char(1),200000)} end}`, "encoded output exceeds"},
		{"too many nodes", `return {api_version=1,action=function()local t={};for i=1,10001 do t[i]=i end;return {data=t}end}`, "conversion limit"},
		{"duplicate finding", `return {api_version=1,action=function()return {findings={{id="x",title="X",severity="info"},{id="x",title="X",severity="info"}}}end}`, "duplicate finding"},
		{"unregistered capability", `return {api_version=1,action=function() return {data=sirius.call("missing")} end}`, "unregistered Sirius capability"},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := runtime.Execute(context.Background(), task(scribe.Sirius, test.source))
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected %q, got %v", test.message, err)
			}
			if len(output.Findings) != 0 || output.Data != nil {
				t.Fatalf("error exposed partial findings: %+v", output)
			}
		})
	}
}

func TestRuleSkipAndIsolation(t *testing.T) {
	runtime := native(t, Options{})
	output, err := runtime.Execute(context.Background(), task(scribe.Sirius, `return {api_version=1,rule=function()return false end,action=function() error("must not run") end}`))
	if err != nil || !output.Skipped {
		t.Fatalf("expected skip: %+v %v", output, err)
	}
	var workers sync.WaitGroup
	for range 24 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			output, err := runtime.Execute(context.Background(), task(scribe.Sirius, `invocations=(invocations or 0)+1; return {api_version=1,action=function()return {data=invocations} end}`))
			if err != nil || output.Data != int64(1) {
				t.Errorf("VM state leaked: %+v %v", output, err)
			}
		}()
	}
	workers.Wait()
}

func TestRestrictedModulesAndGlobals(t *testing.T) {
	for _, dialect := range []scribe.Dialect{scribe.Sirius, scribe.NSE} {
		var runtime scribe.Runtime
		if dialect == scribe.Sirius {
			runtime = native(t, Options{})
		} else {
			runtime, _ = NewNSE(Options{})
		}
		for _, module := range []string{"io", "os", "package", "debug", "golib", "nmap", "../arbitrary"} {
			_, err := runtime.Execute(context.Background(), task(dialect, `require("`+module+`")`))
			if err == nil || !strings.Contains(err.Error(), "unsupported Lua module") {
				t.Errorf("module %s: %v", module, err)
			}
		}
	}
	output, err := native(t, Options{}).Execute(context.Background(), task(scribe.Sirius, `assert(io==nil and os==nil and package==nil and debug==nil and load==nil and dofile==nil and loadfile==nil and collectgarbage==nil and math.random==nil and math.randomseed==nil);return {api_version=1,action=function() return {data=string.packsize("i4")} end}`))
	if err != nil || output.Data != int64(4) {
		t.Fatalf("restricted standard library: %+v %v", output, err)
	}
}

func TestResourceLimitsAndCancellation(t *testing.T) {
	for _, source := range []string{`while true do end`, `return {api_version=1,rule=function()while true do end end}`, `return {api_version=1,action=function()while true do end end}`} {
		_, err := native(t, Options{Limits: Limits{CPU: 10_000, Timeout: time.Second}}).Execute(context.Background(), task(scribe.Sirius, source))
		if err == nil || !strings.Contains(err.Error(), "CPU limit") {
			t.Fatalf("expected CPU limit, got %v", err)
		}
	}
	_, err := native(t, Options{Limits: Limits{Memory: 1 << 20}}).Execute(context.Background(), task(scribe.Sirius, `return {api_version=1,action=function()return {data=string.rep("x",2000000)}end}`))
	if err == nil || !strings.Contains(err.Error(), "memory limit") {
		t.Fatalf("expected memory limit, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = native(t, Options{}).Execute(ctx, task(scribe.Sirius, `while true do end`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	timer := time.AfterFunc(5*time.Millisecond, cancel)
	defer timer.Stop()
	start := time.Now()
	_, err = native(t, Options{Limits: Limits{CPU: 1 << 60, Timeout: 30 * time.Millisecond}}).Execute(ctx, task(scribe.Sirius, `while true do end`))
	if !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatalf("bounded CPU cancellation: %v after %v", err, time.Since(start))
	}
}

func TestCapabilityBoundaries(t *testing.T) {
	for name, function := range map[string]scribe.Function{
		"failure": func(context.Context, scribe.Target, []any) (any, error) { return nil, errors.New("capability failed") },
		"panic":   func(context.Context, scribe.Target, []any) (any, error) { panic("capability panic") },
		"large": func(context.Context, scribe.Target, []any) (any, error) {
			return strings.Repeat("x", MaxOutputBytes+1), nil
		},
		"cycle": func(context.Context, scribe.Target, []any) (any, error) {
			m := map[string]any{}
			m["self"] = m
			return m, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := native(t, Options{Functions: map[string]scribe.Function{name: function}}).Execute(context.Background(), task(scribe.Sirius, `return {api_version=1,action=function()return {data=sirius.call("`+name+`")} end}`))
			if err == nil {
				t.Fatal("expected capability error")
			}
		})
	}
	runtime := native(t, Options{Limits: Limits{Timeout: 20 * time.Millisecond}, Functions: map[string]scribe.Function{"wait": func(ctx context.Context, _ scribe.Target, _ []any) (any, error) { <-ctx.Done(); return nil, ctx.Err() }}})
	_, err := runtime.Execute(context.Background(), task(scribe.Sirius, `return {api_version=1,action=function()return {data=sirius.call("wait")} end}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capability did not receive deadline: %v", err)
	}
}

func TestNSEProfile(t *testing.T) {
	runtime, err := NewNSE(Options{})
	if err != nil {
		t.Fatal(err)
	}
	input := task(scribe.NSE, `local shortport=require "shortport";local stdnse=require "stdnse"
portrule=shortport.port_or_service(80,"http")
action=function(host,port) return {message=stdnse.get_script_args("message"),ip=host.ip,port=port.number,type=SCRIPT_TYPE},"fixture text" end`)
	input.Script.Args = map[string]any{"message": "local fixture"}
	output, err := runtime.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	data := output.Data.(map[string]any)
	structured := data["structured"].(map[string]any)
	if data["text"] != "fixture text" || structured["message"] != "local fixture" || structured["type"] != "portrule" || len(output.Findings) != 0 {
		t.Fatalf("NSE output: %+v", output)
	}
	input.Target.State = ""
	output, err = runtime.Execute(context.Background(), input)
	if err != nil || !output.Skipped {
		t.Fatalf("unknown state should skip shortport: %+v %v", output, err)
	}
	input.Target.State = "open"
	input.Target.Protocol = ""
	output, err = runtime.Execute(context.Background(), input)
	if err != nil || !output.Skipped {
		t.Fatalf("unknown protocol should skip shortport: %+v %v", output, err)
	}
	input = task(scribe.NSE, `local shortport=require "shortport";dependencies={};portrule=shortport.portnumber({8080},"tcp",{"closed"});action=function()return SCRIPT_NAME end`)
	input.Target.State = "closed"
	input.Script.ID = "original-fixture.nse"
	output, err = runtime.Execute(context.Background(), input)
	if err != nil || output.Data != "original-fixture" {
		t.Fatalf("explicit state/name/empty dependencies: %+v %v", output, err)
	}
	input = task(scribe.NSE, `hostrule=function(host)return host.ip=="127.0.0.1" end;action=function(host)return "host fixture"end`)
	output, err = runtime.Execute(context.Background(), input)
	if err != nil || output.Data != "host fixture" {
		t.Fatalf("hostrule: %+v %v", output, err)
	}
	input = task(scribe.NSE, `portrule=function()return true end;action=function()return nil end`)
	output, err = runtime.Execute(context.Background(), input)
	if err != nil || output.Data != nil || len(output.Findings) != 0 {
		t.Fatalf("nil output: %+v %v", output, err)
	}
}

func TestDirectInputValidation(t *testing.T) {
	runtime := native(t, Options{})
	input := task(scribe.Sirius, `return {api_version=1,action=function(target)return {data=target.state}end}`)
	output, err := runtime.Execute(context.Background(), input)
	if err != nil || output.Data != "open" {
		t.Fatalf("native state mapping: %+v %v", output, err)
	}
	input.Script.Source = make([]byte, scribe.MaxSourceBytes+1)
	if _, err = runtime.Execute(context.Background(), input); err == nil {
		t.Fatal("oversized source accepted")
	}
	input = task(scribe.Sirius, `return {api_version=1,action=function()return {}end}`)
	args := map[string]any{}
	args["cycle"] = args
	input.Script.Args = args
	if _, err = runtime.Execute(context.Background(), input); err == nil || !strings.Contains(err.Error(), "nested") {
		t.Fatalf("cyclic Go args accepted: %v", err)
	}
	if _, err = NewNative(Options{Limits: Limits{Timeout: -time.Second}}); err == nil {
		t.Fatal("negative timeout accepted")
	}
}

func TestUnknownSeverity(t *testing.T) {
	output, err := native(t, Options{}).Execute(context.Background(), task(scribe.Sirius, `return {api_version=1,action=function()return {findings={{id="unknown-score",title="Observed issue without a score",severity="unknown"}}}end}`))
	if err != nil || len(output.Findings) != 1 || output.Findings[0].Severity != "unknown" {
		t.Fatalf("unknown severity rejected: %+v %v", output, err)
	}
}

func TestNSEUnsupportedSurface(t *testing.T) {
	runtime, _ := NewNSE(Options{})
	for _, test := range []struct{ source, message string }{
		{`local s=require "stdnse";s.new_thread(function()end)`, "unsupported NSE API stdnse.new_thread"},
		{`prerule=function()return true end`, "prerule is unsupported"},
		{`dependencies={"another"}`, "dependencies are unsupported"},
		{`hostrule=function()return true end;portrule=function()return true end`, "exactly one"},
		{`hostrule=function()return true end;action=function()return 1 end`, "table, string, or nil"},
	} {
		_, err := runtime.Execute(context.Background(), task(scribe.NSE, test.source))
		if err == nil || !strings.Contains(err.Error(), test.message) {
			t.Errorf("expected %q, got %v", test.message, err)
		}
	}
}
