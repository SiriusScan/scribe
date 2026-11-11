package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/capability/httpcap"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

// cliPath is built once per test run from the replaced module, with the module
// proxy disabled: an external consumer must be able to build offline.
var cliPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "scribe-acceptance-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	name := "scribe"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	cliPath = filepath.Join(dir, name)
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	cmd := exec.Command(goBin, "build", "-o", cliPath, "github.com/SiriusScan/scribe/cmd/scribe")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOPROXY=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build scribe CLI: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// fixture is the controlled local HTTP service both SDK and CLI run against.
type fixture struct {
	target   scribe.Target
	requests atomic.Int32
	slowSeen chan struct{}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{slowSeen: make(chan struct{}, 4)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.URL.Path == "/slow" {
			select {
			case f.slowSeen <- struct{}{}:
			default:
			}
			<-r.Context().Done()
			return
		}
		w.Header().Set("X-Sirius-Fixture", "vulnerable")
		_, _ = w.Write([]byte("Scribe acceptance fixture\n"))
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	// Logical host differs from the connection IP on purpose: both surfaces
	// must dial the caller-supplied IP while preserving the hostname.
	f.target = scribe.Target{Host: "fixture.invalid", IP: host, Port: uint16(port), Protocol: "tcp", Service: "http", State: "open"}
	return f
}

func scriptSource(t *testing.T) []byte {
	t.Helper()
	source, err := os.ReadFile("testdata/http-header.lua")
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func scriptPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("testdata/http-header.lua")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func newEngine(t *testing.T, limits lua54.Limits, httpTimeout time.Duration) *scribe.Engine {
	t.Helper()
	if httpTimeout == 0 {
		httpTimeout = 5 * time.Second
	}
	client, err := httpcap.New(httpcap.Options{Timeout: httpTimeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	rt, err := lua54.NewNative(lua54.Options{
		Limits:    limits,
		Functions: map[string]scribe.Function{"http.get": client.Function},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scribe.New(scribe.Options{Concurrency: 2}, rt)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func taskFor(target scribe.Target, source []byte, args map[string]any) scribe.Task {
	// The CLI derives the script ID from the file base name; match it so the
	// two structured outputs are directly comparable.
	return scribe.Task{
		Target: target,
		Script: scribe.Script{ID: "http-header.lua", Dialect: scribe.Sirius, Source: source, Args: args},
	}
}

func runSDK(ctx context.Context, engine *scribe.Engine, task scribe.Task) ([]scribe.Result, error) {
	var results []scribe.Result
	err := engine.Run(ctx, []scribe.Task{task}, func(result scribe.Result) error {
		results = append(results, result)
		return nil
	})
	return results, err
}

func oneResult(t *testing.T, results []scribe.Result, err error) scribe.Result {
	t.Helper()
	if err != nil {
		t.Fatalf("SDK run: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SDK results = %d, want 1", len(results))
	}
	return results[0]
}

func cliArgs(target scribe.Target, script, argsJSON string, extra ...string) []string {
	args := []string{
		"--dialect", "sirius",
		"--script", script,
		"--host", target.Host,
		"--port", strconv.Itoa(int(target.Port)),
		"--protocol", target.Protocol,
		"--service", target.Service,
		"--state", target.State,
		"--args", argsJSON,
	}
	if target.IP != "" {
		args = append(args, "--ip", target.IP)
	}
	return append(args, extra...)
}

func runCLI(ctx context.Context, args ...string) (stdout, stderr string, err error) {
	cmd := exec.CommandContext(ctx, cliPath, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func cliResult(t *testing.T, stdout string) scribe.Result {
	t.Helper()
	line, _, _ := strings.Cut(stdout, "\n")
	var result scribe.Result
	if err := json.Unmarshal([]byte(line), &result); err != nil {
		t.Fatalf("CLI stdout is not a structured result: %v\n%s", err, stdout)
	}
	return result
}

// canonical renders a result as sorted JSON without the volatile elapsed
// field, so SDK and CLI outputs can be compared byte for byte.
func canonical(t *testing.T, result scribe.Result) string {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	delete(generic, "elapsed_ms")
	canonical, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}

func TestSDKAndCLIProduceIdenticalStructuredOutput(t *testing.T) {
	f := newFixture(t)
	args := map[string]any{"path": "/"}

	sdkResults, sdkErr := runSDK(context.Background(), newEngine(t, lua54.Limits{}, 0), taskFor(f.target, scriptSource(t), args))
	sdk := oneResult(t, sdkResults, sdkErr)

	stdout, stderr, err := runCLI(context.Background(), cliArgs(f.target, scriptPath(t), `{"path":"/"}`)...)
	if err != nil || stderr != "" {
		t.Fatalf("CLI run: err=%v stderr=%q stdout=%q", err, stderr, stdout)
	}
	cli := cliResult(t, stdout)

	if got, want := canonical(t, cli), canonical(t, sdk); got != want {
		t.Fatalf("structured output differs\nCLI: %s\nSDK: %s", got, want)
	}
	if sdk.Status != scribe.Completed || len(sdk.Output.Findings) != 1 || sdk.Output.Findings[0].ID != "scribe-demo-marker" {
		t.Fatalf("unexpected SDK result: %+v", sdk)
	}
	data, ok := sdk.Output.Data.(map[string]any)
	if !ok || data["status"] != int64(200) || data["checked_path"] != "/" {
		t.Fatalf("unexpected SDK data: %#v", sdk.Output.Data)
	}
	if f.requests.Load() != 2 {
		t.Fatalf("fixture requests = %d, want 1 SDK + 1 CLI", f.requests.Load())
	}
}

func TestRuleSkipIsIdenticalAndMakesNoRequests(t *testing.T) {
	f := newFixture(t)
	target := f.target
	target.Service = "other" // the fixture script's rule requires service http

	sdkResults, sdkErr := runSDK(context.Background(), newEngine(t, lua54.Limits{}, 0), taskFor(target, scriptSource(t), nil))
	sdk := oneResult(t, sdkResults, sdkErr)

	stdout, stderr, err := runCLI(context.Background(), cliArgs(target, scriptPath(t), `{}`)...)
	if err != nil {
		t.Fatalf("skipped CLI run must exit 0: err=%v stderr=%q", err, stderr)
	}
	cli := cliResult(t, stdout)

	if got, want := canonical(t, cli), canonical(t, sdk); got != want {
		t.Fatalf("skipped output differs\nCLI: %s\nSDK: %s", got, want)
	}
	if sdk.Status != scribe.Skipped || len(sdk.Output.Findings) != 0 {
		t.Fatalf("rule mismatch must skip without findings: %+v", sdk)
	}
	if f.requests.Load() != 0 {
		t.Fatalf("skipped runs made %d HTTP requests, want 0", f.requests.Load())
	}
}

func writeScript(t *testing.T, name, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCancellation(t *testing.T) {
	f := newFixture(t)
	engine := newEngine(t, lua54.Limits{}, 0)
	task := taskFor(f.target, scriptSource(t), map[string]any{"path": "/slow"})

	t.Run("already cancelled SDK context starts nothing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		results, err := runSDK(ctx, engine, task)
		if !errors.Is(err, context.Canceled) || len(results) != 0 {
			t.Fatalf("err=%v results=%d", err, len(results))
		}
	})

	t.Run("in-flight SDK cancellation fails without findings", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		type outcome struct {
			results []scribe.Result
			err     error
		}
		done := make(chan outcome, 1)
		go func() {
			results, err := runSDK(ctx, engine, task)
			done <- outcome{results, err}
		}()
		select {
		case <-f.slowSeen:
		case <-time.After(5 * time.Second):
			t.Fatal("request never reached the fixture")
		}
		cancel()
		select {
		case out := <-done:
			if !errors.Is(out.err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", out.err)
			}
			if len(out.results) != 1 || out.results[0].Status != scribe.Failed || len(out.results[0].Output.Findings) != 0 {
				t.Fatalf("cancelled run must yield one failed, finding-free result: %+v", out.results)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancelled run did not return")
		}
	})

	t.Run("cancelled CLI process reports no clean result", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		type outcome struct {
			stdout, stderr string
			err            error
		}
		done := make(chan outcome, 1)
		go func() {
			stdout, stderr, err := runCLI(ctx, cliArgs(f.target, scriptPath(t), `{"path":"/slow"}`)...)
			done <- outcome{stdout, stderr, err}
		}()
		select {
		case <-f.slowSeen:
		case <-time.After(10 * time.Second):
			t.Fatal("CLI request never reached the fixture")
		}
		cancel()
		select {
		case out := <-done:
			if out.err == nil {
				t.Fatalf("cancelled CLI exited 0: stdout=%q", out.stdout)
			}
			if strings.Contains(out.stdout, `"status":"completed"`) || strings.Contains(out.stdout, "scribe-demo-marker") {
				t.Fatalf("cancelled CLI claimed a completed finding: %q", out.stdout)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("cancelled CLI did not exit")
		}
	})
}

func TestLimits(t *testing.T) {
	f := newFixture(t)
	loop := `return {api_version=1, action=function() while true do end end}`
	loopPath := writeScript(t, "loop.lua", loop)

	assertFailed := func(t *testing.T, result scribe.Result, want string) {
		t.Helper()
		if result.Status != scribe.Failed || !strings.Contains(result.Error, want) || len(result.Output.Findings) != 0 {
			t.Fatalf("result = %+v, want failed containing %q with no findings", result, want)
		}
	}

	t.Run("CPU limit via SDK and CLI", func(t *testing.T) {
		engine := newEngine(t, lua54.Limits{CPU: 10_000, Timeout: time.Second}, 0)
		results, err := runSDK(context.Background(), engine, taskFor(f.target, []byte(loop), nil))
		if err == nil || len(results) != 1 {
			t.Fatalf("err=%v results=%d", err, len(results))
		}
		assertFailed(t, results[0], "CPU limit")

		stdout, _, err := runCLI(context.Background(), cliArgs(f.target, loopPath, `{}`, "--cpu", "10000", "--timeout", "1s")...)
		if err == nil {
			t.Fatalf("CPU-limited CLI exited 0: %q", stdout)
		}
		assertFailed(t, cliResult(t, stdout), "CPU limit")
	})

	t.Run("memory limit via SDK and CLI", func(t *testing.T) {
		big := `return {api_version=1, action=function() return {data=string.rep("x",2000000)} end}`
		bigPath := writeScript(t, "big.lua", big)
		engine := newEngine(t, lua54.Limits{Memory: 1 << 20, Timeout: 5 * time.Second}, 0)
		results, err := runSDK(context.Background(), engine, taskFor(f.target, []byte(big), nil))
		if err == nil || len(results) != 1 {
			t.Fatalf("err=%v results=%d", err, len(results))
		}
		assertFailed(t, results[0], "memory limit")

		stdout, _, err := runCLI(context.Background(), cliArgs(f.target, bigPath, `{}`, "--memory", "1048576")...)
		if err == nil {
			t.Fatalf("memory-limited CLI exited 0: %q", stdout)
		}
		assertFailed(t, cliResult(t, stdout), "memory limit")
	})

	t.Run("timeout against a slow service via SDK and CLI", func(t *testing.T) {
		engine := newEngine(t, lua54.Limits{Timeout: 100 * time.Millisecond}, 100*time.Millisecond)
		start := time.Now()
		results, err := runSDK(context.Background(), engine, taskFor(f.target, scriptSource(t), map[string]any{"path": "/slow"}))
		if err == nil || len(results) != 1 || time.Since(start) > 5*time.Second {
			t.Fatalf("err=%v results=%d elapsed=%v", err, len(results), time.Since(start))
		}
		if results[0].Status != scribe.Failed || len(results[0].Output.Findings) != 0 {
			t.Fatalf("timed-out SDK result: %+v", results[0])
		}

		stdout, _, err := runCLI(context.Background(), cliArgs(f.target, scriptPath(t), `{"path":"/slow"}`, "--timeout", "100ms")...)
		if err == nil {
			t.Fatalf("timed-out CLI exited 0: %q", stdout)
		}
		if result := cliResult(t, stdout); result.Status != scribe.Failed || len(result.Output.Findings) != 0 {
			t.Fatalf("timed-out CLI result: %+v", result)
		}
	})

	t.Run("oversized source is rejected before execution", func(t *testing.T) {
		oversized := []byte(strings.Repeat("x", scribe.MaxSourceBytes+1))
		results, err := runSDK(context.Background(), newEngine(t, lua54.Limits{}, 0), taskFor(f.target, oversized, nil))
		if err == nil || len(results) != 0 {
			t.Fatalf("SDK accepted oversized source: err=%v results=%d", err, len(results))
		}
		path := writeScript(t, "oversized.lua", string(oversized))
		stdout, stderr, err := runCLI(context.Background(), cliArgs(f.target, path, `{}`)...)
		if err == nil || stdout != "" || !strings.Contains(stderr, "bytes") {
			t.Fatalf("CLI accepted oversized source: err=%v stdout=%q stderr=%q", err, stdout, stderr)
		}
	})
}

func TestErrorPropagation(t *testing.T) {
	f := newFixture(t)
	engine := newEngine(t, lua54.Limits{}, 0)

	t.Run("script action error reaches SDK and CLI unchanged", func(t *testing.T) {
		source := `return {api_version=1, action=function() error("probe failed") end}`
		results, err := runSDK(context.Background(), engine, taskFor(f.target, []byte(source), nil))
		if err == nil || len(results) != 1 {
			t.Fatalf("err=%v results=%d", err, len(results))
		}
		if r := results[0]; r.Status != scribe.Failed || !strings.Contains(r.Error, "probe failed") || len(r.Output.Findings) != 0 {
			t.Fatalf("SDK result: %+v", r)
		}

		stdout, stderr, err := runCLI(context.Background(), cliArgs(f.target, writeScript(t, "fail.lua", source), `{}`)...)
		if err == nil || stderr == "" {
			t.Fatalf("failing CLI must exit nonzero with diagnostics: err=%v", err)
		}
		if r := cliResult(t, stdout); r.Status != scribe.Failed || !strings.Contains(r.Error, "probe failed") || len(r.Output.Findings) != 0 {
			t.Fatalf("CLI result: %+v", r)
		}
	})

	t.Run("rule error is a failure, not a skip", func(t *testing.T) {
		source := `return {api_version=1, rule=function() error("rule boom") end, action=function() return {} end}`
		results, err := runSDK(context.Background(), engine, taskFor(f.target, []byte(source), nil))
		if err == nil || len(results) != 1 {
			t.Fatalf("err=%v results=%d", err, len(results))
		}
		if r := results[0]; r.Status != scribe.Failed || !strings.Contains(r.Error, "rule boom") {
			t.Fatalf("SDK result: %+v", r)
		}
	})

	t.Run("unregistered capability fails explicitly", func(t *testing.T) {
		source := `return {api_version=1, action=function() return {data=sirius.call("missing")} end}`
		results, err := runSDK(context.Background(), engine, taskFor(f.target, []byte(source), nil))
		if err == nil || len(results) != 1 {
			t.Fatalf("err=%v results=%d", err, len(results))
		}
		if r := results[0]; r.Status != scribe.Failed || !strings.Contains(r.Error, "unregistered Sirius capability") || len(r.Output.Findings) != 0 {
			t.Fatalf("SDK result: %+v", r)
		}
	})

	t.Run("unreachable endpoint is an error, never a finding", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(listener.Addr().(*net.TCPAddr).Port)
		_ = listener.Close()
		target := f.target
		target.Port = port
		results, err := runSDK(context.Background(), engine, taskFor(target, scriptSource(t), map[string]any{"path": "/"}))
		if err == nil || len(results) != 1 {
			t.Fatalf("err=%v results=%d", err, len(results))
		}
		if r := results[0]; r.Status != scribe.Failed || r.Error == "" || len(r.Output.Findings) != 0 {
			t.Fatalf("SDK result: %+v", r)
		}
	})

	t.Run("no runtime for dialect and invalid target fail before execution", func(t *testing.T) {
		task := taskFor(f.target, scriptSource(t), nil)
		task.Script.Dialect = scribe.NSE
		if results, err := runSDK(context.Background(), engine, task); err == nil || len(results) != 0 || !strings.Contains(err.Error(), "no runtime for dialect") {
			t.Fatalf("err=%v results=%d", err, len(results))
		}
		task = taskFor(f.target, scriptSource(t), nil)
		task.Target.Host = "https://fixture.invalid"
		if results, err := runSDK(context.Background(), engine, task); err == nil || len(results) != 0 {
			t.Fatalf("err=%v results=%d", err, len(results))
		}
	})
}
