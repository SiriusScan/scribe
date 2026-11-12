// Command scribe runs explicitly selected Lua scripts against a known endpoint.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/adapter/pingpp"
	"github.com/SiriusScan/scribe/capability/httpcap"
	"github.com/SiriusScan/scribe/capability/tcpcap"
	"github.com/SiriusScan/scribe/capability/udpcap"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

var version = "dev"
var commit = "unknown"

func buildVersion() string {
	v, c := version, commit
	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "dev" && info.Main.Version != "" {
			v = info.Main.Version
		}
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && c == "unknown" {
				c = s.Value
			}
		}
	}
	return fmt.Sprintf("scribe %s (%s)", v, c)
}

type scriptPaths []string

func (p *scriptPaths) String() string { return fmt.Sprint([]string(*p)) }

func (p *scriptPaths) Set(path string) error {
	if path == "" {
		return errors.New("script path must not be empty")
	}
	if len(*p) >= 64 {
		return errors.New("at most 64 script files may be selected per invocation")
	}
	*p = append(*p, path)
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type inlineScript struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}

func run(ctx context.Context, argv []string, stdout, stderr io.Writer) int {
	return runScripts(ctx, argv, nil, stdout, stderr)
}

func runScripts(ctx context.Context, argv []string, inline []inlineScript, stdout, stderr io.Writer) int {
	if len(argv) > 0 && argv[0] == "serve" {
		return serve(ctx, argv[1:], stderr)
	}
	flags := flag.NewFlagSet("scribe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	pingppPath := flags.String("pingpp-jsonl", "", "read pingpp.scan/v1 JSONL endpoint facts")
	factsJSONL := flags.String("facts-jsonl", "", "stream known endpoint facts from a JSONL file; at most 65536 records of 64 KiB")
	summary := flags.Bool("summary", false, "append a summary JSONL record")
	events := flags.Bool("events", false, "emit schema v1 SDK lifecycle events as JSONL")
	factsPath := flags.String("facts", "", "JSON array of known endpoint facts (maximum 1024)")
	community := flags.String("snmp-community", "", "explicit SNMP v2c planner community (empty disables)")
	strict := flags.Bool("strict-identification", false, "require declared matching product for clean verdicts")
	exhaustive := flags.Bool("exhaustive", false, "execute excluded scripts and report planner misses")
	listModules := flags.Bool("list-modules", false, "emit validated module metadata and lint warnings as JSONL without execution")
	check := flags.Bool("check", false, "compile and check literal module/API references without execution; dynamic access is not certified")
	showVersion := flags.Bool("version", false, "print module version and commit")
	var paths scriptPaths
	flags.Var(&paths, "script", "Lua script file (repeatable, at most 64)")
	dialect := flags.String("dialect", "", "required script contract: sirius or nse (experimental subset)")
	host := flags.String("host", "", "known hostname or IP address, without scheme or port")
	ip := flags.String("ip", "", "optional fixed connection IP, preserving logical host")
	port := flags.Int("port", 0, "known port, 1-65535; 0 for a host-only task")
	protocol := flags.String("protocol", "tcp", "known transport: tcp or udp")
	product := flags.String("product", "", "caller-supplied product identity")
	service := flags.String("service", "", "caller-supplied service name")
	state := flags.String("state", "", "caller-supplied port state, for example open; empty means unknown")
	tls := flags.Bool("tls", false, "known endpoint uses TLS")
	argsJSON := flags.String("args", "{}", "script arguments as a JSON object (at most 64 KiB)")
	plan := flags.Bool("plan", false, "report selection without executing scripts or probes")
	moduleInterval := flags.Duration("module-interval", 0, "minimum interval between starts of the same dialect/script per run")
	moduleConcurrency := flags.Int("module-concurrency", 0, "maximum concurrent invocations per dialect/script; 0 uses concurrency")
	globalInterval := flags.Duration("global-interval", 0, "minimum interval between all script starts per run")
	concurrency := flags.Int("concurrency", 4, "maximum concurrent scripts, 1-256")
	hostConcurrency := flags.Int("host-concurrency", 0, "maximum concurrent scripts per host; 0 uses concurrency")
	hostInterval := flags.Duration("host-interval", 0, "minimum interval between script starts per host")
	hostErrors := flags.Int("host-error-budget", 0, "execution errors before skipping remaining host work; 0 disables")
	strategy := flags.String("strategy", string(scribe.ScriptSpray), "host-spray or script-spray")
	timeout := flags.Duration("timeout", 5*time.Second, "per-script runtime and host-call deadline")
	cpu := flags.Uint64("cpu", 10_000_000, "per-script Lua CPU accounting budget")
	memory := flags.Uint64("memory", 32<<20, "per-script Lua memory accounting budget in bytes")
	if err := flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "scribe: %v\n", err)
		return 1
	}
	if *showVersion {
		fmt.Fprintln(stdout, buildVersion())
		return 0
	}
	if flags.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments; use --script and --host"))
	}
	if *dialect != string(scribe.Sirius) && *dialect != string(scribe.NSE) {
		return fail(errors.New("--dialect must explicitly select sirius or nse"))
	}
	if len(paths)+len(inline) == 0 {
		return fail(errors.New("at least one --script file is required"))
	}
	if len(paths)+len(inline) > 64 {
		return fail(errors.New("at most 64 scripts may be selected per invocation"))
	}
	for _, script := range inline {
		if script.ID == "" || len(script.Source) == 0 || len(script.Source) > scribe.MaxSourceBytes {
			return fail(fmt.Errorf("inline script requires an id and 1-%d source bytes", scribe.MaxSourceBytes))
		}
	}
	if *port < 0 || *port > 65535 {
		return fail(errors.New("--port must be between 0 and 65535"))
	}
	if *timeout <= 0 || *cpu == 0 || *memory == 0 {
		return fail(errors.New("--timeout, --cpu, and --memory must be positive"))
	}
	if *concurrency < 1 || *concurrency > 256 {
		return fail(errors.New("--concurrency must be between 1 and 256"))
	}
	if *listModules {
		scripts := make([]scribe.Script, 0, len(paths)+len(inline))
		for _, path := range paths {
			source, err := readSource(path)
			if err != nil {
				return fail(err)
			}
			scripts = append(scripts, scribe.Script{ID: path, Dialect: scribe.Dialect(*dialect), Source: source})
		}
		for _, item := range inline {
			scripts = append(scripts, scribe.Script{ID: item.ID, Dialect: scribe.Dialect(*dialect), Source: []byte(item.Source)})
		}
		index, err := scribe.NewIndex(scripts)
		if err != nil {
			return fail(err)
		}
		for _, module := range index.Modules() {
			if err := json.NewEncoder(stdout).Encode(module); err != nil {
				return fail(err)
			}
		}
		return 0
	}
	if *check {
		failed := false
		for _, path := range paths {
			source, err := readSource(path)
			if err == nil {
				err = lua54.Check(scribe.Script{ID: filepath.Base(path), Dialect: scribe.Dialect(*dialect), Source: source})
				if err == nil && *strict {
					err = scribe.CheckIdentification(scribe.Script{ID: filepath.Base(path), Dialect: scribe.Dialect(*dialect), Source: source})
				}
			}
			report := struct {
				Script string `json:"script"`
				Status string `json:"status"`
				Error  string `json:"error,omitempty"`
			}{Script: path, Status: "checked"}
			if err != nil {
				report.Status = "error"
				report.Error = err.Error()
				failed = true
			}
			if err := json.NewEncoder(stdout).Encode(report); err != nil {
				return fail(err)
			}
		}
		for _, script := range inline {
			err := lua54.Check(scribe.Script{ID: script.ID, Dialect: scribe.Dialect(*dialect), Source: []byte(script.Source)})
			if err == nil && *strict {
				err = scribe.CheckIdentification(scribe.Script{ID: script.ID, Dialect: scribe.Dialect(*dialect), Source: []byte(script.Source)})
			}
			report := map[string]string{"script": script.ID, "status": "checked"}
			if err != nil {
				report["status"] = "error"
				report["error"] = err.Error()
				failed = true
			}
			if err := json.NewEncoder(stdout).Encode(report); err != nil {
				return fail(err)
			}
		}
		if failed {
			return 1
		}
		return 0
	}
	if (*factsJSONL != "" && *factsPath != "") || (*pingppPath != "" && (*factsPath != "" || *factsJSONL != "")) {
		return fail(errors.New("choose --facts, --facts-jsonl or --pingpp-jsonl"))
	}
	target := scribe.Target{Host: *host, IP: *ip, Port: uint16(*port), Protocol: *protocol, Product: *product, Service: *service, State: *state, TLS: *tls}
	targets := []scribe.Target{target}
	var targetStream func(context.Context) (scribe.Target, bool, error)
	if *pingppPath != "" {
		file, err := os.Open(*pingppPath)
		if err != nil {
			return fail(err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return fail(err)
		}
		if !info.Mode().IsRegular() {
			return fail(errors.New("--pingpp-jsonl requires a regular file"))
		}
		targetStream = pingpp.NewReader(file).Next
		targets = nil
	}
	if *factsJSONL != "" {
		file, err := os.Open(*factsJSONL)
		if err != nil {
			return fail(err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return fail(err)
		}
		if !info.Mode().IsRegular() {
			return fail(errors.New("--facts-jsonl requires a regular file"))
		}
		scan := bufio.NewScanner(file)
		scan.Buffer(make([]byte, 4096), 64<<10)
		count := 0
		targetStream = func(ctx context.Context) (scribe.Target, bool, error) {
			if err := ctx.Err(); err != nil {
				return scribe.Target{}, false, err
			}
			if !scan.Scan() {
				if err := scan.Err(); err != nil {
					return scribe.Target{}, false, err
				}
				if count == 0 {
					return scribe.Target{}, false, errors.New("facts require at least one target")
				}
				return scribe.Target{}, false, nil
			}
			count++
			if count > 65536 {
				return scribe.Target{}, false, errors.New("facts exceed 65536 targets")
			}
			var t scribe.Target
			if err := json.Unmarshal(scan.Bytes(), &t); err != nil {
				return t, false, fmt.Errorf("facts line %d: %w", count, err)
			}
			if err := t.Validate(); err != nil {
				return t, false, fmt.Errorf("facts line %d: %w", count, err)
			}
			return t, true, nil
		}
		targets = nil
	}
	if *factsPath != "" {
		data, err := readSource(*factsPath)
		if err != nil {
			return fail(err)
		}
		if err := json.Unmarshal(data, &targets); err != nil {
			return fail(err)
		}
	}
	if targetStream == nil && (len(targets) == 0 || len(targets) > 1024) {
		return fail(errors.New("facts require 1-1024 targets"))
	}
	for _, target := range targets {
		if err := target.Validate(); err != nil {
			return fail(err)
		}
	}
	if len(*argsJSON) > 64<<10 {
		return fail(errors.New("--args must be at most 64 KiB"))
	}
	var args map[string]any
	decoder := json.NewDecoder(strings.NewReader(*argsJSON))
	decoder.UseNumber()
	if err := decoder.Decode(&args); err != nil {
		return fail(fmt.Errorf("--args must be a JSON object: %w", err))
	}
	if args == nil {
		return fail(errors.New("--args must be a JSON object"))
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fail(errors.New("--args must contain exactly one JSON object"))
	}
	tasks := make([]scribe.Task, 0, len(paths))
	for _, path := range paths {
		source, err := readSource(path)
		if err != nil {
			return fail(err)
		}
		tasks = append(tasks, scribe.Task{
			Script: scribe.Script{ID: filepath.Base(path), Dialect: scribe.Dialect(*dialect), Source: source, Args: args},
			Target: target,
		})
	}
	for _, script := range inline {
		tasks = append(tasks, scribe.Task{Script: scribe.Script{ID: script.ID, Dialect: scribe.Dialect(*dialect), Source: []byte(script.Source), Args: args}, Target: target})
	}
	scripts := make([]scribe.Script, len(tasks))
	for i, t := range tasks {
		scripts[i] = t.Script
	}
	idx, err := scribe.NewIndex(scripts)
	if err != nil {
		return fail(err)
	}
	httpClient, err := httpcap.New(httpcap.Options{Timeout: *timeout})
	if err != nil {
		return fail(err)
	}
	defer httpClient.Close()
	options := lua54.Options{
		Limits:    lua54.Limits{CPU: *cpu, Memory: *memory, Timeout: *timeout},
		Functions: map[string]scribe.Function{"http.get": httpClient.Function, "http.head": httpClient.HeadFunction, "tcp.exchange": tcpcap.Function, "udp.exchange": udpcap.Function},
	}
	var runtime scribe.Runtime
	if *dialect == string(scribe.Sirius) {
		runtime, err = lua54.NewNative(options)
	} else {
		runtime, err = lua54.NewNSE(options)
	}
	if err != nil {
		return fail(err)
	}
	encoder := json.NewEncoder(stdout)
	var observer func(scribe.Event) error
	if *events {
		observer = func(event scribe.Event) error { return encoder.Encode(event) }
	}
	engine, err := scribe.New(scribe.Options{OnEvent: observer, Plan: *plan, ScriptTimeout: *timeout, GlobalInterval: *globalInterval, ModuleInterval: *moduleInterval, ModuleConcurrency: *moduleConcurrency, SNMPCommunity: *community, StrictIdentification: *strict, Exhaustive: *exhaustive, Concurrency: *concurrency, HostConcurrency: *hostConcurrency, HostInterval: *hostInterval, HostErrorBudget: *hostErrors, Strategy: scribe.Strategy(*strategy)}, runtime)
	if err != nil {
		return fail(err)
	}
	counts := scribe.Summarize(nil)
	sink := func(result scribe.Result) error {
		if *summary {
			counts.Add(result)
		}
		if *events {
			return nil
		}
		return encoder.Encode(result)
	}
	if targetStream != nil {
		err = engine.RunTargetStream(ctx, idx, targetStream, sink)
	} else {
		err = engine.RunSelected(ctx, idx, targets, sink)
	}
	if *summary {
		if encodeErr := encoder.Encode(counts); encodeErr != nil {
			return fail(encodeErr)
		}
	}
	if err != nil {
		return fail(err)
	}
	return 0
}

func readSource(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read script %q: %w", path, err)
	}
	defer file.Close()
	source, err := io.ReadAll(io.LimitReader(file, scribe.MaxSourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read script %q: %w", path, err)
	}
	if len(source) == 0 || len(source) > scribe.MaxSourceBytes {
		return nil, fmt.Errorf("script %q must contain 1-%d bytes", path, scribe.MaxSourceBytes)
	}
	return source, nil
}
