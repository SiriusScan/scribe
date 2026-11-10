// Command scribe runs explicitly selected Lua scripts against a known endpoint.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/capability/httpcap"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

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

func run(ctx context.Context, argv []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scribe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var paths scriptPaths
	flags.Var(&paths, "script", "Lua script file (repeatable, at most 64)")
	dialect := flags.String("dialect", "", "required script contract: sirius or nse (experimental subset)")
	host := flags.String("host", "", "known hostname or IP address, without scheme or port")
	ip := flags.String("ip", "", "optional fixed connection IP, preserving logical host")
	port := flags.Int("port", 0, "known port, 1-65535; 0 for a host-only task")
	protocol := flags.String("protocol", "tcp", "known transport: tcp or udp")
	service := flags.String("service", "", "caller-supplied service name")
	state := flags.String("state", "", "caller-supplied port state, for example open; empty means unknown")
	tls := flags.Bool("tls", false, "known endpoint uses TLS")
	argsJSON := flags.String("args", "{}", "script arguments as a JSON object (at most 64 KiB)")
	concurrency := flags.Int("concurrency", 4, "maximum concurrent scripts, 1-256")
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
	if flags.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments; use --script and --host"))
	}
	if *dialect != string(scribe.Sirius) && *dialect != string(scribe.NSE) {
		return fail(errors.New("--dialect must explicitly select sirius or nse"))
	}
	if len(paths) == 0 {
		return fail(errors.New("at least one --script file is required"))
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
	target := scribe.Target{Host: *host, IP: *ip, Port: uint16(*port), Protocol: *protocol, Service: *service, State: *state, TLS: *tls}
	if err := target.Validate(); err != nil {
		return fail(err)
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
	httpClient, err := httpcap.New(httpcap.Options{Timeout: *timeout})
	if err != nil {
		return fail(err)
	}
	defer httpClient.Close()
	options := lua54.Options{
		Limits:    lua54.Limits{CPU: *cpu, Memory: *memory, Timeout: *timeout},
		Functions: map[string]scribe.Function{"http.get": httpClient.Function},
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
	engine, err := scribe.New(scribe.Options{Concurrency: *concurrency}, runtime)
	if err != nil {
		return fail(err)
	}
	encoder := json.NewEncoder(stdout)
	if err := engine.Run(ctx, tasks, func(result scribe.Result) error { return encoder.Encode(result) }); err != nil {
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
