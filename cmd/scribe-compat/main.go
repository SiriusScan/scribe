// Command scribe-compat runs a pinned NSE compatibility manifest through
// Scribe's experimental NSE profile and emits a JSON report with one
// pass, fail, or unsupported entry (plus the exact script digest and
// reason) per case. It exits nonzero when any case fails or is
// unsupported contrary to the manifest's expectation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/SiriusScan/scribe/compat"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, argv []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scribe-compat", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "compatibility manifest JSON file (required)")
	outPath := flags.String("out", "", "write the JSON report to this file instead of stdout")
	if err := flags.Parse(argv); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "scribe-compat: %v\n", err)
		return 1
	}
	if flags.NArg() != 0 || *manifestPath == "" {
		fmt.Fprintln(stderr, "scribe-compat: --manifest is required and positional arguments are not accepted")
		return 2
	}
	manifest, err := compat.LoadManifest(*manifestPath)
	if err != nil {
		return fail(err)
	}
	report, err := compat.Run(ctx, manifest)
	if err != nil && len(report.Results) == 0 {
		return fail(err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fail(err)
	}
	data = append(data, '\n')
	if *outPath != "" {
		if err := os.WriteFile(*outPath, data, 0o644); err != nil {
			return fail(fmt.Errorf("write report: %w", err))
		}
	} else if _, err := stdout.Write(data); err != nil {
		return fail(err)
	}
	if err != nil {
		return fail(err)
	}
	if !report.OK() {
		return fail(fmt.Errorf("compatibility run did not match the manifest: %d fail, %d unexpected unsupported (of %d cases)",
			report.Summary.Fail, report.Summary.Unexpected, report.Summary.Total))
	}
	return 0
}
