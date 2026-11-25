// Command scribe-compat runs a pinned offline NSE fixture manifest and
// emits a versioned compatibility evidence report or verifies supplied lineage.
package main

import (
	"bytes"
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
	if len(argv) > 0 && argv[0] == "lineage" {
		return runLineage(argv[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("scribe-compat", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "compatibility manifest JSON file (required)")
	outPath := flags.String("out", "", "write the JSON report to this file instead of stdout")
	checkPath := flags.String("check", "", "compare the evidence snapshot with this file")
	snapshotPath := flags.String("snapshot", "", "write a portable evidence snapshot to this file")
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
	report, runErr := compat.Run(ctx, manifest)
	if report.SchemaVersion == 0 && runErr != nil {
		return fail(runErr)
	}
	data, err := marshalReport(report)
	if err != nil {
		return fail(err)
	}
	if *outPath != "" {
		if err := os.WriteFile(*outPath, data, 0o644); err != nil {
			return fail(fmt.Errorf("write report: %w", err))
		}
	} else if _, err := stdout.Write(data); err != nil {
		return fail(err)
	}
	if runErr != nil {
		return fail(runErr)
	}
	if !report.OK() {
		return fail(fmt.Errorf("compatibility run did not match the manifest: %d fail, %d unexpected unsupported (of %d cases)",
			report.Summary.Fail, report.Summary.Unexpected, report.Summary.Total))
	}
	if *checkPath != "" || *snapshotPath != "" {
		if err := snapshot(report, *checkPath, *snapshotPath); err != nil {
			return fail(err)
		}
	}
	return 0
}

func marshalReport(report any) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func snapshot(report compat.Report, checkPath, outPath string) error {
	report.Source = nil
	data, err := marshalReport(report)
	if err != nil {
		return err
	}
	if checkPath != "" {
		expected, err := os.ReadFile(checkPath)
		if err != nil {
			return fmt.Errorf("read evidence snapshot: %w", err)
		}
		if !bytes.Equal(data, expected) {
			return fmt.Errorf("evidence snapshot %s is stale; regenerate with make compat", checkPath)
		}
	}
	if outPath != "" {
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			return fmt.Errorf("write evidence snapshot: %w", err)
		}
	}
	return nil
}
