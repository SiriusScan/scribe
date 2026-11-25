package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/SiriusScan/scribe/internal/compatlineage"
)

func runLineage(argv []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scribe-compat lineage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	scopePath := flags.String("scope", "", "trusted workflow plan and pinned review digests (required)")
	candidatePath := flags.String("candidate", "", "supplied candidate records JSON")
	referencePath := flags.String("reference", "", "independently supplied reference records JSON")
	reviewPath := flags.String("review", "", "independently supplied review receipts JSON")
	outPath := flags.String("out", "", "write the JSON receipt to this file instead of stdout")
	requireQualified := flags.Bool("require-qualified", false, "exit nonzero after emitting an unqualified receipt")
	if err := flags.Parse(argv); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *scopePath == "" {
		fmt.Fprintln(stderr, "scribe-compat lineage: --scope is required and positional arguments are not accepted")
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "scribe-compat lineage: %v\n", err)
		return 1
	}
	var plan compatlineage.Plan
	candidate := compatlineage.Records{SchemaVersion: compatlineage.SchemaVersion}
	reference := compatlineage.Records{SchemaVersion: compatlineage.SchemaVersion}
	review := compatlineage.Reviews{SchemaVersion: compatlineage.SchemaVersion}
	if err := compatlineage.Load(*scopePath, &plan); err != nil {
		return fail(err)
	}
	for _, source := range []struct {
		path  string
		value any
	}{{*candidatePath, &candidate}, {*referencePath, &reference}, {*reviewPath, &review}} {
		if source.path != "" {
			if err := compatlineage.Load(source.path, source.value); err != nil {
				return fail(err)
			}
		}
	}
	report, err := compatlineage.Evaluate(plan, candidate, reference, review)
	if err != nil {
		return fail(err)
	}
	data, err := marshalReport(report)
	if err != nil {
		return fail(err)
	}
	if *outPath != "" {
		if err := os.WriteFile(*outPath, data, 0o644); err != nil {
			return fail(fmt.Errorf("write lineage receipt: %w", err))
		}
	} else if _, err := stdout.Write(data); err != nil {
		return fail(err)
	}
	if *requireQualified && !report.ReleaseQualified {
		return fail(fmt.Errorf("release is unqualified"))
	}
	return 0
}
