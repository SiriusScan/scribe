package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// runHandler deliberately delegates validation, execution and result encoding to run.
func runHandler() http.Handler {
	slots := make(chan struct{}, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
		var request struct {
			Args    []string       `json:"args"`
			Scripts []inlineScript `json:"scripts"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&request); err != nil {
			http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
			http.Error(w, "expected one JSON object", http.StatusBadRequest)
			return
		}
		for _, arg := range request.Args {
			if arg == "serve" || arg == "--version" || arg == "-version" || arg == "--help" || arg == "-help" || arg == "-h" {
				http.Error(w, "expected execution arguments", http.StatusBadRequest)
				return
			}
		}
		// Buffer only enough to identify pre-execution failures; results stream as JSONL.
		out := &resultWriter{w: w}
		var diagnostics bytes.Buffer
		code := runScripts(r.Context(), request.Args, request.Scripts, out, &diagnostics)
		if !out.started {
			if code != 0 {
				http.Error(w, diagnostics.String(), http.StatusBadRequest)
			} else {
				http.Error(w, "no results", http.StatusBadRequest)
			}
		}
	})
	return mux
}

type resultWriter struct {
	w       http.ResponseWriter
	started bool
}

func (w *resultWriter) Write(p []byte) (int, error) {
	if !w.started {
		w.w.Header().Set("Content-Type", "application/x-ndjson")
		w.w.WriteHeader(http.StatusOK)
		w.started = true
	}
	n, err := w.w.Write(p)
	if f, ok := w.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

func serve(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("scribe serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "scribe serve: unexpected positional arguments")
		return 1
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	server := &http.Server{Handler: runHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	err = server.Serve(listener)
	close(done)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
