package main

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestServeCancelledShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan int, 1)
	go func() { done <- serve(ctx, []string{"--listen", "127.0.0.1:0"}, &bytes.Buffer{}) }()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal(code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown stalled")
	}
}
