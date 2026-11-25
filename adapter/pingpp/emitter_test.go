package pingpp

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRealEmitter(t *testing.T) {
	repo := os.Getenv("PINGPP_REPO")
	if repo == "" {
		t.Skip("set PINGPP_REPO to enable the external ping++ emitter integration")
	}
	if _, err := os.Stat(filepath.Join(repo, "cmd/pingpp-scan/main.go")); err != nil {
		t.Fatalf("PINGPP_REPO must point to a ping++ checkout: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd := exec.CommandContext(ctx, "go", "run", "./cmd/pingpp-scan", listener.Addr().String())
	cmd.Dir = repo
	wire, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	reader := NewReader(bytes.NewReader(wire))
	target, ok, err := reader.Next(ctx)
	if err != nil || !ok || target.State != "open" || target.Product != "" {
		t.Fatalf("%+v %v %v", target, ok, err)
	}
	if _, ok, err := reader.Next(ctx); ok || err != nil {
		t.Fatalf("incomplete stream: %v %v", ok, err)
	}
}
