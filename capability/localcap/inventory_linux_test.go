//go:build linux

package localcap

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestProcessInventory(t *testing.T) {
	value, err := platformInventory(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range value.([]any) {
		if row.(map[string]any)["pid"] == os.Getpid() {
			found = true
		}
	}
	if !found {
		t.Fatal("own process absent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := platformInventory(ctx, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
