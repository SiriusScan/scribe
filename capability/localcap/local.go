// Package localcap exposes opt-in endpoint-local observations, never commands.
// Files are confined to a caller-selected root. Use a local, trusted filesystem:
// OS filesystem operations cannot be interrupted while blocked in the kernel.
package localcap

import (
	"context"
	"fmt"
	"github.com/SiriusScan/scribe"
	"io"
	"os"
)

// MaxBytes bounds each local file read to 64 KiB.
const MaxBytes = 64 << 10

// MaxEntries bounds local inventory enumeration.
const MaxEntries = 1024

// New registers exact capability names for the existing per-job grant mechanism.
// The caller owns Close and must keep the root open until executions finish.
func New(directory string) (map[string]scribe.Function, func() error, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, err
	}
	file := func(read bool) scribe.Function {
		return func(ctx context.Context, _ scribe.Target, args []any) (any, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if len(args) != 1 {
				return nil, fmt.Errorf("one relative path required")
			}
			path, ok := args[0].(string)
			if !ok {
				return nil, fmt.Errorf("path must be string")
			}
			// Stat first avoids opening named pipes and devices for reads.
			info, err := root.Stat(path)
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("regular file required")
			}
			if !read {
				return map[string]any{"size": info.Size(), "mode": info.Mode().String()}, nil
			}
			if info.Size() > MaxBytes {
				return nil, fmt.Errorf("file exceeds size limit")
			}
			f, err := openRead(root, path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			opened, err := f.Stat()
			if err != nil {
				return nil, err
			}
			if !opened.Mode().IsRegular() {
				return nil, fmt.Errorf("regular file required")
			}
			data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
			if err != nil {
				return nil, err
			}
			if len(data) > MaxBytes {
				return nil, fmt.Errorf("file exceeds size limit")
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return string(data), nil
		}
	}
	return map[string]scribe.Function{"local.file.stat": file(false), "local.file.read": file(true), "local.process.list": inventory(false), "local.package.list": inventory(true)}, root.Close, nil
}
func inventory(packages bool) scribe.Function {
	return func(ctx context.Context, _ scribe.Target, args []any) (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(args) != 0 {
			return nil, fmt.Errorf("inventory takes no arguments")
		}
		return platformInventory(ctx, packages)
	}
}
