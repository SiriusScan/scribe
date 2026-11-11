//go:build linux

package localcap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func platformInventory(ctx context.Context, packages bool) (any, error) {
	if packages {
		f, err := os.Open("/var/lib/dpkg/status")
		if err != nil {
			return nil, fmt.Errorf("dpkg inventory unavailable: %w", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(io.LimitReader(f, 4<<20+1))
		scanner.Buffer(make([]byte, 4096), MaxBytes)
		rows := []any{}
		name := ""
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			line := scanner.Text()
			if strings.HasPrefix(line, "Package: ") {
				name = strings.TrimPrefix(line, "Package: ")
			}
			if strings.HasPrefix(line, "Version: ") {
				rows = append(rows, map[string]any{"name": name, "version": strings.TrimPrefix(line, "Version: ")})
				if len(rows) > MaxEntries {
					return nil, fmt.Errorf("inventory entry limit exceeded")
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		pos, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, err
		}
		if pos > 4<<20 {
			return nil, fmt.Errorf("inventory byte limit exceeded")
		}
		return rows, nil
	}
	f, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows := []any{}
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, err := f.ReadDir(64)
		for _, entry := range entries {
			count++
			if count > 16384 {
				return nil, fmt.Errorf("directory limit exceeded")
			}
			pid, e := strconv.Atoi(entry.Name())
			if e != nil {
				continue
			}
			rows = append(rows, map[string]any{"pid": pid})
			if len(rows) > MaxEntries {
				return nil, fmt.Errorf("inventory entry limit exceeded")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return rows, nil
}
