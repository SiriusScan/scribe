//go:build !linux

package localcap

import (
	"context"
	"fmt"
)

func platformInventory(context.Context, bool) (any, error) {
	return nil, fmt.Errorf("local inventory unsupported on this platform")
}
