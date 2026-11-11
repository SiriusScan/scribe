//go:build linux || darwin

package localcap

import (
	"os"
	"syscall"
)

// Nonblocking open prevents a replaced FIFO from blocking before f.Stat.
func openRead(root *os.Root, path string) (*os.File, error) {
	return root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
