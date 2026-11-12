package tcpcap

import (
	"bytes"
	"io"
	"testing"
)

type noRead struct{ bytes.Buffer }

func (*noRead) Read([]byte) (int, error) { panic("write-only step read from connection") }
func TestWriteOnlyExchange(t *testing.T) {
	s := &noRead{}
	got, err := exchange(s, []any{"command\r\n", int64(0)})
	if err != nil {
		t.Fatal(err)
	}
	r := got.(map[string]any)
	if s.String() != "command\r\n" || r["data"] != "" || r["eof"] != false {
		t.Fatalf("%v %q", got, s.String())
	}
}
func TestWriteOnlyFailure(t *testing.T) {
	s := struct {
		io.Reader
		io.Writer
	}{bytes.NewReader(nil), failingWriter{}}
	if got, err := exchange(s, []any{"command", int64(0)}); err == nil || got != nil {
		t.Fatalf("%v %v", got, err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
