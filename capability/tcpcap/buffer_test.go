package tcpcap

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

type countedReader struct {
	io.Reader
	calls int
}

func (r *countedReader) Read(p []byte) (int, error) { r.calls++; return r.Reader.Read(p) }

func TestBufferedSessionPreservesFrames(t *testing.T) {
	source := &countedReader{Reader: strings.NewReader(strings.Repeat("x", 3000) + "\r\nNEXTtail\n")}
	stream := struct {
		io.Reader
		io.Writer
	}{bufio.NewReaderSize(source, 4096), io.Discard}
	for _, step := range []struct {
		selector any
		want     string
	}{
		{"\r\n", strings.Repeat("x", 3000) + "\r\n"}, {int64(4), "NEXT"}, {"\n", "tail\n"},
	} {
		result, err := exchange(stream, []any{"", step.selector})
		if err != nil {
			t.Fatal(err)
		}
		if result.(map[string]any)["data"] != step.want {
			t.Fatalf("lost frame: %v", result)
		}
	}
	if source.calls != 1 {
		t.Fatalf("underlying reads = %d, want 1", source.calls)
	}
}
