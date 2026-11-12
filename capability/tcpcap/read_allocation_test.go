package tcpcap

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestExactReadLeavesFollowingFrame(t *testing.T) {
	stream := struct{ *bytes.Buffer }{bytes.NewBufferString("ABCnext")}
	got, err := exchange(stream, []any{"", int64(3)})
	if err != nil {
		t.Fatal(err)
	}
	reply := got.(map[string]any)
	if reply["data"] != "ABC" || reply["eof"] != false || stream.String() != "next" {
		t.Fatalf("reply=%v remaining=%q", reply, stream.String())
	}
}

func BenchmarkSmallExactReply(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		stream := struct {
			io.Reader
			io.Writer
		}{strings.NewReader("X"), new(bytes.Buffer)}
		got, err := exchange(stream, []any{"", int64(1)})
		if err != nil || got.(map[string]any)["data"] != "X" {
			b.Fatalf("%v %v", got, err)
		}
	}
}
