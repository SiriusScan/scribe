package tcpcap

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/SiriusScan/scribe"
)

func TestReadToEOF(t *testing.T) {
	for _, size := range []int{0, 8193, 65536, 65537} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				io.WriteString(conn, strings.Repeat("x", size))
			}()
			target := scribe.Target{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Protocol: "tcp"}
			result, err := Function(context.Background(), target, []any{"", int64(-1)})
			<-done
			if size > 65536 {
				if err == nil || result != nil {
					t.Fatalf("overflow: %v %v", result, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			reply := result.(map[string]any)
			if reply["data"] != strings.Repeat("x", size) || reply["eof"] != true {
				t.Fatalf("invalid reply for %d bytes", size)
			}
		})
	}
}

func TestReadToEOFFailureDiscardsData(t *testing.T) {
	stream := struct {
		io.Reader
		io.Writer
	}{io.MultiReader(strings.NewReader("partial"), brokenReader{}), io.Discard}
	if result, err := exchange(stream, []any{"", int64(-1)}); err == nil || result != nil {
		t.Fatalf("%v %v", result, err)
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
