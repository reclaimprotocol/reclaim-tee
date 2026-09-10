package providers

import (
	"strings"
	"testing"
)

func TestHTTPResponseFramer(t *testing.T) {
	tests := []struct {
		name, method, response        string
		complete, invalid, invalidEOF bool
	}{
		{name: "content length", response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", complete: true},
		{name: "zero length", response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", complete: true},
		{name: "chunk trailers", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;name=value\r\nhello\r\n0\r\nX-Trailer: value\r\n\r\n", complete: true},
		{name: "unknown length", response: "HTTP/1.1 200 OK\r\n\r\nhello"},
		{name: "head no length", method: "HEAD", response: "HTTP/1.1 200 OK\r\n\r\n", complete: true},
		{name: "no content", response: "HTTP/1.1 204 No Content\r\n\r\n", complete: true},
		{name: "short body", response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi", invalidEOF: true},
		{name: "missing zero chunk", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", invalidEOF: true},
		{name: "missing trailers end", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: value\r\n", invalidEOF: true},
		{name: "invalid trailer", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\ninvalid\r\n\r\n", invalid: true},
		{name: "framing trailer", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 1\r\n\r\n", invalid: true},
		{name: "missing data CRLF", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello", invalidEOF: true},
		{name: "incomplete headers", response: "HTTP/1.1 200 OK\r\nContent-Length:", invalidEOF: true},
		{name: "trailing bytes", response: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhello", invalid: true},
		{name: "zero trailing bytes", response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nx", invalid: true},
		{name: "duplicate CL", response: "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx", invalid: true},
		{name: "empty CL", response: "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n", invalid: true},
		{name: "ambiguous framing", response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", invalid: true},
		{name: "unsupported interim", response: "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", invalid: true},
		{name: "unsupported upgrade", response: "HTTP/1.1 101 Switching Protocols\r\n\r\n", invalid: true},
		{name: "unsupported connect", method: "CONNECT", response: "HTTP/1.1 200 OK\r\n\r\n", invalid: true},
		{name: "unsupported head representation", method: "HEAD", response: "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n", invalid: true},
		{name: "header limit", response: "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", maxResponseHeaderBytes), invalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, step := range []int{1, 7, len(tt.response)} {
				f := NewHTTPResponseFramer(tt.method)
				var err error
				for offset := 0; offset < len(tt.response); offset += step {
					err = f.OnChunk([]byte(tt.response[offset:min(offset+step, len(tt.response))]))
					if err != nil {
						break
					}
				}
				if (err != nil) != tt.invalid {
					t.Fatalf("step %d: OnChunk error = %v, invalid=%v", step, err, tt.invalid)
				}
				if tt.invalid {
					if f.Complete() {
						t.Fatal("invalid response marked complete")
					}
					continue
				}
				if f.Complete() != tt.complete {
					t.Fatalf("step %d: complete=%v want=%v", step, f.Complete(), tt.complete)
				}
				if err := f.StreamEnded(); (err != nil) != tt.invalidEOF {
					t.Fatalf("step %d: EOF error=%v, invalidEOF=%v", step, err, tt.invalidEOF)
				}
			}
		})
	}
}
