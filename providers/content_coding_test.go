package providers

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"testing"
)

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func responseWithHeaders(headers string, body []byte) []byte {
	return append(fmt.Appendf(nil, "HTTP/1.1 200 OK\r\n%s\r\n", headers), body...)
}

func chunkBody(body []byte, size int) []byte {
	var out []byte
	for len(body) > 0 {
		n := min(size, len(body))
		out = fmt.Appendf(out, "%x\r\n", n)
		out = append(out, body[:n]...)
		out = append(out, "\r\n"...)
		body = body[n:]
	}
	return append(out, "0\r\n\r\n"...)
}

const encodedHTML = `<html><body><span id="lblStdName">Test Student</span></body></html>`

var nameRedaction = ResponseRedaction{Regex: `<span id="lblStdName">(?<fullName>[^<]+)</span>`}

func TestGetResponseRedactionsRejectsContentEncodedBodies(t *testing.T) {
	gz := gzipBytes(t, encodedHTML)

	tests := []struct {
		name     string
		response []byte
		ctx      ProviderCtx
	}{
		{
			name: "gzip with Content-Encoding and Content-Length",
			response: responseWithHeaders(fmt.Sprintf(
				"Content-Type: text/html; charset=utf-8\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n", len(gz)), gz),
		},
		{
			name: "gzip with Content-Encoding and chunked framing",
			response: responseWithHeaders(
				"Content-Type: text/html; charset=utf-8\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
				chunkBody(gz, 16)),
		},
		{
			name: "gzip without any Content-Encoding header",
			response: responseWithHeaders(fmt.Sprintf(
				"Content-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n", len(gz)), gz),
		},
		{
			name: "gzip without Content-Encoding, chunked",
			response: responseWithHeaders(
				"Content-Type: text/html; charset=utf-8\r\nTransfer-Encoding: chunked\r\n",
				chunkBody(gz, 7)),
		},
		{
			name: "br declared (no magic bytes to sniff)",
			response: responseWithHeaders(
				"Content-Type: text/html\r\nContent-Encoding: br\r\nContent-Length: 4\r\n", []byte{0x0b, 0x02, 0x80, 0x00}),
		},
		{
			name: "deflate declared",
			response: responseWithHeaders(
				"Content-Type: application/json\r\nContent-Encoding: deflate\r\nContent-Length: 2\r\n", []byte{0x78, 0x9c}),
		},
		{
			name: "double encoding gzip, gzip",
			response: responseWithHeaders(fmt.Sprintf(
				"Content-Type: text/html\r\nContent-Encoding: gzip, gzip\r\nContent-Length: %d\r\n", len(gz)), gz),
		},
		{
			name: "gzip as transfer coding before chunked",
			response: responseWithHeaders(
				"Content-Type: text/html\r\nTransfer-Encoding: gzip, chunked\r\n", chunkBody(gz, 32)),
		},
		{
			name: "gzip as transfer coding before chunked, strict CBC framing",
			response: responseWithHeaders(
				"Content-Type: text/html\r\nTransfer-Encoding: gzip, chunked\r\n", chunkBody(gz, 32)),
			ctx: ProviderCtx{Version: ATTESTOR_VERSION_3_2_0, TLS12CBC: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := HTTPProviderParams{
				URL:                "https://example.com/",
				Method:             "GET",
				ResponseRedactions: []ResponseRedaction{nameRedaction},
			}
			ctx := tt.ctx
			if ctx.Version == 0 {
				ctx.Version = ATTESTOR_VERSION_3_2_0
			}
			_, err := GetResponseRedactions(tt.response, &params, &ctx, "content-coding")
			if !errors.Is(err, ErrResponseContentEncoded) {
				t.Fatalf("want ErrResponseContentEncoded, got %v", err)
			}
		})
	}
}

func TestGetResponseRedactionsAcceptsIdentityBodies(t *testing.T) {
	body := []byte(encodedHTML)
	tests := []struct {
		name     string
		response []byte
	}{
		{"no Content-Encoding", responseWithBody(body, "text/html; charset=utf-8")},
		{"explicit identity", responseWithHeaders(fmt.Sprintf(
			"Content-Type: text/html; charset=utf-8\r\nContent-Encoding: identity\r\nContent-Length: %d\r\n", len(body)), body)},
		{"chunked identity", chunkedResponse("text/html; charset=utf-8", body[:20], body[20:])},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := HTTPProviderParams{
				URL:                "https://example.com/",
				Method:             "GET",
				ResponseRedactions: []ResponseRedaction{nameRedaction},
			}
			ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}
			redactions, err := GetResponseRedactions(tt.response, &params, &ctx, "identity")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := reconstructRedactedResponse(t, tt.response, redactions); !bytes.Contains(got, []byte("Test Student")) {
				t.Fatalf("name not revealed: %q", got)
			}
		})
	}
}

func TestGetResponseRedactionsIgnoresEncodingWithoutRules(t *testing.T) {
	gz := gzipBytes(t, encodedHTML)
	response := responseWithHeaders(fmt.Sprintf(
		"Content-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n", len(gz)), gz)
	params := HTTPProviderParams{URL: "https://example.com/", Method: "GET"}
	ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}
	if _, err := GetResponseRedactions(response, &params, &ctx, "no-rules"); err != nil {
		t.Fatalf("no redaction rules must not inspect the body: %v", err)
	}
}
