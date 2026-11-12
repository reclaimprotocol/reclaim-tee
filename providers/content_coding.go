package providers

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// ErrResponseContentEncoded marks a response whose body is still compressed
// even though the request sent "Accept-Encoding: identity".
//
// Selective disclosure works on byte ranges of the TLS plaintext. DEFLATE and
// Brotli output has no byte-aligned mapping back to the decompressed text, so a
// field inside a compressed body cannot be revealed on its own. Decoding before
// redaction would match text the verifier never sees. So the only sound action is
// to stop with a clear error: callers may retry (another backend may honour
// identity) and must not treat it as a broken provider config.
var ErrResponseContentEncoded = errors.New("response body is content-encoded although Accept-Encoding: identity was sent")

// gzipMagic is the RFC 1952 member header: ID1, ID2, CM=8 (deflate).
// No HTML, JSON or text body begins with byte 0x1f, so false positives are not
// a practical concern.
var gzipMagic = []byte{0x1f, 0x8b, 0x08}

// checkResponseNotContentEncoded returns ErrResponseContentEncoded (wrapped with
// details) when the response declares a content or transfer coding other than
// identity/chunked, or when the body starts with gzip magic bytes regardless of
// headers (some servers compress without a Content-Encoding header).
//
// headers must be lowercased header names, as built by the response parser.
// body must be the de-chunked body.
func checkResponseNotContentEncoded(headers map[string]string, body []byte) error {
	if coding := nonIdentityCoding(headers["content-encoding"], false); coding != "" {
		return fmt.Errorf("%w (Content-Encoding: %s)", ErrResponseContentEncoded, coding)
	}
	if coding := nonIdentityCoding(headers["transfer-encoding"], true); coding != "" {
		return fmt.Errorf("%w (Transfer-Encoding: %s)", ErrResponseContentEncoded, coding)
	}
	if bytes.HasPrefix(body, gzipMagic) {
		return fmt.Errorf("%w (gzip magic bytes in body without a matching Content-Encoding header)", ErrResponseContentEncoded)
	}
	return nil
}

// nonIdentityCoding returns the first coding in a comma-separated header value
// that is not "identity" (or "chunked" for Transfer-Encoding), or "".
func nonIdentityCoding(value string, allowChunked bool) string {
	for _, coding := range strings.Split(value, ",") {
		coding = strings.ToLower(strings.TrimSpace(coding))
		switch {
		case coding == "", coding == "identity":
			continue
		case allowChunked && coding == "chunked":
			continue
		default:
			return coding
		}
	}
	return ""
}
