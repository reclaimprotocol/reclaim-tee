package providers

import (
	"bytes"
	"fmt"
	"mime"
	"strings"
	"unicode/utf8"

	"github.com/reclaimprotocol/reclaim-tee/shared"
	"golang.org/x/net/html"
	htmlcharset "golang.org/x/net/html/charset"
)

type responseCharsetDetection struct {
	Charset  string
	Source   string
	Evidence []IndexRange
}

// detectResponseBodyCharset uses only response bytes and transport metadata.
// Evidence refers to original dechunked bytes, never decoded character offsets.
// It deliberately does not guess from a browser's locale, history or parent
// frame, which an independent verifier cannot recover from this response.
func detectResponseBodyCharset(raw []byte, contentType string) (responseCharsetDetection, error) {
	headerCharset := responseBodyCharset(contentType)
	// An invalid charset parameter must not prevent HTML declaration fallback.
	essence, _, _ := strings.Cut(contentType, ";")
	mediaType, _, _ := mime.ParseMediaType(essence)
	if mediaType != "text/html" {
		source := "utf-8-default"
		if headerCharset != "" {
			source = "http-header"
		}
		return responseCharsetDetection{Charset: headerCharset, Source: source}, nil
	}
	// For HTML a byte-order mark takes precedence over transport metadata.
	for _, bom := range []struct {
		bytes []byte
		name  string
	}{
		{[]byte{0xef, 0xbb, 0xbf}, "utf-8"},
		{[]byte{0xff, 0xfe}, "utf-16le"},
		{[]byte{0xfe, 0xff}, "utf-16be"},
	} {
		if bytes.HasPrefix(raw, bom.bytes) {
			return responseCharsetDetection{bom.name, "bom", []IndexRange{{Start: 0, End: len(bom.bytes)}}}, nil
		}
	}
	if enc, name := htmlcharset.Lookup(headerCharset); enc != nil {
		return responseCharsetDetection{Charset: name, Source: "http-header"}, nil
	}

	// HTML also recognizes the UTF-16 '<?x' signatures without a BOM.
	for _, signature := range []struct {
		bytes []byte
		name  string
	}{
		{[]byte{'<', 0, '?', 0, 'x', 0}, "utf-16le"},
		{[]byte{0, '<', 0, '?', 0, 'x'}, "utf-16be"},
	} {
		if bytes.HasPrefix(raw, signature.bytes) {
			return responseCharsetDetection{signature.name, "xml-signature", []IndexRange{{Start: 0, End: len(signature.bytes)}}}, nil
		}
	}

	// The complete response is already available. Continue past the browser's
	// initial 1024-byte prescan so late declarations are not silently missed.
	// Tokenization excludes comments and raw-text elements such as scripts.
	if name, span := scanHTMLMetaCharset(raw); name != "" {
		return responseCharsetDetection{name, "html-meta", []IndexRange{span}}, nil
	}
	if name, end := scanHTMLXMLCharset(raw); name != "" {
		return responseCharsetDetection{name, "xml-declaration", []IndexRange{{Start: 0, End: end}}}, nil
	}
	if !utf8.Valid(raw) {
		return responseCharsetDetection{}, fmt.Errorf("cannot determine HTML response charset: no supported HTTP, BOM, or document declaration and body is not valid UTF-8")
	}
	return responseCharsetDetection{Charset: "utf-8", Source: "utf-8-default"}, nil
}

func scanHTMLMetaCharset(raw []byte) (string, IndexRange) {
	z := html.NewTokenizer(bytes.NewReader(raw))
	offset := 0
	for {
		kind := z.Next()
		start := offset
		offset += len(z.Raw())
		if kind == html.ErrorToken {
			return "", IndexRange{}
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		token := z.Token()
		if token.Data != "meta" {
			continue
		}
		attrs := make(map[string]string)
		for _, attr := range token.Attr {
			if _, exists := attrs[attr.Key]; !exists {
				attrs[attr.Key] = attr.Val
			}
		}
		label, direct := attrs["charset"]
		if !direct && strings.EqualFold(attrs["http-equiv"], "content-type") {
			label = metaContentCharset(attrs["content"])
		}
		enc, name := htmlcharset.Lookup(label)
		if enc == nil {
			continue
		}
		// HTML meta declarations cannot switch an ASCII-compatible document
		// to UTF-16. A real UTF-16 document is recognized by its BOM/header.
		if strings.HasPrefix(name, "utf-16") {
			name = "utf-8"
		} else if name == "x-user-defined" {
			name = "windows-1252"
		}
		return name, IndexRange{Start: start, End: offset}
	}
}

// HTML's XML-declaration fallback is intentionally case-sensitive and only
// applies at byte zero. This is not an XML parser or XML media-type support.
func scanHTMLXMLCharset(raw []byte) (string, int) {
	if !bytes.HasPrefix(raw, []byte("<?xml")) {
		return "", 0
	}
	end := bytes.IndexByte(raw, '>')
	if end < 0 {
		return "", 0
	}
	declaration := raw[:end]
	pos := bytes.Index(declaration, []byte("encoding"))
	if pos < 0 {
		return "", 0
	}
	s := declaration[pos+len("encoding"):]
	trim := func(b []byte) []byte {
		for len(b) > 0 && b[0] <= 0x20 {
			b = b[1:]
		}
		return b
	}
	s = trim(s)
	if len(s) == 0 || s[0] != '=' {
		return "", 0
	}
	s = trim(s[1:])
	if len(s) == 0 || (s[0] != '"' && s[0] != '\'') {
		return "", 0
	}
	closeQuote := bytes.IndexByte(s[1:], s[0])
	if closeQuote < 0 {
		return "", 0
	}
	label := s[1 : closeQuote+1]
	for _, b := range label {
		if b <= 0x20 {
			return "", 0
		}
	}
	enc, name := htmlcharset.Lookup(string(label))
	if enc == nil {
		return "", 0
	}
	if strings.HasPrefix(name, "utf-16") {
		name = "utf-8"
	}
	return name, end + 1
}

// HTML's content attribute allows whitespace and quoted labels; it need not
// be a syntactically valid MIME header.
func metaContentCharset(content string) string {
	s := strings.ToLower(content)
	for {
		i := strings.Index(s, "charset")
		if i < 0 {
			return ""
		}
		s = strings.TrimLeft(s[i+len("charset"):], " \t\n\f\r")
		if !strings.HasPrefix(s, "=") {
			continue
		}
		s = strings.TrimLeft(s[1:], " \t\n\f\r")
		if s == "" {
			return ""
		}
		if s[0] == '\'' || s[0] == '"' {
			if end := strings.IndexByte(s[1:], s[0]); end >= 0 {
				return s[1 : end+1]
			}
			return ""
		}
		if end := strings.IndexAny(s, "; \t\n\f\r"); end >= 0 {
			return s[:end]
		}
		return s
	}
}

// Reveal only declaration bytes, splitting at chunk boundaries so a
// declaration spanning chunks cannot accidentally disclose chunk extensions.
func charsetEvidenceReveals(evidence []IndexRange, bodyStart int, chunks []shared.ResponseRedactionRange) []shared.ResponseRedactionRange {
	var reveals []shared.ResponseRedactionRange
	for _, span := range evidence {
		if len(chunks) == 0 {
			reveals = append(reveals, shared.ResponseRedactionRange{Start: bodyStart + span.Start, Length: span.End - span.Start})
			continue
		}
		offset := 0
		for _, chunk := range chunks {
			start, end := max(span.Start, offset), min(span.End, offset+chunk.Length)
			if end > start {
				reveals = append(reveals, shared.ResponseRedactionRange{Start: chunk.Start + start - offset, Length: end - start})
			}
			offset += chunk.Length
		}
	}
	return reveals
}
