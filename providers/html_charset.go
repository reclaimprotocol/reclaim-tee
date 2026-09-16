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
	if name := supportedHTMLCharset(headerCharset); name != "" {
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
	if name, spans, err := scanHTMLMetaCharset(raw); err != nil {
		return responseCharsetDetection{}, err
	} else if name != "" {
		return responseCharsetDetection{name, "html-meta", spans}, nil
	}
	if name, end := scanHTMLXMLCharset(raw); name != "" {
		return responseCharsetDetection{name, "xml-declaration", []IndexRange{{Start: 0, End: end}}}, nil
	}
	if !utf8.Valid(raw) {
		return responseCharsetDetection{}, fmt.Errorf("cannot determine HTML response charset: no supported HTTP, BOM, or document declaration and body is not valid UTF-8")
	}
	return responseCharsetDetection{Charset: "utf-8", Source: "utf-8-default"}, nil
}

func scanHTMLMetaCharset(raw []byte) (string, []IndexRange, error) {
	z := html.NewTokenizer(bytes.NewReader(raw))
	offset := 0
	for {
		kind := z.Next()
		start := offset
		offset += len(z.Raw())
		if kind == html.ErrorToken {
			return "", nil, nil
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
		name := supportedHTMLCharset(label)
		if name == "" {
			continue
		}
		// HTML meta declarations cannot switch an ASCII-compatible document
		// to UTF-16. A real UTF-16 document is recognized by its BOM/header.
		if strings.HasPrefix(name, "utf-16") {
			name = "utf-8"
		} else if name == "x-user-defined" {
			name = "windows-1252"
		}
		spans, err := charsetTagEvidence(raw[start:offset], start, true)
		return name, spans, err
	}
}

// HTML's XML-declaration fallback is intentionally case-sensitive and only
// applies at byte zero. This is not an XML parser or XML media-type support.
func scanHTMLXMLCharset(raw []byte) (string, int) {
	// A processing instruction such as <?xml-stylesheet ...?> is not a
	// declaration. XML whitespace must separate the target and attributes.
	isSpace := func(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }
	if !bytes.HasPrefix(raw, []byte("<?xml")) || len(raw) <= 5 || !isSpace(raw[5]) {
		return "", 0
	}
	pos := 5
	skipSpace := func() {
		for pos < len(raw) && isSpace(raw[pos]) {
			pos++
		}
	}
	var label []byte
	seen := make(map[string]bool)
	for {
		skipSpace()
		if bytes.HasPrefix(raw[pos:], []byte("?>")) {
			pos += 2
			break
		}
		start := pos
		for pos < len(raw) && raw[pos] >= 'a' && raw[pos] <= 'z' {
			pos++
		}
		key := string(raw[start:pos])
		if (key != "version" && key != "encoding" && key != "standalone") || seen[key] {
			return "", 0
		}
		seen[key] = true
		skipSpace()
		if pos == len(raw) || raw[pos] != '=' {
			return "", 0
		}
		pos++
		skipSpace()
		if pos == len(raw) || (raw[pos] != '\'' && raw[pos] != '"') {
			return "", 0
		}
		quote := raw[pos]
		pos++
		start = pos
		for pos < len(raw) && raw[pos] != quote {
			pos++
		}
		if pos == len(raw) {
			return "", 0
		}
		value := raw[start:pos]
		pos++
		switch key {
		case "version":
			if string(value) != "1.0" && string(value) != "1.1" {
				return "", 0
			}
		case "standalone":
			if string(value) != "yes" && string(value) != "no" {
				return "", 0
			}
		case "encoding":
			label = value
			for _, b := range label {
				if b <= 0x20 {
					return "", 0
				}
			}
		}
		if !bytes.HasPrefix(raw[pos:], []byte("?>")) && (pos == len(raw) || !isSpace(raw[pos])) {
			return "", 0
		}
	}
	name := supportedHTMLCharset(string(label))
	if name == "" {
		return "", 0
	}
	if strings.HasPrefix(name, "utf-16") {
		name = "utf-8"
	}
	return name, pos
}

// HTML's content attribute allows whitespace and quoted labels; it need not
// be a syntactically valid MIME header.
func metaContentCharset(content string) string {
	label, _, _ := metaContentCharsetRange(content)
	return label
}

func metaContentCharsetRange(content string) (string, int, int) {
	lower := []byte(content)
	for i, b := range lower {
		if b >= 'A' && b <= 'Z' {
			lower[i] = b + ('a' - 'A')
		}
	}
	s := string(lower)
	for offset := 0; offset < len(s); {
		i := strings.Index(s[offset:], "charset")
		if i < 0 {
			break
		}
		start := offset + i
		offset = start + len("charset")
		for offset < len(s) && strings.ContainsRune(" \t\n\f\r", rune(s[offset])) {
			offset++
		}
		if offset == len(s) || s[offset] != '=' {
			continue
		}
		offset++
		for offset < len(s) && strings.ContainsRune(" \t\n\f\r", rune(s[offset])) {
			offset++
		}
		if offset == len(s) {
			break
		}
		if s[offset] == '\'' || s[offset] == '"' {
			end := strings.IndexByte(s[offset+1:], s[offset])
			if end < 0 {
				break
			}
			return s[offset+1 : offset+1+end], start, offset + end + 2
		}
		end := offset
		for end < len(s) && !strings.ContainsRune("; \t\n\f\r", rune(s[end])) {
			end++
		}
		return s[offset:end], start, end
	}
	return "", 0, 0
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

// The replacement decoder discards the document and is unavailable to the
// verifier's TextDecoder. Treat its labels as unsupported on both sides.
func supportedHTMLCharset(label string) string {
	enc, name := htmlcharset.Lookup(label)
	if enc == nil || name == "replacement" {
		return ""
	}
	return name
}
