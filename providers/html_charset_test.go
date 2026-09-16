package providers

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/unicode"
)

func TestHTMLCharsetRejectsUndeclaredLegacyBytes(t *testing.T) {
	// 0xe9 can be valid text in several legacy encodings. There is no
	// response-local evidence that identifies the intended one.
	raw := []byte("<span>\xe9</span>")
	for _, contentType := range []string{"text/html", "text/html; charset=unknown"} {
		detection, err := detectResponseBodyCharset(raw, contentType)
		if err == nil || !strings.Contains(err.Error(), "cannot determine HTML response charset") {
			t.Fatalf("ambiguous charset must fail explicitly: %+v, %v", detection, err)
		}
		params := HTTPProviderParams{URL: "https://example.com/", Method: "GET", ResponseRedactions: []ResponseRedaction{{XPath: "//span"}}}
		ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}
		ranges, err := GetResponseRedactions(responseWithBody(raw, contentType), &params, &ctx, "ambiguous-charset")
		if err == nil || ranges != nil {
			t.Fatalf("ambiguous response must not produce redaction ranges: %v, %v", ranges, err)
		}
	}
}

func TestHTMLCharsetSourcesPreserveChunkedRawOffsets(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, prefix, target, source string
		encoding                                  encoding.Encoding
	}{
		{"late-meta", "text/html", "<!--" + strings.Repeat("x", 2048) + "--><meta charset=windows-1251>", "Скальська", "html-meta", charmap.Windows1251},
		{"unsupported-header", "text/html; charset=unknown", "<meta charset=windows-1251>", "Скальська", "html-meta", charmap.Windows1251},
		{"xml-fallback", "text/html", "<?xml version='1.0' encoding='windows-1251'?>", "Скальська", "xml-declaration", charmap.Windows1251},
		{"utf16le-signature", "text/html", "<?xml version='1.0'?>", "Скальська", "xml-signature", unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)},
		{"utf16be-bom", "text/html; charset=utf-8", "<?xml version='1.0'?>", "Скальська", "bom", unicode.UTF16(unicode.BigEndian, unicode.UseBOM)},
		{"shift-jis", "text/html", "<meta charset=shift_jis>", "名前", "html-meta", japanese.ShiftJIS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.encoding.NewEncoder().Bytes([]byte(tc.prefix + "<p>PRIVATE_BEFORE</p><span>" + tc.target + "</span><p>PRIVATE_AFTER</p>"))
			if err != nil {
				t.Fatal(err)
			}
			detection, err := detectResponseBodyCharset(raw, tc.contentType)
			if err != nil || detection.Source != tc.source {
				t.Fatalf("detection: %+v, %v", detection, err)
			}
			decoded, err := decodeResponseBody(raw, detection.Charset)
			if err != nil {
				t.Fatal(err)
			}
			pos := strings.Index(decoded.text, tc.target)
			if pos < 0 {
				t.Fatal("target not decoded")
			}
			start, end, err := decoded.rawRange(pos, pos+len(tc.target))
			if err != nil {
				t.Fatal(err)
			}
			// The last split is inside a character for UTF-16 and Shift_JIS.
			response := chunkedResponse(tc.contentType, raw[:1], raw[1:start+1], raw[start+1:])
			params := HTTPProviderParams{URL: "https://example.com/", Method: "GET", ResponseRedactions: []ResponseRedaction{{XPath: "//span/text()", Regex: tc.target}}}
			for _, cbc := range []bool{false, true} {
				ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0, TLS12CBC: cbc}
				ranges, err := GetResponseRedactions(response, &params, &ctx, "independent-charset")
				if err != nil {
					t.Fatal(err)
				}
				revealed := reconstructRedactedResponse(t, response, ranges)
				original, err := parseHTTPResponseBytes(response)
				if err != nil {
					t.Fatal(err)
				}
				var body []byte
				for _, chunk := range original.Chunks {
					body = append(body, revealed[chunk.Start:chunk.Start+chunk.Length]...)
				}
				if !bytes.Equal(body[start:end], raw[start:end]) {
					t.Fatal("raw target bytes changed")
				}
				for _, span := range detection.Evidence {
					if !bytes.Equal(body[span.Start:span.End], raw[span.Start:span.End]) {
						t.Fatal("encoding evidence changed")
					}
				}
				for i, value := range body {
					exposed := i >= start && i < end
					for _, span := range detection.Evidence {
						exposed = exposed || (i >= span.Start && i < span.End)
					}
					if !exposed && value != '*' {
						t.Fatalf("unselected body byte %d revealed", i)
					}
				}
				replay, err := detectResponseBodyCharset(body, tc.contentType)
				if err != nil || replay.Charset != detection.Charset {
					t.Fatalf("redaction changed detection: %+v, %v", replay, err)
				}
				replayBody, err := decodeResponseBody(body, replay.Charset)
				if err != nil || !strings.Contains(replayBody.text, tc.target) {
					t.Fatalf("revealed name cannot be decoded: %v", err)
				}
			}
		})
	}
}

func TestDetectHTMLCharset(t *testing.T) {
	for _, tc := range []struct{ name, contentType, body, want, evidence string }{
		{"http equiv", "text/html", "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1251\">", "windows-1251", "<meta http-equiv=\"Content-Type\" content=\"charset=windows-1251\">"},
		{"short mixed case", "text/html", "<META CHARSET='WINDOWS-1251'/>", "windows-1251", "<META CHARSET='WINDOWS-1251'/>"},
		{"quoted content label", "text/html", "<meta content=\"charset = 'windows-1251'\" http-equiv='content-type'>", "windows-1251", "<meta content=\"charset = 'windows-1251'\" http-equiv='content-type'>"},
		{"header wins", "text/html; charset=utf-8", "<meta charset=windows-1251>", "utf-8", ""},
		{"json ignores meta", "application/json", "<meta charset=windows-1251>", "", ""},
		{"plain ignores meta", "text/plain", "<meta charset=windows-1251>", "", ""},
		{"no declaration", "text/html", "<p>Скальська</p>", "utf-8", ""},
		{"comment", "text/html", "<!-- <meta charset=windows-1251> -->", "utf-8", ""},
		{"script", "text/html", "<script>const s = '<meta charset=windows-1251>';</script>", "utf-8", ""},
		{"missing pragma", "text/html", "<meta content='text/html; charset=windows-1251'>", "utf-8", ""},
		{"invalid then valid", "text/html", "<meta charset=nonsense><meta charset=windows-1251>", "windows-1251", "<meta charset=windows-1251>"},
		{"duplicate attribute", "text/html", "<meta charset=utf-8 charset=windows-1251>", "utf-8", "<meta charset=utf-8 charset=>"},
		{"late declaration", "text/html", strings.Repeat(" ", 1024) + "<meta charset=windows-1251>", "windows-1251", "<meta charset=windows-1251>"},
		{"partial declaration", "text/html", strings.Repeat(" ", 1010) + "<meta charset=windows-1251>", "windows-1251", "<meta charset=windows-1251>"},
		{"utf16 meta", "text/html", "<meta charset=utf-16le>", "utf-8", "<meta charset=utf-16le>"},
		{"utf8 bom", "text/html; charset=windows-1251", "\xef\xbb\xbf<meta charset=windows-1251>", "utf-8", "\xef\xbb\xbf"},
		{"utf16 bom", "text/html", "\xff\xfe<\x00", "utf-16le", "\xff\xfe"},
		{"unknown header falls back", "text/html; charset=not-a-charset", "<meta charset=windows-1251>", "windows-1251", "<meta charset=windows-1251>"},
		{"unknown header UTF8 fallback", "text/html; charset=not-a-charset", "<p>hello</p>", "utf-8", ""},
		{"malformed header parameter", "text/html; charset", "<meta charset=windows-1251>", "windows-1251", "<meta charset=windows-1251>"},
		{"header alias", "text/html; charset=ISO-8859-1", "<meta charset=utf-8>", "windows-1252", ""},
		{"first declaration wins", "text/html", "<meta charset=windows-1251><meta charset=utf-8>", "windows-1251", "<meta charset=windows-1251>"},
		{"x-user-defined meta", "text/html", "<meta charset=x-user-defined>", "windows-1252", "<meta charset=x-user-defined>"},
		{"xml declaration", "text/html", "<?xml version='1.0' encoding='windows-1251'?><p>x</p>", "windows-1251", "<?xml version='1.0' encoding='windows-1251'?>"},
		{"meta precedes XML fallback", "text/html", "<?xml encoding='windows-1251'?><meta charset=utf-8>", "utf-8", "<meta charset=utf-8>"},
		{"late meta precedes XML fallback", "text/html", "<?xml encoding='windows-1251'?>" + strings.Repeat(" ", 1024) + "<meta charset=utf-8>", "utf-8", "<meta charset=utf-8>"},
		{"header precedes XML fallback", "text/html; charset=utf-8", "<?xml encoding='windows-1251'?>", "utf-8", ""},
		{"xml declaration must be first", "text/html", " <?xml encoding='windows-1251'?>", "utf-8", ""},
		{"xml declaration case sensitive", "text/html", "<?XML encoding='windows-1251'?>", "utf-8", ""},
		{"xml encoding needs quotes", "text/html", "<?xml encoding=windows-1251?>", "utf-8", ""},
		{"xml encoding needs terminator", "text/html", "<?xml encoding='windows-1251'", "utf-8", ""},
		{"xml encoding outside declaration", "text/html", "<?xml?><p encoding='windows-1251'>", "utf-8", ""},
		{"xml encoding whitespace invalid", "text/html", "<?xml encoding=' windows-1251'?>", "utf-8", ""},
		{"utf16 XML declaration", "text/html", "<?xml encoding='utf-16'?>", "utf-8", "<?xml encoding='utf-16'?>"},
		{"utf16le signature", "text/html", "<\x00?\x00x\x00m\x00l\x00", "utf-16le", "<\x00?\x00x\x00"},
		{"utf16be signature", "text/html", "\x00<\x00?\x00x\x00m\x00l", "utf-16be", "\x00<\x00?\x00x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detection, err := detectResponseBodyCharset([]byte(tc.body), tc.contentType)
			if err != nil {
				t.Fatal(err)
			}
			got, spans := detection.Charset, detection.Evidence
			if got != tc.want {
				t.Fatalf("charset = %q, want %q", got, tc.want)
			}
			var evidence string
			for _, span := range spans {
				evidence += tc.body[span.Start:span.End]
			}
			if evidence != tc.evidence {
				t.Fatalf("evidence = %q, want %q", evidence, tc.evidence)
			}
		})
	}
}

func TestHTMLXMLCharsetRejectsProcessingInstructionsAndEmbeddedEncoding(t *testing.T) {
	for _, prefix := range []string{
		"<?xml-stylesheet encoding='windows-1251'?>",
		"<?xmlfoo encoding='windows-1251'?>",
		"<?xmlencoding='windows-1251'?>",
		"<?xml\fencoding='windows-1251'?>",
		"<?xml notencoding='windows-1251'?>",
		"<?xml version=\"encoding='windows-1251'\"?>",
		"<?xml version='1.0' note=\"encoding='windows-1251'\"?>",
		"<?xml version='1.0'encoding='windows-1251'?>",
		"<?xml encoding='windows-1251' encoding='utf-8'?>",
		"<?xml encoding='windows-1251'>",
		"<?xml encoding='windows-1251' broken?>",
	} {
		t.Run(prefix, func(t *testing.T) {
			const target = "Скальська"
			raw := []byte(prefix + "<span>" + target + "</span>")
			detection, err := detectResponseBodyCharset(raw, "text/html")
			if err != nil || detection.Charset != "utf-8" || len(detection.Evidence) != 0 {
				t.Fatalf("non-declaration changed UTF-8 detection: %+v, %v", detection, err)
			}
			params := HTTPProviderParams{URL: "https://example.com/", Method: "GET", ResponseRedactions: []ResponseRedaction{{XPath: "//span/text()", Regex: target}}}
			ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0}
			response := responseWithBody(raw, "text/html")
			ranges, err := GetResponseRedactions(response, &params, &ctx, "xml-instruction-regression")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(reconstructRedactedResponse(t, response, ranges), []byte(target)) {
				t.Fatal("UTF-8 name was lost during redaction")
			}
		})
	}
}

func TestHTMLXMLCharsetParsesDeclarationAttributes(t *testing.T) {
	for _, declaration := range []string{
		"<?xml version='1.0' encoding='windows-1251'?>",
		"<?xml\nversion = \"1.1\"\tencoding = \"windows-1251\"\rstandalone='yes' ?>",
		"<?xml encoding='windows-1251'?>",
	} {
		t.Run(declaration, func(t *testing.T) {
			charset, end := scanHTMLXMLCharset([]byte(declaration + "<p>body</p>"))
			if charset != "windows-1251" || end != len(declaration) {
				t.Fatalf("declaration parse = (%q, %d), want (%q, %d)", charset, end, "windows-1251", len(declaration))
			}
		})
	}
}

func TestHTMLMetaCharsetRedactionPreservesOriginalBytes(t *testing.T) {
	const meta = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1251\">"
	const name = "Скальська"
	raw, err := charmap.Windows1251.NewEncoder().Bytes([]byte("<html><head>" + meta + "</head><body><p>Приватні дані</p><table><tr><td id='TabCell'>" + name + "</td></tr></table><p>PRIVATE_AFTER</p></body></html>"))
	if err != nil {
		t.Fatal(err)
	}
	rawName, err := charmap.Windows1251.NewEncoder().Bytes([]byte(name))
	if err != nil {
		t.Fatal(err)
	}
	nameStart := bytes.Index(raw, rawName)
	for _, chunked := range []bool{false, true} {
		for _, cbc := range []bool{false, true} {
			for _, xpath := range []string{"", "//td[@id='TabCell'][1]/text()"} {
				t.Run(strings.Join([]string{map[bool]string{true: "chunked", false: "fixed"}[chunked], map[bool]string{true: "CBC", false: "AEAD"}[cbc], xpath}, "/"), func(t *testing.T) {
					response := responseWithBody(raw, "text/html")
					if chunked {
						// Split both the declaration and the single-byte Cyrillic name.
						response = chunkedResponse("text/html", raw[:35], raw[35:nameStart+3], raw[nameStart+3:])
					}
					params := HTTPProviderParams{URL: "https://example.com/", Method: "GET", ResponseRedactions: []ResponseRedaction{{XPath: xpath, Regex: name}}}
					ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0, TLS12CBC: cbc}
					ranges, err := GetResponseRedactions(response, &params, &ctx, "meta-charset-regression")
					if err != nil {
						t.Fatal(err)
					}
					revealed := reconstructRedactedResponse(t, response, ranges)
					parsed, err := parseHTTPResponseBytesWithFraming(response, cbc)
					if err != nil {
						t.Fatal(err)
					}
					// AEAD redacts header CRLFs as well as their values. Use
					// the original framing to inspect its authenticated body.
					revealedBody := revealed[parsed.BodyStartIndex:]
					if chunked {
						revealedBody = nil
						for _, chunk := range parsed.Chunks {
							revealedBody = append(revealedBody, revealed[chunk.Start:chunk.Start+chunk.Length]...)
						}
					}
					if cbc {
						if _, err := parseHTTPResponseBytesWithFraming(revealed, true); err != nil {
							t.Fatalf("CBC framing no longer parses: %v", err)
						}
					}
					if !bytes.Contains(revealedBody, rawName) {
						t.Fatal("raw name lost or truncated")
					}
					if !bytes.Contains(revealedBody, []byte("charset=windows-1251")) {
						t.Fatal("charset evidence lost")
					}
					if bytes.Contains(revealedBody, []byte("PRIVATE_AFTER")) {
						t.Fatal("unselected body leaked")
					}
					detection, err := detectResponseBodyCharset(revealedBody, parsed.Headers["content-type"])
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := decodeResponseBody(revealedBody, detection.Charset)
					if err != nil || !strings.Contains(decoded.text, name) {
						t.Fatalf("revealed response cannot match expected name: %v", err)
					}
				})
			}
		}
	}
}

func TestHTMLCharsetDoesNotGuessUTF16FromLessThan(t *testing.T) {
	for _, enc := range []encoding.Encoding{unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM), unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM)} {
		for _, markup := range []string{"<!doctype html><p>ASCII</p>", "<html><p>ASCII</p></html>", "<meta charset=utf-16>"} {
			raw, err := enc.NewEncoder().Bytes([]byte(markup))
			if err != nil {
				t.Fatal(err)
			}
			detected, err := detectResponseBodyCharset(raw, "text/html")
			if err != nil || detected.Charset != "utf-8" {
				t.Fatalf("generic '<' must not override UTF-8 fallback: %+v %v", detected, err)
			}
		}
	}
}
