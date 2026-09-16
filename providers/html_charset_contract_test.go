package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/unicode"
)

// These fixtures are consumed by attestor-core's provider receipt verifier.
// Regenerate explicitly with UPDATE_HTML_CHARSET_FIXTURES=1 go test ./providers
// -run TestHTMLCharsetReceiptContract.
func TestHTMLCharsetReceiptContract(t *testing.T) {
	type fixture struct {
		Name         string `json:"name"`
		ContentType  string `json:"contentType"`
		Charset      string `json:"charset"`
		OriginalBody []byte `json:"originalBody"`
		Response     []byte `json:"response"`
		Match        string `json:"match"`
	}
	const realMeta = "<meta charset=windows-1251>"
	const fakeMeta = "<meta charset=windows-1252>"
	const name = "Скальська"
	var fixtures []fixture
	for _, tc := range []struct {
		name, body, match string
		encoder           encoding.Encoding
		rules             []ResponseRedaction
	}{
		{"extended-header", fakeMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"continued-header", fakeMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"extended-precedence", fakeMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"invalid-extended-header", realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"escaped-token-header", realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"unknown-entity-private", "<meta http-equiv='Content-Type' content='text/html; &PRIVATEcharset=utf-8'><span>TARGET</span>", "TARGET", nil, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"partial-entity-private", "<meta http-equiv='Content-Type' content='text/html; &#32PRIVATEcharset=utf-8'><span>TARGET</span>", "TARGET", nil, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"noscript-literal", "<noscript>" + fakeMeta + "</noscript>" + realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{Regex: regexp.QuoteMeta(fakeMeta)}, {XPath: "//span/text()"}}},
		{"selfclosing-script", "<script/>" + fakeMeta + "</script>" + realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{Regex: regexp.QuoteMeta(fakeMeta)}, {XPath: "//span/text()"}}},
		{"replacement-meta", "<meta charset=replacement>" + realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"replacement-alias", "<meta charset=iso-2022-kr>" + realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"duplicate-header", realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"malformed-header", realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"replacement-header", realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"quoted-header", realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"utf16-header-Little", "<!doctype html><html><span>" + name + "</span></html>", name, unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM), []ResponseRedaction{{XPath: "//span/text()"}}},
		{"utf16-header-Big", "<!doctype html><html><span>" + name + "</span></html>", name, unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM), []ResponseRedaction{{XPath: "//span/text()"}}},
		{"private-attributes", "<meta charset=utf-8 data-private='PRIVATE'><span>TARGET</span>", "TARGET", nil, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"private-content", "<meta data-private='PRIVATE' http-equiv='Content-Type' content='text/html; private=PRIVATE; charset=windows-1251; token=PRIVATE'><span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"entities", "<meta http-equiv='Content-Type' content='text/html; char&#115;et=windows&#45;1251; token=PRIVATE'><span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"script-literal", "<script data-private='PRIVATE'>{\"fake\":\"" + fakeMeta + "\",\"name\":\"" + name + "\"}</script>" + realMeta, name, charmap.Windows1251, []ResponseRedaction{{XPath: "//script/text()"}}},
		{"script-default", "<script>{\"fake\":\"" + fakeMeta + "\",\"name\":\"" + name + "\"}</script>", name, nil, []ResponseRedaction{{XPath: "//script/text()"}}},
		{"comment-literal", "<!-- PRIVATE " + fakeMeta + " -->" + realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{Regex: regexp.QuoteMeta(fakeMeta)}, {XPath: "//span/text()"}}},
		{"comment-bang-end", "<!-- PRIVATE " + fakeMeta + " --!>" + realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{Regex: regexp.QuoteMeta(fakeMeta)}, {XPath: "//span/text()"}}},
		{"attribute-literal", "<div data-private='PRIVATE' title='" + fakeMeta + "'></div>" + realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{Regex: regexp.QuoteMeta(fakeMeta)}, {XPath: "//span/text()"}}},
		{"textarea-literal", "<textarea>" + fakeMeta + "</textarea>" + realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//textarea/text()"}, {XPath: "//span/text()"}}},
		{"style-literal", "<style>" + fakeMeta + "</style>" + realMeta + "<span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//style/text()"}, {XPath: "//span/text()"}}},
		{"xml", "<?xml version='1.0' encoding='windows-1251'?><span>" + name + "</span>", name, charmap.Windows1251, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"xml-stylesheet", "<?xml-stylesheet encoding='windows-1251'?><span>" + name + "</span>", name, nil, []ResponseRedaction{{XPath: "//span/text()"}}},
		{"utf16-bom", "<span>" + name + "</span>", name, unicode.UTF16(unicode.BigEndian, unicode.UseBOM), []ResponseRedaction{{XPath: "//span/text()"}}},
		{"utf16-signature", "<?xml version='1.0'?><span>" + name + "</span>", name, unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM), []ResponseRedaction{{XPath: "//span/text()"}}},
		{"shift-jis", "<meta charset=shift_jis><span>名前</span>", "名前", japanese.ShiftJIS, []ResponseRedaction{{XPath: "//span/text()"}}},
	} {
		contentType := "text/html"
		switch tc.name {
		case "extended-header":
			contentType += "; charset*=utf-8''windows-1251"
		case "continued-header":
			contentType += "; charset*0*=utf-8''windows%2D; charset*1=1251"
		case "extended-precedence":
			contentType += "; charset=windows-1252; charset*=us-ascii'en'windows-1251"
		case "invalid-extended-header":
			contentType += "; charset*=utf-8''windows%ZZ1252"
		case "escaped-token-header":
			contentType += `; charset="windows\-1252"`

		case "duplicate-header":
			contentType += "; charset=windows-1252; charset=utf-8"
		case "malformed-header":
			contentType += "; broken; charset=windows-1252"
		case "replacement-header":
			contentType += "; charset=replacement"
		case "quoted-header":
			contentType += `; other="; charset=windows-1252"`
		case "utf16-header-Little":
			contentType += "; charset=utf-16le"
		case "utf16-header-Big":
			contentType += "; charset=utf-16be"
		}
		for _, chunked := range []bool{false, true} {
			for _, cbc := range []bool{false, true} {
				label := fmt.Sprintf("%s/chunked=%v/cbc=%v", tc.name, chunked, cbc)
				t.Run(label, func(t *testing.T) {
					body := []byte(tc.body)
					if tc.encoder != nil {
						var err error
						body, err = tc.encoder.NewEncoder().Bytes(body)
						if err != nil {
							t.Fatal(err)
						}
					}
					detected, err := detectResponseBodyCharset(body, contentType)
					if err != nil {
						t.Fatal(err)
					}
					response := responseWithBody(body, contentType)
					if chunked {
						response = chunkedResponse(contentType, body[:2], body[2:len(body)/2], body[len(body)/2:])
					}
					params := HTTPProviderParams{URL: "https://example.com/", Method: "GET", ResponseRedactions: tc.rules}
					ctx := ProviderCtx{Version: ATTESTOR_VERSION_3_2_0, TLS12CBC: cbc}
					ranges, err := GetResponseRedactions(response, &params, &ctx, label)
					if err != nil {
						t.Fatal(err)
					}
					revealed := reconstructRedactedResponse(t, response, ranges)
					if bytes.Contains(revealed, []byte("PRIVATE")) {
						t.Fatal("private attribute or comment text disclosed")
					}
					parsed, err := parseHTTPResponseBytes(response)
					if err != nil {
						t.Fatal(err)
					}
					revealedBody := revealed[parsed.BodyStartIndex : parsed.BodyStartIndex+len(body)]
					if chunked {
						revealedBody = nil
						for _, ch := range parsed.Chunks {
							revealedBody = append(revealedBody, revealed[ch.Start:ch.Start+ch.Length]...)
						}
					}
					replayed, err := detectResponseBodyCharset(revealedBody, contentType)
					if err != nil || detected.Charset != replayed.Charset {
						t.Fatalf("encoding changed: %+v -> %+v (%v)", detected, replayed, err)
					}
					decoded, err := decodeResponseBody(revealedBody, replayed.Charset)
					if err != nil || !bytes.Contains([]byte(decoded.text), []byte(tc.match)) {
						t.Fatalf("revealed match lost: %v", err)
					}
					fixtures = append(fixtures, fixture{label, contentType, detected.Charset, body, revealed, tc.match})
				})
			}
		}
	}
	if t.Failed() {
		return
	}
	data, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := "testdata/html_charset_receipts.json"
	if os.Getenv("UPDATE_HTML_CHARSET_FIXTURES") == "1" {
		if err := os.MkdirAll("testdata", 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), data) {
		t.Fatal("charset receipt fixtures changed; regenerate and verify in attestor-core")
	}
}
