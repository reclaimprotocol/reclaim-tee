package providers

import (
	"strings"
	"testing"
)

func TestExtractHTMLElementsIndexesIncludesParserError(t *testing.T) {
	for _, input := range []string{
		"\x1f\x8b",
		"<p>\x01</p>",
	} {
		_, err := ExtractHTMLElementsIndexes(input, `//span`, false)
		if err == nil {
			t.Fatalf("expected binary input error for %q", input)
		}

		for _, expected := range []string{
			`failed to find XPath: "//span"`,
			"binary input is not supported",
		} {
			if !strings.Contains(err.Error(), expected) {
				t.Errorf("expected error %q to contain %q", err, expected)
			}
		}
	}
}

func TestExtractHTMLElementsIndexesRejectsComputedValues(t *testing.T) {
	const html = `<input id="firstname" value="Ada"><input id="lastname" value="Lovelace">` +
		`<oxd-layout :user='{ "firstName":"Ada","lastName":"Lovelace"}'></oxd-layout>`
	for _, expression := range []string{
		`concat(//input[@id='firstname']/@value, ' ', //input[@id='lastname']/@value)`,
		`concat(substring-before(substring-after(string(//oxd-layout/@*[name()=':user']), '"firstName":"'), '"'), ' ', substring-before(substring-after(string(//oxd-layout/@*[name()=':user']), '"lastName":"'), '"'))`,
		`string(//missing)`, `count(//input)`, `boolean(//input)`,
	} {
		ranges, err := ExtractHTMLElementsIndexes(html, expression, false)
		if err == nil || !strings.Contains(err.Error(), "response redactions require node selections with source byte ranges") || len(ranges) != 0 {
			t.Errorf("%s = %v, %v; want scalar source-range error", expression, ranges, err)
		}
	}
}

func TestExtractHTMLElementsIndexesSupportsSubstringPredicates(t *testing.T) {
	const html = `<p data-name="other:person">Skip</p><p data-name="Ada:Lovelace">Match</p>`
	const expression = `//p[substring-before(@data-name, ':')='Ada' and substring-after(@data-name, ':')='Lovelace']`
	ranges, err := ExtractHTMLElementsIndexes(html, expression, false)
	if err != nil || len(ranges) != 1 {
		t.Fatalf("got %v, %v; want one node range", ranges, err)
	}
	if got := html[ranges[0].Start:ranges[0].End]; got != `<p data-name="Ada:Lovelace">Match</p>` {
		t.Fatalf("source range = %q", got)
	}
}

func TestExtractHTMLElementsIndexesRejectsAttributesWithoutSourceRanges(t *testing.T) {
	ranges, err := ExtractHTMLElementsIndexes(`<input value="Ada">`, `//input/@value`, false)
	if len(ranges) != 0 || err == nil || !strings.Contains(err.Error(), "extract the raw attribute with regex instead") {
		t.Fatalf("got %v, %v; want missing attribute source-range error", ranges, err)
	}
}
