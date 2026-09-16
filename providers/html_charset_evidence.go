package providers

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

type charsetAttribute struct {
	name  string
	value IndexRange
}

// Keep tag syntax and quotes, not unrelated attribute values. The lexer only
// locates raw ranges; the HTML tokenizer remains responsible for semantics.
func charsetTagEvidence(tag []byte, base int, declaration bool) ([]IndexRange, error) {
	space := func(b byte) bool { return strings.ContainsRune(" \t\r\n\f", rune(b)) }
	i := 1
	if i < len(tag) && tag[i] == '/' {
		i++
	}
	for i < len(tag) && !space(tag[i]) && tag[i] != '>' && tag[i] != '/' {
		i++
	}
	var attrs []charsetAttribute
	for i < len(tag) {
		for i < len(tag) && (space(tag[i]) || tag[i] == '/') {
			i++
		}
		if i == len(tag) || tag[i] == '>' {
			break
		}
		start := i
		for i < len(tag) && !space(tag[i]) && tag[i] != '=' && tag[i] != '>' && tag[i] != '/' {
			i++
		}
		if start == i {
			return nil, fmt.Errorf("cannot preserve malformed charset tag context")
		}
		key := strings.ToLower(string(tag[start:i]))
		for i < len(tag) && space(tag[i]) {
			i++
		}
		value := IndexRange{Start: i, End: i}
		if i < len(tag) && tag[i] == '=' {
			i++
			for i < len(tag) && space(tag[i]) {
				i++
			}
			if i < len(tag) && (tag[i] == '\'' || tag[i] == '"') {
				quote := tag[i]
				i++
				start = i
				for i < len(tag) && tag[i] != quote {
					i++
				}
				if i == len(tag) {
					return nil, fmt.Errorf("unterminated charset tag attribute")
				}
				value = IndexRange{Start: start, End: i}
				i++
			} else {
				start = i
				for i < len(tag) && !space(tag[i]) && tag[i] != '>' {
					i++
				}
				value = IndexRange{Start: start, End: i}
			}
		}
		attrs = append(attrs, charsetAttribute{key, value})
	}
	var spans []IndexRange
	cursor := 0
	first := map[string]charsetAttribute{}
	for _, attr := range attrs {
		if cursor < attr.value.Start {
			spans = append(spans, IndexRange{Start: base + cursor, End: base + attr.value.Start})
		}
		cursor = attr.value.End
		if _, exists := first[attr.name]; !exists {
			first[attr.name] = attr
		}
	}
	if cursor < len(tag) {
		spans = append(spans, IndexRange{Start: base + cursor, End: base + len(tag)})
	}
	if !declaration {
		return spans, nil
	}
	reveal := func(span IndexRange) {
		if span.End > span.Start {
			spans = append(spans, IndexRange{Start: base + span.Start, End: base + span.End})
		}
	}
	if attr, ok := first["charset"]; ok {
		reveal(attr.value)
	} else {
		reveal(first["http-equiv"].value)
		attr := first["content"]
		value := tag[attr.value.Start:attr.value.End]
		decoded, mapping := charsetAttributeText(value)
		label, start, end := metaContentCharsetRange(decoded)
		if label == "" || end > len(mapping) {
			return nil, fmt.Errorf("cannot preserve charset content attribute")
		}
		// Keep the delimiter after an unquoted label. Replacing it with '*'
		// would extend the label into the redacted private parameters.
		if end < len(mapping) && strings.ContainsRune("; \t\n\f\r", rune(decoded[end])) {
			end++
		}
		reveal(IndexRange{Start: attr.value.Start + mapping[start].Start, End: attr.value.Start + mapping[end-1].End})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
	return spans, nil
}

// Track entity-decoded attribute bytes back to their original wire bytes.
func charsetAttributeText(raw []byte) (string, []IndexRange) {
	var out strings.Builder
	var mapping []IndexRange
	for i := 0; i < len(raw); {
		end := i + 1
		text := string(raw[i:end])
		if raw[i] == '&' {
			for end < len(raw) && ((raw[end] >= 'a' && raw[end] <= 'z') || (raw[end] >= 'A' && raw[end] <= 'Z') || (raw[end] >= '0' && raw[end] <= '9') || raw[end] == '#') {
				end++
			}
			if end < len(raw) && raw[end] == ';' {
				end++
			}
			// Decode in attribute context (legacy entities followed by an
			// alphanumeric byte or '=' must remain literal).
			z := html.NewTokenizer(strings.NewReader(`<a x="` + string(raw[i:end]) + `">`))
			z.Next()
			text = z.Token().Attr[0].Val
			if end < len(raw) && raw[end] == '=' && raw[end-1] != ';' && i+1 < end && raw[i+1] != '#' {
				text = string(raw[i:end])
			}
			// An entity may leave an unchanged suffix. Those bytes retain
			// individual offsets, rather than inheriting the entity's span.
			for end > i && len(text) > 0 && raw[end-1] == text[len(text)-1] {
				end--
				text = text[:len(text)-1]
			}
			if end == i {
				end = i + 1
				text = string(raw[i:end])
			}
		}
		out.WriteString(text)
		for range len(text) {
			mapping = append(mapping, IndexRange{Start: i, End: end})
		}
		i = end
	}
	return out.String(), mapping
}

// A revealed literal <meta> in script/comment text or an attribute must stay
// inside its original lexical container when the verifier scans the body.
func charsetContextEvidence(raw []byte) ([]IndexRange, error) {
	z := html.NewTokenizer(bytes.NewReader(raw))
	var spans, rawTextOpening []IndexRange
	rawTextNeedsClose := false
	offset := 0
	containsMeta := func(b []byte) bool { return bytes.Contains(bytes.ToLower(b), []byte("<meta")) }
	for {
		kind := z.Next()
		start := offset
		tokenBytes := bytes.Clone(z.Raw())
		offset += len(tokenBytes)
		if kind == html.ErrorToken {
			return spans, nil
		}
		switch kind {
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			token := z.Token()
			if kind == html.EndTagToken && rawTextNeedsClose {
				syntax, err := charsetTagEvidence(tokenBytes, start, false)
				if err != nil {
					return nil, err
				}
				spans = append(spans, syntax...)
			}
			rawTextOpening = nil
			rawTextNeedsClose = false
			isRawText := strings.Contains("|script|style|title|textarea|xmp|iframe|noembed|noframes|noscript|plaintext|", "|"+token.Data+"|")
			if (isRawText && (kind == html.StartTagToken || kind == html.SelfClosingTagToken)) || containsMeta(tokenBytes[1:]) {
				syntax, err := charsetTagEvidence(tokenBytes, start, false)
				if err != nil {
					return nil, err
				}
				if isRawText && (kind == html.StartTagToken || kind == html.SelfClosingTagToken) {
					rawTextOpening = syntax
				}
				if containsMeta(tokenBytes[1:]) {
					spans = append(spans, syntax...)
				}
			}
		case html.TextToken:
			if len(rawTextOpening) > 0 && containsMeta(tokenBytes) {
				spans = append(spans, rawTextOpening...)
				rawTextNeedsClose = true
			}
		case html.CommentToken:
			if !containsMeta(tokenBytes) {
				continue
			}
			left, right := 2, 1
			if bytes.HasPrefix(tokenBytes, []byte("<!--")) {
				left = 4
			}
			if bytes.HasSuffix(tokenBytes, []byte("-->")) {
				right = 3
			} else if bytes.HasSuffix(tokenBytes, []byte("--!>")) {
				right = 4
			}
			spans = append(spans, IndexRange{Start: start, End: start + min(left, len(tokenBytes))})
			if len(tokenBytes) >= right && tokenBytes[len(tokenBytes)-1] == '>' {
				spans = append(spans, IndexRange{Start: offset - right, End: offset})
			}
		}
	}
}
