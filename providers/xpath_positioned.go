package providers

import (
	"fmt"
	"strings"

	xp "github.com/reclaimprotocol/xpath-go"
)

// findInnerContent finds the content between opening and closing tags
func findInnerContent(html string, start, end int) (int, int) {
	// Find the end of the opening tag
	openTagEnd := strings.Index(html[start:end], ">")
	if openTagEnd == -1 {
		return start, end // Self-closing or malformed, return original range
	}
	openTagEnd += start + 1 // Convert to absolute position and skip the '>'

	// Find the start of the closing tag by looking for the last '<'
	closeTagStart := strings.LastIndex(html[start:end], "<")
	if closeTagStart == -1 || closeTagStart == 0 {
		return openTagEnd, end // No closing tag found, return from opening tag end
	}
	closeTagStart += start // Convert to absolute position

	// Make sure we found a real closing tag, not the opening tag
	if closeTagStart <= openTagEnd {
		return openTagEnd, end // Invalid closing tag position
	}

	return openTagEnd, closeTagStart
}

// extractHTMLElementsIndexes evaluates an XPath against the provided HTML string
// and returns absolute byte ranges for each matched element. When contentsOnly
// is true, the range covers only the element's inner content if available.
func extractHTMLElementsIndexes(html string, xpathExpression string, contentsOnly bool) ([]indexRange, error) {
	processedHTML := html

	// Since we pass the full HTML unchanged, there is no offset
	offset := 0

	matches, err := xp.Query(xpathExpression, processedHTML)
	if err != nil {
		return nil, fmt.Errorf("Failed to find XPath: \"%s\"", xpathExpression)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("Failed to find XPath: \"%s\"", xpathExpression)
	}

	out := make([]indexRange, 0, len(matches))
	for _, m := range matches {
		start := m.StartLocation + offset
		end := m.EndLocation + offset

		if contentsOnly {
			// Extract inner content between tags
			innerStart, innerEnd := findInnerContent(html, start, end)
			out = append(out, indexRange{start: innerStart, end: innerEnd})
		} else {
			// Use the full element range
			out = append(out, indexRange{start: start, end: end})

		}
	}
	return out, nil
}
