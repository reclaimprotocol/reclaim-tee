package providers

import (
	"fmt"

	xp "github.com/reclaimprotocol/xpath-go"
)

// extractHTMLElementsIndexes evaluates an XPath against the provided HTML string
// and returns absolute byte ranges for each matched element. When contentsOnly
// is true, the range covers only the element's inner content if available.
func extractHTMLElementsIndexes(html string, xpathExpression string, contentsOnly bool) ([]indexRange, error) {
	processedHTML := html

	matches, err := xp.QueryWithOptions(xpathExpression, processedHTML, xp.Options{
		IncludeLocation: true,
		OutputFormat:    "nodes",
		ContentsOnly:    contentsOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to find XPath: \"%s\"", xpathExpression)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("Failed to find XPath: \"%s\"", xpathExpression)
	}

	out := make([]indexRange, 0, len(matches))
	for _, m := range matches {
		out = append(out, indexRange{start: m.StartLocation, end: m.EndLocation})
	}
	return out, nil
}
