package providers

import (
	"fmt"

	xp "github.com/reclaimprotocol/xpath-go"
)

// extractHTMLElementsIndexes evaluates an XPath against the provided HTML string
// and returns absolute byte ranges for each matched element. When contentsOnly
// is true, the range covers only the element's inner content if available.
func extractHTMLElementsIndexes(html string, xpathExpression string, contentsOnly bool) ([]indexRange, error) {
	TraceStart("XPath", "extractHTMLElementsIndexes", "XPath", xpathExpression, "HTML size", len(html), "ContentsOnly", contentsOnly)
	
	processedHTML := html
	TraceDebug("XPath", "extractHTMLElementsIndexes", "Executing XPath query with options")

	matches, err := xp.QueryWithOptions(xpathExpression, processedHTML, xp.Options{
		IncludeLocation: true,
		OutputFormat:    "nodes",
		ContentsOnly:    contentsOnly,
	})
	if err != nil {
		TraceError("XPath", "extractHTMLElementsIndexes", "XPath query failed: %v", err)
		return nil, fmt.Errorf("Failed to find XPath: \"%s\"", xpathExpression)
	}
	if len(matches) == 0 {
		TraceWarn("XPath", "extractHTMLElementsIndexes", "XPath returned no matches")
		return nil, fmt.Errorf("Failed to find XPath: \"%s\"", xpathExpression)
	}
	
	TraceDebug("XPath", "extractHTMLElementsIndexes", "XPath found %d matches", len(matches))

	out := make([]indexRange, 0, len(matches))
	for i, m := range matches {
		TraceVerbose("XPath", "extractHTMLElementsIndexes", "Match %d: range [%d:%d] = '%s'", 
			i+1, m.StartLocation, m.EndLocation, truncateData(html[m.StartLocation:m.EndLocation]))
		out = append(out, indexRange{start: m.StartLocation, end: m.EndLocation})
	}
	
	TraceInfo("XPath", "extractHTMLElementsIndexes", "XPath extraction complete - found %d ranges", len(out))
	return out, nil
}
