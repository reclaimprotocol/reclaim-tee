package providers

import (
	"fmt"
	"strconv"
	"strings"

	gojson "github.com/coreos/go-json"
	jp "github.com/reclaimprotocol/jsonpathplus-go"
)

// extractJSONValueIndexex:
// 1) Evaluate JSONPath using jsonpathplus-go as provided
// 2) Parse JSON into a Node tree with byte offsets (coreos/go-json)
// 3) Traverse the Node tree by path segments and return exact byte ranges
func extractJSONValueIndexes(doc []byte, jsonPathExpr string) ([]indexRange, error) {
	// Step 1: evaluate JSONPath against the original JSON string
	results, err := jp.Query(jsonPathExpr, string(doc))
	if err != nil {
		return nil, fmt.Errorf("JSONPath query failed: %v", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("jsonPath not found")
	}

	// Step 2: parse JSON once to a Node tree with offsets
	var root gojson.Node
	if err := gojson.Unmarshal(doc, &root); err != nil {
		return nil, fmt.Errorf("failed to parse JSON for offsets: %v", err)
	}

	// Step 3: traverse the Node tree for each result path
	ranges := make([]indexRange, 0, len(results))
	for _, r := range results {
		segments := jsonPathToSegments(r.Path)
		n, err := findNodeBySegments(&root, segments)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path %q: %v", r.Path, err)
		}
		// coreos/go-json Node.Start/End are byte offsets into original doc.
		// End appears to be inclusive; Go slices are exclusive on end → use End+1.
		start := n.Start
		end := n.End + 1
		if start < 0 || end > len(doc) || start > end {
			return nil, fmt.Errorf("invalid range computed for path %q: [%d,%d)", r.Path, start, end)
		}
		ranges = append(ranges, indexRange{start: start, end: end})
	}
	return ranges, nil
}

// jsonPathToSegments converts a JSONPath like $.a[1].b to segments ["a","1","b"].
func jsonPathToSegments(path string) []string {
	p := strings.TrimPrefix(path, "$")
	p = strings.TrimPrefix(p, ".")
	if p == "" {
		return nil
	}
	segments := make([]string, 0)
	cur := strings.Builder{}
	inBracket := false
	for _, r := range p {
		switch r {
		case '.':
			if !inBracket {
				if cur.Len() > 0 {
					segments = append(segments, cur.String())
					cur.Reset()
				}
				continue
			}
		case '[':
			if cur.Len() > 0 {
				segments = append(segments, cur.String())
				cur.Reset()
			}
			inBracket = true
			continue
		case ']':
			if inBracket {
				seg := cur.String()
				cur.Reset()
				inBracket = false
				seg = strings.Trim(seg, "'\"")
				segments = append(segments, seg)
				continue
			}
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		segments = append(segments, cur.String())
	}
	return segments
}

// findNodeBySegments walks a coreos/go-json Node tree following the provided segments.
func findNodeBySegments(node *gojson.Node, segments []string) (*gojson.Node, error) {
	cur := node
	for i, seg := range segments {
		switch v := cur.Value.(type) {
		case map[string]gojson.Node:
			next, ok := v[seg]
			if !ok {
				return nil, fmt.Errorf("object key %q not found at segment %d", seg, i)
			}
			cur = &next
		case []gojson.Node:
			idx, err := strconv.Atoi(seg)
			if err != nil {
				return nil, fmt.Errorf("invalid array index %q at segment %d", seg, i)
			}
			if idx < 0 || idx >= len(v) {
				return nil, fmt.Errorf("array index %d out of bounds at segment %d", idx, i)
			}
			cur = &v[idx]
		default:
			return nil, fmt.Errorf("cannot traverse into %T at segment %d", v, i)
		}
	}
	return cur, nil
}
