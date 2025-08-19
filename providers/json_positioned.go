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
	TraceStart("JSON", "extractJSONValueIndexes", "JSONPath", jsonPathExpr, "Doc size", len(doc))
	
	// Step 1: evaluate JSONPath against the original JSON string
	TraceStep("JSON", "extractJSONValueIndexes", 1, 3, "Evaluating JSONPath query")
	results, err := jp.Query(jsonPathExpr, string(doc))
	if err != nil {
		TraceError("JSON", "extractJSONValueIndexes", "JSONPath query failed: %v", err)
		return nil, fmt.Errorf("JSONPath query failed: %v", err)
	}
	if len(results) == 0 {
		TraceWarn("JSON", "extractJSONValueIndexes", "JSONPath returned no results")
		return nil, fmt.Errorf("jsonPath not found")
	}
	TraceDebug("JSON", "extractJSONValueIndexes", "JSONPath found %d results", len(results))

	// Step 2: parse JSON once to a Node tree with offsets
	TraceStep("JSON", "extractJSONValueIndexes", 2, 3, "Parsing JSON for byte offsets")
	var root gojson.Node
	if err := gojson.Unmarshal(doc, &root); err != nil {
		TraceError("JSON", "extractJSONValueIndexes", "JSON parsing for offsets failed: %v", err)
		return nil, fmt.Errorf("failed to parse JSON for offsets: %v", err)
	}
	TraceDebug("JSON", "extractJSONValueIndexes", "JSON parsed into Node tree")

	// Step 3: traverse the Node tree for each result path
	TraceStep("JSON", "extractJSONValueIndexes", 3, 3, "Traversing Node tree for byte ranges")
	ranges := make([]indexRange, 0, len(results))
	for i, r := range results {
		TraceVerbose("JSON", "extractJSONValueIndexes", "Processing result %d/%d: path '%s'", i+1, len(results), r.Path)
		segments := jsonPathToSegments(r.Path)
		TraceVerbose("JSON", "extractJSONValueIndexes", "Path segments: %v", segments)
		
		n, keyValueRange, err := findNodeBySegments(doc, &root, segments)
		if err != nil {
			TraceError("JSON", "extractJSONValueIndexes", "Failed to resolve path '%s': %v", r.Path, err)
			return nil, fmt.Errorf("failed to resolve path %q: %v", r.Path, err)
		}
		
		// Use key:value range if available (for object properties), otherwise use node range
		var start, end int
		if keyValueRange != nil {
			// Use the key:value range to match TypeScript behavior
			start = keyValueRange.start
			end = keyValueRange.end
			TraceVerbose("JSON", "extractJSONValueIndexes", "Using key:value range for path '%s'", r.Path)
		} else {
			// coreos/go-json Node.Start/End are byte offsets into original doc.
			// End appears to be inclusive; Go slices are exclusive on end → use End+1.
			start = n.Start
			end = n.End + 1
			TraceVerbose("JSON", "extractJSONValueIndexes", "Using value-only range for path '%s'", r.Path)
		}
		
		if start < 0 || end > len(doc) || start > end {
			TraceError("JSON", "extractJSONValueIndexes", "Invalid range for path '%s': [%d,%d)", r.Path, start, end)
			return nil, fmt.Errorf("invalid range computed for path %q: [%d,%d)", r.Path, start, end)
		}
		
		TraceVerbose("JSON", "extractJSONValueIndexes", "Result %d: range [%d:%d] = '%s'", 
			i+1, start, end, truncateData(string(doc[start:end])))
		ranges = append(ranges, indexRange{start: start, end: end})
	}
	
	TraceInfo("JSON", "extractJSONValueIndexes", "JSON extraction complete - found %d ranges", len(ranges))
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
// Returns the target node and information about whether this is the final key in an object
func findNodeBySegments(doc []byte, node *gojson.Node, segments []string) (*gojson.Node, *keyValueRange, error) {
	cur := node
	var finalKeyRange *keyValueRange
	
	for i, seg := range segments {
		switch v := cur.Value.(type) {
		case map[string]gojson.Node:
			next, ok := v[seg]
			if !ok {
				return nil, nil, fmt.Errorf("object key %q not found at segment %d", seg, i)
			}
			
			// If this is the final segment, we need to find the key:value range to match TypeScript
			if i == len(segments)-1 {
				keyRange, err := findKeyValueRange(doc, cur, seg, &next)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to find key:value range for %q: %v", seg, err)
				}
				finalKeyRange = keyRange
			}
			
			cur = &next
		case []gojson.Node:
			idx, err := strconv.Atoi(seg)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid array index %q at segment %d", seg, i)
			}
			if idx < 0 || idx >= len(v) {
				return nil, nil, fmt.Errorf("array index %d out of bounds at segment %d", idx, i)
			}
			cur = &v[idx]
		default:
			return nil, nil, fmt.Errorf("cannot traverse into %T at segment %d", v, i)
		}
	}
	return cur, finalKeyRange, nil
}

type keyValueRange struct {
	start int
	end   int
}

// findKeyValueRange finds the byte range of "key":value in the JSON for the given key
func findKeyValueRange(doc []byte, parentNode *gojson.Node, key string, valueNode *gojson.Node) (*keyValueRange, error) {
	// Search backwards from the value node's start position to find the key
	valueStart := valueNode.Start
	parentStart := parentNode.Start
	
	// Look for the key pattern within the parent node's range
	keyPattern := fmt.Sprintf("\"%s\"", key)
	
	// Search backwards from valueStart within the parent range for the key
	searchStart := parentStart
	searchEnd := valueStart
	
	if searchEnd > len(doc) {
		searchEnd = len(doc)
	}
	if searchStart < 0 {
		searchStart = 0
	}
	
	searchRegion := doc[searchStart:searchEnd]
	keyIndex := strings.LastIndex(string(searchRegion), keyPattern)
	
	if keyIndex == -1 {
		// Fallback: estimate based on key length (like before)
		keyWithQuotesAndColon := fmt.Sprintf("\"%s\":", key)
		estimatedKeyStart := valueStart - len(keyWithQuotesAndColon)
		if estimatedKeyStart < parentStart {
			estimatedKeyStart = parentStart
		}
		return &keyValueRange{
			start: estimatedKeyStart,
			end:   valueNode.End + 1,
		}, nil
	}
	
	// Found the key, return the range from key start to value end
	keyStart := searchStart + keyIndex
	return &keyValueRange{
		start: keyStart,
		end:   valueNode.End + 1,
	}, nil
}
