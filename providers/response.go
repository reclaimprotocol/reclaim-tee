package providers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// internal structure mirroring the TS parseHttpResponse return
type httpParsedResponse struct {
	StatusCode          int
	StatusMessage       string
	StatusLineEndIndex  int
	HeaderEndIdx        int
	BodyStartIndex      int
	Body                []byte
	HeaderLowerToRanges map[string]RedactedOrHashedArraySlice
	Chunks              []RedactedOrHashedArraySlice // slice ranges for each chunk body (absolute positions)
}

// RedactionItem mirrors TS: an item with a reveal and accompanying redactions
type RedactionItem struct {
	Reveal     RedactedOrHashedArraySlice
	Redactions []RedactedOrHashedArraySlice
}

// makeRegex mirrors the TS makeRegex: enable dotAll and case-insensitive, and
// convert JS-style named groups (?<name>...) to Go/RE2-style (?P<name>...)
func makeRegex(str string) (*regexp.Regexp, error) {
	converted := convertJsNamedGroupsToGo(str)
	return regexp.Compile("(?si)" + converted)
}

var jsNamedGroupPattern = regexp.MustCompile(`\(\?<([A-Za-z][A-Za-z0-9_]*)>`)

func convertJsNamedGroupsToGo(s string) string {
	// Replace `(?<name>` with `(?P<name>`
	return jsNamedGroupPattern.ReplaceAllString(s, `(?P<$1>`)
}

// processRedactionRequest implements TS semantics for XPath/JSONPath/Regex and hashed groups
func processRedactionRequest(
	body string,
	rs *ResponseRedaction,
	bodyStartIdx int,
	resChunks []RedactedOrHashedArraySlice,
) ([]RedactionItem, error) {
	items := []RedactionItem{}

	// 1) XPath branch
	if rs.XPath != "" {
		contentsOnly := rs.JSONPath != ""
		locs, err := extractHTMLElementsIndexes(body, rs.XPath, contentsOnly)
		if err != nil {
			return nil, err
		}
		for _, ix := range locs {
			startAbs := ix.start
			endAbs := ix.end
			if rs.JSONPath != "" {
				// run JSONPath within element
				elem := body[startAbs:endAbs]
				jlocs, err := extractJSONValueIndexes([]byte(elem), rs.JSONPath)
				if err != nil {
					return nil, err
				}
				for _, j := range jlocs {
					jStartAbs := startAbs + j.start
					jEndAbs := startAbs + j.end
					proc, err := applyRegexWindow(body, *rs, jStartAbs, jEndAbs, bodyStartIdx, resChunks)
					if err != nil {
						return nil, err
					}
					items = append(items, proc...)
				}
				continue
			}
			proc, err := applyRegexWindow(body, *rs, startAbs, endAbs, bodyStartIdx, resChunks)
			if err != nil {
				return nil, err
			}
			items = append(items, proc...)
		}
		return items, nil
	}

	// 2) JSONPath-only branch
	if rs.JSONPath != "" {
		locs, err := extractJSONValueIndexes([]byte(body), rs.JSONPath)
		if err != nil {
			return nil, err
		}
		for _, j := range locs {
			startAbs := j.start
			endAbs := j.end
			proc, err := applyRegexWindow(body, *rs, startAbs, endAbs, bodyStartIdx, resChunks)
			if err != nil {
				return nil, err
			}
			items = append(items, proc...)
		}
		return items, nil
	}

	// 3) Regex-only branch
	if rs.Regex != "" {
		proc, err := applyRegexWindow(body, *rs, 0, len(body), bodyStartIdx, resChunks)
		if err != nil {
			return nil, err
		}
		return proc, nil
	}

	return nil, fmt.Errorf("Expected either xPath, jsonPath or regex for redaction")
}

// convertResponsePosToAbsolutePos converts a position within the response body to absolute position in the full response,
// accounting for chunked transfer encoding.
func convertResponsePosToAbsolutePos(pos int, bodyStartIdx int, chunks []RedactedOrHashedArraySlice) int {
	if len(chunks) > 0 {
		chunkBodyStart := 0
		for _, ch := range chunks {
			chunkSize := ch.To - ch.From
			if pos >= chunkBodyStart && pos <= chunkBodyStart+chunkSize {
				return pos - chunkBodyStart + ch.From
			}
			chunkBodyStart += chunkSize
		}
		panic("position out of range")
	}
	return bodyStartIdx + pos
}

// getRedactionsForChunkHeaders returns redaction ranges for chunk headers between chunk bodies if a reveal spans across them.
func getRedactionsForChunkHeaders(from, to int, chunks []RedactedOrHashedArraySlice) []RedactedOrHashedArraySlice {
	res := []RedactedOrHashedArraySlice{}
	if len(chunks) == 0 {
		return res
	}
	for i := 1; i < len(chunks); i++ {
		ch := chunks[i]
		if ch.From > from && ch.From < to {
			res = append(res, RedactedOrHashedArraySlice{From: chunks[i-1].To, To: ch.From})
		}
	}
	return res
}

// parseHTTPResponseBytes parses an HTTP/1.1 response and returns structural metadata and chunk ranges.
func parseHTTPResponseBytes(data []byte) (*httpParsedResponse, error) {
	res := &httpParsedResponse{
		StatusCode:          0,
		StatusMessage:       "",
		StatusLineEndIndex:  -1,
		HeaderEndIdx:        -1,
		BodyStartIndex:      -1,
		HeaderLowerToRanges: map[string]RedactedOrHashedArraySlice{},
	}

	// find status line end
	statusLineEnd := bytes.Index(data, []byte("\r\n"))
	if statusLineEnd == -1 {
		return nil, errors.New("invalid HTTP response: no CRLF for status line")
	}
	res.StatusLineEndIndex = statusLineEnd
	statusLine := string(data[:statusLineEnd])
	// parse status code and message
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) >= 2 {
		code, _ := strconv.Atoi(parts[1])
		res.StatusCode = code
		if len(parts) >= 3 {
			res.StatusMessage = parts[2]
		}
	}

	// find header end (double CRLF)
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, errors.New("invalid HTTP response: no header/body separator found")
	}
	res.HeaderEndIdx = headerEnd
	res.BodyStartIndex = headerEnd + 4

	// locate headers and build header map (lower-case names)
	headersSection := data[res.StatusLineEndIndex+2 : headerEnd]
	lower := bytes.ToLower(headersSection)

	// Walk each header line to compute ranges
	offset := res.StatusLineEndIndex + 2
	lines := bytes.Split(headersSection, []byte("\r\n"))
	pos := offset
	for _, line := range lines {
		if len(line) == 0 {
			pos += 2
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon > 0 {
			name := strings.ToLower(string(line[:colon]))
			// store full header line range
			res.HeaderLowerToRanges[name] = RedactedOrHashedArraySlice{From: pos, To: pos + len(line)}
		}
		pos += len(line) + 2
	}

	res.Body = data[res.BodyStartIndex:]

	// detect chunked transfer-encoding
	transfer := findHeaderValue(lower, []byte("transfer-encoding"))
	if strings.Contains(strings.ToLower(transfer), "chunked") {
		chunks, err := parseChunkBodyRanges(data, res.BodyStartIndex)
		if err != nil {
			return nil, err
		}
		res.Chunks = chunks

		// Reconstruct the actual body content from chunks (without chunk headers/separators)
		var bodyContent []byte
		for _, chunk := range chunks {
			bodyContent = append(bodyContent, data[chunk.From:chunk.To]...)
		}
		res.Body = bodyContent
	}

	return res, nil
}

// findHeaderValue extracts the header value (best-effort) from the lower-cased header section
func findHeaderValue(lowerHeaders []byte, lowerKey []byte) string {
	// this is a best-effort fallback; reliable ranges are computed above
	lines := bytes.Split(lowerHeaders, []byte("\r\n"))
	for _, l := range lines {
		if bytes.HasPrefix(l, append(lowerKey, []byte(":")...)) {
			v := strings.TrimSpace(string(l[len(lowerKey)+1:]))
			return v
		}
	}
	return ""
}

// parseChunkBodyRanges parses chunked transfer-encoding body and returns absolute ranges for each chunk body.
func parseChunkBodyRanges(data []byte, bodyStart int) ([]RedactedOrHashedArraySlice, error) {
	res := []RedactedOrHashedArraySlice{}
	idx := bodyStart
	for {
		// read size line (hex) up to CRLF
		szEnd := bytes.Index(data[idx:], []byte("\r\n"))
		if szEnd == -1 {
			return nil, errors.New("invalid chunked response: size line not terminated")
		}
		sizeLine := string(data[idx : idx+szEnd])
		// strip chunk extensions if any
		if semi := strings.IndexByte(sizeLine, ';'); semi != -1 {
			sizeLine = sizeLine[:semi]
		}
		sizeLine = strings.TrimSpace(sizeLine)
		chunkSize, err := strconv.ParseInt(sizeLine, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk size %q: %w", sizeLine, err)
		}
		idx += szEnd + 2 // move past size line CRLF

		if chunkSize == 0 {
			// final chunk; there may be trailer headers terminated by CRLFCRLF
			break
		}

		from := idx
		to := idx + int(chunkSize)
		if to > len(data) {
			return nil, errors.New("invalid chunk size exceeding response length")
		}
		res = append(res, RedactedOrHashedArraySlice{From: from, To: to})
		idx = to

		// skip the CRLF after the chunk data
		if idx+2 > len(data) || !bytes.Equal(data[idx:idx+2], []byte("\r\n")) {
			return nil, errors.New("invalid chunk: missing CRLF after data")
		}
		idx += 2
	}
	return res, nil
}

type indexRange struct{ start, end int }

// applyRegexWindow encapsulates the regex application and hashing semantics
// over a [startAbs, endAbs) window in the response body, mirroring TS behavior.
func applyRegexWindow(
	body string,
	rs ResponseRedaction,
	startAbs int,
	endAbs int,
	bodyStartIdx int,
	resChunks []RedactedOrHashedArraySlice,
) ([]RedactionItem, error) {
	items := []RedactionItem{}

	// Helper to add a reveal for [startAbs, endAbs)
	addRange := func(sAbs, eAbs int, hash *string) {
		if sAbs < 0 || eAbs <= sAbs {
			return
		}
		reveal := getReveal(sAbs, eAbs-sAbs, bodyStartIdx, resChunks, hash)
		items = append(items, RedactionItem{Reveal: reveal, Redactions: getRedactionsForChunkHeaders(reveal.From, reveal.To, resChunks)})
	}

	segment := body[startAbs:endAbs]
	if rs.Regex == "" {
		addRange(startAbs, endAbs, rs.Hash)
		return items, nil
	}

	re, err := makeRegex(rs.Regex)
	if err != nil {
		return nil, fmt.Errorf("invalid regexp %q: %w", rs.Regex, err)
	}

	if rs.Hash == nil {
		loc := re.FindStringIndex(segment)
		if loc == nil {
			enc := base64.StdEncoding.EncodeToString([]byte(segment))
			return nil, fmt.Errorf("regexp %s does not match found element '%s'", rs.Regex, enc)
		}
		matchStart := startAbs + loc[0]
		matchEnd := startAbs + loc[1]
		addRange(matchStart, matchEnd, nil)
		return items, nil
	}

	// Hash semantics with exactly one named capture group
	smi := re.FindStringSubmatchIndex(segment)
	if smi == nil {
		enc := base64.StdEncoding.EncodeToString([]byte(segment))
		return nil, fmt.Errorf("regexp %s does not match found element '%s'", rs.Regex, enc)
	}
	names := re.SubexpNames()
	totalNamed := 0
	grpFromRel, grpToRel := -1, -1
	fullFromRel := smi[0]
	fullToRel := smi[1]
	for gi, name := range names {
		if gi == 0 {
			continue
		}
		from := smi[2*gi]
		to := smi[2*gi+1]
		if name != "" && from >= 0 && to >= 0 {
			totalNamed++
			grpFromRel, grpToRel = from, to
		}
	}
	if totalNamed != 1 {
		return nil, fmt.Errorf("Exactly one named capture group is needed per hashed redaction")
	}
	fullFrom := startAbs + fullFromRel
	fullTo := startAbs + fullToRel
	grpFrom := startAbs + grpFromRel
	grpTo := startAbs + grpToRel

	// pre-group (unhashed)
	if grpFrom > fullFrom {
		addRange(fullFrom, grpFrom, nil)
	}
	// group (hashed) — must not span chunks
	reveal := getReveal(grpFrom, grpTo-grpFrom, bodyStartIdx, resChunks, rs.Hash)
	chunkReds := getRedactionsForChunkHeaders(reveal.From, reveal.To, resChunks)
	if len(chunkReds) > 0 {
		return nil, fmt.Errorf("Hash redactions cannot be performed if the redacted string is split between 2 or more HTTP chunks")
	}
	items = append(items, RedactionItem{Reveal: reveal, Redactions: chunkReds})

	// post-group (unhashed)
	if grpTo < fullTo {
		addRange(grpTo, fullTo, nil)
	}

	return items, nil
}

func getReveal(startIdx, length, bodyStartIdx int, resChunks []RedactedOrHashedArraySlice, hash *string) RedactedOrHashedArraySlice {
	from := convertResponsePosToAbsolutePos(startIdx, bodyStartIdx, resChunks)
	to := convertResponsePosToAbsolutePos(startIdx+length, bodyStartIdx, resChunks)
	return RedactedOrHashedArraySlice{From: from, To: to, Hash: hash}
}
