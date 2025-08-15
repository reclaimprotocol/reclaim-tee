package providers

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"sort"
)

// CreateRequest builds the HTTP/1.1 request bytes and redaction ranges
func CreateRequest(secret *HTTPProviderSecretParams, params *HTTPProviderParams) (CreateRequestResult, error) {
	if secret.CookieStr == "" && secret.AuthorisationHeader == "" && len(secret.Headers) == 0 {
		return CreateRequestResult{}, fmt.Errorf("auth parameters are not set")
	}

	pubHeaders := map[string]string{}
	maps.Copy(pubHeaders, params.Headers)

	// Build secret headers list in TS order: Cookie, Authorization, then any extra secret headers
	secHeadersList := []string{}
	if secret.CookieStr != "" {
		secHeadersList = append(secHeadersList, fmt.Sprintf("Cookie: %s", secret.CookieStr))
	}
	if secret.AuthorisationHeader != "" {
		secHeadersList = append(secHeadersList, fmt.Sprintf("Authorization: %s", secret.AuthorisationHeader))
	}
	for k, v := range secret.Headers {
		secHeadersList = append(secHeadersList, fmt.Sprintf("%s: %s", k, v))
	}

	// Default UA if not provided anywhere
	hasUA := false
	for k := range pubHeaders {
		if equalsFoldUserAgent(k) {
			hasUA = true
			break
		}
	}
	if !hasUA {
		for _, line := range secHeadersList {
			if len(line) >= len("User-Agent:") && equalsFoldUserAgent(line[:len("User-Agent:")]) {
				hasUA = true
				break
			}
		}
	}
	if !hasUA {
		pubHeaders["User-Agent"] = DEFAULT_USER_AGENT
	}

	sp := substituteParamValues(params, secret, false)
	p := sp.NewParams

	u, err := url.Parse(p.URL)
	if err != nil {
		return CreateRequestResult{}, fmt.Errorf("invalid url: %w", err)
	}
	path := u.EscapedPath()
	query := u.RawQuery
	reqTarget := path
	if query != "" {
		reqTarget = reqTarget + "?" + query
	}
	reqLine := fmt.Sprintf("%s %s HTTP/1.1", p.Method, reqTarget)

	bodyBytes := strToUint8Array(p.Body)
	contentLength := len(bodyBytes)

	pubHeadersList := buildHeadersList(pubHeaders)
	hostHeader := getHostHeaderString(u)
	lines := []string{
		reqLine,
		fmt.Sprintf("Host: %s", hostHeader),
		fmt.Sprintf("Content-Length: %d", contentLength),
		"Connection: close",
		"Accept-Encoding: identity",
	}
	lines = append(lines, pubHeadersList...)
	lines = append(lines, secHeadersList...)
	lines = append(lines, "\r\n")
	headersStr := joinCRLF(lines)
	headerBytes := []byte(headersStr)
	data := append(headerBytes, bodyBytes...)

	// redactions: hide all secret headers block
	redactions := []RedactedOrHashedArraySlice{}
	if len(secHeadersList) > 0 {
		secHeadersStr := joinCRLF(secHeadersList)
		idx := bytes.Index(data, []byte(secHeadersStr))
		if idx >= 0 {
			redactions = append(redactions, RedactedOrHashedArraySlice{From: idx, To: idx + len(secHeadersStr)})
		}
	}
	// hidden body parts
	for _, hb := range sp.HiddenBodyParts {
		if hb.Length > 0 {
			redactions = append(redactions, RedactedOrHashedArraySlice{From: len(headerBytes) + hb.Index, To: len(headerBytes) + hb.Index + hb.Length})
		}
	}
	// hidden URL parts
	for _, hu := range sp.HiddenURLParts {
		if hu.Length > 0 {
			redactions = append(redactions, RedactedOrHashedArraySlice{From: hu.Index, To: hu.Index + hu.Length})
		}
	}
	sort.Slice(redactions, func(i, j int) bool { return redactions[i].To < redactions[j].To })
	return CreateRequestResult{Data: data, Redactions: redactions}, nil
}

// GetResponseRedactions computes redaction ranges for an HTTP response based on responseRedactions in params
func GetResponseRedactions(response []byte, rawParams *HTTPProviderParams, ctx *ProviderCtx) ([]RedactedOrHashedArraySlice, error) {
	res, err := parseHTTPResponseBytes(response)
	if err != nil {
		return nil, err
	}

	if len(rawParams.ResponseRedactions) == 0 {
		return []RedactedOrHashedArraySlice{}, nil
	}

	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("Expected status 2xx, got %d (%s)", res.StatusCode, res.StatusMessage)
	}

	// substitute placeholders in params (ignoreMissing = true)
	sp := substituteParamValues(rawParams, nil, true)
	params := sp.NewParams

	headerEndIndex := res.StatusLineEndIndex
	bodyStartIdx := res.BodyStartIndex
	if bodyStartIdx < 4 {
		return nil, errors.New("Failed to find response body")
	}

	reveals := []RedactedOrHashedArraySlice{{From: 0, To: headerEndIndex}}

	// CRLF boundary: only verify and reveal when client supports it
	if shouldRevealCrlf(ctx) {
		if res.HeaderEndIdx < 0 || res.HeaderEndIdx+4 > len(response) {
			return nil, fmt.Errorf("Failed to find header/body separator at index %d", res.HeaderEndIdx)
		}
		if !bytes.Equal(response[res.HeaderEndIdx:res.HeaderEndIdx+4], []byte("\r\n\r\n")) {
			return nil, fmt.Errorf("Failed to find header/body separator at index %d", res.HeaderEndIdx)
		}
	}

	// always reveal the double CRLF which separates headers from body (mirror TS)
	reveals = append(reveals, RedactedOrHashedArraySlice{From: res.HeaderEndIdx, To: res.HeaderEndIdx + 4})

	// reveal Date header if present
	if rng, ok := res.HeaderLowerToRanges["date"]; ok && rng.To > rng.From {
		reveals = append(reveals, rng)
	}

	bodyStr := uint8ArrayToStr(res.Body)
	redactions := []RedactedOrHashedArraySlice{}

	for _, rs := range params.ResponseRedactions {
		proc, err := processRedactionRequest(bodyStr, &rs, bodyStartIdx, res.Chunks)
		if err != nil {
			return nil, err
		}
		for _, item := range proc {
			reveals = append(reveals, item.Reveal)
			redactions = append(redactions, item.Redactions...)
		}
	}

	sort.Slice(reveals, func(i, j int) bool { return reveals[i].To < reveals[j].To })

	if len(reveals) > 1 {
		currentIndex := 0
		for _, r := range reveals {
			if currentIndex < r.From {
				redactions = append(redactions, RedactedOrHashedArraySlice{From: currentIndex, To: r.From})
			}
			currentIndex = r.To
		}
		redactions = append(redactions, RedactedOrHashedArraySlice{From: currentIndex, To: len(response)})
	}

	// include hashed reveals if any
	for _, r := range reveals {
		if r.Hash != nil {
			redactions = append(redactions, r)
		}
	}

	sort.Slice(redactions, func(i, j int) bool { return redactions[i].To < redactions[j].To })
	return redactions, nil
}
