package providers

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"sort"
	"strconv"
	"tee-mpc/shared"
)

// CreateRequest builds the HTTP/1.1 request bytes and redaction ranges
func CreateRequest(secret *HTTPProviderSecretParams, params *HTTPProviderParams) (CreateRequestResult, error) {
	TraceStart("HTTP", "CreateRequest", "URL", params.URL, "Method", params.Method)

	if secret.CookieStr == "" && secret.AuthorisationHeader == "" && len(secret.Headers) == 0 {
		TraceError("HTTP", "CreateRequest", "auth parameters are not set")
		return CreateRequestResult{}, fmt.Errorf("auth parameters are not set")
	}

	TraceDebug("HTTP", "CreateRequest", "Secret params provided - Cookie: %t, Auth: %t, Headers: %d",
		secret.CookieStr != "", secret.AuthorisationHeader != "", len(secret.Headers))

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

	TraceStep("HTTP", "CreateRequest", 1, 5, "Substituting template parameters")
	sp := substituteParamValues(params, secret, false)
	p := sp.NewParams
	TraceDebug("HTTP", "CreateRequest", "Parameter substitution complete - extracted %d values", len(sp.ExtractedValues))

	TraceStep("HTTP", "CreateRequest", 2, 5, "Parsing URL and building request line")
	u, err := url.Parse(p.URL)
	if err != nil {
		TraceError("HTTP", "CreateRequest", "invalid url: %v", err)
		return CreateRequestResult{}, fmt.Errorf("invalid url: %w", err)
	}
	TraceVerbose("HTTP", "CreateRequest", "Parsed URL - Host: %s, Path: %s", u.Host, u.Path)
	path := u.EscapedPath()
	query := u.RawQuery
	reqTarget := path
	if query != "" {
		reqTarget = reqTarget + "?" + query
	}
	reqLine := fmt.Sprintf("%s %s HTTP/1.1", p.Method, reqTarget)

	TraceStep("HTTP", "CreateRequest", 3, 5, "Building request body and headers")
	bodyBytes := strToUint8Array(p.Body)
	contentLength := len(bodyBytes)
	TraceDebug("HTTP", "CreateRequest", "Body length: %d bytes", contentLength)

	pubHeadersList := buildHeadersList(pubHeaders)
	hostHeader := getHostHeaderString(u)
	TraceVerbose("HTTP", "CreateRequest", "Host header: %s, Public headers: %d", hostHeader, len(pubHeadersList))
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
	TraceStep("HTTP", "CreateRequest", 4, 5, "Assembling final request")
	headersStr := joinCRLF(lines)
	headerBytes := []byte(headersStr)
	data := append(headerBytes, bodyBytes...)
	TraceVerbose("HTTP", "CreateRequest", "Total request size: %d bytes (headers: %d, body: %d)",
		len(data), len(headerBytes), len(bodyBytes))

	TraceStep("HTTP", "CreateRequest", 5, 5, "Computing redaction ranges")
	// redactions: hide all secret headers block
	redactions := []shared.RequestRedactionRange{}
	if len(secHeadersList) > 0 {
		secHeadersStr := joinCRLF(secHeadersList)
		idx := bytes.Index(data, []byte(secHeadersStr))
		if idx >= 0 {
			redactions = append(redactions, shared.RequestRedactionRange{Start: idx, Length: len(secHeadersStr), Type: "sensitive"})
		}
	}
	// hidden body parts
	for _, hb := range sp.HiddenBodyParts {
		if hb.Length > 0 {
			redactions = append(redactions, shared.RequestRedactionRange{Start: len(headerBytes) + hb.Index, Length: hb.Length, Type: "sensitive"})
		}
	}
	// hidden URL parts
	for _, hu := range sp.HiddenURLParts {
		if hu.Length > 0 {
			redactions = append(redactions, shared.RequestRedactionRange{Start: hu.Index, Length: hu.Length, Type: "sensitive"})
		}
	}
	sort.Slice(redactions, func(i, j int) bool {
		return redactions[i].Start+redactions[i].Length < redactions[j].Start+redactions[j].Length
	})

	TraceDebug("HTTP", "CreateRequest", "Created %d redaction ranges", len(redactions))
	TraceData("HTTP", "CreateRequest", "Request Headers", string(headerBytes))
	if IsTraceEnabled(TraceLevelVerbose) {
		TraceBinary("HTTP", "CreateRequest", "Full Request", data, 512)
	}

	TraceInfo("HTTP", "CreateRequest", "Request created successfully")
	return CreateRequestResult{Data: data, Redactions: redactions}, nil
}

// GetResponseRedactions computes redaction ranges for an HTTP response based on responseRedactions in params
func GetResponseRedactions(response []byte, rawParams *HTTPProviderParams, ctx *ProviderCtx) ([]shared.RequestRedactionRange, error) {
	TraceStart("HTTP", "GetResponseRedactions", "Response size", len(response), "Redaction rules", len(rawParams.ResponseRedactions))

	TraceStep("HTTP", "GetResponseRedactions", 1, 4, "Parsing HTTP response")
	res, err := parseHTTPResponseBytes(response)
	if err != nil {
		TraceError("HTTP", "GetResponseRedactions", "Failed to parse response: %v", err)
		return nil, err
	}
	TraceDebug("HTTP", "GetResponseRedactions", "Response parsed - Status: %d %s, Body size: %d bytes",
		res.StatusCode, res.StatusMessage, len(res.Body))

	if len(rawParams.ResponseRedactions) == 0 {
		TraceInfo("HTTP", "GetResponseRedactions", "No redaction rules specified, returning empty redactions")
		return []shared.RequestRedactionRange{}, nil
	}

	if res.StatusCode/100 != 2 {
		TraceError("HTTP", "GetResponseRedactions", "Non-2xx status code: %d (%s)", res.StatusCode, res.StatusMessage)
		return nil, fmt.Errorf("Expected status 2xx, got %d (%s)", res.StatusCode, res.StatusMessage)
	}

	TraceStep("HTTP", "GetResponseRedactions", 2, 4, "Substituting parameters in redaction rules")
	// substitute placeholders in params (ignoreMissing = true)
	sp := substituteParamValues(rawParams, nil, true)
	params := sp.NewParams
	TraceDebug("HTTP", "GetResponseRedactions", "Parameter substitution complete for redaction rules")

	TraceStep("HTTP", "GetResponseRedactions", 3, 4, "Identifying response structure and reveals")
	headerEndIndex := res.StatusLineEndIndex
	bodyStartIdx := res.BodyStartIndex
	if bodyStartIdx < 4 {
		TraceError("HTTP", "GetResponseRedactions", "Failed to find response body (bodyStartIdx: %d)", bodyStartIdx)
		return nil, errors.New("Failed to find response body")
	}
	TraceVerbose("HTTP", "GetResponseRedactions", "Response structure - Header end: %d, Body start: %d",
		headerEndIndex, bodyStartIdx)

	reveals := []shared.RequestRedactionRange{{Start: 0, Length: headerEndIndex, Type: "sensitive"}}
	TraceDebug("HTTP", "GetResponseRedactions", "Initial status line reveal: [0:%d]", headerEndIndex)

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
	reveals = append(reveals, shared.RequestRedactionRange{Start: res.HeaderEndIdx, Length: 4, Type: "sensitive"})

	// reveal Date header if present
	if rng, ok := res.HeaderLowerToRanges["date"]; ok && rng.Start+rng.Length > rng.Start {
		reveals = append(reveals, rng)
	}

	TraceStep("HTTP", "GetResponseRedactions", 4, 4, "Processing redaction requests")
	bodyStr := uint8ArrayToStr(res.Body)
	redactions := []shared.RequestRedactionRange{}
	TraceDebug("HTTP", "GetResponseRedactions", "Processing %d redaction requests on body (%d chars)",
		len(params.ResponseRedactions), len(bodyStr))

	for i, rs := range params.ResponseRedactions {
		TraceVerbose("HTTP", "GetResponseRedactions", "Processing redaction %d/%d - XPath: '%s', JSONPath: '%s', Regex: '%s'",
			i+1, len(params.ResponseRedactions), rs.XPath, rs.JSONPath, rs.Regex)

		proc, err := processRedactionRequest(bodyStr, &rs, bodyStartIdx, res.Chunks)
		if err != nil {
			TraceError("HTTP", "GetResponseRedactions", "Redaction %d failed: %v", i+1, err)
			return nil, err
		}

		TraceDebug("HTTP", "GetResponseRedactions", "Redaction %d produced %d items", i+1, len(proc))
		for _, item := range proc {
			reveals = append(reveals, item.Reveal)
			redactions = append(redactions, item.Redactions...)
		}
	}

	sort.Slice(reveals, func(i, j int) bool { return reveals[i].Start+reveals[i].Length < reveals[j].Start+reveals[j].Length })


	if len(reveals) > 1 {
		currentIndex := 0
		for i, r := range reveals {
			if currentIndex < r.Start {
				redactions = append(redactions, shared.RequestRedactionRange{Start: currentIndex, Length: r.Start - currentIndex, Type: "sensitive"})
			}
			currentIndex = r.Start + r.Length
			
			// For chunked responses, check if this is the final reveal that spans the entire body
			// This matches TypeScript behavior which includes chunked termination sequences
			if len(res.Chunks) > 0 && i == len(reveals)-1 {
				// Check if this reveal ends at the exact end of the body content
				// by checking if it maps to the end of the last chunk
				if len(res.Chunks) > 0 {
					lastChunk := res.Chunks[len(res.Chunks)-1]
					lastChunkEnd := lastChunk.Start + lastChunk.Length
					
					// If the final reveal ends exactly where the last chunk ends,
					// and there's trailing data, extend to include it (like TypeScript)
					if currentIndex == lastChunkEnd && currentIndex < len(response) {
						TraceDebug("HTTP", "GetResponseRedactions", "Extending final chunked reveal from position %d to %d (response end) to match TypeScript behavior", currentIndex, len(response))
						currentIndex = len(response)
					}
				}
			}
		}
		// Always use the full response length to match TypeScript behavior
		// TypeScript includes all data including chunked termination sequences
		endIndex := len(response)
		if currentIndex < endIndex {
			redactions = append(redactions, shared.RequestRedactionRange{Start: currentIndex, Length: endIndex - currentIndex, Type: "sensitive"})
		}
	}

	sort.Slice(redactions, func(i, j int) bool {
		return redactions[i].Start+redactions[i].Length < redactions[j].Start+redactions[j].Length
	})

	TraceInfo("HTTP", "GetResponseRedactions", "Response redaction complete - %d reveals, %d redactions",
		len(reveals), len(redactions))
	TraceDebug("HTTP", "GetResponseRedactions", "Total redacted bytes: %d",
		func() int {
			total := 0
			for _, r := range redactions {
				total += r.Length
			}
			return total
		}())

	return redactions, nil
}


func GetHostPort(params *HTTPProviderParams, secretParams *HTTPProviderSecretParams) (string, int, error) {
	TraceStart("HTTP", "GetHostPort", "URL", params.URL)

	urlStr, err := getURL(params, secretParams)
	if err != nil {
		TraceError("HTTP", "GetHostPort", "Failed to get URL: %v", err)
		return "", -1, err
	}
	TraceVerbose("HTTP", "GetHostPort", "Processed URL: %s", urlStr)

	u, err := url.Parse(urlStr)
	if err != nil {
		TraceError("HTTP", "GetHostPort", "URL parsing failed: %v", err)
		return "", -1, fmt.Errorf("url is incorrect: %w", err)
	}

	if u.Host == "" {
		TraceError("HTTP", "GetHostPort", "No host found in URL")
		return "", -1, fmt.Errorf("url is incorrect: no host found")
	}

	// Only support HTTPS
	if u.Scheme != "https" {
		TraceError("HTTP", "GetHostPort", "Non-HTTPS scheme not supported: %s", u.Scheme)
		return "", -1, fmt.Errorf("only HTTPS URLs are supported, got: %s", u.Scheme)
	}
	TraceDebug("HTTP", "GetHostPort", "HTTPS URL validated, extracting host/port from: %s", u.Host)

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		var addrError *net.AddrError
		if errors.As(err, &addrError) {
			// No port specified, use HTTPS default
			TraceDebug("HTTP", "GetHostPort", "No explicit port, using default HTTPS port")
			TraceInfo("HTTP", "GetHostPort", "Resolved to %s:%d", u.Host, DEFAULT_HTTPS_PORT)
			return u.Host, DEFAULT_HTTPS_PORT, nil
		}
		TraceError("HTTP", "GetHostPort", "Failed to split host:port: %v", err)
		return "", -1, fmt.Errorf("url is incorrect: %w", err)
	}

	intPort, err := strconv.Atoi(port)
	if err != nil {
		TraceError("HTTP", "GetHostPort", "Invalid port number: %s", port)
		return "", -1, fmt.Errorf("url is incorrect: invalid port %q: %w", port, err)
	}

	TraceInfo("HTTP", "GetHostPort", "Resolved to %s:%d", host, intPort)
	return host, intPort, nil
}

