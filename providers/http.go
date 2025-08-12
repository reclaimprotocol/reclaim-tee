package providers

import (
	"bytes"
	"fmt"
	"maps"
	"net/url"
	"sort"
)

// CreateRequest builds the HTTP/1.1 request bytes and redaction ranges
func CreateRequest(secret HTTPProviderSecretParams, params HTTPProviderParams) (CreateRequestResult, error) {
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

	sp := substituteParamValues(params, &secret, false)
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
	hostHeader := getHostHeaderString(*u)
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
