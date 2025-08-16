package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const DEFAULT_USER_AGENT = "reclaim-attestor"
const DEFAULT_HTTPS_PORT = 443

func equalsFoldUserAgent(s string) bool { return strings.EqualFold(s, "user-agent") }

func buildHeadersList(h map[string]string) []string {
	if len(h) == 0 {
		return nil
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	res := make([]string, 0, len(keys))
	for _, k := range keys {
		res = append(res, fmt.Sprintf("%s: %s", k, h[k]))
	}
	return res
}

func getHostHeaderString(u *url.URL) string {
	port := u.Port()
	if port != "" && port != strconv.Itoa(DEFAULT_HTTPS_PORT) {
		return u.Host
	}
	return u.Hostname()
}

func joinCRLF(lines []string) string { return strings.Join(lines, "\r\n") }

// Template substitution with offsets, mirroring TS logic
var paramsRegex = regexp.MustCompile(`{{([^{}]+)}}`)

type hiddenPart struct {
	Index  int
	Length int
}

type substituteResult struct {
	NewParams       HTTPProviderParams
	ExtractedValues map[string]string
	HiddenBodyParts []hiddenPart
	HiddenURLParts  []hiddenPart
}

func substituteParamValues(current *HTTPProviderParams, secret *HTTPProviderSecretParams, ignoreMissing bool) substituteResult {
	// deep copy via json
	var params HTTPProviderParams
	b, _ := json.Marshal(*current)
	_ = json.Unmarshal(b, &params)

	extracted := map[string]string{}

	// URL
	hiddenURL := []hiddenPart{}
	urlParams := extractAndReplaceTemplateValues(params.URL, &params, secret, ignoreMissing)
	if urlParams.NewParam != "" || len(urlParams.ExtractedValues) > 0 {
		params.URL = urlParams.NewParam
		maps.Copy(extracted, urlParams.ExtractedValues)
		if len(urlParams.HiddenParts) > 0 {
			host := getHostHeaderString(mustParseURL(params.URL))
			offset := len("https://"+host) - len(current.Method) - 1 // space after method
			for _, hp := range urlParams.HiddenParts {
				hiddenURL = append(hiddenURL, hiddenPart{Index: hp.Index - offset, Length: hp.Length})
			}
		}
	}

	// Body
	hiddenBody := []hiddenPart{}
	if params.Body != nil {
		bodyStr := uint8ArrayToStr(normalizeBodyToBytes(params.Body))
		br := extractAndReplaceTemplateValues(bodyStr, &params, secret, ignoreMissing)
		if br.NewParam != "" || len(br.ExtractedValues) > 0 {
			params.Body = br.NewParam
			maps.Copy(extracted, br.ExtractedValues)
			hiddenBody = br.HiddenParts
		}
	}

	// Geo
	geoParams := extractAndReplaceTemplateValues(params.GeoLocation, &params, secret, ignoreMissing)
	if geoParams.NewParam != "" || len(geoParams.ExtractedValues) > 0 {
		params.GeoLocation = geoParams.NewParam
		maps.Copy(extracted, geoParams.ExtractedValues)
	}

	if params.ResponseRedactions != nil {
		for _, r := range params.ResponseRedactions {
			if r.Regex != "" {
				regexParams := extractAndReplaceTemplateValues(r.Regex, &params, secret, ignoreMissing)
				r.Regex = regexParams.NewParam
			}

			if r.XPath != "" {
				xpathParams := extractAndReplaceTemplateValues(r.XPath, &params, secret, ignoreMissing)
				r.XPath = xpathParams.NewParam
			}

			if r.JSONPath != "" {
				jsonPathParams := extractAndReplaceTemplateValues(r.JSONPath, &params, secret, ignoreMissing)
				r.JSONPath = jsonPathParams.NewParam
			}
		}
	}

	if params.ResponseMatches != nil {
		for _, r := range params.ResponseMatches {
			if r.Value != "" {
				matchParams := extractAndReplaceTemplateValues(r.Value, &params, secret, ignoreMissing)
				r.Value = matchParams.NewParam
				maps.Copy(extracted, matchParams.ExtractedValues)
			}
		}
	}

	return substituteResult{NewParams: params, ExtractedValues: extracted, HiddenBodyParts: hiddenBody, HiddenURLParts: hiddenURL}
}

func strToUint8Array(body any) []byte {
	switch b := body.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	case nil:
		return []byte("")
	default:
		return []byte("") // or return nil/error if you prefer
	}
}

func uint8ArrayToStr(b []byte) string { return string(bytes.ToValidUTF8(b, []byte("�"))) }

func normalizeBodyToBytes(body any) []byte {
	switch b := body.(type) {
	case string:
		return []byte(b)
	case []byte:
		return b
	case nil:
		return nil
	default:
		return nil

	}
}

type replacedParams struct {
	NewParam        string
	ExtractedValues map[string]string
	HiddenParts     []hiddenPart
}

func extractAndReplaceTemplateValues(param string, params *HTTPProviderParams, secret *HTTPProviderSecretParams, ignoreMissing bool) replacedParams {
	if param == "" {
		return replacedParams{NewParam: "", ExtractedValues: map[string]string{}, HiddenParts: nil}
	}
	matches := paramsRegex.FindAllStringSubmatchIndex(param, -1)
	if len(matches) == 0 {
		return replacedParams{NewParam: param, ExtractedValues: map[string]string{}, HiddenParts: nil}
	}

	extracted := map[string]string{}
	hidden := []hiddenPart{}
	var b strings.Builder
	last := 0
	totalOffset := 0
	for _, m := range matches {
		start, end := m[0], m[1]
		nameStart, nameEnd := m[2], m[3]
		pn := param[nameStart:nameEnd]
		// write text before match
		b.WriteString(param[last:start])

		if params.ParamValues != nil {
			if val, ok := params.ParamValues[pn]; ok {
				extracted[pn] = val
				b.WriteString(val)
				totalOffset += len(val) - (end - start)
				last = end
				continue
			}
		}

		if secret != nil {
			if secret.ParamValues != nil {
				if val, ok := secret.ParamValues[pn]; ok {
					hidden = append(hidden, hiddenPart{Index: start + totalOffset, Length: len(val)})
					b.WriteString(val)
					totalOffset += len(val) - (end - start)
					last = end
					continue
				}
			}
			// secret present but not found
			panic(fmt.Errorf("parameter's \"%s\" value not found in paramValues and secret parameter's paramValues", pn))
		}

		// no secret provided
		if !ignoreMissing {
			panic(fmt.Errorf("parameter's \"%s\" value not found in paramValues", pn))
		}
		// keep as-is
		b.WriteString(param[start:end])
		last = end
	}
	// tail
	b.WriteString(param[last:])

	return replacedParams{NewParam: b.String(), ExtractedValues: extracted, HiddenParts: hidden}
}

func mustParseURL(s string) *url.URL { u, _ := url.Parse(s); return u }

// getURL mirrors the TypeScript getURL function - only processes URL string with parameter substitution
func getURL(params *HTTPProviderParams, secretParams *HTTPProviderSecretParams) (string, error) {
	urlStr := params.URL
	if urlStr == "" {
		return "", fmt.Errorf("url is required")
	}

	// Extract parameter names from URL (mirror TS paramsRegex behavior)
	paramNames := make(map[string]bool)
	re := regexp.MustCompile(`\{\{([^{}]+)\}\}`)
	matches := re.FindAllStringSubmatch(urlStr, -1)
	for _, match := range matches {
		if len(match) > 1 {
			paramNames[match[1]] = true
		}
	}

	// Substitute parameters in URL only
	for paramName := range paramNames {
		placeholder := fmt.Sprintf("{{%s}}", paramName)
		var value string
		var found bool

		// Check public params first
		if params.ParamValues != nil {
			if val, exists := params.ParamValues[paramName]; exists {
				value = val
				found = true
			}
		}

		// Check secret params if not found in public
		if !found && secretParams != nil && secretParams.ParamValues != nil {
			if val, exists := secretParams.ParamValues[paramName]; exists {
				value = val
				found = true
			}
		}

		if !found {
			return "", fmt.Errorf("parameter \"%s\" value not found in templateParams", paramName)
		}

		urlStr = strings.ReplaceAll(urlStr, placeholder, value)
	}

	return urlStr, nil
}
