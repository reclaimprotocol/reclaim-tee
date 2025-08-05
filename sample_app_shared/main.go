package main

// #cgo CFLAGS: -I.
// #cgo LDFLAGS: -L../lib -lreclaim
/*
#include <stddef.h>

// Opaque handle for protocol session
typedef struct reclaim_protocol* reclaim_protocol_t;

// Error codes
typedef enum {
    RECLAIM_SUCCESS = 0,
    RECLAIM_ERROR_INVALID_ARGS = -1,
    RECLAIM_ERROR_CONNECTION_FAILED = -2,
    RECLAIM_ERROR_PROTOCOL_FAILED = -3,
    RECLAIM_ERROR_TIMEOUT = -4,
    RECLAIM_ERROR_MEMORY = -5,
    RECLAIM_ERROR_SESSION_NOT_FOUND = -6,
    RECLAIM_ERROR_ALREADY_COMPLETED = -7
} reclaim_error_t;

// Function declarations
reclaim_error_t reclaim_start_protocol(char* host, char* request_json, reclaim_protocol_t* protocol_handle);
reclaim_error_t reclaim_get_response(reclaim_protocol_t protocol_handle, char** response_json, int* response_length);
reclaim_error_t reclaim_finish_protocol(reclaim_protocol_t protocol_handle, char* response_redaction_json, char** verification_bundle_json, int* bundle_length);
reclaim_error_t reclaim_cleanup(reclaim_protocol_t protocol_handle);
void reclaim_free_string(char* str);
char* reclaim_get_error_message(reclaim_error_t error);
char* reclaim_get_version(void);
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"tee-mpc/proofverifier"
	"tee-mpc/shared"
)

func main() {
	fmt.Println("=== Sample Application using libreclaim Shared Library ===")

	// Create demo request and redaction ranges using demo functions
	host := "github.com:443"
	rawRequest := createDemoRequest("github.com")
	demoRanges := createDemoRedactionRanges(rawRequest)

	// Convert demo ranges to the format expected by the C library
	requestRanges := make([]map[string]interface{}, len(demoRanges))
	for i, r := range demoRanges {
		requestRanges[i] = map[string]interface{}{
			"start":  r.Start,
			"length": r.Length,
			"type":   r.Type,
		}
	}

	// Create request JSON
	requestData := map[string]interface{}{
		"host":                     host,
		"raw_request":              rawRequest,
		"request_redaction_ranges": requestRanges,
	}

	requestJSON, err := json.Marshal(requestData)
	if err != nil {
		log.Fatalf("Failed to marshal request JSON: %v", err)
	}

	fmt.Printf("Starting protocol with host: %s\n", host)
	fmt.Printf("Request size: %d bytes\n", len(rawRequest))
	fmt.Printf("Request redaction ranges: %d\n", len(requestRanges))

	// Step 1: Start the protocol
	cRequestJSON := C.CString(string(requestJSON))
	defer C.reclaim_free_string(cRequestJSON)

	var protocolHandle C.reclaim_protocol_t
	result := C.reclaim_start_protocol(C.CString(host), cRequestJSON, &protocolHandle)
	if result != C.RECLAIM_SUCCESS {
		errorMsg := C.reclaim_get_error_message(result)
		log.Fatalf("Failed to start protocol: %s", C.GoString(errorMsg))
	}
	defer C.reclaim_cleanup(protocolHandle)

	fmt.Printf("Protocol started successfully!\n")

	// Step 2: Get response data
	var responseJSON *C.char
	var responseLength C.int
	result = C.reclaim_get_response(protocolHandle, &responseJSON, &responseLength)
	if result != C.RECLAIM_SUCCESS {
		errorMsg := C.reclaim_get_error_message(result)
		log.Fatalf("Failed to get response: %s", C.GoString(errorMsg))
	}
	defer C.reclaim_free_string(responseJSON)

	// Parse response data
	responseDataStr := C.GoStringN(responseJSON, responseLength)
	var responseData map[string]interface{}
	if err := json.Unmarshal([]byte(responseDataStr), &responseData); err != nil {
		log.Fatalf("Failed to parse response JSON: %v", err)
	}

	protocolID := responseData["protocol_id"].(string)
	rawResponse := responseData["raw_response"].(string)
	responseLengthInt := int(responseData["response_length"].(float64))

	fmt.Printf("Protocol ID: %s\n", protocolID)
	fmt.Printf("Response received: %d bytes\n", responseLengthInt)
	fmt.Printf("Success: %v\n", responseData["success"])

	// Step 3: Calculate response redaction ranges
	responseRanges := calculateResponseRedactionRanges([]byte(rawResponse))
	fmt.Printf("Calculated response redaction ranges: %d\n", len(responseRanges))

	// Create response redaction JSON
	responseRedactionData := map[string]interface{}{
		"response_redaction_ranges": responseRanges,
	}

	responseRedactionJSON, err := json.Marshal(responseRedactionData)
	if err != nil {
		log.Fatalf("Failed to marshal response redaction JSON: %v", err)
	}

	// Step 4: Finish the protocol with response redaction ranges
	cResponseRedactionJSON := C.CString(string(responseRedactionJSON))
	defer C.reclaim_free_string(cResponseRedactionJSON)

	var bundleJSON *C.char
	var bundleLength C.int
	result = C.reclaim_finish_protocol(protocolHandle, cResponseRedactionJSON, &bundleJSON, &bundleLength)
	if result != C.RECLAIM_SUCCESS {
		errorMsg := C.reclaim_get_error_message(result)
		log.Fatalf("Failed to finish protocol: %s", C.GoString(errorMsg))
	}
	defer C.reclaim_free_string(bundleJSON)

	// Parse verification bundle data
	bundleDataStr := C.GoStringN(bundleJSON, bundleLength)
	var bundleData map[string]interface{}
	if err := json.Unmarshal([]byte(bundleDataStr), &bundleData); err != nil {
		log.Fatalf("Failed to parse bundle JSON: %v", err)
	}

	bundleSize := int(bundleData["bundle_size"].(float64))
	verificationBundle := bundleData["verification_bundle"].(string)

	fmt.Printf("Protocol finished successfully!\n")
	fmt.Printf("Verification bundle size: %d bytes\n", bundleSize)
	fmt.Printf("Success: %v\n", bundleData["success"])

	// Display some information about the verification bundle
	if len(verificationBundle) > 0 {
		fmt.Printf("Verification bundle preview: %s...\n",
			verificationBundle[:min(50, len(verificationBundle))])
	}

	// Save verification bundle to file for offline verification
	bundlePath := fmt.Sprintf("/tmp/verification_bundle_%s.json", protocolID)
	if err := writeVerificationBundle(bundlePath, []byte(verificationBundle)); err != nil {
		log.Printf("Failed to write verification bundle: %v", err)
	} else {
		fmt.Printf("Verification bundle saved to: %s\n", bundlePath)
	}

	// Run offline verification to display the final redacted response
	fmt.Println("\n🔍 Running offline verification to display final redacted response...")
	if err := proofverifier.Validate(bundlePath); err != nil {
		log.Printf("🔴 Offline verification failed: %v", err)
	} else {
		fmt.Println("✅ Offline verification succeeded")
	}

	fmt.Println("Sample application completed successfully!")
}

// PatternMatch represents a pattern match result (moved from libclient)
type PatternMatch struct {
	Start  int
	Length int
	Value  string
}

// findPatternMatches finds all matches for a pattern in the request string (moved from libclient)
// This is demo-specific pattern matching logic
func findPatternMatches(request, pattern string) []PatternMatch {
	var matches []PatternMatch

	// For now, implement simple literal matching
	// In a full implementation, this would use regex
	if strings.Contains(pattern, "Authorization: Bearer") {
		// Handle Authorization header pattern
		start := strings.Index(request, "Authorization: Bearer ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the token part
				tokenStart := start + len("Authorization: Bearer ")
				tokenEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  tokenStart,
					Length: tokenEnd - tokenStart,
					Value:  request[tokenStart:tokenEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "X-Account-ID:") {
		// Handle X-Account-ID header pattern
		start := strings.Index(request, "X-Account-ID: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the account ID part
				idStart := start + len("X-Account-ID: ")
				idEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  idStart,
					Length: idEnd - idStart,
					Value:  request[idStart:idEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "User-Agent") {
		// Handle User-Agent header pattern
		start := strings.Index(request, "User-Agent: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the user agent part
				uaStart := start + len("User-Agent: ")
				uaEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  uaStart,
					Length: uaEnd - uaStart,
					Value:  request[uaStart:uaEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "Accept:") {
		// Handle Accept header pattern
		start := strings.Index(request, "Accept: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the accept part
				acceptStart := start + len("Accept: ")
				acceptEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  acceptStart,
					Length: acceptEnd - acceptStart,
					Value:  request[acceptStart:acceptEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "X-Session-Token:") {
		// Handle X-Session-Token header pattern
		start := strings.Index(request, "X-Session-Token: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the session token part
				tokenStart := start + len("X-Session-Token: ")
				tokenEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  tokenStart,
					Length: tokenEnd - tokenStart,
					Value:  request[tokenStart:tokenEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "X-API-Key:") {
		// Handle X-API-Key header pattern
		start := strings.Index(request, "X-API-Key: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the API key part
				keyStart := start + len("X-API-Key: ")
				keyEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  keyStart,
					Length: keyEnd - keyStart,
					Value:  request[keyStart:keyEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "X-User-ID:") {
		// Handle X-User-ID header pattern
		start := strings.Index(request, "X-User-ID: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the user ID part
				userIdStart := start + len("X-User-ID: ")
				userIdEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  userIdStart,
					Length: userIdEnd - userIdStart,
					Value:  request[userIdStart:userIdEnd],
				})
			}
		}
	}

	return matches
}

// createDemoRedactionRanges creates redaction ranges for the demo request
// This function applies demo-specific redaction specifications to create ranges
func createDemoRedactionRanges(httpRequest []byte) []shared.RequestRedactionRange {
	var ranges []shared.RequestRedactionRange
	requestStr := string(httpRequest)

	// Demo redaction specifications
	demoSpecs := []struct {
		Pattern string
		Type    string
	}{
		{Pattern: "Authorization: Bearer", Type: shared.RedactionTypeSensitiveProof},
		{Pattern: "X-Account-ID:", Type: shared.RedactionTypeSensitive},
		{Pattern: "X-Session-Token:", Type: shared.RedactionTypeSensitiveProof},
		{Pattern: "X-API-Key:", Type: shared.RedactionTypeSensitiveProof},
		{Pattern: "X-User-ID:", Type: shared.RedactionTypeSensitiveProof},
	}

	// Apply demo redaction specifications
	for _, spec := range demoSpecs {
		matches := findPatternMatches(requestStr, spec.Pattern)
		for _, match := range matches {
			ranges = append(ranges, shared.RequestRedactionRange{
				Start:  match.Start,
				Length: match.Length,
				Type:   spec.Type,
			})
		}
	}

	return ranges
}

// createDemoRequest creates the demo HTTP request
func createDemoRequest(host string) []byte {
	// Create HTTP request with test sensitive data including multiple R_SP headers
	testRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer secret_auth_token_12345\r\nX-Account-ID: ACC987654321\r\nX-Session-Token: sess_abc123def456\r\nX-API-Key: api_key_xyz789uvw012\r\nX-User-ID: user_987654321\r\nConnection: close\r\n\r\n", host)
	return []byte(testRequest)
}

// calculateResponseRedactionRanges calculates redaction ranges for the response
// This mimics the logic from the original client's DemoResponseCallback
func calculateResponseRedactionRanges(responseData []byte) []map[string]interface{} {
	var ranges []map[string]interface{}

	responseStr := string(responseData)

	// Find the end of headers (double CRLF)
	headerEndIndex := strings.Index(responseStr, "\r\n\r\n")
	if headerEndIndex == -1 {
		// Try with just LF
		headerEndIndex = strings.Index(responseStr, "\n\n")
		if headerEndIndex != -1 {
			headerEndIndex += 2 // Account for \n\n
		}
	} else {
		headerEndIndex += 4 // Account for \r\n\r\n
	}

	if headerEndIndex == -1 {
		// No clear header/body separation found, preserve everything
		return ranges
	}

	// Body section - look for title content to preserve
	bodyContent := responseStr[headerEndIndex:]

	if len(bodyContent) == 0 {
		// Only headers, nothing to redact
		return ranges
	}

	// Find ALL title content within the body to preserve (only text between tags)
	titleStartTag := "<title>"
	titleEndTag := "</title>"

	// Find all title tag pairs
	type titleRange struct {
		contentStart int
		contentEnd   int
		textContent  string
	}

	var titleRanges []titleRange
	searchStart := 0

	for {
		titleStartIndex := strings.Index(bodyContent[searchStart:], titleStartTag)
		if titleStartIndex == -1 {
			break // No more title tags
		}

		titleStartIndex += searchStart // Adjust for search offset
		titleContentStartIndex := titleStartIndex + len(titleStartTag)

		titleEndIndex := strings.Index(bodyContent[titleContentStartIndex:], titleEndTag)
		if titleEndIndex != -1 {
			titleEndIndex = titleContentStartIndex + titleEndIndex

			// Extract the text content only
			titleText := bodyContent[titleContentStartIndex:titleEndIndex]

			titleRanges = append(titleRanges, titleRange{
				contentStart: titleContentStartIndex,
				contentEnd:   titleEndIndex,
				textContent:  titleText,
			})

			// Continue searching after this closing tag
			searchStart = titleEndIndex + len(titleEndTag)
		} else {
			// Found opening tag but no closing tag, skip it
			searchStart = titleContentStartIndex
		}
	}

	// Calculate absolute positions in the full HTTP response
	bodyStartInFull := headerEndIndex

	if len(titleRanges) > 0 {
		// Build redaction ranges for all content except title texts
		lastEnd := 0

		for _, tr := range titleRanges {
			// Redact from lastEnd to start of this title content
			if tr.contentStart > lastEnd {
				beforeTitleStart := bodyStartInFull + lastEnd
				beforeTitleLength := tr.contentStart - lastEnd

				ranges = append(ranges, map[string]interface{}{
					"start":  beforeTitleStart,
					"length": beforeTitleLength,
				})
			}

			lastEnd = tr.contentEnd
		}

		// Redact everything after the last title
		if lastEnd < len(bodyContent) {
			afterTitleStart := bodyStartInFull + lastEnd
			afterTitleLength := len(bodyContent) - lastEnd

			ranges = append(ranges, map[string]interface{}{
				"start":  afterTitleStart,
				"length": afterTitleLength,
			})
		}
	} else {
		// No title tags found, redact entire body
		ranges = append(ranges, map[string]interface{}{
			"start":  headerEndIndex,
			"length": len(bodyContent),
		})
	}

	return ranges
}

// writeVerificationBundle writes the verification bundle data to a file
func writeVerificationBundle(path string, bundleData []byte) error {
	return os.WriteFile(path, bundleData, 0644)
}
