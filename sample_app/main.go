package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"tee-mpc/libreclaim"
	"tee-mpc/proofverifier"
	"tee-mpc/shared"
)

func main() {
	fmt.Println("=== Sample Application using libreclaim Library ===")

	// Example host and HTTP request (same format as original client)
	host := "github.com:443"
	rawRequest := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer secret_auth_token_12345\r\nX-Account-ID: ACC987654321\r\nConnection: close\r\n\r\n", "github.com"))

	// Example request redaction ranges (redact Authorization and add proof)
	authStart := strings.Index(string(rawRequest), "Authorization: Bearer ")
	accountIdStart := strings.Index(string(rawRequest), "X-Account-ID: ")

	requestRanges := []shared.RedactionRange{
		{
			Start:  authStart + len("Authorization: Bearer "),
			Length: len("secret_auth_token_12345"),
			Type:   "sensitive",
		},
		{
			Start:  accountIdStart + len("X-Account-ID: "),
			Length: len("ACC987654321"),
			Type:   "sensitive_proof",
		},
	}

	fmt.Printf("Starting protocol with host: %s\n", host)
	fmt.Printf("Request size: %d bytes\n", len(rawRequest))
	fmt.Printf("Request redaction ranges: %d\n", len(requestRanges))

	// Step 1: Start the protocol
	result, err := libreclaim.StartProtocol(host, rawRequest, requestRanges)
	if err != nil {
		log.Fatalf("Failed to start protocol: %v", err)
	}

	fmt.Printf("Protocol started successfully!\n")
	fmt.Printf("Protocol ID: %s\n", result.ProtocolID)
	fmt.Printf("Response received: %d bytes\n", result.ResponseLength)
	fmt.Printf("Success: %v\n", result.Success)

	// Step 2: Calculate response redaction ranges
	// This simulates the callback logic from the original client
	responseRanges := calculateResponseRedactionRanges(result.RawResponse)

	fmt.Printf("Calculated response redaction ranges: %d\n", len(responseRanges))

	// Step 3: Finish the protocol with response redaction ranges
	finishResult, err := libreclaim.FinishProtocol(result.ProtocolID, responseRanges)
	if err != nil {
		log.Fatalf("Failed to finish protocol: %v", err)
	}

	fmt.Printf("Protocol finished successfully!\n")
	fmt.Printf("Verification bundle size: %d bytes\n", finishResult.BundleSize)
	fmt.Printf("Success: %v\n", finishResult.Success)

	// Display some information about the verification bundle
	if len(finishResult.VerificationBundle) > 0 {
		fmt.Printf("Verification bundle preview: %s...\n",
			string(finishResult.VerificationBundle[:min(50, len(finishResult.VerificationBundle))]))
	}

	// Run offline verification to display the final redacted response
	fmt.Println("\n🔍 Running offline verification to display final redacted response...")

	// Write the verification bundle to a temporary file for offline verification
	bundlePath := fmt.Sprintf("/tmp/verification_bundle_%s.json", result.ProtocolID)
	if err := writeVerificationBundle(bundlePath, finishResult.VerificationBundle); err != nil {
		log.Printf("Failed to write verification bundle: %v", err)
	} else {
		// Run offline verification
		if err := proofverifier.Validate(bundlePath); err != nil {
			log.Printf("🔴 Offline verification failed: %v", err)
		} else {
			fmt.Println("✅ Offline verification succeeded")
		}
	}

	fmt.Println("Sample application completed successfully!")
}

// calculateResponseRedactionRanges calculates redaction ranges for the response
// This mimics the logic from the original client's DemoResponseCallback
func calculateResponseRedactionRanges(responseData []byte) []shared.RedactionRange {
	var ranges []shared.RedactionRange

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

				ranges = append(ranges, shared.RedactionRange{
					Start:  beforeTitleStart,
					Length: beforeTitleLength,
					Type:   "body_before_title",
				})
			}

			lastEnd = tr.contentEnd
		}

		// Redact everything after the last title
		if lastEnd < len(bodyContent) {
			afterTitleStart := bodyStartInFull + lastEnd
			afterTitleLength := len(bodyContent) - lastEnd

			ranges = append(ranges, shared.RedactionRange{
				Start:  afterTitleStart,
				Length: afterTitleLength,
				Type:   "body_after_title",
			})
		}
	} else {
		// No title tags found, redact entire body
		ranges = append(ranges, shared.RedactionRange{
			Start:  headerEndIndex,
			Length: len(bodyContent),
			Type:   "body_no_title",
		})
	}

	return ranges
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// writeVerificationBundle writes the verification bundle data to a file
func writeVerificationBundle(path string, bundleData []byte) error {
	return os.WriteFile(path, bundleData, 0644)
}
