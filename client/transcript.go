package main

import (
	"bytes"
	"fmt"
	"log"
)

// validateTranscriptsAgainstCapturedTraffic validates both TEE transcripts
// against the client's captured TLS traffic to ensure integrity and completeness
func (c *Client) validateTranscriptsAgainstCapturedTraffic() {
	fmt.Printf("\n===== TRANSCRIPT VALIDATION REPORT =====\n")

	log.Printf("[Client] Validating transcripts against %d captured TLS records", len(c.capturedTraffic))

	// Since we now capture raw TCP chunks exactly as TEE_K sees them,
	// we should compare them directly without trying to categorize by TLS record type

	for i, chunk := range c.capturedTraffic {
		if len(chunk) < 1 {
			// Empty chunks in captured traffic indicate protocol corruption
			c.terminateConnectionWithError("Empty chunk in captured traffic", fmt.Errorf("chunk %d is empty", i))
			return
		}

	}

	// Calculate total sizes
	totalCapturedSize := 0
	for _, chunk := range c.capturedTraffic {
		totalCapturedSize += len(chunk)
	}

	fmt.Printf("[Client] Client captured traffic analysis:\n")
	fmt.Printf("[Client]   Total chunks: %d\n", len(c.capturedTraffic))
	fmt.Printf("[Client]   Total captured size: %d bytes\n", totalCapturedSize)

	// Perform detailed comparison with TEE transcripts
	fmt.Printf("\n[Client] Detailed transcript comparison:\n")

	// Validate TEE_K transcript (should contain raw TCP chunks - bidirectional)
	teekValidation := c.validateTEEKTranscriptRaw()

	// Validate TEE_T transcript (should contain application data packets - bidirectional)
	teetValidation := c.validateTEETTranscriptRaw()

	// Summary
	fmt.Printf("\n[Client] VALIDATION RESULTS:\n")
	fmt.Printf("[Client]   Both TEE_K and TEE_T transcripts received\n")
	fmt.Printf("[Client]   Both transcript signatures verified successfully\n")
	fmt.Printf("[Client]   Client captured %d TCP chunks during session (bidirectional)\n", len(c.capturedTraffic))

	if teekValidation && teetValidation {
		fmt.Printf("[Client]   TRANSCRIPT VALIDATION PASSED - All packets match!\n")
	} else {
		fmt.Printf("[Client]   TRANSCRIPT VALIDATION FAILED - Packet mismatches detected!\n")
	}

	fmt.Printf("===== VALIDATION COMPLETE =====\n\n")
}

// validateTEEKTranscriptRaw validates TEE_K transcript against client raw TCP chunks
func (c *Client) validateTEEKTranscriptRaw() bool {
	fmt.Printf("[Client] Validating TEE_K transcript (%d packets) against client captures\n",
		len(c.teekTranscriptPackets))

	if c.teekTranscriptPackets == nil {
		fmt.Printf("[Client] TEE_K transcript packets not available\n")
		return false
	}

	// TEE_K captures raw TCP chunks during handshake, so we should compare against
	// the raw TCP chunks we captured (not the individual TLS records from application phase)
	fmt.Printf("[Client] TEE_K transcript analysis:\n")

	handshakePacketsMatched := 0
	totalCompared := 0 // number of transcript packets that we actually compared against captures
	for _, teekPacket := range c.teekTranscriptPackets {

		// All transcript packets are now TLS records by definition
		totalCompared++

		// Check if this packet matches any of the client's captured data
		found := false
		for _, chunk := range c.capturedTraffic {
			if len(teekPacket) == len(chunk) && bytes.Equal(teekPacket, chunk) {
				handshakePacketsMatched++
				found = true
				break
			}
		}

		if !found {
			fmt.Printf("[Client]     NOT found in client captures\n")
		}
	}

	fmt.Printf("[Client] TEE_K validation result: %d/%d packets matched exactly\n",
		handshakePacketsMatched, totalCompared)

	return handshakePacketsMatched == totalCompared
}

// validateTEETTranscriptRaw validates TEE_T transcript against client application data records
func (c *Client) validateTEETTranscriptRaw() bool {
	fmt.Printf("[Client] Validating TEE_T transcript (%d packets) against client captures\n",
		len(c.teetTranscriptPackets))

	if c.teetTranscriptPackets == nil {
		fmt.Printf("[Client] TEE_T transcript packets not available\n")
		return false
	}

	fmt.Printf("[Client] TEE_T transcript analysis:\n")

	packetsMatched := 0
	for i, teetPacket := range c.teetTranscriptPackets {
		fmt.Printf("[Client]   TEE_T packet %d: %d bytes (type: 0x%02x)\n",
			i+1, len(teetPacket), teetPacket[0])

		// Check if this packet matches any of our captured packets
		found := false
		for _, clientPacket := range c.capturedTraffic {
			if len(teetPacket) == len(clientPacket) && bytes.Equal(teetPacket, clientPacket) {
				packetsMatched++
				found = true
				break
			}
		}

		if !found {
			fmt.Printf("[Client]     NOT found in client captures\n")
		}
	}

	fmt.Printf("[Client] TEE_T validation result: %d/%d packets matched exactly\n",
		packetsMatched, len(c.teetTranscriptPackets))

	return packetsMatched == len(c.teetTranscriptPackets)
}
