package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tee-mpc/shared"

	"github.com/anjuna-security/go-nitro-attestation/verifier"
	"github.com/gorilla/websocket"
)

// Client state constants for atomic state machine
const (
	ClientStateInitial = iota
	ClientStateConnecting
	ClientStateHandshaking
	ClientStateReady
	ClientStateProcessingRecords
	ClientStateEOFReached
	ClientStateRedactionSent
	ClientStateFinished
	ClientStateCompleted
)

// Completion flags for atomic bit operations
const (
	CompletionFlagRedactionExpected = 1 << iota
	CompletionFlagRedactionReceived
	CompletionFlagSignedTranscriptsExpected
	CompletionFlagTEEKTranscriptReceived
	CompletionFlagTEETTranscriptReceived
	CompletionFlagTEEKSignatureValid
	CompletionFlagTEETSignatureValid
	CompletionFlagRedactedStreamsExpected
)

type Client struct {
	wsConn   *websocket.Conn
	teetConn *websocket.Conn
	tcpConn  net.Conn

	// Session management
	sessionID string // Session ID received from TEE_K

	teekURL           string
	teetURL           string
	targetHost        string
	targetPort        int
	isClosing         bool
	capturedTraffic   [][]byte // Store all captured traffic for verification
	handshakeComplete bool     // Track if TLS handshake is complete

	// Pending connection request data (to be sent once session ID is received)
	pendingConnectionRequest *RequestConnectionData
	connectionRequestPending bool

	// Phase 4: Response handling
	responseSeqNum       uint64            // TLS sequence number for response AEAD
	firstApplicationData bool              // Track if this is the first ApplicationData record
	pendingResponsesData map[uint64][]byte // Encrypted response data by sequence number

	// Protocol completion signaling
	completionChan chan struct{} // Signals when protocol is complete

	// *** Add sync.Once to prevent double-close panic ***
	completionOnce sync.Once // Ensures completion channel is only closed once

	// *** Atomic state machine for lock-free protocol management ***
	state int64 // Atomic state field using ClientState constants

	// *** Track records sent vs processed instead of streams ***
	recordsSent               int64 // TLS records sent for split AEAD processing (atomic)
	recordsProcessed          int64 // TLS records that completed split AEAD processing (atomic)
	decryptionStreamsReceived int64 // *** FIX: Track received decryption streams to prevent premature redaction *** (atomic)
	eofReached                int64 // Whether we've reached EOF on TCP connection (atomic)

	// *** Atomic completion flags (replaces multiple boolean fields) ***
	completionFlags int64 // Atomic bit flags for completion state tracking

	// Track HTTP request/response lifecycle
	httpRequestSent        bool              // Track if HTTP request has been sent
	httpResponseExpected   bool              // Track if we should expect HTTP response
	httpResponseReceived   bool              // Track if HTTP response content has been received
	responseContentBySeq   map[uint64][]byte // Store decrypted response content by sequence
	responseContentMutex   sync.Mutex        // *** USE THIS MUTEX FOR ALL RESPONSE MAPS ***
	ciphertextBySeq        map[uint64][]byte // Store encrypted response data by sequence
	decryptionStreamBySeq  map[uint64][]byte // Store decryption streams by sequence
	redactedPlaintextBySeq map[uint64][]byte // *** ADDED: Store final redacted plaintext for ordered printing ***

	// Attestation verification fields
	teekAttestationPublicKey []byte // Public key extracted from TEE_K attestation
	teetAttestationPublicKey []byte // Public key extracted from TEE_T attestation
	teekTranscriptPublicKey  []byte // Public key from TEE_K signed transcript
	teetTranscriptPublicKey  []byte // Public key from TEE_T signed transcript
	attestationVerified      bool   // Flag to track if attestation verification passed
	publicKeyComparisonDone  bool   // Flag to track if public key comparison was completed

	// Transcript validation fields
	teekTranscriptPackets     [][]byte // Packets from TEE_K signed transcript for validation
	teetTranscriptPackets     [][]byte // Packets from TEE_T signed transcript for validation
	teekTranscriptPacketTypes []string // Packet type annotations from TEE_K transcript
	teetTranscriptPacketTypes []string // Packet type annotations from TEE_T transcript

	// Library interface fields
	requestRedactions []RedactionSpec  // Request redactions from config
	responseCallback  ResponseCallback // Response callback for redactions

	// Result tracking fields
	protocolStartTime            time.Time                     // When protocol started
	lastResponseData             *HTTPResponse                 // Last received HTTP response
	lastProofClaims              []ProofClaim                  // Last generated proof claims
	transcriptValidationResults  *TranscriptValidationResults  // Cached validation results
	attestationValidationResults *AttestationValidationResults // Cached attestation results

	// Verification bundle tracking fields
	handshakeDisclosure   *HandshakeKeyDisclosureData             // store handshake keys
	teekSignedTranscript  *shared.SignedTranscript                // full signed transcript from TEE_K
	teetSignedTranscript  *shared.SignedTranscript                // full signed transcript from TEE_T
	signedRedactedStreams []shared.SignedRedactedDecryptionStream // ordered collection of redacted streams
	redactedRequestPlain  []byte                                  // R_red plaintext sent to TEE_K
	fullRedactedResponse  []byte                                  // final redacted HTTP response (concatenated)

	// commitment opening for proof
	proofStream []byte
	proofKey    []byte
}

func NewClient(teekURL string) *Client {
	return &Client{
		teekURL:                      teekURL,
		teetURL:                      "wss://tee-t.reclaimprotocol.org/ws", // Default TEE_T URL (enclave mode)
		pendingResponsesData:         make(map[uint64][]byte),
		completionChan:               make(chan struct{}),
		state:                        ClientStateInitial,
		recordsSent:                  0,
		recordsProcessed:             0,
		decryptionStreamsReceived:    0,
		eofReached:                   0,
		completionFlags:              0,
		httpRequestSent:              false,
		httpResponseExpected:         false,
		httpResponseReceived:         false,
		responseContentBySeq:         make(map[uint64][]byte),
		responseContentMutex:         sync.Mutex{},
		ciphertextBySeq:              make(map[uint64][]byte),
		decryptionStreamBySeq:        make(map[uint64][]byte),
		redactedPlaintextBySeq:       make(map[uint64][]byte),
		teekAttestationPublicKey:     nil,
		teetAttestationPublicKey:     nil,
		teekTranscriptPublicKey:      nil,
		teetTranscriptPublicKey:      nil,
		attestationVerified:          false,
		publicKeyComparisonDone:      false,
		teekTranscriptPackets:        nil,
		teetTranscriptPackets:        nil,
		teekTranscriptPacketTypes:    nil,
		teetTranscriptPacketTypes:    nil,
		requestRedactions:            nil,
		responseCallback:             nil,
		protocolStartTime:            time.Now(),
		lastResponseData:             nil,
		lastProofClaims:              nil,
		transcriptValidationResults:  nil,
		attestationValidationResults: nil,
		signedRedactedStreams:        make([]shared.SignedRedactedDecryptionStream, 0),
		proofStream:                  nil,
		proofKey:                     nil,
	}
}

// SetTEETURL sets the TEE_T connection URL
func (c *Client) SetTEETURL(url string) {
	c.teetURL = url
}

// WaitForCompletion - moved to completion.go

// createEnclaveWebSocketDialer - moved to websocket.go

// ConnectToTEEK - moved to websocket.go

// ConnectToTEET - moved to websocket.go

func (c *Client) RequestHTTP(hostname string, port int) error {
	c.targetHost = hostname
	c.targetPort = port

	fmt.Printf("[Client] Requesting connection to %s:%d\n", hostname, port)

	// Store connection request data to be sent once session ID is received
	c.pendingConnectionRequest = &RequestConnectionData{
		Hostname: hostname,
		Port:     port,
		SNI:      hostname,
		ALPN:     []string{"http/1.1"},
	}
	c.connectionRequestPending = true

	// Check if we already have a session ID and send immediately
	if c.sessionID != "" {
		return c.sendPendingConnectionRequest()
	}

	// Otherwise, request will be sent when session ID is received in handleSessionReady
	return nil
}

// sendPendingConnectionRequest - moved to websocket.go

// handleMessages - moved to websocket.go

// handleTEETMessages - moved to websocket.go

// isClientNetworkShutdownError - moved to tcp.go

// handleConnectionReady - moved to tcp.go

// sendTCPReady - moved to tcp.go

// handleSendTCPData - moved to tcp.go

// handleHTTPResponse - moved to websocket.go

// handleError - moved to websocket.go

// handleHandshakeComplete - moved to tls.go

// handleHandshakeKeyDisclosure - moved to tls.go

// verifyCertificateInTraffic - moved to tls.go

// decryptAndVerifyCertificate - moved to tls.go

// parseCertificateMessage - moved to tls.go

// tcpToWebsocket - moved to tcp.go

// processCompleteRecords - moved to tls.go

// processAllRemainingRecords - moved to tls.go

// processSingleTLSRecord - moved to tls.go

// sendMessage - moved to websocket.go

// sendMessageToTEET - moved to websocket.go

// sendError - moved to websocket.go

// Phase 2: TEE_T message handlers

// handleEncryptedData - moved to websocket.go

// handleTEETReady - moved to websocket.go

// handleRedactionVerification - moved to websocket.go

// handleTEETError - moved to websocket.go

// Close - moved to websocket.go

// Phase 3: Redaction system implementation

// createRedactedRequest creates a redacted HTTP request with XOR streams and commitments
func (c *Client) createRedactedRequest(httpRequest []byte) (RedactedRequestData, RedactionStreamsData, error) {
	// Create HTTP request with test sensitive data
	testRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer secret_auth_token_12345\r\nX-Account-ID: ACC987654321\r\nConnection: close\r\n\r\n", c.targetHost)
	httpRequest = []byte(testRequest)

	fmt.Printf("[Client] ORIGINAL REQUEST (length=%d):\n%s\n", len(httpRequest), string(httpRequest))
	fmt.Printf("[Client] TARGET HOST: '%s' (length=%d)\n", c.targetHost, len(c.targetHost))

	// Show the complete HTTP request with sensitive data before redaction
	fmt.Printf("[Client] COMPLETE HTTP REQUEST (before redaction):\n%s\n", string(httpRequest))
	fmt.Printf("[Client] Request analysis:\n")
	fmt.Printf(" Total length: %d bytes\n", len(httpRequest))

	// Apply redaction specifications from config
	ranges, err := c.applyRedactionSpecs(httpRequest)
	if err != nil {
		return RedactedRequestData{}, RedactionStreamsData{}, fmt.Errorf("failed to apply redaction specs: %v", err)
	}

	fmt.Printf("[Client] REDACTION CONFIGURATION:\n")
	fmt.Printf(" Found %d redaction ranges\n", len(ranges))
	for i, r := range ranges {
		fmt.Printf(" Range %d: [%d:%d] type=%s\n", i, r.Start, r.Start+r.Length, r.Type)
	}

	// Validate redaction ranges
	if err := c.validateRedactionRanges(ranges, len(httpRequest)); err != nil {
		return RedactedRequestData{}, RedactionStreamsData{}, fmt.Errorf("invalid redaction ranges: %v", err)
	}

	// Generate redaction streams and commitment keys
	streams, keys, err := c.generateRedactionStreams(ranges)
	if err != nil {
		return RedactedRequestData{}, RedactionStreamsData{}, fmt.Errorf("failed to generate redaction streams: %v", err)
	}

	// Apply redaction using XOR streams
	redactedRequest := c.applyRedaction(httpRequest, ranges, streams)

	fmt.Printf("[Client] REDACTED REQUEST:\n%s\n", string(redactedRequest))

	// Show non-sensitive parts remain unchanged
	fmt.Printf("[Client] NON-SENSITIVE PARTS (unchanged):\n")
	lines := strings.Split(string(httpRequest), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "Host: ") ||
			strings.HasPrefix(line, "Connection: ") || line == "" {
			fmt.Printf(" R_NS: %s\n", line)
		}
	}

	// Compute commitments
	commitments := c.computeCommitments(streams, keys)

	// Store proof stream/key (first range with type containing "proof")
	for idx, r := range ranges {
		if strings.Contains(r.Type, "proof") {
			c.proofStream = streams[idx]
			c.proofKey = keys[idx]
			break
		}
	}

	fmt.Printf("[Client] REDACTION SUMMARY:\n")
	fmt.Printf(" Original length: %d bytes\n", len(httpRequest))
	fmt.Printf(" Redacted length: %d bytes (same, redaction via XOR)\n", len(redactedRequest))
	fmt.Printf(" Redaction ranges: %d\n", len(ranges))

	c.redactedRequestPlain = redactedRequest

	return RedactedRequestData{
			RedactedRequest: redactedRequest,
			Commitments:     commitments,
			RedactionRanges: ranges,
		}, RedactionStreamsData{
			Streams:        streams,
			CommitmentKeys: keys,
		}, nil
}

// generateRedactionStreams generates random XOR streams and commitment keys for each redaction range
func (c *Client) generateRedactionStreams(ranges []RedactionRange) ([][]byte, [][]byte, error) {
	streams := make([][]byte, len(ranges))
	keys := make([][]byte, len(ranges))

	for i, r := range ranges {
		// Generate random stream for XOR redaction
		stream := make([]byte, r.Length)
		if _, err := rand.Read(stream); err != nil {
			return nil, nil, fmt.Errorf("failed to generate stream %d: %v", i, err)
		}
		streams[i] = stream

		// Generate random commitment key
		key := make([]byte, 32) // 256-bit key for HMAC-SHA256
		if _, err := rand.Read(key); err != nil {
			return nil, nil, fmt.Errorf("failed to generate key %d: %v", i, err)
		}
		keys[i] = key
	}

	return streams, keys, nil
}

// applyRedaction applies XOR streams to sensitive data ranges in the HTTP request
func (c *Client) applyRedaction(request []byte, ranges []RedactionRange, streams [][]byte) []byte {
	redacted := make([]byte, len(request))
	copy(redacted, request)

	for i, r := range ranges {
		if i >= len(streams) {
			continue
		}

		// Apply XOR stream to redact sensitive data
		for j := 0; j < r.Length && r.Start+j < len(redacted); j++ {
			redacted[r.Start+j] ^= streams[i][j]
		}
	}

	return redacted
}

// computeCommitments computes HMAC commitments for each stream using its corresponding key
func (c *Client) computeCommitments(streams, keys [][]byte) [][]byte {
	commitments := make([][]byte, len(streams))

	for i := 0; i < len(streams) && i < len(keys); i++ {
		// Compute HMAC(stream, key)
		h := hmac.New(sha256.New, keys[i])
		h.Write(streams[i])
		commitments[i] = h.Sum(nil)
	}

	return commitments
}

// validateRedactionRanges ensures redaction ranges don't overlap and are within bounds
func (c *Client) validateRedactionRanges(ranges []RedactionRange, requestLen int) error {
	for _, r := range ranges {
		if r.Start < 0 || r.Length < 0 || r.Start+r.Length > requestLen {
			return fmt.Errorf("invalid redaction range: start=%d, length=%d, requestLen=%d", r.Start, r.Length, requestLen)
		}
	}
	return nil
}

// applyRedactionSpecs applies redaction specifications from config to find redaction ranges
func (c *Client) applyRedactionSpecs(httpRequest []byte) ([]RedactionRange, error) {
	var ranges []RedactionRange
	requestStr := string(httpRequest)

	// If no redaction specs configured, fall back to default patterns
	if len(c.requestRedactions) == 0 {
		// Default fallback: hardcoded patterns for backward compatibility
		authTokenStart := strings.Index(requestStr, "secret_auth_token_12345")
		accountIdStart := strings.Index(requestStr, "ACC987654321")

		if authTokenStart != -1 {
			ranges = append(ranges, RedactionRange{
				Start:  authTokenStart,
				Length: len("secret_auth_token_12345"),
				Type:   "sensitive",
			})
		}
		if accountIdStart != -1 {
			ranges = append(ranges, RedactionRange{
				Start:  accountIdStart,
				Length: len("ACC987654321"),
				Type:   "sensitive_proof",
			})
		}
		return ranges, nil
	}

	// Apply configured redaction specs
	for _, spec := range c.requestRedactions {
		matches := findPatternMatches(requestStr, spec.Pattern)
		for _, match := range matches {
			ranges = append(ranges, RedactionRange{
				Start:  match.Start,
				Length: match.Length,
				Type:   spec.Type,
			})
		}
	}

	return ranges, nil
}

// PatternMatch represents a pattern match result
type PatternMatch struct {
	Start  int
	Length int
	Value  string
}

// findPatternMatches finds all matches for a pattern in the request string
func findPatternMatches(request, pattern string) []PatternMatch {
	var matches []PatternMatch

	// For now, implement simple literal matching
	// In a full implementation, this would use regex
	if strings.Contains(pattern, "Authorization: Bearer") {
		// Handle Authorization header pattern
		start := strings.Index(request, "Authorization: Bearer ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
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
	}

	return matches
}

// triggerResponseCallback triggers the response callback if configured
func (c *Client) triggerResponseCallback(responseData []byte) {
	if c.responseCallback == nil {
		return
	}

	// Parse HTTP response to extract status code and headers
	response := c.parseHTTPResponse(responseData)

	fmt.Printf("[Client] Triggering response callback with %d bytes of data\n", len(responseData))

	// Store the response data for library access
	c.lastResponseData = response

	// Call the user-provided callback
	result, err := c.responseCallback.OnResponseReceived(response)
	if err != nil {
		fmt.Printf("[Client] Response callback error: %v\n", err)
		return
	}

	if result != nil {
		fmt.Printf("[Client] Response callback completed with %d redaction ranges and %d proof claims\n",
			len(result.RedactionRanges), len(result.ProofClaims))

		// Store proof claims for library access
		c.lastProofClaims = result.ProofClaims

		// Log proof claims for debugging
		for i, claim := range result.ProofClaims {
			fmt.Printf("[Client] Proof claim %d: %s - %s\n", i+1, claim.Type, claim.Description)
		}
	}
}

// parseHTTPResponse parses raw HTTP response data into structured format
func (c *Client) parseHTTPResponse(data []byte) *HTTPResponse {
	dataStr := string(data)
	lines := strings.Split(dataStr, "\r\n")

	response := &HTTPResponse{
		StatusCode: 200, // Default
		Headers:    make(map[string]string),
		Body:       data,
		Metadata: ResponseMetadata{
			Timestamp:     time.Now().Unix(),
			ContentLength: len(data),
			TLSVersion:    "1.3",
			CipherSuite:   "AES-256-GCM",
			ServerName:    c.targetHost,
			RequestID:     c.sessionID,
		},
	}

	// Parse status line
	if len(lines) > 0 && strings.HasPrefix(lines[0], "HTTP/") {
		parts := strings.Split(lines[0], " ")
		if len(parts) >= 2 {
			if statusCode, err := fmt.Sscanf(parts[1], "%d", &response.StatusCode); err == nil && statusCode == 1 {
				// Status code parsed successfully
			}
		}
	}

	// Parse headers
	bodyStart := 0
	for i, line := range lines {
		if line == "" {
			bodyStart = i + 1
			break
		}
		if i > 0 { // Skip status line
			if colonIdx := strings.Index(line, ":"); colonIdx != -1 {
				key := strings.TrimSpace(line[:colonIdx])
				value := strings.TrimSpace(line[colonIdx+1:])
				response.Headers[key] = value

				// Extract metadata from specific headers
				switch strings.ToLower(key) {
				case "content-type":
					response.Metadata.ContentType = value
				case "content-length":
					if length, err := fmt.Sscanf(value, "%d", &response.Metadata.ContentLength); err == nil && length == 1 {
						// Content length parsed successfully
					}
				}
			}
		}
	}

	// Extract body
	if bodyStart < len(lines) {
		bodyLines := lines[bodyStart:]
		response.Body = []byte(strings.Join(bodyLines, "\r\n"))
	}

	return response
}

// *** Atomic completion flag helper functions ***

// setCompletionFlag atomically sets a completion flag
func (c *Client) setCompletionFlag(flag int64) {
	atomic.StoreInt64(&c.completionFlags, atomic.LoadInt64(&c.completionFlags)|flag)
}

// clearCompletionFlag atomically clears a completion flag
func (c *Client) clearCompletionFlag(flag int64) {
	atomic.StoreInt64(&c.completionFlags, atomic.LoadInt64(&c.completionFlags)&^flag)
}

// hasCompletionFlag atomically checks if a completion flag is set
func (c *Client) hasCompletionFlag(flag int64) bool {
	return atomic.LoadInt64(&c.completionFlags)&flag != 0
}

// setCompletionFlags atomically sets multiple completion flags
func (c *Client) setCompletionFlags(flags int64) {
	atomic.StoreInt64(&c.completionFlags, atomic.LoadInt64(&c.completionFlags)|flags)
}

// hasAllCompletionFlags atomically checks if all specified completion flags are set
func (c *Client) hasAllCompletionFlags(flags int64) bool {
	return atomic.LoadInt64(&c.completionFlags)&flags == flags
}

// Phase 4: Response handling methods

// processResponseRecords processes accumulated response data for complete TLS records

// processTLSRecord - moved to tls.go

// handleResponseTagVerification - moved to tls.go

// handleResponseDecryptionStream - moved to tls.go

// handleDecryptedResponse - moved to tls.go

// analyzeServerContent - moved to tls.go

// analyzeHandshakeMessage - moved to tls.go

// analyzeNewSessionTicket - moved to tls.go

// analyzeHTTPContent - moved to tls.go

// analyzeAlertMessage - moved to tls.go

// getClientAlertDescription - moved to tls.go

// removeTLSPadding - moved to tls.go

// checkProtocolCompletion - moved to completion.go

// sendFinishedCommand - moved to completion.go

// handleSessionReady processes session ready messages from TEE_K
// handleSessionReady - moved to websocket.go

// handleSignedTranscript - moved to websocket.go

// handleSignedRedactedDecryptionStream - moved to websocket.go

// min - moved to tls.go

// calculateRedactionBytes - moved to completion.go

// analyzeResponseRedaction - moved to completion.go

// analyzeHTTPRedactionWithBytes - moved to completion.go

// sendRedactionSpec - moved to completion.go

// isStandaloneMode checks if the client is running in standalone mode
func (c *Client) isStandaloneMode() bool {

	standalone := strings.HasPrefix(c.teekURL, "ws://") || strings.HasPrefix(c.teetURL, "ws://")

	return standalone
}

// fetchAndVerifyAttestations fetches attestations from both TEE_K and TEE_T and verifies them
func (c *Client) fetchAndVerifyAttestations() error {
	if c.isStandaloneMode() {
		fmt.Printf("[Client] Standalone mode detected - skipping attestation verification\n")
		return nil
	}

	fmt.Printf("[Client] Enclave mode detected - fetching attestations from both TEE_K and TEE_T\n")

	// Fetch attestation from TEE_K
	teekAttestationURL := c.getAttestationURL(c.teekURL)
	fmt.Printf("[Client] Fetching TEE_K attestation from: %s\n", teekAttestationURL)

	teekAttestation, err := c.fetchAttestation(teekAttestationURL)
	if err != nil {
		return fmt.Errorf("failed to fetch TEE_K attestation: %v", err)
	}

	// Fetch attestation from TEE_T
	teetAttestationURL := c.getAttestationURL(c.teetURL)
	fmt.Printf("[Client] Fetching TEE_T attestation from: %s\n", teetAttestationURL)

	teetAttestation, err := c.fetchAttestation(teetAttestationURL)
	if err != nil {
		return fmt.Errorf("failed to fetch TEE_T attestation: %v", err)
	}

	// Verify TEE_K attestation
	teekPublicKey, err := c.verifyAttestation(teekAttestation, "tee_k")
	if err != nil {
		return fmt.Errorf("failed to verify TEE_K attestation: %v", err)
	}
	c.teekAttestationPublicKey = teekPublicKey

	// Verify TEE_T attestation
	teetPublicKey, err := c.verifyAttestation(teetAttestation, "tee_t")
	if err != nil {
		return fmt.Errorf("failed to verify TEE_T attestation: %v", err)
	}
	c.teetAttestationPublicKey = teetPublicKey

	fmt.Printf("[Client] Successfully verified both TEE_K and TEE_T attestations\n")

	// Display public keys in a more distinguishable way
	// For P-256 keys, skip the common DER header (first ~26 bytes) and show the actual key material
	teekDisplayBytes := teekPublicKey
	if len(teekPublicKey) > 26 {
		teekDisplayBytes = teekPublicKey[26:] // Skip DER header, show actual key material
	}

	teetDisplayBytes := teetPublicKey
	if len(teetPublicKey) > 26 {
		teetDisplayBytes = teetPublicKey[26:] // Skip DER header, show actual key material
	}

	fmt.Printf("[Client] TEE_K public key (key material): %x\n", teekDisplayBytes[:min(32, len(teekDisplayBytes))])
	fmt.Printf("[Client] TEE_T public key (key material): %x\n", teetDisplayBytes[:min(32, len(teetDisplayBytes))])
	fmt.Printf("[Client] TEE_K full key length: %d bytes\n", len(teekPublicKey))
	fmt.Printf("[Client] TEE_T full key length: %d bytes\n", len(teetPublicKey))

	c.attestationVerified = true
	return nil
}

// getAttestationURL converts a WebSocket URL to the corresponding /attest HTTP endpoint
func (c *Client) getAttestationURL(wsURL string) string {
	// Replace ws:// with http:// and wss:// with https://
	attestURL := strings.Replace(wsURL, "ws://", "http://", 1)
	attestURL = strings.Replace(attestURL, "wss://", "https://", 1)

	// Remove /ws suffix and add /attest
	attestURL = strings.TrimSuffix(attestURL, "/ws")
	attestURL = attestURL + "/attest"

	return attestURL
}

// fetchAttestation fetches a base64-encoded attestation document from the specified URL
func (c *Client) fetchAttestation(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	// Read the base64-encoded attestation document
	base64Data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Decode the base64 data to get the binary attestation document
	attestationDoc, err := base64.StdEncoding.DecodeString(string(base64Data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 attestation: %v", err)
	}

	fmt.Printf("[Client] Fetched attestation document: %d bytes\n", len(attestationDoc))
	return attestationDoc, nil
}

// verifyAttestation verifies an attestation document and extracts the public key from user data
func (c *Client) verifyAttestation(attestationDoc []byte, expectedSource string) ([]byte, error) {
	// Parse the attestation document
	signedReport, err := verifier.NewSignedAttestationReport(strings.NewReader(string(attestationDoc)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation document: %v", err)
	}

	// Verify the attestation (root of trust validation)
	if err := verifier.Validate(signedReport, nil); err != nil {
		return nil, fmt.Errorf("attestation validation failed: %v", err)
	}

	fmt.Printf("[Client] Attestation root of trust validation passed for %s\n", expectedSource)

	// Extract user data from the attestation
	userData := signedReport.Document.UserData
	if len(userData) == 0 {
		return nil, fmt.Errorf("no user data found in attestation")
	}

	// Parse the user data to extract the public key
	userDataStr := string(userData)
	expectedPrefix := fmt.Sprintf("%s_public_key:", expectedSource)

	if !strings.HasPrefix(userDataStr, expectedPrefix) {
		return nil, fmt.Errorf("user data does not have expected prefix '%s', got: %s", expectedPrefix, userDataStr)
	}

	// Extract the hex-encoded public key
	hexPublicKey := strings.TrimPrefix(userDataStr, expectedPrefix)
	publicKey, err := hex.DecodeString(hexPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex public key: %v", err)
	}

	fmt.Printf("[Client] Extracted public key from %s attestation: %d bytes\n", expectedSource, len(publicKey))
	return publicKey, nil
}

// verifyAttestationPublicKeys compares the public keys from attestations with those from signed transcripts
func (c *Client) verifyAttestationPublicKeys() error {
	if c.isStandaloneMode() {
		fmt.Printf("[Client] Standalone mode - skipping attestation vs transcript public key comparison\n")
		return nil
	}

	// Check if we have both transcript public keys
	if c.teekTranscriptPublicKey == nil || c.teetTranscriptPublicKey == nil {
		return fmt.Errorf("not all transcript public keys are available yet")
	}

	// Check if we have both attestation public keys
	if c.teekAttestationPublicKey == nil || c.teetAttestationPublicKey == nil {
		return fmt.Errorf("not all attestation public keys are available yet")
	}

	// Compare TEE_K public keys
	if !bytes.Equal(c.teekAttestationPublicKey, c.teekTranscriptPublicKey) {
		return fmt.Errorf("TEE_K public key mismatch: attestation=%x, transcript=%x",
			c.teekAttestationPublicKey[:16], c.teekTranscriptPublicKey[:16])
	}

	// Compare TEE_T public keys
	if !bytes.Equal(c.teetAttestationPublicKey, c.teetTranscriptPublicKey) {
		return fmt.Errorf("TEE_T public key mismatch: attestation=%x, transcript=%x",
			c.teetAttestationPublicKey[:16], c.teetTranscriptPublicKey[:16])
	}

	fmt.Printf("[Client] Public key verification SUCCESS!\n")
	fmt.Printf("[Client] TEE_K: attestation and transcript public keys match\n")
	fmt.Printf("[Client] TEE_T: attestation and transcript public keys match\n")

	c.publicKeyComparisonDone = true
	return nil
}

// *** RESULT BUILDING METHODS FOR LIBRARY INTERFACE ***

// buildProtocolResult constructs the complete protocol execution results
func (c *Client) buildProtocolResult() (*ProtocolResult, error) {
	transcripts, _ := c.buildTranscriptResults()
	validation, _ := c.buildValidationResults()
	attestation, _ := c.buildAttestationResults()
	response, _ := c.buildResponseResults()

	success := transcripts.BothReceived && transcripts.BothSignaturesValid &&
		validation.AllValidationsPassed && c.httpResponseReceived

	var errorMessage string
	if !success {
		if !transcripts.BothReceived {
			errorMessage = "Not all transcripts received"
		} else if !transcripts.BothSignaturesValid {
			errorMessage = "Invalid transcript signatures"
		} else if !validation.AllValidationsPassed {
			errorMessage = "Validation failed"
		} else if !c.httpResponseReceived {
			errorMessage = "HTTP response not received"
		}
	}

	return &ProtocolResult{
		SessionID:         c.sessionID,
		StartTime:         c.protocolStartTime,
		CompletionTime:    time.Now(),
		Success:           success,
		ErrorMessage:      errorMessage,
		RequestTarget:     c.targetHost,
		RequestPort:       c.targetPort,
		RequestRedactions: c.requestRedactions,
		Transcripts:       *transcripts,
		Validation:        *validation,
		Attestation:       *attestation,
		Response:          *response,
	}, nil
}

// buildTranscriptResults constructs the transcript results
func (c *Client) buildTranscriptResults() (*TranscriptResults, error) {
	var teekTranscript, teetTranscript *SignedTranscriptData

	// Build TEE_K transcript data
	if c.teekTranscriptPackets != nil {
		totalSize := 0
		for _, packet := range c.teekTranscriptPackets {
			totalSize += len(packet)
		}

		teekTranscript = &SignedTranscriptData{
			Source:         "tee_k",
			Packets:        c.teekTranscriptPackets,
			PublicKey:      c.teekTranscriptPublicKey,
			TotalSize:      totalSize,
			PacketCount:    len(c.teekTranscriptPackets),
			Timestamp:      time.Now(), // TODO: Track actual timestamp
			SignatureValid: c.hasCompletionFlag(CompletionFlagTEEKSignatureValid),
		}
	}

	// Build TEE_T transcript data
	if c.teetTranscriptPackets != nil {
		totalSize := 0
		for _, packet := range c.teetTranscriptPackets {
			totalSize += len(packet)
		}

		teetTranscript = &SignedTranscriptData{
			Source:         "tee_t",
			Packets:        c.teetTranscriptPackets,
			PublicKey:      c.teetTranscriptPublicKey,
			TotalSize:      totalSize,
			PacketCount:    len(c.teetTranscriptPackets),
			Timestamp:      time.Now(), // TODO: Track actual timestamp
			SignatureValid: c.hasCompletionFlag(CompletionFlagTEETSignatureValid),
		}
	}

	bothReceived := c.hasAllCompletionFlags(CompletionFlagTEEKTranscriptReceived | CompletionFlagTEETTranscriptReceived)
	bothValid := c.hasAllCompletionFlags(CompletionFlagTEEKSignatureValid | CompletionFlagTEETSignatureValid)

	return &TranscriptResults{
		TEEK:                teekTranscript,
		TEET:                teetTranscript,
		BothReceived:        bothReceived,
		BothSignaturesValid: bothValid,
	}, nil
}

// buildValidationResults constructs the validation results
func (c *Client) buildValidationResults() (*ValidationResults, error) {
	// Build transcript validation results
	transcriptValidation := c.buildTranscriptValidationResults()

	// Build attestation validation results
	attestationValidation := c.buildAttestationValidationResults()

	allValid := transcriptValidation.OverallValid && attestationValidation.OverallValid

	var summary string
	if allValid {
		summary = "All validations passed successfully"
	} else {
		summary = "Some validations failed"
	}

	return &ValidationResults{
		TranscriptValidation:  *transcriptValidation,
		AttestationValidation: *attestationValidation,
		AllValidationsPassed:  allValid,
		ValidationSummary:     summary,
	}, nil
}

// buildAttestationResults constructs the attestation results
func (c *Client) buildAttestationResults() (*AttestationResults, error) {
	verification := c.buildAttestationValidationResults()

	return &AttestationResults{
		TEEKPublicKey: c.teekAttestationPublicKey,
		TEETPublicKey: c.teetAttestationPublicKey,
		Verification:  *verification,
	}, nil
}

// buildResponseResults constructs the response results
func (c *Client) buildResponseResults() (*ResponseResults, error) {
	var responseTimestamp time.Time
	if c.httpResponseReceived {
		responseTimestamp = time.Now() // TODO: Track actual timestamp
	}

	// Calculate total decrypted data size
	c.responseContentMutex.Lock()
	totalDataSize := 0
	for _, data := range c.responseContentBySeq {
		totalDataSize += len(data)
	}
	c.responseContentMutex.Unlock()

	return &ResponseResults{
		HTTPResponse:         c.lastResponseData,
		ProofClaims:          c.lastProofClaims,
		ResponseReceived:     c.httpResponseReceived,
		CallbackExecuted:     c.responseCallback != nil && c.httpResponseReceived,
		ResponseTimestamp:    responseTimestamp,
		DecryptionSuccessful: totalDataSize > 0,
		DecryptedDataSize:    totalDataSize,
	}, nil
}

// buildTranscriptValidationResults constructs detailed transcript validation results
func (c *Client) buildTranscriptValidationResults() *TranscriptValidationResults {
	if c.transcriptValidationResults != nil {
		return c.transcriptValidationResults
	}

	// Calculate client captured data
	totalCapturedSize := 0
	for _, chunk := range c.capturedTraffic {
		totalCapturedSize += len(chunk)
	}

	// Build TEE_K validation details
	teekValidation := c.buildTEEValidationDetails("tee_k", c.teekTranscriptPackets)

	// Build TEE_T validation details
	teetValidation := c.buildTEEValidationDetails("tee_t", c.teetTranscriptPackets)

	overallValid := teekValidation.ValidationPassed && teetValidation.ValidationPassed

	var summary string
	if overallValid {
		summary = "All transcript packets validated successfully"
	} else {
		summary = fmt.Sprintf("Validation issues: TEE_K (%d/%d matched), TEE_T (%d/%d matched)",
			teekValidation.PacketsMatched, teekValidation.PacketsReceived,
			teetValidation.PacketsMatched, teetValidation.PacketsReceived)
	}

	result := &TranscriptValidationResults{
		ClientCapturedPackets: len(c.capturedTraffic),
		ClientCapturedBytes:   totalCapturedSize,
		TEEKValidation:        teekValidation,
		TEETValidation:        teetValidation,
		OverallValid:          overallValid,
		Summary:               summary,
	}

	// Cache the result
	c.transcriptValidationResults = result
	return result
}

// buildAttestationValidationResults constructs attestation validation results
func (c *Client) buildAttestationValidationResults() *AttestationValidationResults {
	if c.attestationValidationResults != nil {
		return c.attestationValidationResults
	}

	// In standalone mode, attestation verification is skipped
	isStandalone := c.isStandaloneMode()

	teekAttestation := AttestationVerificationResult{
		AttestationReceived: c.teekAttestationPublicKey != nil,
		RootOfTrustValid:    isStandalone || c.attestationVerified,
		PublicKeyExtracted:  c.teekAttestationPublicKey != nil,
		PublicKeySize:       len(c.teekAttestationPublicKey),
	}

	teetAttestation := AttestationVerificationResult{
		AttestationReceived: c.teetAttestationPublicKey != nil,
		RootOfTrustValid:    isStandalone || c.attestationVerified,
		PublicKeyExtracted:  c.teetAttestationPublicKey != nil,
		PublicKeySize:       len(c.teetAttestationPublicKey),
	}

	publicKeyComparison := PublicKeyComparisonResult{
		ComparisonPerformed: isStandalone || c.publicKeyComparisonDone,
		TEEKKeysMatch:       isStandalone || (c.publicKeyComparisonDone && c.attestationVerified),
		TEETKeysMatch:       isStandalone || (c.publicKeyComparisonDone && c.attestationVerified),
		BothTEEsMatch:       isStandalone || (c.publicKeyComparisonDone && c.attestationVerified),
	}

	// In standalone mode, attestation validation always passes since it's bypassed
	overallValid := isStandalone || (teekAttestation.RootOfTrustValid && teetAttestation.RootOfTrustValid && publicKeyComparison.BothTEEsMatch)

	var summary string
	if isStandalone {
		summary = "Standalone mode - attestation verification bypassed"
	} else if overallValid {
		summary = "All attestations verified successfully"
	} else {
		summary = "Some attestation verifications failed"
	}

	result := &AttestationValidationResults{
		TEEKAttestation:     teekAttestation,
		TEETAttestation:     teetAttestation,
		PublicKeyComparison: publicKeyComparison,
		OverallValid:        overallValid,
		Summary:             summary,
	}

	// Cache the result
	c.attestationValidationResults = result
	return result
}

// buildTEEValidationDetails constructs validation details for one TEE's transcript
func (c *Client) buildTEEValidationDetails(source string, packets [][]byte) TranscriptPacketValidation {
	var packetTypes []string
	if source == "tee_k" {
		packetTypes = c.teekTranscriptPacketTypes
	} else if source == "tee_t" {
		packetTypes = c.teetTranscriptPacketTypes
	}

	if packets == nil {
		return TranscriptPacketValidation{
			PacketsReceived:  0,
			PacketsMatched:   0,
			ValidationPassed: false,
			PacketDetails:    []PacketValidationDetail{},
		}
	}

	var details []PacketValidationDetail
	packetsMatched := 0

	for i, packet := range packets {
		// Decide whether this packet must have a matching capture.
		mustMatch := true
		if len(packetTypes) > i {
			if packetTypes[i] != shared.TranscriptPacketTypeTLSRecord {
				mustMatch = false
			}
		}

		var packetType string
		if len(packet) > 0 {
			packetType = fmt.Sprintf("0x%02x", packet[0])
		} else {
			packetType = "empty"
		}

		// Check if this packet matches any captured traffic
		matchedCapture := false
		captureIndex := -1

		if mustMatch {
			for j, capturedChunk := range c.capturedTraffic {
				if len(packet) == len(capturedChunk) && bytes.Equal(packet, capturedChunk) {
					matchedCapture = true
					captureIndex = j
					packetsMatched++
					break
				}
			}
		} else {
			// Non-TLS packet types are considered matched by definition
			matchedCapture = true
		}

		detail := PacketValidationDetail{
			PacketIndex:    i,
			PacketSize:     len(packet),
			PacketType:     packetType,
			MatchedCapture: matchedCapture,
		}

		if matchedCapture {
			detail.CaptureIndex = captureIndex
		}

		details = append(details, detail)
	}

	// Only require TLSRecord packets to be matched.
	requiredMatches := 0
	for i := range packets {
		need := true
		if len(packetTypes) > i && packetTypes[i] != shared.TranscriptPacketTypeTLSRecord {
			need = false
		}
		if need {
			requiredMatches++
		}
	}

	return TranscriptPacketValidation{
		PacketsReceived:  len(packets),
		PacketsMatched:   packetsMatched,
		ValidationPassed: packetsMatched == requiredMatches,
		PacketDetails:    details,
	}
}
