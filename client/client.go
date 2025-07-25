package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tee-mpc/shared"

	"github.com/anjuna-security/go-nitro-attestation/verifier"
	"github.com/gorilla/websocket"
)

const (
	ClientStateInitial = iota
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
	forceTLSVersion   string // Force specific TLS version: "1.2", "1.3", or "" for auto
	forceCipherSuite  string // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
	targetHost        string
	targetPort        int
	isClosing         bool
	capturedTraffic   [][]byte // Store all captured traffic for verification
	handshakeComplete bool     // Track if TLS handshake is complete

	// Pending connection request data (to be sent once session ID is received)
	pendingConnectionRequest *shared.RequestConnectionData
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
	recordTypeBySeq        map[uint64]byte   // *** NEW: Store TLS record type by sequence number ***

	// *** NEW: Response packet batching fields ***
	batchedResponses      []EncryptedResponseData // Collect response packets until EOF
	batchedResponsesMutex sync.Mutex              // Protect batched responses collection

	// *** NEW: Response processing success tracking ***
	responseProcessingSuccessful bool       // Track if response was successfully processed
	reconstructedResponseSize    int        // Size of reconstructed response data
	responseProcessingMutex      sync.Mutex // Protect response processing flags

	// Track redaction ranges so we can prettify later and include in bundle
	requestRedactionRanges []RedactionRange
	// Attestation verification fields
	teekAttestationPublicKey []byte // Public key extracted from TEE_K attestation
	teetAttestationPublicKey []byte // Public key extracted from TEE_T attestation
	teekTranscriptPublicKey  []byte // Public key from TEE_K signed transcript
	teetTranscriptPublicKey  []byte // Public key from TEE_T signed transcript
	attestationVerified      bool   // Flag to track if attestation verification passed
	publicKeyComparisonDone  bool   // Flag to track if public key comparison was completed

	// Transcript validation fields
	teekTranscriptPackets [][]byte // Packets from TEE_K signed transcript for validation
	teetTranscriptPackets [][]byte // Packets from TEE_T signed transcript for validation

	// Library interface fields
	requestRedactions []RedactionSpec  // Request redactions from config
	responseCallback  ResponseCallback // Response callback for redactions
	clientMode        ClientMode       // Client operational mode (enclave vs standalone)

	// Result tracking fields
	protocolStartTime            time.Time                     // When protocol started
	lastResponseData             *HTTPResponse                 // Last received HTTP response
	lastProofClaims              []ProofClaim                  // Last generated proof claims
	lastRedactionRanges          []RedactionRange              // Last redaction ranges from callback
	lastRedactedResponse         []byte                        // Last redacted response from callback
	responseReconstructed        bool                          // Flag to prevent multiple response reconstruction
	transcriptValidationResults  *TranscriptValidationResults  // Cached validation results
	attestationValidationResults *AttestationValidationResults // Cached attestation results

	// Verification bundle tracking fields
	handshakeDisclosure     *HandshakeKeyDisclosureData             // store handshake keys
	teekSignedTranscript    *shared.SignedTranscript                // full signed transcript from TEE_K
	teetSignedTranscript    *shared.SignedTranscript                // full signed transcript from TEE_T
	signedRedactedStreams   []shared.SignedRedactedDecryptionStream // ordered collection of redacted streams
	redactedRequestPlain    []byte                                  // R_red plaintext sent to TEE_K
	fullRedactedResponse    []byte                                  // final redacted HTTP response (concatenated)
	expectedRedactedStreams int                                     // expected number of redacted streams from response sequences

	// commitment opening for proof
	proofStream []byte
	proofKey    []byte
}

func NewClient(teekURL string) *Client {
	return &Client{
		teekURL:                   teekURL,
		teetURL:                   "wss://tee-t.reclaimprotocol.org/ws", // Default TEE_T URL (enclave mode)
		pendingResponsesData:      make(map[uint64][]byte),
		completionChan:            make(chan struct{}),
		state:                     ClientStateInitial,
		recordsSent:               0,
		recordsProcessed:          0,
		decryptionStreamsReceived: 0,
		eofReached:                0,
		completionFlags:           0,
		httpRequestSent:           false,
		httpResponseExpected:      false,
		httpResponseReceived:      false,
		responseContentMutex:      sync.Mutex{},
		ciphertextBySeq:           make(map[uint64][]byte),
		decryptionStreamBySeq:     make(map[uint64][]byte),
		redactedPlaintextBySeq:    make(map[uint64][]byte),
		recordTypeBySeq:           make(map[uint64]byte),
		requestRedactionRanges:    nil,

		// *** NEW: Initialize batching fields ***
		batchedResponses:             make([]EncryptedResponseData, 0),
		batchedResponsesMutex:        sync.Mutex{},
		responseProcessingSuccessful: false,
		reconstructedResponseSize:    0,
		responseProcessingMutex:      sync.Mutex{},
		teekAttestationPublicKey:     nil,
		teetAttestationPublicKey:     nil,
		teekTranscriptPublicKey:      nil,
		teetTranscriptPublicKey:      nil,
		attestationVerified:          false,
		publicKeyComparisonDone:      false,
		teekTranscriptPackets:        nil,
		teetTranscriptPackets:        nil,
		requestRedactions:            nil,
		responseCallback:             nil,
		clientMode:                   ModeAuto, // Default to auto-detect
		protocolStartTime:            time.Now(),
		lastResponseData:             nil,
		lastProofClaims:              nil,
		transcriptValidationResults:  nil,
		attestationValidationResults: nil,
		signedRedactedStreams:        make([]shared.SignedRedactedDecryptionStream, 0),
		proofStream:                  nil,
		proofKey:                     nil,
		expectedRedactedStreams:      0,
	}
}

// SetTEETURL sets the TEE_T connection URL
func (c *Client) SetTEETURL(url string) {
	c.teetURL = url
}

// SetMode sets the client operational mode
func (c *Client) SetMode(mode ClientMode) {
	c.clientMode = mode
}

func (c *Client) RequestHTTP(hostname string, port int) error {
	c.targetHost = hostname
	c.targetPort = port

	fmt.Printf("[Client] Requesting connection to %s:%d\n", hostname, port)

	// Store connection request data to be sent once session ID is received
	c.pendingConnectionRequest = &shared.RequestConnectionData{
		Hostname:         hostname,
		Port:             port,
		SNI:              hostname,
		ALPN:             []string{"http/1.1"},
		ForceTLSVersion:  c.forceTLSVersion,
		ForceCipherSuite: c.forceCipherSuite,
	}
	c.connectionRequestPending = true

	// Check if we already have a session ID and send immediately
	if c.sessionID != "" {
		return c.sendPendingConnectionRequest()
	}

	// Otherwise, request will be sent when session ID is received in handleSessionReady
	return nil
}

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

	// Pretty-print: overlay '*' over redacted ranges so output is readable.
	prettyReq := append([]byte(nil), redactedRequest...)
	for _, r := range ranges {
		end := r.Start + r.Length
		if r.Start < 0 || end > len(prettyReq) {
			continue
		}
		for i := r.Start; i < end; i++ {
			prettyReq[i] = '*'
		}
	}
	fmt.Printf("[Client] REDACTED REQUEST (pretty):\n%s\n", string(prettyReq))

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
	c.requestRedactionRanges = ranges // Save redaction ranges

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

	// If no redaction specs configured, return empty ranges
	if len(c.requestRedactions) == 0 {
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

		// Store proof claims
		c.lastProofClaims = result.ProofClaims
		log.Printf("[Client] Stored %d proof claims from callback", len(result.ProofClaims))

		// Store redaction ranges
		c.lastRedactionRanges = result.RedactionRanges
		log.Printf("[Client] Stored %d redaction ranges from callback", len(result.RedactionRanges))

		// Log proof claims
		for i, claim := range result.ProofClaims {
			log.Printf("[Client] Proof claim %d: %s = %s (%s)", i+1, claim.Type, claim.Value, claim.Description)
		}

		// Log redaction ranges
		for i, r := range result.RedactionRanges {
			log.Printf("[Client] Redaction range %d: [%d:%d] type=%s", i+1, r.Start, r.Start+r.Length-1, r.Type)
		}
	}
}

// parseHTTPResponse parses raw HTTP response data into structured format
func (c *Client) parseHTTPResponse(data []byte) *HTTPResponse {
	dataStr := string(data)
	lines := strings.Split(dataStr, "\r\n")

	response := &HTTPResponse{
		StatusCode:   200, // Default
		Headers:      make(map[string]string),
		Body:         data, // Will be updated to just body part below
		FullResponse: data, // Complete HTTP response for redaction calculations
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

	// Extract body (just the body part for Body field)
	if bodyStart < len(lines) {
		bodyLines := lines[bodyStart:]
		response.Body = []byte(strings.Join(bodyLines, "\r\n"))
	} else {
		response.Body = []byte{} // No body found
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

// handleSessionReady processes session ready messages from TEE_K

// fetchAndVerifyAttestations fetches attestations from both TEE_K and TEE_T via WebSocket
// Now waits for session coordination before sending requests
func (c *Client) fetchAndVerifyAttestations() error {
	// Skip attestations entirely in standalone mode
	if c.clientMode == ModeStandalone {
		fmt.Printf("[Client] Skipping attestation in standalone mode - public keys will be extracted from signed transcripts\n")
		return nil
	}

	fmt.Printf("[Client] Requesting attestations from both TEE_K and TEE_T via WebSocket\n")

	// Wait for session ID from TEE_K (indicates successful session coordination)
	// This is a simple polling approach for now
	maxWait := 30 * time.Second
	waitStart := time.Now()

	for c.sessionID == "" {
		if time.Since(waitStart) > maxWait {
			return fmt.Errorf("timeout waiting for session coordination")
		}
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("[Client] Session coordinated (%s), proceeding with attestation requests\n", c.sessionID)

	// Create attestation request (no request ID needed)
	attestReq := shared.AttestationRequestData{}

	// Send to TEE_K
	teekMsg, err := CreateMessage(MsgAttestationRequest, attestReq)
	if err != nil {
		return fmt.Errorf("failed to create TEE_K attestation request: %v", err)
	}

	if err := c.sendMessage(teekMsg); err != nil {
		return fmt.Errorf("failed to send TEE_K attestation request: %v", err)
	}
	fmt.Printf("[Client] Sent attestation request to TEE_K\n")

	// Send to TEE_T
	teetMsg, err := CreateMessage(MsgAttestationRequest, attestReq)
	if err != nil {
		return fmt.Errorf("failed to create TEE_T attestation request: %v", err)
	}

	if err := c.sendMessageToTEET(teetMsg); err != nil {
		return fmt.Errorf("failed to send TEE_T attestation request: %v", err)
	}
	fmt.Printf("[Client] Sent attestation request to TEE_T\n")

	// Responses will be handled asynchronously by handleAttestationResponse
	fmt.Printf("[Client] Waiting for attestation responses from both TEE_K and TEE_T...\n")
	return nil
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
			Packets:   c.teekTranscriptPackets,
			PublicKey: c.teekTranscriptPublicKey,
		}
	}

	// Build TEE_T transcript data
	if c.teetTranscriptPackets != nil {
		totalSize := 0
		for _, packet := range c.teetTranscriptPackets {
			totalSize += len(packet)
		}

		teetTranscript = &SignedTranscriptData{
			Packets:   c.teetTranscriptPackets,
			PublicKey: c.teetTranscriptPublicKey,
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

	// *** NEW: Use batched response processing success flags ***
	c.responseProcessingMutex.Lock()
	batchedSuccess := c.responseProcessingSuccessful
	batchedDataSize := c.reconstructedResponseSize
	c.responseProcessingMutex.Unlock()

	// Calculate total decrypted data size (fallback if batched processing didn't run)
	c.responseContentMutex.Lock()
	totalDataSize := 0
	for _, data := range c.responseContentBySeq {
		totalDataSize += len(data)
	}
	c.responseContentMutex.Unlock()

	// Use batched data size if available, otherwise fall back to individual processing
	finalDataSize := batchedDataSize
	if finalDataSize == 0 {
		finalDataSize = totalDataSize
	}

	return &ResponseResults{
		HTTPResponse:         c.lastResponseData,
		ProofClaims:          c.lastProofClaims,
		ResponseReceived:     batchedSuccess || c.httpResponseReceived,
		CallbackExecuted:     batchedSuccess || (c.responseCallback != nil && c.httpResponseReceived),
		DecryptionSuccessful: batchedSuccess || (finalDataSize > 0),
		DecryptedDataSize:    finalDataSize,
		ResponseTimestamp:    responseTimestamp,
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

	teekAttestation := AttestationVerificationResult{
		AttestationReceived: c.teekAttestationPublicKey != nil,
		RootOfTrustValid:    c.attestationVerified,
		PublicKeyExtracted:  c.teekAttestationPublicKey != nil,
		PublicKeySize:       len(c.teekAttestationPublicKey),
	}

	teetAttestation := AttestationVerificationResult{
		AttestationReceived: c.teetAttestationPublicKey != nil,
		RootOfTrustValid:    c.attestationVerified,
		PublicKeyExtracted:  c.teetAttestationPublicKey != nil,
		PublicKeySize:       len(c.teetAttestationPublicKey),
	}

	publicKeyComparison := PublicKeyComparisonResult{
		ComparisonPerformed: c.publicKeyComparisonDone,
		TEEKKeysMatch:       c.publicKeyComparisonDone && c.attestationVerified,
		TEETKeysMatch:       c.publicKeyComparisonDone && c.attestationVerified,
		BothTEEsMatch:       c.publicKeyComparisonDone && c.attestationVerified,
	}

	overallValid := teekAttestation.RootOfTrustValid && teetAttestation.RootOfTrustValid && publicKeyComparison.BothTEEsMatch

	var summary string
	if overallValid {
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
	// All transcript packets are now TLS records

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
		// With the new structure, all packets in the Packets array are TLS records
		var packetType string
		if len(packet) > 0 {
			packetType = fmt.Sprintf("0x%02x", packet[0])
		} else {
			packetType = "empty"
		}

		// Check if this packet matches any captured traffic
		matchedCapture := false
		captureIndex := -1

		for j, capturedChunk := range c.capturedTraffic {
			if len(packet) == len(capturedChunk) && bytes.Equal(packet, capturedChunk) {
				matchedCapture = true
				captureIndex = j
				packetsMatched++
				break
			}
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

	// All packets are now TLS records and should be matched
	requiredMatches := len(packets)

	return TranscriptPacketValidation{
		PacketsReceived:  len(packets),
		PacketsMatched:   packetsMatched,
		ValidationPassed: packetsMatched == requiredMatches,
		PacketDetails:    details,
	}
}

// RequestAttestation requests attestation from both TEE_K and TEE_T
// Now waits for session coordination before sending requests
func (c *Client) RequestAttestation() (*AttestationResponseData, *AttestationResponseData, error) {
	// Wait for session ID from TEE_K (indicates successful session coordination)
	if c.sessionID == "" {
		return nil, nil, fmt.Errorf("session not established - cannot request attestation")
	}

	fmt.Printf("[Client] Requesting attestation for session: %s\n", c.sessionID)

	// Create attestation request (no request ID needed)
	attestReq := shared.AttestationRequestData{}

	// Send to TEE_K
	teekMsg, err := CreateMessage(MsgAttestationRequest, attestReq)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TEE_K attestation request: %v", err)
	}

	if err := c.sendMessage(teekMsg); err != nil {
		return nil, nil, fmt.Errorf("failed to send TEE_K attestation request: %v", err)
	}

	// Send to TEE_T
	teetMsg, err := CreateMessage(MsgAttestationRequest, attestReq)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TEE_T attestation request: %v", err)
	}

	if err := c.sendMessageToTEET(teetMsg); err != nil {
		return nil, nil, fmt.Errorf("failed to send TEE_T attestation request: %v", err)
	}

	// Wait for both responses
	var teekResponse, teetResponse *AttestationResponseData
	responsesReceived := 0

	for responsesReceived < 2 {
		select {
		case <-time.After(30 * time.Second):
			return nil, nil, fmt.Errorf("timeout waiting for attestation responses")
		case <-c.completionChan:
			return nil, nil, fmt.Errorf("client closed while waiting for attestation")
		default:
			// Check for responses (simplified without request ID matching)
			time.Sleep(100 * time.Millisecond)
			// Response handling is done in message handlers
		}
	}

	return teekResponse, teetResponse, nil
}
