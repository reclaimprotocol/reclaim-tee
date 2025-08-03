package clientlib

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"tee-mpc/shared"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/anjuna-security/go-nitro-attestation/verifier"
)

const (
	ClientStateInitial = iota
)

// Completion flags for atomic bit operations
const (
	CompletionFlagTEEKSignatureValid = 1 << iota
)

type ProtocolPhase int

const (
	PhaseHandshaking ProtocolPhase = iota
	PhaseCollectingResponses
	PhaseSendingBatch
	PhaseReceivingDecryption
	PhaseWaitingForRedactionRanges // NEW: Phase for waiting for response redaction ranges
	PhaseSendingRedaction
	PhaseReceivingRedacted
	PhaseReceivingTranscripts
	PhaseComplete
)

func (p ProtocolPhase) String() string {
	switch p {
	case PhaseHandshaking:
		return "Handshaking"
	case PhaseCollectingResponses:
		return "CollectingResponses"
	case PhaseSendingBatch:
		return "SendingBatch"
	case PhaseReceivingDecryption:
		return "ReceivingDecryption"
	case PhaseWaitingForRedactionRanges:
		return "WaitingForRedactionRanges"
	case PhaseSendingRedaction:
		return "SendingRedaction"
	case PhaseReceivingRedacted:
		return "ReceivingRedacted"
	case PhaseReceivingTranscripts:
		return "ReceivingTranscripts"
	case PhaseComplete:
		return "Complete"
	default:
		return "Unknown"
	}
}

type Client struct {
	wsConn   *websocket.Conn
	teetConn *websocket.Conn
	tcpConn  net.Conn

	// Logging
	logger *shared.Logger

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

	completionOnce sync.Once // Ensures completion channel is only closed once

	state int64 // Basic state field

	completionFlags int64 // Atomic bit flags for completion state tracking

	protocolPhase       ProtocolPhase // Current protocol phase
	transcriptsReceived int           // Count of transcripts received (0, 1, 2)
	protocolStateMutex  sync.RWMutex  // Protect simple state

	// Track HTTP request/response lifecycle
	httpRequestSent        bool              // Track if HTTP request has been sent
	httpResponseExpected   bool              // Track if we should expect HTTP response
	httpResponseReceived   bool              // Track if HTTP response content has been received
	responseContentBySeq   map[uint64][]byte // Store decrypted response content by sequence
	responseContentMutex   sync.Mutex        // For all response maps
	ciphertextBySeq        map[uint64][]byte // Store encrypted response data by sequence
	decryptionStreamBySeq  map[uint64][]byte // Store decryption streams by sequence
	redactedPlaintextBySeq map[uint64][]byte // Store final redacted plaintext for ordered printing ***
	recordTypeBySeq        map[uint64]byte   // Store TLS record type by sequence number

	// Batched response tracking (collection until EOF)
	batchedResponses []shared.EncryptedResponseData // Collect response packets until EOF

	// Response processing success tracking
	responseProcessingSuccessful bool // Track if response was successfully processed
	reconstructedResponseSize    int  // Size of reconstructed response data

	// Track redaction ranges so we can prettify later and include in bundle
	requestRedactionRanges []shared.RequestRedactionRange
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
	responseCallback ResponseCallback // Response callback for redactions
	clientMode       ClientMode       // Client operational mode (enclave vs standalone)

	// 2-phase operation support
	twoPhaseMode     bool          // Whether to operate in 2-phase mode
	phase1Completed  bool          // Whether phase 1 (response decryption) is complete
	phase1Completion chan struct{} // Channel to signal phase 1 completion

	// Result tracking fields
	protocolStartTime            time.Time                       // When protocol started
	lastResponseData             *HTTPResponse                   // Last received HTTP response
	lastProofClaims              []ProofClaim                    // Last generated proof claims
	lastRedactionRanges          []shared.ResponseRedactionRange // Last redaction ranges from callback
	lastRedactedResponse         []byte                          // Last redacted response from callback
	responseReconstructed        bool                            // Flag to prevent multiple response reconstruction
	transcriptValidationResults  *TranscriptValidationResults    // Cached validation results
	attestationValidationResults *AttestationValidationResults   // Cached attestation results

	// Verification bundle tracking fields
	handshakeDisclosure     *shared.HandshakeKeyDisclosureData      // store handshake keys
	teekSignedTranscript    *shared.SignedTranscript                // full signed transcript from TEE_K
	teetSignedTranscript    *shared.SignedTranscript                // full signed transcript from TEE_T
	signedRedactedStreams   []shared.SignedRedactedDecryptionStream // ordered collection of redacted streams
	redactedRequestPlain    []byte                                  // R_red plaintext sent to TEE_K
	fullRedactedResponse    []byte                                  // final redacted HTTP response (concatenated)
	expectedRedactedStreams int                                     // expected number of redacted streams from response sequences

	// commitment opening for proof (R_SP streams only, as per protocol)
	proofStream []byte // Concatenated R_SP streams
	proofKey    []byte // First R_SP key (protocol assumes single K_SP)

	// Request data from libreclaim library
	requestData []byte
}

func NewClient(teekURL string) *Client {
	// Initialize logger for client
	logger, err := shared.NewLoggerFromEnv("client")
	if err != nil {
		// Fallback to basic logger if initialization fails
		logger, _ = shared.NewLogger(shared.LoggerConfig{
			ServiceName: "client",
			EnclaveMode: false,
			Development: true,
		})
	}

	return &Client{
		logger:               logger,
		teekURL:              teekURL,
		teetURL:              "wss://tee-t.reclaimprotocol.org/ws", // Default TEE_T URL (enclave mode)
		pendingResponsesData: make(map[uint64][]byte),
		completionChan:       make(chan struct{}),
		state:                ClientStateInitial,
		completionFlags:      0,

		protocolPhase:          PhaseHandshaking,
		transcriptsReceived:    0,
		protocolStateMutex:     sync.RWMutex{},
		httpRequestSent:        false,
		httpResponseExpected:   false,
		httpResponseReceived:   false,
		responseContentMutex:   sync.Mutex{},
		ciphertextBySeq:        make(map[uint64][]byte),
		decryptionStreamBySeq:  make(map[uint64][]byte),
		redactedPlaintextBySeq: make(map[uint64][]byte),
		recordTypeBySeq:        make(map[uint64]byte),
		requestRedactionRanges: nil,

		// Initialize batching fields
		batchedResponses: make([]shared.EncryptedResponseData, 0),

		// Response processing success tracking
		responseProcessingSuccessful: false,
		reconstructedResponseSize:    0,
		teekAttestationPublicKey:     nil,
		teetAttestationPublicKey:     nil,
		teekTranscriptPublicKey:      nil,
		teetTranscriptPublicKey:      nil,

		// 2-phase operation support
		twoPhaseMode:            false,
		phase1Completed:         false,
		phase1Completion:        make(chan struct{}),
		attestationVerified:     false,
		publicKeyComparisonDone: false,
		teekTranscriptPackets:   nil,
		teetTranscriptPackets:   nil,

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

// SetRequestRedactionRanges sets the redaction ranges directly (for libreclaim compatibility)
func (c *Client) SetRequestRedactionRanges(ranges []shared.RequestRedactionRange) {
	c.requestRedactionRanges = ranges
}

func (c *Client) RequestHTTP(hostname string, port int) error {
	c.targetHost = hostname
	c.targetPort = port

	c.logger.Info("Requesting connection",
		zap.String("hostname", hostname),
		zap.Int("port", port))

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
func (c *Client) createRedactedRequest(httpRequest []byte) (shared.RedactedRequestData, shared.RedactionStreamsData, error) {
	c.logger.Info("Creating redacted request",
		zap.Int("request_data_length", len(c.requestData)),
		zap.Int("http_request_length", len(httpRequest)))

	// Use the stored request data if available, otherwise use provided request
	if len(c.requestData) > 0 {
		c.logger.Info("Using stored request data")
		httpRequest = c.requestData
	} else if len(httpRequest) == 0 {
		return shared.RedactedRequestData{}, shared.RedactionStreamsData{}, fmt.Errorf("no request data provided")
	} else {
		c.logger.Info("Using provided HTTP request")
	}

	c.logger.Debug("Original request details",
		zap.Int("length", len(httpRequest)),
		zap.String("target_host", c.targetHost),
		zap.Int("host_length", len(c.targetHost)))

	// Show the complete HTTP request with sensitive data before redaction
	c.logger.Debug("Complete HTTP request before redaction",
		zap.String("request", string(httpRequest)),
		zap.Int("total_length", len(httpRequest)))

	// Use only the redaction ranges provided by the user
	ranges := c.requestRedactionRanges
	if len(ranges) == 0 {
		return shared.RedactedRequestData{}, shared.RedactionStreamsData{}, fmt.Errorf("no redaction ranges provided - library requires explicit redaction ranges")
	}

	c.logger.Info("Redaction configuration",
		zap.Int("ranges_count", len(ranges)))
	for i, r := range ranges {
		c.logger.Debug("Redaction range",
			zap.Int("index", i),
			zap.Int("start", r.Start),
			zap.Int("end", r.Start+r.Length),
			zap.String("type", r.Type))
	}

	// Validate redaction ranges
	if err := c.validateRedactionRanges(ranges, len(httpRequest)); err != nil {
		return shared.RedactedRequestData{}, shared.RedactionStreamsData{}, fmt.Errorf("invalid redaction ranges: %v", err)
	}

	// Generate redaction streams and commitment keys
	streams, keys, err := c.generateRedactionStreams(ranges)
	if err != nil {
		return shared.RedactedRequestData{}, shared.RedactionStreamsData{}, fmt.Errorf("failed to generate redaction streams: %v", err)
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
	c.logger.Debug("Redacted request (pretty)",
		zap.String("request", string(prettyReq)))

	// Show non-sensitive parts remain unchanged
	c.logger.Debug("Non-sensitive parts (unchanged)")
	lines := strings.Split(string(httpRequest), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "Host: ") ||
			strings.HasPrefix(line, "Connection: ") || line == "" {
			c.logger.Debug("Non-sensitive line", zap.String("line", line))
		}
	}

	// Compute commitments
	commitments := c.computeCommitments(streams, keys)

	// Collect proof streams and keys for R_SP ranges (only these are needed for verification)
	var proofStreams [][]byte
	var proofKeys [][]byte

	for idx, r := range ranges {
		if r.Type == shared.RedactionTypeSensitiveProof {
			proofStreams = append(proofStreams, streams[idx])
			proofKeys = append(proofKeys, keys[idx])
		}
	}

	// Concatenate all R_SP streams and keys
	if len(proofStreams) > 0 {
		totalStreamLen := 0
		for _, stream := range proofStreams {
			totalStreamLen += len(stream)
		}
		c.proofStream = make([]byte, totalStreamLen)
		offset := 0
		for _, stream := range proofStreams {
			copy(c.proofStream[offset:], stream)
			offset += len(stream)
		}
		c.proofKey = proofKeys[0] // Use first R_SP key (protocol assumes single K_SP)

		c.logger.Info("R_SP streams concatenated",
			zap.Int("r_sp_ranges", len(proofStreams)),
			zap.Int("total_proof_stream_length", len(c.proofStream)),
			zap.Int("proof_key_length", len(c.proofKey)))
	}

	c.logger.Info("Redaction summary",
		zap.Int("original_length", len(httpRequest)),
		zap.Int("redacted_length", len(redactedRequest)),
		zap.Int("redaction_ranges", len(ranges)))

	c.redactedRequestPlain = redactedRequest
	c.requestRedactionRanges = ranges // Save redaction ranges

	return shared.RedactedRequestData{
			RedactedRequest: redactedRequest,
			Commitments:     commitments,
			RedactionRanges: ranges,
		}, shared.RedactionStreamsData{
			Streams:        streams,
			CommitmentKeys: keys,
		}, nil
}

// generateRedactionStreams generates random XOR streams and commitment keys for each redaction range
func (c *Client) generateRedactionStreams(ranges []shared.RequestRedactionRange) ([][]byte, [][]byte, error) {
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
func (c *Client) applyRedaction(request []byte, ranges []shared.RequestRedactionRange, streams [][]byte) []byte {
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
func (c *Client) validateRedactionRanges(ranges []shared.RequestRedactionRange, requestLen int) error {
	for _, r := range ranges {
		if r.Start < 0 || r.Length < 0 || r.Start+r.Length > requestLen {
			return fmt.Errorf("invalid redaction range: start=%d, length=%d, requestLen=%d", r.Start, r.Length, requestLen)
		}
	}
	return nil
}

// applyRedactionSpecs applies redaction specifications from config to find redaction ranges

// triggerResponseCallback triggers the response callback if configured
func (c *Client) triggerResponseCallback(responseData []byte) {
	if c.responseCallback == nil {
		return
	}

	// Parse HTTP response to extract status code and headers
	response := c.parseHTTPResponse(responseData)

	c.logger.Info("Triggering response callback", zap.Int("data_bytes", len(responseData)))

	// Store the response data for library access
	c.lastResponseData = response

	// Call the user-provided callback
	result, err := c.responseCallback.OnResponseReceived(response)
	if err != nil {
		c.logger.Error("Response callback error", zap.Error(err))
		return
	}

	if result != nil {
		c.logger.Info("Response callback completed",
			zap.Int("redaction_ranges", len(result.RedactionRanges)),
			zap.Int("proof_claims", len(result.ProofClaims)))

		// Store proof claims
		c.lastProofClaims = result.ProofClaims
		c.logger.Info("Stored proof claims from callback", zap.Int("count", len(result.ProofClaims)))

		// Store redaction ranges
		c.lastRedactionRanges = result.RedactionRanges
		c.logger.Info("Stored redaction ranges from callback", zap.Int("count", len(result.RedactionRanges)))

		// Log proof claims
		for i, claim := range result.ProofClaims {
			c.logger.Debug("Proof claim",
				zap.Int("index", i+1),
				zap.String("type", claim.Type),
				zap.String("value", claim.Value),
				zap.String("description", claim.Description))
		}

		// Log redaction ranges
		for i, r := range result.RedactionRanges {
			c.logger.Debug("Redaction range",
				zap.Int("index", i+1),
				zap.Int("start", r.Start),
				zap.Int("end", r.Start+r.Length-1))
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

// setCompletionFlag atomically sets a completion flag
func (c *Client) setCompletionFlag(flag int64) {
	atomic.StoreInt64(&c.completionFlags, atomic.LoadInt64(&c.completionFlags)|flag)
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

// setBatchCollectionComplete is now handled by phase transition to PhaseSendingBatch
func (c *Client) setBatchCollectionComplete() {
}

// setBatchSentToTEET is now handled by phase transition to PhaseReceivingDecryption
func (c *Client) setBatchSentToTEET() {
}

// setBatchDecryptionReceived is now handled by phase transition to PhaseSendingRedaction
func (c *Client) setBatchDecryptionReceived() {
}

// getBatchState returns current batch state based on protocol phase (thread-safe)
func (c *Client) getBatchState() (collectionComplete, sentToTEET, decryptionReceived bool) {
	c.protocolStateMutex.RLock()
	defer c.protocolStateMutex.RUnlock()

	// Derive batch state from protocol phase
	collectionComplete = c.protocolPhase >= PhaseSendingBatch
	sentToTEET = c.protocolPhase >= PhaseReceivingDecryption
	decryptionReceived = c.protocolPhase >= PhaseSendingRedaction
	return
}

// isBatchProcessingComplete checks if all batch operations are complete
func (c *Client) isBatchProcessingComplete() bool {
	collection, sent, decryption := c.getBatchState()
	return collection && sent && decryption
}

// getCurrentPhase returns the current protocol phase (thread-safe)
func (c *Client) getCurrentPhase() ProtocolPhase {
	c.protocolStateMutex.RLock()
	defer c.protocolStateMutex.RUnlock()
	return c.protocolPhase
}

// advanceToPhase transitions to a new protocol phase (thread-safe)
func (c *Client) advanceToPhase(newPhase ProtocolPhase) {
	c.protocolStateMutex.Lock()
	oldPhase := c.protocolPhase
	c.protocolPhase = newPhase
	c.protocolStateMutex.Unlock()

	c.logger.Info("Phase transition", zap.String("from", oldPhase.String()), zap.String("to", newPhase.String()))

	// Signal completion when protocol is complete
	if newPhase == PhaseComplete {
		c.completionOnce.Do(func() {
			c.logger.Info("Protocol complete - closing completion channel")
			close(c.completionChan)
		})
	}
}

// incrementTranscriptCount increments transcript count and advances to PhaseComplete if both received
func (c *Client) incrementTranscriptCount() {
	c.protocolStateMutex.Lock()
	c.transcriptsReceived++
	count := c.transcriptsReceived
	c.protocolStateMutex.Unlock()

	c.logger.Info("Transcript received", zap.Int("count", count), zap.Int("total", 2))

	if count >= 2 {
		// Check if comprehensive signature verification is also complete
		if c.hasCompletionFlag(CompletionFlagTEEKSignatureValid) {
			c.logger.Info("Both transcripts received AND redacted streams processed - completing protocol")
			c.advanceToPhase(PhaseComplete)
		} else {
			c.logger.Info("Both transcripts received but waiting for redacted streams processing...")
		}
	}
}

// getProtocolState returns current phase and transcript count (thread-safe)
func (c *Client) getProtocolState() (ProtocolPhase, int) {
	c.protocolStateMutex.RLock()
	defer c.protocolStateMutex.RUnlock()
	return c.protocolPhase, c.transcriptsReceived
}

// Phase 4: Response handling methods

// processResponseRecords processes accumulated response data for complete TLS records

// handleSessionReady processes session ready messages from TEE_K

// fetchAndVerifyAttestations fetches attestations from both TEE_K and TEE_T via WebSocket
// Now waits for session coordination before sending requests
func (c *Client) fetchAndVerifyAttestations() error {
	// Skip attestations entirely in standalone mode
	if c.clientMode == ModeStandalone {
		c.logger.Info("Skipping attestation in standalone mode - public keys will be extracted from signed transcripts")
		return nil
	}

	c.logger.Info("Requesting attestations from both TEE_K and TEE_T via WebSocket")

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

	c.logger.Info("Session coordinated, proceeding with attestation requests", zap.String("session_id", c.sessionID))

	// Create attestation request (no request ID needed)
	attestReq := shared.AttestationRequestData{}

	// Send to TEE_K
	teekMsg := shared.CreateMessage(shared.MsgAttestationRequest, attestReq)

	if err := c.sendMessage(teekMsg); err != nil {
		return fmt.Errorf("failed to send TEE_K attestation request: %v", err)
	}
	c.logger.Info("Sent attestation request to TEE_K")

	// Send to TEE_T
	teetMsg := shared.CreateMessage(shared.MsgAttestationRequest, attestReq)

	if err := c.sendMessageToTEET(teetMsg); err != nil {
		return fmt.Errorf("failed to send TEE_T attestation request: %v", err)
	}
	c.logger.Info("Sent attestation request to TEE_T")

	// Responses will be handled asynchronously by handleAttestationResponse
	c.logger.Info("Waiting for attestation responses from both TEE_K and TEE_T")
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

	c.logger.Info("Attestation root of trust validation passed", zap.String("source", expectedSource))

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

	c.logger.Info("Extracted public key from attestation", zap.String("source", expectedSource), zap.Int("bytes", len(publicKey)))
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

	c.logger.Info("Public key verification SUCCESS!")
	c.logger.Info("TEE_K: attestation and transcript public keys match")
	c.logger.Info("TEE_T: attestation and transcript public keys match")

	c.publicKeyComparisonDone = true
	return nil
}

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
		RequestRedactions: nil, // No longer used - ranges are set directly
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

	bothReceived := c.transcriptsReceived >= 2
	bothValid := c.hasCompletionFlag(CompletionFlagTEEKSignatureValid)

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

	// Use batched response processing success flags
	batchedSuccess := c.responseProcessingSuccessful
	batchedDataSize := c.reconstructedResponseSize

	// Use batched response processing data size (batching always runs)
	finalDataSize := batchedDataSize

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

// EnableTwoPhaseMode enables 2-phase operation mode
func (c *Client) EnableTwoPhaseMode() {
	c.twoPhaseMode = true
	c.logger.Info("2-phase mode enabled")
}

// WaitForPhase1Completion returns a channel that closes when phase 1 (response decryption) is complete
func (c *Client) WaitForPhase1Completion() <-chan struct{} {
	return c.phase1Completion
}

// ContinueToPhase2 continues the protocol to phase 2 (redaction and completion)
func (c *Client) ContinueToPhase2() error {
	if !c.twoPhaseMode {
		return fmt.Errorf("not in 2-phase mode")
	}
	if !c.phase1Completed {
		return fmt.Errorf("phase 1 not completed yet")
	}

	c.logger.Info("Continuing to phase 2 (redaction and completion)")

	// If we have a response callback and response data, call it to get redaction ranges
	if c.responseCallback != nil && c.lastResponseData != nil {
		c.logger.Info("Calling response callback to get redaction ranges")
		result, err := c.responseCallback.OnResponseReceived(c.lastResponseData)
		if err != nil {
			c.logger.Error("Response callback error", zap.Error(err))
		} else if result != nil {
			c.logger.Info("Response callback returned redaction ranges", zap.Int("count", len(result.RedactionRanges)))
			c.lastRedactionRanges = result.RedactionRanges
			c.lastProofClaims = result.ProofClaims
			if result.RedactedBody != nil {
				c.lastRedactedResponse = result.RedactedBody
			}
		}
	}

	// Advance to the redaction phase
	c.advanceToPhase(PhaseSendingRedaction)

	// Send redaction specification
	c.logger.Info("Sending redaction specification")
	if err := c.sendRedactionSpec(); err != nil {
		return fmt.Errorf("failed to send redaction spec: %v", err)
	}

	return nil
}
