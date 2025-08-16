package clientlib

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	teeproto "tee-mpc/proto"
	"tee-mpc/shared"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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

	// Validation tracking to ensure validation runs exactly once
	validationExecuted bool       // Track if transcript validation has been executed
	validationMutex    sync.Mutex // Protect validation state

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
	lastRedactionRanges          []shared.ResponseRedactionRange // Last redaction ranges from callback
	responseReconstructed        bool                            // Flag to prevent multiple response reconstruction
	transcriptValidationResults  *TranscriptValidationResults    // Cached validation results
	attestationValidationResults *AttestationValidationResults   // Cached attestation results

	// Verification bundle tracking fields
	handshakeDisclosure     *shared.HandshakeKeyDisclosureData      // store handshake keys
	teekSignedMessage       *teeproto.SignedMessage                 // original protobuf SignedMessage from TEE_K
	teetSignedMessage       *teeproto.SignedMessage                 // original protobuf SignedMessage from TEE_T
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
		validationExecuted:     false,
		validationMutex:        sync.Mutex{},
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

		// 2-phase operation support
		twoPhaseMode:          false,
		phase1Completed:       false,
		phase1Completion:      make(chan struct{}),
		teekTranscriptPackets: nil,
		teetTranscriptPackets: nil,

		responseCallback:             nil,
		clientMode:                   ModeAuto, // Default to auto-detect
		protocolStartTime:            time.Now(),
		lastResponseData:             nil,
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

// applyRedactionSpecs applies redaction specifications from config to find redaction ranges

// triggerResponseCallback triggers the response callback if configured

// parseHTTPResponse parses raw HTTP response data into structured format

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

// checkValidationAndCompletion performs centralized validation and completion check
// This ensures validation runs exactly once when both transcripts are ready, before completion
func (c *Client) checkValidationAndCompletion(reason string) {
	c.protocolStateMutex.Lock()
	transcriptCount := c.transcriptsReceived
	currentPhase := c.protocolPhase
	c.protocolStateMutex.Unlock()

	hasValidSignature := c.hasCompletionFlag(CompletionFlagTEEKSignatureValid)
	transcriptsComplete := transcriptCount >= 2
	signaturesValid := hasValidSignature

	c.logger.Info("Checking validation and completion",
		zap.String("reason", reason),
		zap.Int("transcript_count", transcriptCount),
		zap.Bool("has_valid_signature", hasValidSignature),
		zap.String("current_phase", currentPhase.String()))

	// First, check if we need to run validation
	if transcriptsComplete && signaturesValid && !c.hasValidationRun() {
		c.logger.Info("Both transcripts received with valid signatures - performing transcript validation")
		c.runValidationOnce()
	}

	// Then, check for completion (validation must be complete)
	if transcriptsComplete && signaturesValid && c.hasValidationRun() && currentPhase != PhaseComplete {
		c.logger.Info("All completion conditions met (including validation) - advancing to complete phase")
		c.advanceToPhase(PhaseComplete)
	} else if transcriptCount < 2 {
		c.logger.Debug("Completion pending: waiting for more transcripts",
			zap.Int("current", transcriptCount), zap.Int("needed", 2))
	} else if !hasValidSignature {
		c.logger.Debug("Completion pending: waiting for valid TEE_K signature")
	} else if !c.hasValidationRun() {
		c.logger.Debug("Completion pending: validation not yet complete")
	} else if currentPhase == PhaseComplete {
		c.logger.Debug("Already in complete phase")
	}
}

// Convenience function - delegates to the centralized function
func (c *Client) checkFinalCompletion(reason string) {
	c.checkValidationAndCompletion(reason)
}

// hasValidationRun checks if transcript validation has been executed (thread-safe)
func (c *Client) hasValidationRun() bool {
	c.validationMutex.Lock()
	defer c.validationMutex.Unlock()
	return c.validationExecuted
}

// runValidationOnce executes transcript validation exactly once (thread-safe)
func (c *Client) runValidationOnce() {
	c.validationMutex.Lock()
	defer c.validationMutex.Unlock()

	if c.validationExecuted {
		c.logger.Debug("Validation already executed, skipping duplicate call")
		return
	}

	c.logger.Info("Starting transcript validation (first and only execution)")
	c.validationExecuted = true

	// Run the actual validation
	c.validateTranscriptsAgainstCapturedTraffic()

	c.logger.Info("Transcript validation completed")
}

// getProtocolState returns current phase and transcript count (thread-safe)
func (c *Client) getProtocolState() (ProtocolPhase, int) {
	c.protocolStateMutex.RLock()
	defer c.protocolStateMutex.RUnlock()
	return c.protocolPhase, c.transcriptsReceived
}

// fetchAndVerifyAttestations is deprecated - attestations are now included in SignedMessage
func (c *Client) fetchAndVerifyAttestations() error {
	// Attestation requests removed - attestations are now included directly in SignedMessage
	c.logger.Info("Skipping separate attestation requests - attestations now included in SignedMessage")

	// Wait for session ID from TEE_K (indicates successful session coordination)
	// This is still needed for session management
	maxWait := 30 * time.Second
	waitStart := time.Now()

	for c.sessionID == "" {
		if time.Since(waitStart) > maxWait {
			return fmt.Errorf("timeout waiting for session coordination")
		}
		time.Sleep(100 * time.Millisecond)
	}

	c.logger.Info("Session coordinated, ready for protocol", zap.String("session_id", c.sessionID))
	return nil
}

// verifyAttestationReportETH verifies a protobuf AttestationReport and extracts the ETH address from the report itself
func (c *Client) verifyAttestationReportETH(report *teeproto.AttestationReport, expectedSource string) (common.Address, error) {
	c.logger.Info("verifyAttestationReportETH called", zap.String("type", report.Type), zap.String("source", expectedSource), zap.Int("report_bytes", len(report.Report)))
	switch report.Type {
	case "nitro":
		c.logger.Info("Attempting to parse Nitro attestation report for ETH address", zap.String("source", expectedSource))
		sr, err := verifier.NewSignedAttestationReport(strings.NewReader(string(report.Report)))
		if err != nil {
			c.logger.Error("Failed to parse Nitro attestation report", zap.Error(err))
			return common.Address{}, fmt.Errorf("failed to parse nitro report: %v", err)
		}
		if err := verifier.Validate(sr, nil); err != nil {
			return common.Address{}, fmt.Errorf("nitro validation failed: %v", err)
		}

		// Extract ETH address from user data in the attestation document
		userDataStr := string(sr.Document.UserData)
		expectedPrefix := fmt.Sprintf("%s_public_key:", strings.ToLower(expectedSource))
		if !strings.HasPrefix(userDataStr, expectedPrefix) {
			return common.Address{}, fmt.Errorf("invalid user data format, expected prefix %s", expectedPrefix)
		}

		ethAddressHex := userDataStr[len(expectedPrefix):]
		if !strings.HasPrefix(ethAddressHex, "0x") {
			return common.Address{}, fmt.Errorf("invalid ETH address format, expected 0x prefix")
		}

		if !common.IsHexAddress(ethAddressHex) {
			return common.Address{}, fmt.Errorf("invalid ETH address format: %s", ethAddressHex)
		}

		ethAddress := common.HexToAddress(ethAddressHex)
		c.logger.Info("Extracted ETH address from Nitro attestation", zap.String("source", expectedSource), zap.String("eth_address", ethAddress.Hex()))
		return ethAddress, nil

	case "gcp":
		att, err := shared.NewGoogleAttestor()
		if err != nil {
			return common.Address{}, fmt.Errorf("failed to create google attestor: %v", err)
		}
		if err := att.Validate(context.Background(), report.Report); err != nil {
			return common.Address{}, fmt.Errorf("google attestation validation failed: %v", err)
		}

		// For GCP, we need to extract the ETH address from the attestation token
		// This is a placeholder - GCP attestation ETH address extraction needs specific implementation
		return common.Address{}, fmt.Errorf("GCP ETH address extraction not yet implemented for protobuf format")

	default:
		return common.Address{}, fmt.Errorf("unsupported attestation type: %s", report.Type)
	}
}

// verifySignedMessage verifies a protobuf SignedMessage using the same logic as the offline verifier
// Now supports both enclave mode (with AttestationReport) and standalone mode (with PublicKey)
func (c *Client) verifySignedMessage(signedMsg *teeproto.SignedMessage, source string) error {
	if signedMsg == nil {
		return fmt.Errorf("SECURITY ERROR: %s signed message is nil", source)
	}

	// Validate required fields
	if len(signedMsg.GetSignature()) == 0 {
		return fmt.Errorf("SECURITY ERROR: %s missing signature", source)
	}
	if len(signedMsg.GetBody()) == 0 {
		return fmt.Errorf("SECURITY ERROR: %s missing body", source)
	}

	// Validate body type
	expectedBodyType := teeproto.BodyType_BODY_TYPE_K_OUTPUT
	if source == "TEE_T" {
		expectedBodyType = teeproto.BodyType_BODY_TYPE_T_OUTPUT
	}
	if signedMsg.GetBodyType() != expectedBodyType {
		return fmt.Errorf("SECURITY ERROR: %s wrong body type, expected %v got %v", source, expectedBodyType, signedMsg.GetBodyType())
	}

	// Extract ETH address - either from AttestationReport (enclave mode) or PublicKey field (standalone mode)
	var ethAddress common.Address
	var err error

	if signedMsg.GetAttestationReport() != nil {
		// Enclave mode: extract ETH address from attestation report
		attestationReport := signedMsg.GetAttestationReport()
		c.logger.Info("Verifying attestation and extracting ETH address", zap.String("source", source), zap.String("attestation_type", attestationReport.GetType()), zap.Int("report_bytes", len(attestationReport.GetReport())))

		// Verify attestation and extract ETH address
		ethAddress, err = c.verifyAttestationReportETH(attestationReport, source)
		if err != nil {
			return fmt.Errorf("SECURITY ERROR: %s attestation verification failed: %v", source, err)
		}
		c.logger.Info("Attestation verification SUCCESS", zap.String("source", source), zap.String("eth_address", ethAddress.Hex()))
	} else if len(signedMsg.GetEthAddress()) > 0 {
		ethAddress = common.HexToAddress(string(signedMsg.GetEthAddress()))
		c.logger.Info("Using standalone mode ETH address", zap.String("source", source), zap.String("eth_address", ethAddress.Hex()))
	} else {
		return fmt.Errorf("SECURITY ERROR: %s missing both attestation report and public key", source)
	}

	// SECURITY: Verify ETH signature against the exact signed bytes (SignedMessage.Body)
	if err := shared.VerifySignatureWithETH(signedMsg.GetBody(), signedMsg.GetSignature(), ethAddress); err != nil {
		return fmt.Errorf("SECURITY ERROR: %s cryptographic signature verification FAILED: %v", source, err)
	}

	c.logger.Info("SignedMessage verification SUCCESS", zap.String("source", source), zap.Int("body_bytes", len(signedMsg.GetBody())))
	return nil
}

// buildTranscriptResults constructs the transcript results from SignedMessage data
// moved to results_build.go

// extractEthAddressFromSignedMessage extracts the ETH address from a SignedMessage (attestation or direct address)
func extractEthAddressFromSignedMessage(signedMsg *teeproto.SignedMessage) []byte {
	if signedMsg.GetAttestationReport() != nil {
		// In enclave mode, ETH address should be extracted from attestation (but that's complex)
		// For now, return empty - the ETH address extraction happens during verification
		return nil
	}
	// In standalone mode, return the direct ETH address
	return signedMsg.GetEthAddress()
}

// buildValidationResults constructs the validation results
// moved to results_build.go

// buildAttestationResults constructs the attestation results (legacy compatibility)
// moved to results_build.go

// buildResponseResults constructs the response results
// moved to results_build.go

// buildTranscriptValidationResults constructs detailed transcript validation results
// moved to results_build.go

// buildAttestationValidationResults constructs attestation validation results
// moved to results_build.go

// buildTEEValidationDetails constructs validation details for one TEE's transcript
// moved to results_build.go

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

// SubmitToAttestorCore submits the completed verification bundle to attestor-core for claim validation
func (c *Client) SubmitToAttestorCore(attestorURL string, privateKey *ecdsa.PrivateKey, params ClaimTeeBundleParams) (*teeproto.ProviderClaimData, error) {

	// Example private key (use your own in production)
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		c.logger.Fatal("Failed to generate private key:", zap.Error(err))
	}

	// Submit to attestor-core
	c.logger.Info("Submitting verification bundle to attestor-core...")

	// attestorURL := "wss://attestor.reclaimprotocol.org/ws" // Production
	attestorURL = "ws://localhost:8001/ws" // Local development

	// Ensure we have a verification bundle ready
	if c.teekSignedMessage == nil || c.teetSignedMessage == nil {
		return nil, fmt.Errorf("TEE protocol not completed - no signed messages available")
	}

	// Build verification bundle
	bundle := &teeproto.VerificationBundle{
		TeekSigned: c.teekSignedMessage,
		TeetSigned: c.teetSignedMessage,
	}

	// Add handshake keys if available
	if c.handshakeDisclosure != nil {
		bundle.HandshakeKeys = &teeproto.HandshakeSecrets{
			HandshakeKey: c.handshakeDisclosure.HandshakeKey,
			HandshakeIv:  c.handshakeDisclosure.HandshakeIV,
			CipherSuite:  uint32(c.handshakeDisclosure.CipherSuite),
			Algorithm:    c.handshakeDisclosure.Algorithm,
		}
	}

	// Add proof opening if available
	if c.proofStream != nil || c.proofKey != nil {
		bundle.Opening = &teeproto.Opening{
			ProofStream: c.proofStream,
		}
	}

	c.logger.Info("Submitting verification bundle to attestor-core",
		zap.String("attestor_url", attestorURL))

	// Create attestor client and submit
	attestorClient := NewAttestorClient(attestorURL, privateKey, c.logger)

	if err := attestorClient.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to attestor-core: %v", err)
	}
	defer attestorClient.Close()

	claim, err := attestorClient.SubmitTeeBundle(bundle, params)
	if err != nil {
		return nil, fmt.Errorf("failed to submit TEE bundle: %v", err)
	}

	c.logger.Info("Successfully submitted TEE bundle to attestor-core",
		zap.String("claim_id", claim.Identifier),
		zap.String("provider", claim.Provider))

	return claim, nil
}
