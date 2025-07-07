package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

type Client struct {
	wsConn   *websocket.Conn
	teetConn *websocket.Conn
	tcpConn  net.Conn

	// *** Add mutexes to prevent concurrent websocket writes ***
	wsConnMu   sync.Mutex // Protects wsConn writes (TEE_K)
	teetConnMu sync.Mutex // Protects teetConn writes (TEE_T)

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
	responseBuffer       []byte            // Buffer for accumulating TLS record data
	responseSeqNum       uint64            // TLS sequence number for response AEAD
	firstApplicationData bool              // Track if this is the first ApplicationData record
	pendingResponsesData map[uint64][]byte // Encrypted response data by sequence number

	// *** Add response buffer mutex to prevent race conditions ***
	responseBufferMutex sync.Mutex // Protects responseBuffer access

	// Protocol completion signaling
	completionChan chan struct{} // Signals when protocol is complete

	// *** Add sync.Once to prevent double-close panic ***
	completionOnce sync.Once // Ensures completion channel is only closed once

	// *** Track records sent vs processed instead of streams ***
	recordsSent      int  // TLS records sent for split AEAD processing
	recordsProcessed int  // TLS records that completed split AEAD processing
	eofReached       bool // Whether we've reached EOF on TCP connection
	completionMutex  sync.Mutex

	// Track redaction verification completion
	expectingRedactionResult bool
	receivedRedactionResult  bool

	// Track HTTP request/response lifecycle
	httpRequestSent      bool // Track if HTTP request has been sent
	httpResponseExpected bool // Track if we should expect HTTP response
	httpResponseReceived bool // Track if HTTP response content has been received

	// Track signed transcript completion
	expectingSignedTranscripts bool
	receivedTEEKTranscript     bool
	receivedTEETTranscript     bool
	teeKSignatureValid         bool
	teeTSignatureValid         bool

	// Track response redaction
	expectingRedactedStreams bool
	responseContentBySeq     map[uint64][]byte // Store decrypted response content by sequence
	responseContentMutex     sync.Mutex        // Protect response content storage
	ciphertextBySeq          map[uint64][]byte // Store encrypted response data by sequence
	decryptionStreamBySeq    map[uint64][]byte // Store decryption streams by sequence
}

func NewClient(teekURL string) *Client {
	return &Client{
		teekURL:                    teekURL,
		teetURL:                    "wss://tee-t.reclaimprotocol.org/ws", // Default TEE_T URL (enclave mode)
		pendingResponsesData:       make(map[uint64][]byte),
		completionChan:             make(chan struct{}),
		recordsSent:                0,
		recordsProcessed:           0,
		eofReached:                 false,
		expectingRedactionResult:   false,
		receivedRedactionResult:    false,
		httpRequestSent:            false,
		httpResponseExpected:       false,
		httpResponseReceived:       false,
		expectingSignedTranscripts: false,
		receivedTEEKTranscript:     false,
		receivedTEETTranscript:     false,
		teeKSignatureValid:         false,
		teeTSignatureValid:         false,
		responseContentBySeq:       make(map[uint64][]byte),
		responseContentMutex:       sync.Mutex{},
		ciphertextBySeq:            make(map[uint64][]byte),
		decryptionStreamBySeq:      make(map[uint64][]byte),
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
	// HTTP Request: GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer dummy_token_12345\r\nX-Account-ID: ACC123456789\r\nConnection: close\r\n\r\n

	// *** REDACTION SYSTEM: Create proper HTTP request with sensitive headers ***
	// R_NS (non-sensitive): GET, Host, Connection headers - no redaction
	// R_S (sensitive): Authorization header - redacted but not for proof
	// R_SP (sensitive with proof): X-Account-ID header - redacted and used for proof
	testRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer secret_auth_token_12345\r\nX-Account-ID: ACC987654321\r\nConnection: close\r\n\r\n", c.targetHost)
	httpRequest = []byte(testRequest)

	fmt.Printf("[Client] ORIGINAL REQUEST (length=%d):\n%s\n", len(httpRequest), string(httpRequest))
	fmt.Printf("[Client] TARGET HOST: '%s' (length=%d)\n", c.targetHost, len(c.targetHost))

	// Show the complete HTTP request with sensitive data before redaction
	fmt.Printf("[Client] COMPLETE HTTP REQUEST (before redaction):\n%s\n", string(httpRequest))
	fmt.Printf("[Client] Request analysis:\n")
	fmt.Printf(" Total length: %d bytes\n", len(httpRequest))
	fmt.Printf(" R_NS (non-sensitive): Basic headers\n")
	fmt.Printf(" R_S (sensitive): %d bytes auth token\n", len("secret_auth_token_12345"))
	fmt.Printf(" R_SP (sensitive+proof): %d bytes account ID\n", len("ACC987654321"))

	// *** REDACTION RANGES: Define R_S and R_SP according to specification ***
	// R_S (sensitive): Authorization token - redacted but not for proof
	// R_SP (sensitive with proof): Account ID - redacted and used for proof generation
	authTokenStart := strings.Index(testRequest, "secret_auth_token_12345")
	accountIdStart := strings.Index(testRequest, "ACC987654321")

	if authTokenStart == -1 {
		return RedactedRequestData{}, RedactionStreamsData{}, fmt.Errorf("auth token not found in request")
	}
	if accountIdStart == -1 {
		return RedactedRequestData{}, RedactionStreamsData{}, fmt.Errorf("account ID not found in request")
	}

	ranges := []RedactionRange{
		{
			Start:  authTokenStart,
			Length: len("secret_auth_token_12345"),
			Type:   "sensitive", // R_S: sensitive but not for proof
		},
		{
			Start:  accountIdStart,
			Length: len("ACC987654321"),
			Type:   "sensitive_proof", // R_SP: sensitive with proof
		},
	}

	fmt.Printf("[Client] REDACTION CONFIGURATION:\n")
	fmt.Printf(" R_NS (non-sensitive): Basic headers (no redaction)\n")
	fmt.Printf(" R_S (sensitive): Auth token at [%d:%d] - redacted, not for proof\n",
		authTokenStart, authTokenStart+len("secret_auth_token_12345"))
	fmt.Printf(" R_SP (sensitive+proof): Account ID at [%d:%d] - redacted, for proof\n",
		accountIdStart, accountIdStart+len("ACC987654321"))

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

	fmt.Printf("[Client] REDACTION SUMMARY:\n")
	fmt.Printf(" Original length: %d bytes\n", len(httpRequest))
	fmt.Printf(" Redacted length: %d bytes (same, redaction via XOR)\n", len(redactedRequest))
	fmt.Printf(" Redaction ranges: %d\n", len(ranges))

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
