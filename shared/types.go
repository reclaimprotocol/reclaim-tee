package shared

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Connection abstraction for WebSocket connections
type Connection interface {
	WriteJSON(v interface{}) error
	ReadJSON(v interface{}) error
	Close() error
	RemoteAddr() string
}

// WebSocket connection adapter
type WSConnection struct {
	conn  *websocket.Conn
	mutex sync.Mutex
}

func NewWSConnection(conn *websocket.Conn) *WSConnection {
	return &WSConnection{conn: conn}
}

func (w *WSConnection) WriteJSON(v interface{}) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.conn.WriteJSON(v)
}

func (w *WSConnection) ReadJSON(v interface{}) error {
	return w.conn.ReadJSON(v)
}

func (w *WSConnection) Close() error {
	return w.conn.Close()
}

func (w *WSConnection) RemoteAddr() string {
	return w.conn.RemoteAddr().String()
}

// GetWebSocketConn returns the underlying websocket.Conn for compatibility
func (w *WSConnection) GetWebSocketConn() *websocket.Conn {
	return w.conn
}

// Message types for websocket communication
type MessageType string

const (
	// Client to TEE_K messages
	MsgRequestConnection MessageType = "request_connection"
	MsgTCPData           MessageType = "tcp_data"
	MsgTCPReady          MessageType = "tcp_ready"

	// TEE_K to Client messages
	MsgConnectionReady        MessageType = "connection_ready"
	MsgSendTCPData            MessageType = "send_tcp_data"
	MsgHandshakeComplete      MessageType = "handshake_complete"
	MsgHandshakeKeyDisclosure MessageType = "handshake_key_disclosure"
	MsgHTTPResponse           MessageType = "http_response"

	// Client-specific response handling messages
	MsgEncryptedResponse        MessageType = "encrypted_response"
	MsgResponseTagVerification  MessageType = "response_tag_verification"
	MsgResponseDecryptionStream MessageType = "response_decryption_stream"

	// Phase 2: Split AEAD messages
	// TEE_K to TEE_T messages
	MsgKeyShareRequest  MessageType = "key_share_request"
	MsgEncryptedRequest MessageType = "encrypted_request"

	// TEE_T to TEE_K messages
	MsgKeyShareResponse MessageType = "key_share_response"

	// Phase 3: Client to TEE_T messages
	MsgRedactedRequest       MessageType = "redacted_request"
	MsgRedactionVerification MessageType = "redaction_verification"
	MsgEncryptedData         MessageType = "encrypted_data"

	// Session management messages
	MsgSessionCreated MessageType = "session_created"
	MsgSessionReady   MessageType = "session_ready"

	// Additional message types
	MsgError            MessageType = "error"
	MsgTEETReady        MessageType = "teet_ready"
	MsgRedactionStreams MessageType = "redaction_streams"

	// Attestation request over WebSocket
	MsgAttestationRequest  MessageType = "attestation_request"
	MsgAttestationResponse MessageType = "attestation_response"

	// Single Session Mode message types
	MsgFinished                       MessageType = "finished"
	MsgSignedTranscript               MessageType = "signed_transcript"
	MsgRedactionSpec                  MessageType = "redaction_spec"
	MsgSignedRedactedDecryptionStream MessageType = "signed_redacted_decryption_stream"
)

// *** NEW: Batched message types for response optimization ***
const (
	MsgBatchedEncryptedResponses MessageType = "batched_encrypted_responses"
	MsgBatchedResponseLengths    MessageType = "batched_response_lengths"
	MsgBatchedTagSecrets         MessageType = "batched_tag_secrets"
	MsgBatchedTagVerifications   MessageType = "batched_tag_verifications"
	MsgBatchedDecryptionStreams  MessageType = "batched_decryption_streams"
)

// Message represents a protocol message with session context
type Message struct {
	Type      MessageType `json:"type"`
	SessionID string      `json:"session_id,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// UnmarshalData unmarshals the Data field into the provided interface
func (m *Message) UnmarshalData(v interface{}) error {
	// Convert Data to JSON bytes first if it's not already
	var jsonData []byte
	var err error

	switch data := m.Data.(type) {
	case []byte:
		jsonData = data
	case string:
		jsonData = []byte(data)
	default:
		jsonData, err = json.Marshal(data)
		if err != nil {
			return err
		}
	}

	return json.Unmarshal(jsonData, v)
}

// SessionState represents the current state of a session
type SessionState string

const (
	SessionStateNew         SessionState = "new"
	SessionStateActive      SessionState = "active"
	SessionStateHandshaking SessionState = "handshaking"
	SessionStateReady       SessionState = "ready"
	SessionStateClosed      SessionState = "closed"
)

// Session represents a complete client session across both TEE_K and TEE_T
type Session struct {
	ID           string
	ClientConn   Connection
	TEEKConn     Connection
	TEETConn     Connection // Per-session connection to TEE_T
	CreatedAt    time.Time
	LastActiveAt time.Time
	State        SessionState

	// Protocol state per session
	TLSState       *TLSSessionState
	RedactionState *RedactionSessionState
	ResponseState  *ResponseSessionState
	ConnectionData interface{} // Store connection request data

	// Per-session transcript storage
	TranscriptPackets     [][]byte   `json:"-"` // Collect all packets for transcript signing
	TranscriptPacketTypes []string   `json:"-"` // Parallel slice describing packet types
	TranscriptMutex       sync.Mutex // Protect transcript collection

	// Per-session finished state tracking
	ClientFinished     bool       // Whether client has sent finished message
	TEEKFinished       bool       // Whether TEE_K has sent finished message
	FinishedStateMutex sync.Mutex // Protect finished state

	// Master signature generation
	RedactedStreams             []SignedRedactedDecryptionStream `json:"-"` // Collect streams for master signature
	RedactionProcessingComplete bool                             `json:"-"` // Flag to track when redaction processing is complete
	StreamsMutex                sync.Mutex                       // Protect streams collection

	// Connection management
	IsClosed bool
	Context  context.Context
	Cancel   context.CancelFunc

	// Additional connection state migrated from TEE_T global state
	TEETClientConn interface{} // *websocket.Conn (using interface{} to avoid import cycle)
}

// TLSSessionState holds TLS-specific state for each session
type TLSSessionState struct {
	HandshakeComplete bool
	ClientHello       []byte
	ServerHello       []byte
	MasterSecret      []byte
	KeyBlock          []byte
	KeyShare          []byte
	CipherSuite       uint16

	// TLS client and connection state
	TLSClient         interface{} // *minitls.Client (using interface{} to avoid import cycle)
	WSConn2TLS        interface{} // *WebSocketConn (using interface{} to avoid import cycle)
	CurrentConn       interface{} // *websocket.Conn (using interface{} to avoid import cycle)
	CurrentRequest    *RequestConnectionData
	TCPReady          chan bool
	CombinedKey       []byte
	ServerSequenceNum uint64
}

// RedactionSessionState holds redaction-specific state for each session
type RedactionSessionState struct {
	Ranges                []RedactionRange
	CommitmentOpenings    [][]byte
	EncryptedRequestData  []EncryptedRequestData
	EncryptedResponseData []EncryptedResponseData
	RedactionStreams      [][]byte
	CommitmentKeys        [][]byte

	// Additional redaction state migrated from TEE_T global state
	KeyShare                []byte
	CipherSuite             uint16
	PendingEncryptedRequest *EncryptedRequestData
	TEETConnForPending      interface{} // *websocket.Conn (using interface{} to avoid import cycle)
}

// ResponseSessionState holds response handling state for each session
type ResponseSessionState struct {
	PendingResponses        map[string][]byte
	ResponseSequence        int
	LastResponseTime        time.Time
	ResponseLengthBySeq     map[uint64]uint32
	PendingEncryptedRequest *EncryptedRequestData

	// Per-session pending encrypted responses
	PendingEncryptedResponses map[uint64]*EncryptedResponseData // Responses awaiting tag secrets by seq num
	ResponsesMutex            sync.Mutex                        // Protects PendingEncryptedResponses map access

	// Additional response state migrated from global state
	ResponseLengthBySeqInt map[uint64]int // Keep both for compatibility
	ExplicitIVBySeq        map[uint64][]byte
	TEETConnForPending     interface{} // *websocket.Conn (using interface{} to avoid import cycle)
}

// Protocol data structures
type RedactionRange struct {
	Start          int    `json:"start"`                     // Start position in the decryption stream
	Length         int    `json:"length"`                    // Length of the range to redact
	Type           string `json:"type"`                      // "sensitive" or "sensitive_proof", etc.
	RedactionBytes []byte `json:"redaction_bytes,omitempty"` // Bytes to use in redacted stream (calculated to produce '*' when XORed with ciphertext)
}

// Client to TEE_K: Request to establish connection
type RequestConnectionData struct {
	Hostname         string   `json:"hostname"`
	Port             int      `json:"port"`
	SNI              string   `json:"sni"`
	ALPN             []string `json:"alpn"`
	ForceTLSVersion  string   `json:"force_tls_version,omitempty"`  // Force specific TLS version: "1.2", "1.3", or "" for auto
	ForceCipherSuite string   `json:"force_cipher_suite,omitempty"` // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
}

// TEE_K to Client: Connection is ready
type ConnectionReadyData struct {
	Success bool `json:"success"`
}

// Client to TEE_K: TCP connection established
type TCPReadyData struct {
	Success bool `json:"success"`
}

// Bidirectional: TCP data transfer
type TCPData struct {
	Data []byte `json:"data"`
}

// TEE_K to Client: TLS handshake completed
type HandshakeCompleteData struct {
	Success          bool     `json:"success"`
	CertificateChain [][]byte `json:"certificate_chain"`
}

// TEE_K to Client: Handshake key disclosure for certificate verification
type HandshakeKeyDisclosureData struct {
	HandshakeKey      []byte `json:"handshake_key"`      // Server handshake traffic secret
	HandshakeIV       []byte `json:"handshake_iv"`       // Server handshake IV
	CertificatePacket []byte `json:"certificate_packet"` // Raw encrypted certificate packet
	CipherSuite       uint16 `json:"cipher_suite"`       // TLS cipher suite (e.g., 0x1302 for TLS_AES_256_GCM_SHA384)
	Algorithm         string `json:"algorithm"`          // Algorithm name (e.g., "AES-256-GCM", "ChaCha20-Poly1305")
	Success           bool   `json:"success"`
}

// TEE_K to Client: HTTP response received
type HTTPResponseData struct {
	Response []byte `json:"response"` // Optional: nil in first stage per protocol design
	Success  bool   `json:"success"`
}

// Error message
type ErrorData struct {
	Message string `json:"message"`
}

// TEE_K to TEE_T: Request key share for split AEAD
type KeyShareRequestData struct {
	CipherSuite uint16 `json:"cipher_suite"`
	KeyLength   int    `json:"key_length"`
	IVLength    int    `json:"iv_length"`
}

// TEE_T to TEE_K: Response with key share
type KeyShareResponseData struct {
	KeyShare []byte `json:"key_share"`
	Success  bool   `json:"success"`
}

// TEE_T to Client: Send encrypted data with authentication tag
type EncryptedDataResponse struct {
	EncryptedData []byte `json:"encrypted_data"` // R_Enc
	AuthTag       []byte `json:"auth_tag"`       // Authentication tag T
	Success       bool   `json:"success"`
}

// TEE_T ready confirmation
type TEETReadyData struct {
	Success bool `json:"success"`
}

// AttestationRequestData represents a request for attestation
type AttestationRequestData struct {
	// RequestID removed - no longer needed since we wait for session coordination
}

// AttestationResponseData represents an attestation response
type AttestationResponseData struct {
	// RequestID removed - no longer needed since we wait for session coordination
	AttestationDoc []byte `json:"attestation_doc,omitempty"`
	Success        bool   `json:"success"`
	ErrorMessage   string `json:"error_message,omitempty"`
}

// Client to TEE_K: Send plaintext data for encryption
type PlaintextData struct {
	Data []byte `json:"data"`
}

// RedactedRequestData contains the redacted request and associated metadata
type RedactedRequestData struct {
	RedactedRequest []byte           `json:"redacted_request"` // R_red
	Commitments     [][]byte         `json:"commitments"`      // [comm_s, comm_sp]
	RedactionRanges []RedactionRange `json:"redaction_ranges"` // Position metadata
}

// RedactionStreamsData contains the XOR streams and commitment keys for revelation
type RedactionStreamsData struct {
	Streams        [][]byte `json:"streams"`         // [Str_S, Str_SP]
	CommitmentKeys [][]byte `json:"commitment_keys"` // [K_S, K_SP]
}

// RedactionVerificationData contains the result of redaction verification
type RedactionVerificationData struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Individual response data structures removed - now using batched approach only

// DecryptedResponseData contains decrypted response data
type DecryptedResponseData struct {
	PlaintextData []byte `json:"plaintext_data"` // Decrypted response data
	SeqNum        uint64 `json:"seq_num"`        // TLS sequence number for AEAD
	Success       bool   `json:"success"`        // Whether decryption was successful
}

// Session-ready data structure
type SessionReadyData struct {
	SessionID string `json:"session_id"`
	Ready     bool   `json:"ready"`
}

type EncryptedRequestData struct {
	EncryptedData   []byte           `json:"encrypted_data"` // R_red_Enc
	TagSecrets      []byte           `json:"tag_secrets"`    // Data needed for tag computation
	CipherSuite     uint16           `json:"cipher_suite"`
	SeqNum          uint64           `json:"seq_num"`          // Sequence number for AEAD
	RedactionRanges []RedactionRange `json:"redaction_ranges"` // Redaction position metadata for stream application
}

type EncryptedResponseData struct {
	EncryptedData []byte `json:"encrypted_data"`        // Raw TLS record payload (encrypted data + tag)
	Tag           []byte `json:"tag"`                   // Authentication tag extracted from TLS record
	RecordHeader  []byte `json:"record_header"`         // Actual TLS record header used by server (5 bytes)
	SeqNum        uint64 `json:"seq_num"`               // TLS sequence number for AEAD
	CipherSuite   uint16 `json:"cipher_suite"`          // TLS cipher suite
	ExplicitIV    []byte `json:"explicit_iv,omitempty"` // TLS 1.2 AES-GCM explicit IV (8 bytes, nil for TLS 1.3)
}

// ResponseTagVerificationData contains result of tag verification by TEE_T
type ResponseTagVerificationData struct {
	Success bool   `json:"success"` // Whether tag verification passed
	SeqNum  uint64 `json:"seq_num"` // TLS sequence number for AEAD
	Message string `json:"message"` // Optional error message
}

// ResponseDecryptionStreamData contains AES-CTR decryption stream from TEE_K
type ResponseDecryptionStreamData struct {
	DecryptionStream []byte `json:"decryption_stream"` // AES-CTR keystream for XOR decryption
	SeqNum           uint64 `json:"seq_num"`           // TLS sequence number for AEAD
	Length           int    `json:"length"`            // Length of encrypted data to decrypt
}

// Single Session Mode data structures

// FinishedMessage represents a finished message from any party
type FinishedMessage struct {
}

// SignedTranscript represents a signed transcript with packets, signature, and public key
type SignedTranscript struct {
	Packets [][]byte `json:"packets"` // TLS packets only (binary data)

	// Request metadata (formerly included in packets for TEE_K)
	RequestMetadata *RequestMetadata `json:"request_metadata,omitempty"`

	Signature []byte `json:"signature"`  // Comprehensive signature over all data (TLS packets + metadata + streams)
	PublicKey []byte `json:"public_key"` // Public key in DER format (binary data)
}

// Transcript packet type constants – exported so both client and TEEs can reference them.
const (
	TranscriptPacketTypeTLSRecord           = "tls_record"
	TranscriptPacketTypeHTTPRequestRedacted = "http_request_redacted"
	TranscriptPacketTypeCommitment          = "commitment"
)

// RedactionSpec specifies which parts of the response should be redacted
type RedactionSpec struct {
	Ranges                     []RedactionRange `json:"ranges"`                        // Specific ranges to redact
	AlwaysRedactSessionTickets bool             `json:"always_redact_session_tickets"` // Always redact session tickets
}

// SignedRedactedDecryptionStream represents a redacted decryption stream
type SignedRedactedDecryptionStream struct {
	RedactedStream []byte `json:"redacted_stream"` // Decryption stream with "*" for redacted parts
	SeqNum         uint64 `json:"seq_num"`         // TLS sequence number
}

// *** NEW: Batched response data structures (built from existing individual types) ***

// BatchedEncryptedResponseData contains multiple encrypted response packets for batch processing
type BatchedEncryptedResponseData struct {
	Responses  []EncryptedResponseData `json:"responses"`   // Array of individual encrypted responses
	SessionID  string                  `json:"session_id"`  // Session identifier
	TotalCount int                     `json:"total_count"` // Total number of responses in batch
}

// BatchedResponseLengthData contains multiple response lengths for batch processing
type BatchedResponseLengthData struct {
	Lengths []struct {
		Length       int    `json:"length"`                // Length of encrypted response data (without tag)
		RecordHeader []byte `json:"record_header"`         // Actual TLS record header used by server (5 bytes)
		SeqNum       uint64 `json:"seq_num"`               // TLS sequence number for AEAD
		CipherSuite  uint16 `json:"cipher_suite"`          // TLS cipher suite
		ExplicitIV   []byte `json:"explicit_iv,omitempty"` // TLS 1.2 AES-GCM explicit IV (8 bytes, nil for TLS 1.3)
	} `json:"lengths"` // Array of individual response lengths
	SessionID  string `json:"session_id"`  // Session identifier
	TotalCount int    `json:"total_count"` // Total number of lengths in batch
}

// BatchedTagSecretsData contains multiple tag secrets for batch processing
type BatchedTagSecretsData struct {
	TagSecrets []struct {
		TagSecrets  []byte `json:"tag_secrets"`  // E_K(0^128) and E_K(nonce||1) for GCM
		SeqNum      uint64 `json:"seq_num"`      // TLS sequence number for AEAD
		CipherSuite uint16 `json:"cipher_suite"` // TLS cipher suite
	} `json:"tag_secrets"` // Array of individual tag secrets
	SessionID  string `json:"session_id"`  // Session identifier
	TotalCount int    `json:"total_count"` // Total number of tag secrets in batch
}

// BatchedTagVerificationData contains multiple tag verification results for batch processing
type BatchedTagVerificationData struct {
	Verifications []ResponseTagVerificationData `json:"verifications"`  // Array of verification results
	SessionID     string                        `json:"session_id"`     // Session identifier
	TotalCount    int                           `json:"total_count"`    // Total number of verifications in batch
	AllSuccessful bool                          `json:"all_successful"` // True if all verifications passed
}

// BatchedDecryptionStreamData contains multiple decryption streams for batch processing
type BatchedDecryptionStreamData struct {
	DecryptionStreams []ResponseDecryptionStreamData `json:"decryption_streams"` // Array of decryption streams
	SessionID         string                         `json:"session_id"`         // Session identifier
	TotalCount        int                            `json:"total_count"`        // Total number of streams in batch
}

// Single Session Mode: Cryptographic signing infrastructure

// SigningKeyPair represents a cryptographic ECDSA signing key pair
type SigningKeyPair struct {
	PrivateKey *ecdsa.PrivateKey `json:"private_key"`
	PublicKey  *ecdsa.PublicKey  `json:"public_key"`
}

// GenerateSigningKeyPair generates a new ECDSA signing key pair using P-256 curve
func GenerateSigningKeyPair() (*SigningKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key pair: %v", err)
	}

	return &SigningKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// SignData signs the given data using ECDSA and returns the signature
func (kp *SigningKeyPair) SignData(data []byte) ([]byte, error) {
	// Hash the data with SHA-256
	hash := sha256.Sum256(data)

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, kp.PrivateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	// Encode r and s as a simple concatenation (32 bytes each for P-256)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	return signature, nil
}

// VerifySignature verifies a signature against the given data using a public key
func VerifySignature(data []byte, signature []byte, publicKey *ecdsa.PublicKey) error {
	if len(signature) != 64 {
		return fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(signature))
	}

	// Hash the data with SHA-256
	hash := sha256.Sum256(data)

	// Extract r and s from signature
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	// Verify the signature
	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// VerifySignature method on SigningKeyPair
func (kp *SigningKeyPair) VerifySignature(data []byte, signature []byte) bool {
	err := VerifySignature(data, signature, kp.PublicKey)
	return err == nil
}

// GetPublicKeyDER returns the public key in DER format for JSON serialization
func (kp *SigningKeyPair) GetPublicKeyDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(kp.PublicKey)
}

// ParsePublicKeyFromDER parses a public key from DER format
func ParsePublicKeyFromDER(derBytes []byte) (*ecdsa.PublicKey, error) {
	pubKeyInterface, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER public key: %v", err)
	}

	ecdsaPubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an ECDSA key")
	}

	return ecdsaPubKey, nil
}

// VerifySignatureWithDER verifies a signature using a public key in DER format
func VerifySignatureWithDER(data []byte, signature []byte, publicKeyDER []byte) error {
	// Parse public key from DER
	pubKey, err := ParsePublicKeyFromDER(publicKeyDER)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// Verify signature
	return VerifySignature(data, signature, pubKey)
}

// VerifyTranscriptSignature verifies a signed transcript's signature
func VerifyTranscriptSignature(transcript *SignedTranscript) error {
	// Reconstruct the original data that was signed (TLS packets only)
	var buffer bytes.Buffer

	// Write each TLS packet to buffer
	for _, packet := range transcript.Packets {
		buffer.Write(packet)
	}

	originalData := buffer.Bytes()

	// Verify signature using the public key
	return VerifySignatureWithDER(originalData, transcript.Signature, transcript.PublicKey)
}

// VerifyComprehensiveSignature verifies TEE_K's comprehensive signature over all data
func VerifyComprehensiveSignature(transcript *SignedTranscript, redactedStreams []SignedRedactedDecryptionStream) error {
	if transcript == nil {
		return fmt.Errorf("transcript is nil")
	}

	if len(transcript.Signature) == 0 {
		return fmt.Errorf("signature is empty")
	}

	// Reconstruct the original data that was signed
	var buffer bytes.Buffer

	// Add request metadata
	if transcript.RequestMetadata != nil {
		buffer.Write(transcript.RequestMetadata.RedactedRequest)
		buffer.Write(transcript.RequestMetadata.CommSP)

		// Include redaction ranges in signature verification (same as signing)
		if len(transcript.RequestMetadata.RedactionRanges) > 0 {
			redactionRangesBytes, err := json.Marshal(transcript.RequestMetadata.RedactionRanges)
			if err != nil {
				return fmt.Errorf("failed to marshal redaction ranges for verification: %v", err)
			}
			buffer.Write(redactionRangesBytes)
		}
	}

	// Add concatenated redacted streams
	for _, stream := range redactedStreams {
		buffer.Write(stream.RedactedStream)
	}

	// Add TLS packets
	for _, packet := range transcript.Packets {
		buffer.Write(packet)
	}

	originalData := buffer.Bytes()

	// Verify signature using the public key
	return VerifySignatureWithDER(originalData, transcript.Signature, transcript.PublicKey)
}

// SignTranscript signs a transcript of packets and returns the signature
func (kp *SigningKeyPair) SignTranscript(packets [][]byte) ([]byte, error) {
	// Concatenate all packets for signing
	var allData []byte
	for _, packet := range packets {
		allData = append(allData, packet...)
	}

	return kp.SignData(allData)
}

// Helper functions
func CreateMessage(msgType MessageType, data interface{}, sessionID ...string) *Message {
	msg := &Message{
		Type:      msgType,
		Data:      data,
		Timestamp: time.Now(),
	}

	// If sessionID is provided and not empty, set it
	if len(sessionID) > 0 && sessionID[0] != "" {
		msg.SessionID = sessionID[0]
	}

	return msg
}

// CreateSessionMessage calls CreateMessage
func CreateSessionMessage(msgType MessageType, sessionID string, data interface{}) *Message {
	return CreateMessage(msgType, data, sessionID)
}

// Helper functions for message creation and parsing
func ParseMessage(msgBytes []byte) (*Message, error) {
	var msg Message
	err := json.Unmarshal(msgBytes, &msg)
	return &msg, err
}
