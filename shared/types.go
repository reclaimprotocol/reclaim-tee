package shared

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Connection abstraction for WebSocket connections
type Connection interface {
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
	MsgFinished                    MessageType = "finished"
	MsgSignedTranscript            MessageType = "signed_transcript"
	MsgSignedTranscriptWithStreams MessageType = "signed_transcript_with_streams"
	MsgRedactionSpec               MessageType = "redaction_spec"
)

const (
	MsgBatchedEncryptedResponses              MessageType = "batched_encrypted_responses"
	MsgBatchedResponseLengths                 MessageType = "batched_response_lengths"
	MsgBatchedTagSecrets                      MessageType = "batched_tag_secrets"
	MsgBatchedTagVerifications                MessageType = "batched_tag_verifications"
	MsgBatchedDecryptionStreams               MessageType = "batched_decryption_streams"
	MsgBatchedSignedRedactedDecryptionStreams MessageType = "batched_signed_redacted_decryption_streams"
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
	if v == nil {
		return fmt.Errorf("nil destination")
	}
	if m == nil {
		return fmt.Errorf("nil message")
	}
	// Fast-path: if Data is nil
	if m.Data == nil {
		return fmt.Errorf("no data in message")
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("destination must be non-nil pointer")
	}
	dv := reflect.ValueOf(m.Data)
	// Allow assignment when types match or are assignable
	if dv.Type().AssignableTo(rv.Elem().Type()) {
		rv.Elem().Set(dv)
		return nil
	}
	return fmt.Errorf("type mismatch: cannot assign %s to %s", dv.Type().String(), rv.Elem().Type().String())
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
	RedactionState *RedactionSessionState
	ResponseState  *ResponseSessionState
	ConnectionData interface{} // Store connection request data

	// Per-session transcript storage
	TranscriptPackets     [][]byte   `json:"-"` // Collect all packets for transcript signing
	TranscriptPacketTypes []string   `json:"-"` // Parallel slice describing packet types
	TranscriptMutex       sync.Mutex // Protect transcript collection

	// Per-session finished state tracking
	TEEKFinished       bool       // Whether TEE_K has sent finished message
	FinishedStateMutex sync.Mutex // Protect finished state

	// Master signature generation
	RedactedStreams             []SignedRedactedDecryptionStream `json:"-"` // Collect streams for master signature
	RedactionProcessingComplete bool                             `json:"-"` // Flag to track when redaction processing is complete
	SignatureSent               bool                             `json:"-"` // Flag to prevent duplicate signature generation
	StreamsMutex                sync.Mutex                       // Protect streams collection

	// Cache for original decryption streams to avoid regeneration during redaction
	CachedDecryptionStreams map[uint64][]byte `json:"-"` // Cache original streams by seqNum for redaction reuse

	// Connection management
	IsClosed bool
	Context  context.Context
	Cancel   context.CancelFunc
}

// RedactionSessionState holds redaction-specific state for each session
type RedactionSessionState struct {
	Ranges                []RequestRedactionRange
	CommitmentOpenings    [][]byte
	ExpectedCommitments   [][]byte // [comm_s, comm_sp] received from TEE_K
	EncryptedRequestData  []EncryptedRequestData
	EncryptedResponseData []EncryptedResponseData
	RedactionStreams      [][]byte
	CommitmentKeys        [][]byte
}

// ResponseSessionState holds response handling state for each session
type ResponseSessionState struct {
	PendingResponses    map[string][]byte
	ResponseSequence    int
	LastResponseTime    time.Time
	ResponseLengthBySeq map[uint64]uint32

	// Per-session pending encrypted responses
	PendingEncryptedResponses map[uint64]*EncryptedResponseData // Responses awaiting tag secrets by seq num
	ResponsesMutex            sync.Mutex                        // Protects PendingEncryptedResponses map access

	// Additional response state migrated from global state
	ResponseLengthBySeqInt map[uint64]int // Keep both for compatibility
	ExplicitIVBySeq        map[uint64][]byte

	// Response redaction ranges for transcript signature
	ResponseRedactionRanges []ResponseRedactionRange `json:"response_redaction_ranges,omitempty"`
}

// Protocol data structures

// Request redaction type constants
const (
	RedactionTypeSensitive      = "sensitive"       // R_S: Sensitive data not used in proofs
	RedactionTypeSensitiveProof = "sensitive_proof" // R_SP: Sensitive data used in proofs
)

// RequestRedactionRange is used for request redaction (needs types for proof verification)
type RequestRedactionRange struct {
	Start          int    `json:"start"`                     // Start position in the decryption stream
	Length         int    `json:"length"`                    // Length of the range to redact
	Type           string `json:"type"`                      // Use RedactionTypeSensitive or RedactionTypeSensitiveProof
	RedactionBytes []byte `json:"redaction_bytes,omitempty"` // Bytes to use in redacted stream (calculated to produce '*' when XORed with ciphertext)
}

// ResponseRedactionRange is used for response redaction (no types needed - binary redaction)
type ResponseRedactionRange struct {
	Start  int `json:"start"`  // Start position in the decryption stream
	Length int `json:"length"` // Length of the range to redact
}

// ConsolidateResponseRedactionRanges merges consecutive or overlapping redaction ranges
func ConsolidateResponseRedactionRanges(ranges []ResponseRedactionRange) []ResponseRedactionRange {
	if len(ranges) == 0 {
		return ranges
	}

	// Sort by start position
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].Start < ranges[j].Start
	})

	var consolidated []ResponseRedactionRange
	current := ranges[0]

	for i := 1; i < len(ranges); i++ {
		next := ranges[i]
		// If ranges are consecutive or overlapping, merge them
		if current.Start+current.Length >= next.Start {
			current.Length = max(current.Start+current.Length, next.Start+next.Length) - current.Start
		} else {
			consolidated = append(consolidated, current)
			current = next
		}
	}
	consolidated = append(consolidated, current)

	return consolidated
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
	Source         string `json:"source,omitempty"` // "tee_k" or "tee_t"
}

// Client to TEE_K: Send plaintext data for encryption
type PlaintextData struct {
	Data []byte `json:"data"`
}

// RedactedRequestData contains the redacted request and associated metadata
type RedactedRequestData struct {
	RedactedRequest []byte                  `json:"redacted_request"` // R_red
	Commitments     [][]byte                `json:"commitments"`      // [comm_s, comm_sp]
	RedactionRanges []RequestRedactionRange `json:"redaction_ranges"` // Position metadata
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
	EncryptedData   []byte                  `json:"encrypted_data"` // R_red_Enc
	TagSecrets      []byte                  `json:"tag_secrets"`    // Data needed for tag computation
	Commitments     [][]byte                `json:"commitments"`    // [comm_s, comm_sp] from TEE_K
	CipherSuite     uint16                  `json:"cipher_suite"`
	SeqNum          uint64                  `json:"seq_num"`          // Sequence number for AEAD
	RedactionRanges []RequestRedactionRange `json:"redaction_ranges"` // Redaction position metadata for stream application
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

	// Response redaction ranges for verifier display
	ResponseRedactionRanges []ResponseRedactionRange `json:"response_redaction_ranges,omitempty"`

	Signature []byte `json:"signature"`  // Comprehensive signature over all data (TLS packets + metadata + streams)
	PublicKey []byte `json:"public_key"` // Public key in DER format (binary data)
}

// Transcript packet type constants – exported so both client and TEEs can reference them.
const (
	TranscriptPacketTypeTLSRecord           = "tls_record"
	TranscriptPacketTypeHTTPRequestRedacted = "http_request_redacted"
	TranscriptPacketTypeCommitment          = "commitment"
)

// RequestRedactionSpec specifies which parts of the request should be redacted
type RequestRedactionSpec struct {
	Ranges []RequestRedactionRange `json:"ranges"` // Request redaction ranges with types
}

// ResponseRedactionSpec specifies which parts of the response should be redacted
type ResponseRedactionSpec struct {
	Ranges                     []ResponseRedactionRange `json:"ranges"`                        // Response redaction ranges (no types needed)
	AlwaysRedactSessionTickets bool                     `json:"always_redact_session_tickets"` // Always redact session tickets
}

// SignedRedactedDecryptionStream represents a redacted decryption stream
type SignedRedactedDecryptionStream struct {
	RedactedStream []byte `json:"redacted_stream"` // Decryption stream with "*" for redacted parts
	SeqNum         uint64 `json:"seq_num"`         // TLS sequence number
}

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
		ExplicitIV   []byte `json:"explicit_iv,omitempty"` // TLS 1.2 AES-GCM explicit IV (8 bytes, nil for TLS 1.3)
	} `json:"lengths"` // Array of individual response lengths
	SessionID  string `json:"session_id"`  // Session identifier
	TotalCount int    `json:"total_count"` // Total number of lengths in batch
}

// BatchedTagSecretsData contains multiple tag secrets for batch processing
type BatchedTagSecretsData struct {
	TagSecrets []struct {
		TagSecrets []byte `json:"tag_secrets"` // E_K(0^128) and E_K(nonce||1) for GCM
		SeqNum     uint64 `json:"seq_num"`     // TLS sequence number for AEAD
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

// BatchedSignedRedactedDecryptionStreamData contains multiple signed redacted decryption streams for batch processing
type BatchedSignedRedactedDecryptionStreamData struct {
	SignedRedactedStreams []SignedRedactedDecryptionStream `json:"signed_redacted_streams"` // Array of signed redacted decryption streams
	SessionID             string                           `json:"session_id"`              // Session identifier
	TotalCount            int                              `json:"total_count"`             // Total number of streams in batch
}

// SignedTranscriptWithStreams combines SignedTranscript and SignedRedactedStreams for efficient TEE_K messaging
type SignedTranscriptWithStreams struct {
	SignedTranscript                                       // Embed the existing SignedTranscript structure
	SignedRedactedStreams []SignedRedactedDecryptionStream `json:"signed_redacted_streams,omitempty"` // Optional redacted streams
	TotalStreamsCount     int                              `json:"total_streams_count"`               // Total number of streams included
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
