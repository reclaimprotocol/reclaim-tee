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
	MsgPlaintextData     MessageType = "plaintext_data"

	// TEE_K to Client messages
	MsgConnectionReady        MessageType = "connection_ready"
	MsgSendTCPData            MessageType = "send_tcp_data"
	MsgHandshakeComplete      MessageType = "handshake_complete"
	MsgHandshakeKeyDisclosure MessageType = "handshake_key_disclosure"
	MsgHTTPResponse           MessageType = "http_response"

	// Phase 2: Split AEAD messages
	// TEE_K to TEE_T messages
	MsgKeyShareRequest   MessageType = "key_share_request"
	MsgEncryptedRequest  MessageType = "encrypted_request"
	MsgResponseLength    MessageType = "response_length"
	MsgEncryptedResponse MessageType = "encrypted_response"

	// TEE_T to TEE_K messages
	MsgKeyShareResponse MessageType = "key_share_response"
	MsgRequestEncrypted MessageType = "request_encrypted"
	MsgResponseTag      MessageType = "response_tag"
	MsgRedactionProof   MessageType = "redaction_proof"

	// Phase 3: Client to TEE_T messages
	MsgRedactionData         MessageType = "redaction_data"
	MsgRedactedRequest       MessageType = "redacted_request"
	MsgRedactionVerification MessageType = "redaction_verification"
	MsgEncryptedData         MessageType = "encrypted_data"

	// Session management messages
	MsgSessionCreated MessageType = "session_created"
	MsgSessionReady   MessageType = "session_ready"

	// Additional message types
	MsgResponseTagVerification  MessageType = "response_tag_verification"
	MsgTagComputationReady      MessageType = "tag_computation_ready"
	MsgError                    MessageType = "error"
	MsgTEETReady                MessageType = "teet_ready"
	MsgRedactionStreams         MessageType = "redaction_streams"
	MsgResponseTagSecrets       MessageType = "response_tag_secrets"
	MsgResponseDecryptionStream MessageType = "response_decryption_stream"

	// Single Session Mode message types
	MsgFinished                       MessageType = "finished"
	MsgSignedTranscript               MessageType = "signed_transcript"
	MsgRedactionSpec                  MessageType = "redaction_spec"
	MsgSignedRedactedDecryptionStream MessageType = "signed_redacted_decryption_stream"
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

	// Connection management
	IsClosed bool
	Context  context.Context
	Cancel   context.CancelFunc
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
}

// RedactionSessionState holds redaction-specific state for each session
type RedactionSessionState struct {
	Ranges                []RedactionRange
	CommitmentOpenings    [][]byte
	EncryptedRequestData  []EncryptedRequestData
	EncryptedResponseData []EncryptedResponseData
	RedactionStreams      [][]byte
	CommitmentKeys        [][]byte
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
}

// Protocol data structures
type RedactionRange struct {
	Start          int    `json:"start"`           // Start position in the decryption stream
	Length         int    `json:"length"`          // Length of the range to redact
	Type           string `json:"type"`            // "sensitive" or "sensitive_proof", etc.
	RedactionBytes []byte `json:"redaction_bytes"` // Bytes to use in redacted stream (calculated to produce '*' when XORed with ciphertext)
}

// Client to TEE_K: Request to establish connection
type RequestConnectionData struct {
	Hostname string   `json:"hostname"`
	Port     int      `json:"port"`
	SNI      string   `json:"sni"`
	ALPN     []string `json:"alpn"`
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

// Tag computation ready confirmation
type TagComputationReadyData struct {
	Success bool `json:"success"`
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

// ResponseLengthData contains response length information
type ResponseLengthData struct {
	Length       int    `json:"length"`        // Length of encrypted response data (without tag)
	RecordHeader []byte `json:"record_header"` // Actual TLS record header used by server (5 bytes)
	SeqNum       uint64 `json:"seq_num"`       // TLS sequence number for AEAD
	CipherSuite  uint16 `json:"cipher_suite"`  // TLS cipher suite
}

// ResponseTagSecretsData contains tag secrets for response verification
type ResponseTagSecretsData struct {
	TagSecrets  []byte `json:"tag_secrets"`  // E_K(0^128) and E_K(nonce||1) for GCM
	SeqNum      uint64 `json:"seq_num"`      // TLS sequence number for AEAD
	CipherSuite uint16 `json:"cipher_suite"` // TLS cipher suite
}

// ResponseTagVerificationData contains tag verification results
type ResponseTagVerificationData struct {
	Success bool   `json:"success"` // Whether tag verification passed
	SeqNum  uint64 `json:"seq_num"` // TLS sequence number for AEAD
	Message string `json:"message"` // Optional error message
}

// ResponseDecryptionStreamData contains decryption stream data
type ResponseDecryptionStreamData struct {
	DecryptionStream []byte `json:"decryption_stream"` // AES-CTR keystream for XOR decryption
	SeqNum           uint64 `json:"seq_num"`           // TLS sequence number for AEAD
	Length           int    `json:"length"`            // Length of encrypted data to decrypt
}

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
	EncryptedData []byte `json:"encrypted_data"` // Raw TLS record payload (encrypted data + tag)
	Tag           []byte `json:"tag"`            // Authentication tag extracted from TLS record
	RecordHeader  []byte `json:"record_header"`  // Actual TLS record header used by server (5 bytes)
	SeqNum        uint64 `json:"seq_num"`        // TLS sequence number for AEAD
	CipherSuite   uint16 `json:"cipher_suite"`   // TLS cipher suite
}

// Single Session Mode data structures

// FinishedMessage represents a finished command from client or coordination between TEEs
type FinishedMessage struct {
	Source string `json:"source"` // "client", "tee_k", "tee_t"
}

// SignedTranscript represents a signed transcript with packets, signature, and public key
type SignedTranscript struct {
	Packets [][]byte `json:"packets"` // All packets in chronological order (binary data)
	// PacketTypes describes what each entry in Packets represents.
	// It is aligned by index with Packets. Example values:
	//   "tls_record"            – bytes that were sent/received on the TCP connection as TLS records
	//   "http_request_redacted" – plaintext redacted HTTP request added before encryption
	//   "commitment"            – commitment bytes inserted into transcript
	// Additional values may be defined later; verifiers MUST ignore unknown strings.
	PacketTypes []string `json:"packet_types,omitempty"`
	Signature   []byte   `json:"signature"`  // Cryptographic signature (binary data)
	PublicKey   []byte   `json:"public_key"` // Public key in DER format (binary data)
	Source      string   `json:"source"`     // "tee_k" or "tee_t"
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

// SignedRedactedDecryptionStream represents a signed redacted decryption stream
type SignedRedactedDecryptionStream struct {
	RedactedStream []byte `json:"redacted_stream"` // Decryption stream with "*" for redacted parts
	Signature      []byte `json:"signature"`       // Cryptographic signature
	SeqNum         uint64 `json:"seq_num"`         // TLS sequence number
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

// VerifySignature method on SigningKeyPair for backward compatibility
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
	// Reconstruct the original data that was signed
	// This should match the SignTranscript function logic
	var buffer bytes.Buffer

	// Write each packet to buffer
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

// CreateSessionMessage is kept for backward compatibility but now calls CreateMessage
func CreateSessionMessage(msgType MessageType, sessionID string, data interface{}) *Message {
	return CreateMessage(msgType, data, sessionID)
}

// Helper functions for message creation and parsing
func ParseMessage(msgBytes []byte) (*Message, error) {
	var msg Message
	err := json.Unmarshal(msgBytes, &msg)
	return &msg, err
}
