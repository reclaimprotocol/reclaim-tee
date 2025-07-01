package shared

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Connection abstraction that works for both WebSocket and VSock
type Connection interface {
	WriteJSON(v interface{}) error
	ReadJSON(v interface{}) error
	Close() error
	RemoteAddr() string
}

// WebSocket connection adapter (for both standalone and enclave modes)
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
	CreatedAt    time.Time
	LastActiveAt time.Time
	State        SessionState

	// Protocol state per session
	TLSState       *TLSSessionState
	RedactionState *RedactionSessionState
	ResponseState  *ResponseSessionState
	ConnectionData interface{} // Store connection request data

	// Connection management
	ConnectionMutex sync.RWMutex
	IsClosed        bool
	Context         context.Context
	Cancel          context.CancelFunc
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
}

// Protocol data structures
type RedactionRange struct {
	Start  int    `json:"start"`
	Length int    `json:"length"`
	Type   string `json:"type"` // "sensitive" or "sensitive_proof"
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

// Helper functions
func CreateMessage(msgType MessageType, data interface{}) *Message {
	return &Message{
		Type:      msgType,
		Data:      data,
		Timestamp: time.Now(),
	}
}

func CreateSessionMessage(msgType MessageType, sessionID string, data interface{}) *Message {
	return &Message{
		Type:      msgType,
		SessionID: sessionID,
		Data:      data,
		Timestamp: time.Now(),
	}
}

// Helper functions for message creation and parsing
func ParseMessage(msgBytes []byte) (*Message, error) {
	var msg Message
	err := json.Unmarshal(msgBytes, &msg)
	return &msg, err
}
