package main

import (
	"encoding/json"
	"time"
)

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
	MsgTagSecretsRequest MessageType = "tag_secrets_request"

	// TEE_T to TEE_K messages
	MsgKeyShareResponse    MessageType = "key_share_response"
	MsgTagComputationReady MessageType = "tag_computation_ready"

	// TEE_T to Client messages
	MsgEncryptedData MessageType = "encrypted_data"

	// Client to TEE_T messages
	MsgTEETReady MessageType = "teet_ready"

	// Error messages
	MsgError MessageType = "error"

	// Phase 3: Redaction system messages
	MsgRedactedRequest       MessageType = "redacted_request"
	MsgRedactionStreams      MessageType = "redaction_streams"
	MsgRedactionVerification MessageType = "redaction_verification"

	// Phase 4: Split AEAD response handling messages
	MsgEncryptedResponse        MessageType = "encrypted_response"
	MsgResponseLength           MessageType = "response_length"
	MsgResponseTagSecrets       MessageType = "response_tag_secrets"
	MsgResponseTagVerification  MessageType = "response_tag_verification"
	MsgResponseDecryptionStream MessageType = "response_decryption_stream"
	MsgDecryptedResponse        MessageType = "decrypted_response"

	// Session management messages
	MsgSessionCreated MessageType = "session_created"
	MsgSessionReady   MessageType = "session_ready"
)

// Base message structure with session support
type Message struct {
	Type      MessageType `json:"type"`
	SessionID string      `json:"session_id,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
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

// Helper functions for message creation
func CreateMessage(msgType MessageType, data interface{}) (*Message, error) {
	return &Message{
		Type:      msgType,
		Data:      data,
		Timestamp: time.Now(),
	}, nil
}

func CreateSessionMessage(msgType MessageType, sessionID string, data interface{}) (*Message, error) {
	return &Message{
		Type:      msgType,
		SessionID: sessionID,
		Data:      data,
		Timestamp: time.Now(),
	}, nil
}

func ParseMessage(msgBytes []byte) (*Message, error) {
	var msg Message
	err := json.Unmarshal(msgBytes, &msg)
	return &msg, err
}

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

// Session-ready data structure
type SessionReadyData struct {
	SessionID string `json:"session_id"`
	Ready     bool   `json:"ready"`
}

// CreateHandshakeKeyDisclosureMessage creates a handshake key disclosure message
func CreateHandshakeKeyDisclosureMessage(handshakeKey, handshakeIV, certificatePacket []byte, cipherSuite uint16, algorithm string, success bool) Message {
	data := HandshakeKeyDisclosureData{
		HandshakeKey:      handshakeKey,
		HandshakeIV:       handshakeIV,
		CertificatePacket: certificatePacket,
		CipherSuite:       cipherSuite,
		Algorithm:         algorithm,
		Success:           success,
	}
	return Message{
		Type:      "handshake_key_disclosure",
		Data:      data,
		Timestamp: time.Now(),
	}
}

// Phase 2: New message structures for split AEAD protocol

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

// TEE_K to TEE_T: Send encrypted request data and tag computation material
type EncryptedRequestData struct {
	EncryptedData   []byte           `json:"encrypted_data"` // R_red_Enc
	TagSecrets      []byte           `json:"tag_secrets"`    // Data needed for tag computation
	CipherSuite     uint16           `json:"cipher_suite"`
	SeqNum          uint64           `json:"seq_num"`          // Sequence number for AEAD
	RedactionRanges []RedactionRange `json:"redaction_ranges"` // Redaction position metadata for stream application
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

// Phase 3: Redaction system data structures

// RedactionRange defines a byte range to be redacted in the plaintext request
type RedactionRange struct {
	Start  int    `json:"start"`  // Byte offset in plaintext request
	Length int    `json:"length"` // Number of bytes to redact
	Type   string `json:"type"`   // "sensitive" or "sensitive_proof"
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

// Phase 4: Split AEAD response handling data structures

// EncryptedResponseData contains encrypted response data and tag from website
type EncryptedResponseData struct {
	EncryptedData []byte `json:"encrypted_data"` // Raw TLS record payload (encrypted data + tag)
	Tag           []byte `json:"tag"`            // Authentication tag extracted from TLS record
	RecordHeader  []byte `json:"record_header"`  // Actual TLS record header used by server (5 bytes)
	SeqNum        uint64 `json:"seq_num"`        // TLS sequence number for AEAD
	CipherSuite   uint16 `json:"cipher_suite"`   // TLS cipher suite
}

// ResponseLengthData contains the length of encrypted response for tag secret generation
type ResponseLengthData struct {
	Length       int    `json:"length"`        // Length of encrypted response data (without tag)
	RecordHeader []byte `json:"record_header"` // Actual TLS record header used by server (5 bytes)
	SeqNum       uint64 `json:"seq_num"`       // TLS sequence number for AEAD
	CipherSuite  uint16 `json:"cipher_suite"`  // TLS cipher suite
}

// ResponseTagSecretsData contains tag computation secrets from TEE_K to TEE_T
type ResponseTagSecretsData struct {
	TagSecrets  []byte `json:"tag_secrets"`  // E_K(0^128) and E_K(nonce||1) for GCM
	SeqNum      uint64 `json:"seq_num"`      // TLS sequence number for AEAD
	CipherSuite uint16 `json:"cipher_suite"` // TLS cipher suite
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

// DecryptedResponseData contains final decrypted response for client
type DecryptedResponseData struct {
	PlaintextData []byte `json:"plaintext_data"` // Decrypted response data
	SeqNum        uint64 `json:"seq_num"`        // TLS sequence number for AEAD
	Success       bool   `json:"success"`        // Whether decryption was successful
}
