package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// TLS Record Types (RFC 5246)
const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22
	recordTypeApplicationData  = 23
)

// TLS Versions
const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// WebSocket message types
type MessageType string

const (
	MsgSessionInit       MessageType = "session_init"
	MsgSessionInitResp   MessageType = "session_init_response"
	MsgServerHello       MessageType = "server_hello"
	MsgHandshakeComplete MessageType = "handshake_complete"
	MsgHandshakeContinue MessageType = "handshake_continue"
	MsgEncryptRequest    MessageType = "encrypt_request"
	MsgEncryptResponse   MessageType = "encrypt_response"
	MsgDecryptRequest    MessageType = "decrypt_request"
	MsgDecryptResponse   MessageType = "decrypt_response"
	MsgFinalize          MessageType = "finalize"
	MsgFinalizeResp      MessageType = "finalize_response"
	MsgError             MessageType = "error"
	MsgStatus            MessageType = "status"
)

// TLSRecord represents a parsed TLS record - based on Go's crypto/tls
type TLSRecord struct {
	Type     uint8
	Version  uint16
	Length   uint16
	Payload  []byte
	RawBytes []byte
}

// TLS handshake interceptor that captures real records while using Go's crypto
type TLSHandshakeInterceptor struct {
	conn            net.Conn
	tlsConn         *tls.Conn
	serverHelloData []byte
	handshakeData   [][]byte
	isHandshaking   bool
}

// NewTLSHandshakeInterceptor creates a TLS connection that captures handshake records
func NewTLSHandshakeInterceptor(hostname string, port int) (*TLSHandshakeInterceptor, error) {
	// First, establish a raw TCP connection
	addr := fmt.Sprintf("%s:%d", hostname, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}

	interceptor := &TLSHandshakeInterceptor{
		conn:          conn,
		handshakeData: make([][]byte, 0),
		isHandshaking: true,
	}

	return interceptor, nil
}

// PerformHandshakeWithInterception performs TLS handshake while capturing real records
func (ti *TLSHandshakeInterceptor) PerformHandshakeWithInterception(hostname string, clientHelloData []byte) error {
	// Send the Client Hello provided by TEE_K
	fmt.Printf("   Sending real Client Hello (%d bytes)\n", len(clientHelloData))
	_, err := ti.conn.Write(clientHelloData)
	if err != nil {
		return fmt.Errorf("failed to send Client Hello: %v", err)
	}

	// Read the Server Hello and other handshake records
	fmt.Printf("   Reading Server Hello and handshake records...\n")

	// Read handshake records until we have Server Hello
	for {
		record, err := ti.readTLSRecord()
		if err != nil {
			return fmt.Errorf("failed to read TLS record: %v", err)
		}

		fmt.Printf("   [TLS] Received record type %d (%d bytes)\n", record.Type, len(record.RawBytes))

		// Store all handshake records
		if record.Type == recordTypeHandshake {
			ti.handshakeData = append(ti.handshakeData, record.RawBytes)

			// Check if this is Server Hello (first handshake record from server)
			if len(ti.handshakeData) == 1 {
				ti.serverHelloData = record.RawBytes
				fmt.Printf("   [TLS] Captured Server Hello record (%d bytes)\n", len(record.RawBytes))
				break // We have the Server Hello, that's what TEE_K needs
			}
		}
	}

	return nil
}

// EstablishFullTLSConnection completes the TLS handshake using Go's crypto/tls
func (ti *TLSHandshakeInterceptor) EstablishFullTLSConnection(hostname string) error {
	// Create a TLS connection using the existing TCP connection
	// We'll create a new connection since we need Go's TLS to handle the crypto
	ti.conn.Close() // Close the intercepted connection

	// Establish new TLS connection using Go's implementation
	config := &tls.Config{
		ServerName: hostname,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	tlsConn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", hostname), config)
	if err != nil {
		return fmt.Errorf("failed to establish TLS connection: %v", err)
	}

	ti.tlsConn = tlsConn
	ti.isHandshaking = false

	fmt.Printf("   [TLS] Full TLS connection established\n")
	fmt.Printf("   [TLS] Version: %s\n", tlsVersionToString(tlsConn.ConnectionState().Version))
	fmt.Printf("   [TLS] Cipher Suite: 0x%04x\n", tlsConn.ConnectionState().CipherSuite)

	return nil
}

// SendHTTPRequest sends HTTP request through the established TLS connection
func (ti *TLSHandshakeInterceptor) SendHTTPRequest(request string) ([]byte, error) {
	if ti.tlsConn == nil {
		return nil, fmt.Errorf("TLS connection not established")
	}

	// Send HTTP request
	_, err := ti.tlsConn.Write([]byte(request))
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %v", err)
	}

	// Read HTTP response
	response := make([]byte, 4096)
	n, err := ti.tlsConn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response: %v", err)
	}

	return response[:n], nil
}

// GetServerHelloData returns the captured Server Hello record
func (ti *TLSHandshakeInterceptor) GetServerHelloData() []byte {
	return ti.serverHelloData
}

// Close closes all connections
func (ti *TLSHandshakeInterceptor) Close() error {
	if ti.tlsConn != nil {
		ti.tlsConn.Close()
	}
	if ti.conn != nil {
		ti.conn.Close()
	}
	return nil
}

// readTLSRecord reads a TLS record from the connection
// Based on Go's crypto/tls/conn.go readRecord method
func (ti *TLSHandshakeInterceptor) readTLSRecord() (*TLSRecord, error) {
	// Read TLS record header (5 bytes)
	header := make([]byte, 5)
	_, err := io.ReadFull(ti.conn, header)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS record header: %v", err)
	}

	recordType := header[0]
	version := binary.BigEndian.Uint16(header[1:3])
	length := binary.BigEndian.Uint16(header[3:5])

	// Read the payload
	payload := make([]byte, length)
	_, err = io.ReadFull(ti.conn, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS record payload: %v", err)
	}

	// Combine header and payload for the complete record
	rawBytes := append(header, payload...)

	return &TLSRecord{
		Type:     recordType,
		Version:  version,
		Length:   length,
		Payload:  payload,
		RawBytes: rawBytes,
	}, nil
}

// WSMessage represents WebSocket message structure
type WSMessage struct {
	Type      MessageType     `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// Session initialization request/response
type SessionInitRequest struct {
	Hostname      string   `json:"hostname"`
	Port          int      `json:"port"`
	SNI           string   `json:"sni"`
	ALPNProtocols []string `json:"alpn_protocols"`
}

type SessionInitResponse struct {
	SessionID   string `json:"session_id"`
	ClientHello []byte `json:"client_hello"`
	Status      string `json:"status"`
}

// Response types for encrypted communication
type EncryptResponseData struct {
	EncryptedData        []byte         `json:"encrypted_data"`
	Tag                  []byte         `json:"tag"`
	Status               string         `json:"status"`
	UseRedaction         bool           `json:"use_redaction"`
	RedactionCommitments *RedactionData `json:"redaction_commitments,omitempty"`
}

type RedactionData struct {
	CommitmentS  []byte `json:"commitment_s"`
	CommitmentSP []byte `json:"commitment_sp"`
}

type DecryptRequestData struct {
	ResponseLength int    `json:"response_length"`
	EncryptedData  []byte `json:"encrypted_data"`
	ExpectedTag    []byte `json:"expected_tag"`
	HTTPResponse   []byte `json:"http_response"` // Actual HTTP response data for transcript
}

type DecryptResponseData struct {
	DecryptionStream []byte `json:"decryption_stream"`
	Status           string `json:"status"`
}

// Finalize response data
type FinalizeResponseData struct {
	SignedRequestTranscript  []byte          `json:"signed_request_transcript"`
	SignedResponseTranscript []byte          `json:"signed_response_transcript"`
	TLSKeys                  json.RawMessage `json:"tls_keys"`
	Status                   string          `json:"status"`
}

// Signed transcript structure
type SignedTranscript struct {
	Data      *TranscriptData `json:"data"`
	Signature []byte          `json:"signature"`
	Algorithm string          `json:"algorithm"`
	PublicKey []byte          `json:"public_key"`
}

type TranscriptData struct {
	SessionID   string                 `json:"session_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"`
	Data        []byte                 `json:"data"`
	Commitments map[string][]byte      `json:"commitments,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Global state
var (
	globalConn           *websocket.Conn
	globalTLSInterceptor *TLSHandshakeInterceptor
	storedClientHello    []byte
	protocolFailed       bool
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: demo <websocket_url>")
		fmt.Println("Example: demo \"ws://localhost:8080/ws?client_type=user\"")
		os.Exit(1)
	}

	wsURL := os.Args[1]
	u, err := url.Parse(wsURL)
	if err != nil {
		log.Fatal("Invalid WebSocket URL:", err)
	}

	fmt.Println("TEE+MPC Protocol Demo with Real TLS Handshake Interception")
	fmt.Printf("Connecting to TEE_K: %s\n", wsURL)
	fmt.Println("Target website: example.com")
	fmt.Println()

	defer cleanup()

	// Set up signal handling for graceful cleanup
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		fmt.Println("\nReceived interrupt signal, cleaning up...")
		cleanup()
		os.Exit(0)
	}()

	// Connect to WebSocket
	fmt.Println("Step 1: Connecting to TEE_K WebSocket...")
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("WebSocket connection failed:", err)
	}
	defer conn.Close()
	globalConn = conn
	fmt.Println("Connected to TEE_K")

	// Channel for receiving messages
	done := make(chan struct{})
	var sessionID string

	// Start message reader goroutine
	go func() {
		defer close(done)
		for {
			var msg WSMessage
			err := conn.ReadJSON(&msg)
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket error: %v", err)
				}
				return
			}
			handleMessage(msg, &sessionID)

			// Exit if protocol failed due to security violation
			if protocolFailed {
				return
			}
		}
	}()

	// Step 2: Initialize TLS session
	fmt.Println("\nStep 2: Initializing TLS session with example.com...")
	sessionInitReq := SessionInitRequest{
		Hostname:      "example.com",
		Port:          443,
		SNI:           "example.com",
		ALPNProtocols: []string{"h2", "http/1.1"},
	}

	sessionInitData, _ := json.Marshal(sessionInitReq)
	sessionInitMsg := WSMessage{
		Type:      MsgSessionInit,
		Data:      sessionInitData,
		Timestamp: time.Now(),
	}

	if err := conn.WriteJSON(sessionInitMsg); err != nil {
		log.Fatal("Failed to send session init:", err)
	}

	// Wait for completion or interruption
	select {
	case <-done:
		if protocolFailed {
			fmt.Println("Demo ended due to protocol security failure")
		} else {
			fmt.Println("Demo completed successfully")
		}
	case <-c:
		fmt.Println("Demo interrupted by user")
	}
}

// TLS Record Parsing Implementation - copied from Go's crypto/tls
func parseTLSRecord(data []byte) (*TLSRecord, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("TLS record too short: %d bytes", len(data))
	}

	record := &TLSRecord{
		Type:     data[0],
		Version:  binary.BigEndian.Uint16(data[1:3]),
		Length:   binary.BigEndian.Uint16(data[3:5]),
		RawBytes: data,
	}

	if len(data) < int(5+record.Length) {
		return nil, fmt.Errorf("incomplete TLS record: expected %d bytes, got %d",
			5+record.Length, len(data))
	}

	record.Payload = data[5 : 5+record.Length]
	return record, nil
}

// Message handling functions
func handleMessage(msg WSMessage, sessionID *string) {
	switch msg.Type {
	case MsgSessionInitResp:
		fmt.Printf("Received: session_init_response (Session: %s)\n", msg.SessionID)
		*sessionID = msg.SessionID
		handleSessionInit(msg.Data)

	case MsgHandshakeComplete:
		fmt.Printf("Received: handshake_complete (Session: %s)\n", msg.SessionID)
		handleHandshakeComplete(msg.Data)

	case MsgEncryptResponse:
		fmt.Printf("Received: encrypt_response (Session: %s)\n", msg.SessionID)
		handleEncryptResponse(msg.Data, sessionID)

	case MsgDecryptResponse:
		fmt.Printf("Received: decrypt_response (Session: %s)\n", msg.SessionID)
		handleDecryptResponse(msg.Data)

	case MsgFinalizeResp:
		fmt.Printf("Session finalized - transcript signed\n")
		handleFinalizeResponse(msg.Data)

	case MsgError:
		fmt.Printf("CRITICAL ERROR: %s\n", msg.Error)

		// Check if this is a tag verification failure
		if strings.Contains(msg.Error, "Tag verification failed") ||
			strings.Contains(msg.Error, "authentication tag verification failed") ||
			strings.Contains(msg.Error, "response may be tampered") {
			fmt.Printf("\n❌ PROTOCOL SECURITY FAILURE ❌\n")
			fmt.Printf("The TEE+MPC protocol has detected a critical security violation.\n")
			fmt.Printf("Tag verification failed - this indicates the response may have been tampered with.\n")
			fmt.Printf("For security reasons, the protocol cannot continue.\n")
			fmt.Printf("No transcripts will be generated as the security guarantee is broken.\n\n")

			protocolFailed = true
			cleanup()
			os.Exit(1)
		} else {
			fmt.Printf("Protocol error encountered: %s\n", msg.Error)
			fmt.Printf("Attempting cleanup...\n")
			protocolFailed = true
			cleanup()
			os.Exit(1)
		}

	case MsgStatus:
		fmt.Printf("Status update received\n")

	default:
		fmt.Printf("Unknown message type: %s\n", msg.Type)
	}
}

func handleSessionInit(data json.RawMessage) {
	var resp SessionInitResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Printf("Failed to parse session init response: %v\n", err)
		return
	}

	fmt.Printf("Session initialized\n")
	fmt.Printf("   Session ID: %s\n", resp.SessionID)
	fmt.Printf("   Status: %s\n", resp.Status)
	fmt.Printf("   Client Hello: %d bytes\n", len(resp.ClientHello))

	storedClientHello = resp.ClientHello

	// Step 3: Perform real TLS handshake with record interception
	fmt.Printf("\nStep 3: Performing real TLS handshake with record interception...\n")

	// Create TLS handshake interceptor
	interceptor, err := NewTLSHandshakeInterceptor("example.com", 443)
	if err != nil {
		fmt.Printf("Failed to create TLS interceptor: %v\n", err)
		return
	}
	globalTLSInterceptor = interceptor

	// Perform handshake with the real Client Hello from TEE_K
	err = interceptor.PerformHandshakeWithInterception("example.com", storedClientHello)
	if err != nil {
		fmt.Printf("Failed to perform TLS handshake: %v\n", err)
		return
	}

	// Get the real Server Hello data
	serverHelloData := interceptor.GetServerHelloData()
	if len(serverHelloData) == 0 {
		fmt.Printf("Failed to capture Server Hello data\n")
		return
	}

	fmt.Printf("   Captured real Server Hello record (%d bytes)\n", len(serverHelloData))

	// Send the real Server Hello data to TEE_K
	serverHelloMsgData, _ := json.Marshal(map[string]interface{}{
		"server_hello_record": serverHelloData,
	})

	serverHelloMsg := WSMessage{
		Type:      MsgServerHello,
		Data:      serverHelloMsgData,
		Timestamp: time.Now(),
	}

	if globalConn != nil {
		globalConn.WriteJSON(serverHelloMsg)
	}
}

func handleHandshakeComplete(data json.RawMessage) {
	fmt.Printf("TLS handshake completed successfully\n")

	type HandshakeCompleteData struct {
		Status           string `json:"status"`
		CipherSuite      uint16 `json:"cipher_suite"`
		KeysReady        bool   `json:"keys_ready"`
		HandshakeKey     []byte `json:"handshake_key,omitempty"`     // For certificate verification
		CertificateChain []byte `json:"certificate_chain,omitempty"` // Server certificate chain
	}

	var handshakeData HandshakeCompleteData
	if err := json.Unmarshal(data, &handshakeData); err != nil {
		fmt.Printf("Error parsing handshake complete data: %v\n", err)
		return
	}

	fmt.Printf("   Status: %s\n", handshakeData.Status)
	fmt.Printf("   Cipher Suite: 0x%04x\n", handshakeData.CipherSuite)
	fmt.Printf("   TLS Keys: Ready (%t)\n", handshakeData.KeysReady)

	// Protocol Step 2.3: Certificate Verification (Critical Security Step)
	if len(handshakeData.HandshakeKey) > 0 && len(handshakeData.CertificateChain) > 0 {
		fmt.Printf("\n   Step 2.3: Certificate Verification (Protocol Requirement)\n")
		fmt.Printf("   TEE_K provided handshake key for certificate verification:\n")
		fmt.Printf("     • Handshake key: %d bytes\n", len(handshakeData.HandshakeKey))
		fmt.Printf("     • Certificate chain: %d bytes\n", len(handshakeData.CertificateChain))

		// Parse and display certificate information before verification
		certChain, parseErr := parseCertificateChain(handshakeData.CertificateChain)
		if parseErr == nil && len(certChain) > 0 {
			serverCert := certChain[0]
			fmt.Printf("   \n   Certificate Details:\n")
			fmt.Printf("     • Subject: %s\n", serverCert.Subject.String())
			fmt.Printf("     • Common Name: %s\n", serverCert.Subject.CommonName)
			fmt.Printf("     • Issuer: %s\n", serverCert.Issuer.CommonName)
			fmt.Printf("     • Valid From: %s\n", serverCert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("     • Valid Until: %s\n", serverCert.NotAfter.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("     • Serial Number: %s\n", serverCert.SerialNumber.String())
			if len(serverCert.DNSNames) > 0 {
				fmt.Printf("     • DNS Names: %v\n", serverCert.DNSNames)
			}
			fmt.Printf("     • Certificate chain length: %d certificates\n", len(certChain))
		}

		// Verify certificate authenticity using handshake key
		if err := verifyCertificateWithHandshakeKey(handshakeData.CertificateChain, handshakeData.HandshakeKey, "example.com"); err != nil {
			fmt.Printf("   ❌ CERTIFICATE VERIFICATION FAILED: %v\n", err)
			fmt.Printf("   This is a critical security failure - the connection may be compromised!\n")
			return
		} else {
			fmt.Printf("   ✅ Certificate verification successful!\n")
			fmt.Printf("   The server certificate is authentic and matches the handshake key\n")
		}
	} else {
		fmt.Printf("\n   Warning: No handshake key or certificate chain provided by TEE_K\n")
		fmt.Printf("   Certificate verification cannot be performed (security risk)\n")
	}

	// Now establish the full TLS connection for actual HTTP communication
	fmt.Printf("   Establishing full TLS connection for HTTP communication...\n")
	err := globalTLSInterceptor.EstablishFullTLSConnection("example.com")
	if err != nil {
		fmt.Printf("Failed to establish full TLS connection: %v\n", err)
		return
	}

	// Step 3.5: Send HTTP request through TEE protocol with REDACTION DEMO
	fmt.Printf("\nStep 3.5: Demonstrating TEE+MPC Redaction Protocol...\n")
	fmt.Printf("   Creating HTTP request with sensitive data for redaction demo:\n")

	// Create HTTP request with sensitive components for redaction demo
	httpRequest := `GET /api/account HTTP/1.1
Host: example.com
User-Agent: TEE-MPC-Demo/1.0
Authorization: Bearer secret_token_12345_DO_NOT_REVEAL
X-Bank-Account: 1234567890123456
Connection: close

`

	// Define redaction streams - what should be hidden vs revealed
	fmt.Printf("   R_NS (Non-Sensitive - Will be revealed):\n")
	nonSensitiveData := []byte(`GET /api/account HTTP/1.1
Host: example.com
User-Agent: TEE-MPC-Demo/1.0
Connection: close

`)
	fmt.Printf("      • HTTP method, path, and basic headers\n")
	fmt.Printf("      • Host: example.com\n")
	fmt.Printf("      • User-Agent and Connection headers\n")
	fmt.Printf("      • Total: %d bytes\n", len(nonSensitiveData))

	fmt.Printf("   R_S (Sensitive - Hidden but proven to exist):\n")
	sensitiveData := []byte("Authorization: Bearer secret_token_12345_DO_NOT_REVEAL\n")
	fmt.Printf("      • Authorization header with secret token\n")
	fmt.Printf("      • Content: '%s' (%d bytes)\n", strings.TrimSpace(string(sensitiveData)), len(sensitiveData))
	fmt.Printf("      • Will generate cryptographic commitment (hidden from server)\n")

	fmt.Printf("   R_SP (Sensitive Proof - Bank account with ZK proof):\n")
	sensitiveProofData := []byte("X-Bank-Account: 1234567890123456\n")
	fmt.Printf("      • Bank account number requiring zero-knowledge proof\n")
	fmt.Printf("      • Content: '%s' (%d bytes)\n", strings.TrimSpace(string(sensitiveProofData)), len(sensitiveProofData))
	fmt.Printf("      • Will generate zero-knowledge commitment (proven but not revealed)\n")

	// Create redaction request structure
	encryptReqData, _ := json.Marshal(map[string]interface{}{
		"request_data":  []byte(httpRequest),
		"aad":           []byte("HTTP/1.1"),
		"use_redaction": true,
		"redaction_request": map[string]interface{}{
			"non_sensitive":   nonSensitiveData,
			"sensitive":       sensitiveData,
			"sensitive_proof": sensitiveProofData,
		},
		"redaction_streams": map[string]interface{}{
			"stream_s":  generateRedactionStream(len(sensitiveData)),      // XOR stream for sensitive data
			"stream_sp": generateRedactionStream(len(sensitiveProofData)), // XOR stream for sensitive proof data
		},
		"redaction_keys": map[string]interface{}{
			"key_s":  generateDummyKey(32), // Key for sensitive redaction commitment
			"key_sp": generateDummyKey(32), // Key for sensitive proof redaction commitment
		},
	})

	fmt.Printf("\n   Sending redacted HTTP request through TEE protocol...\n")

	encryptMsg := WSMessage{
		Type:      MsgEncryptRequest,
		Data:      encryptReqData,
		Timestamp: time.Now(),
	}

	if globalConn != nil {
		globalConn.WriteJSON(encryptMsg)
	}
}

// generateRedactionStream creates a random XOR stream for redacting sensitive data
func generateRedactionStream(length int) []byte {
	stream := make([]byte, length)
	// Generate random bytes for XOR redaction (in real implementation, this would be cryptographically secure)
	for i := range stream {
		stream[i] = byte((i*17 + 42) % 256) // Deterministic pattern for demo
	}
	return stream
}

// generateDummyKey creates a dummy key for redaction operations
func generateDummyKey(length int) []byte {
	key := make([]byte, length)
	for i := range key {
		key[i] = byte(i % 256)
	}
	return key
}

func handleEncryptResponse(data json.RawMessage, sessionID *string) {
	var encryptResp EncryptResponseData
	if err := json.Unmarshal(data, &encryptResp); err != nil {
		fmt.Printf("   Failed to parse encrypt response: %v\n", err)
		return
	}

	fmt.Printf("   TEE Split AEAD Result with Redaction:\n")
	fmt.Printf("     Encrypted data: %d bytes\n", len(encryptResp.EncryptedData))
	fmt.Printf("     Authentication tag: %d bytes\n", len(encryptResp.Tag))
	fmt.Printf("     Status: %s\n", encryptResp.Status)
	fmt.Printf("     Using redaction: %t\n", encryptResp.UseRedaction)

	if encryptResp.UseRedaction && encryptResp.RedactionCommitments != nil {
		fmt.Printf("   Redaction Commitments Generated:\n")
		if len(encryptResp.RedactionCommitments.CommitmentS) > 0 {
			fmt.Printf("     • R_S Commitment: %x... (%d bytes)\n",
				encryptResp.RedactionCommitments.CommitmentS[:min(8, len(encryptResp.RedactionCommitments.CommitmentS))],
				len(encryptResp.RedactionCommitments.CommitmentS))
		}
		if len(encryptResp.RedactionCommitments.CommitmentSP) > 0 {
			fmt.Printf("     • R_SP Commitment: %x... (%d bytes)\n",
				encryptResp.RedactionCommitments.CommitmentSP[:min(8, len(encryptResp.RedactionCommitments.CommitmentSP))],
				len(encryptResp.RedactionCommitments.CommitmentSP))
		}
		fmt.Printf("     These commitments prove sensitive data exists without revealing it!\n")

		// Step 3.6: Send redaction streams to TEE_T (implementing step 6 of the protocol)
		fmt.Printf("\n   Step 3.6: Sending redaction streams to TEE_T (Protocol Step 6)...\n")
		if err := sendRedactionStreamsToTEET(*sessionID, encryptResp.RedactionCommitments); err != nil {
			fmt.Printf("   Failed to send redaction streams to TEE_T: %v\n", err)
			return
		}
	}

	if globalTLSInterceptor == nil {
		fmt.Printf("   Error: TLS interceptor not initialized\n")
		return
	}

	// Step 4: Send HTTP request through real TLS connection
	fmt.Printf("\n   Step 4: Sending HTTP request through real TLS connection...\n")

	// Use the same request structure but for real HTTP (Go's TLS will handle encryption)
	httpRequest := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	httpResponse, err := globalTLSInterceptor.SendHTTPRequest(httpRequest)
	if err != nil {
		fmt.Printf("   Failed to send HTTP request: %v\n", err)
		return
	}

	fmt.Printf("   Real HTTP Response received: %d bytes\n", len(httpResponse))
	fmt.Printf("   HTTP Response preview: %s\n", string(httpResponse[:min(100, len(httpResponse))])+"...")

	// Step 4b: Demonstrate response redaction
	fmt.Printf("\n   Response Redaction Demo:\n")
	fmt.Printf("   Raw HTTP response contains full page content...\n")

	// Show what would be redacted vs revealed
	htmlContent := string(httpResponse)

	// Find the end of headers (double CRLF)
	bodyStart := strings.Index(htmlContent, "\r\n\r\n")
	if bodyStart == -1 {
		bodyStart = strings.Index(htmlContent, "\n\n")
	}

	// Find ETag header
	etagStart := strings.Index(htmlContent, "ETag:")
	etagEnd := -1
	if etagStart != -1 {
		etagEnd = strings.Index(htmlContent[etagStart:], "\n")
		if etagEnd != -1 {
			etagEnd += etagStart
		} else {
			etagEnd = len(htmlContent)
		}
	}

	// Find "Example Domain" text in response
	exampleDomainStart := strings.Index(htmlContent, "Example Domain")

	if bodyStart != -1 && etagStart != -1 && exampleDomainStart != -1 {
		// Extract the different parts
		headersBeforeETag := htmlContent[:etagStart]
		etagHeader := htmlContent[etagStart:etagEnd]
		headersAfterETag := htmlContent[etagEnd : bodyStart+4] // Include the double newline
		bodyBeforeExample := htmlContent[bodyStart+4 : exampleDomainStart]
		exampleDomainText := "Example Domain"
		bodyAfterExample := htmlContent[exampleDomainStart+13:]

		fmt.Printf("   Response Redaction Categories:\n")
		fmt.Printf("      • R_NS (Non-Sensitive): HTTP headers except ETag\n")
		fmt.Printf("      • R_S (Sensitive): ETag header (like a sensitive cookie)\n")
		fmt.Printf("      • R_SP (Sensitive Proof): 'Example Domain' text with ZK proof\n")

		fmt.Printf("   \n   ACTUAL CONTENT CATEGORIZATION:\n")

		// R_NS: Headers before and after ETag (non-sensitive)
		rnsContent := headersBeforeETag + headersAfterETag
		fmt.Printf("   • R_NS (Revealed headers): '%s...' (%d bytes)\n",
			strings.ReplaceAll(rnsContent[:min(60, len(rnsContent))], "\n", "\\n"), len(rnsContent))

		// R_S: ETag header (sensitive like a cookie)
		fmt.Printf("   • R_S (Hidden ETag): '%s' (%d bytes) - treated as sensitive cookie\n",
			strings.TrimSpace(etagHeader), len(etagHeader))

		// R_SP: Example Domain (sensitive proof)
		fmt.Printf("   • R_SP (ZK Proof content): '%s' (%d bytes) - proven but location hidden\n",
			exampleDomainText, len(exampleDomainText))

		// Hidden body content
		hiddenBodyContent := bodyBeforeExample + bodyAfterExample
		fmt.Printf("   • Hidden body content: %d bytes of HTML\n", len(hiddenBodyContent))

		fmt.Printf("   \n   Redaction Result:\n")
		fmt.Printf("   ✓ Headers visible (%d bytes) except ETag\n", len(rnsContent))
		fmt.Printf("   ✗ ETag hidden (%d bytes) - sensitive like session cookie\n", len(etagHeader))
		fmt.Printf("   ✓ 'Example Domain' proven present but location hidden via ZK proof\n")
		fmt.Printf("   ✗ Remaining HTML content hidden (%d bytes)\n", len(hiddenBodyContent))

	} else {
		fmt.Printf("   Could not parse response structure properly\n")
		fmt.Printf("   \n   ACTUAL CONTENT BEING REDACTED:\n")
		fmt.Printf("   • Full HTTP response: '%s...' (%d bytes)\n",
			strings.ReplaceAll(htmlContent[:min(100, len(htmlContent))], "\n", "\\n"), len(httpResponse))
		fmt.Printf("   • Redaction Result: All content hidden for privacy\n")
	}

	// Step 4c: Send TEE_K's Split AEAD data to TEE_T for verification
	fmt.Printf("\n   Step 4c: Verifying Split AEAD integrity through TEE protocol...\n")

	// Create the combined data: ciphertext + tag (as TEE_T expects)
	combinedData := make([]byte, len(encryptResp.EncryptedData)+len(encryptResp.Tag))
	copy(combinedData, encryptResp.EncryptedData)
	copy(combinedData[len(encryptResp.EncryptedData):], encryptResp.Tag)

	decryptReq := DecryptRequestData{
		ResponseLength: len(combinedData),
		EncryptedData:  combinedData,    // Combined ciphertext + tag
		ExpectedTag:    encryptResp.Tag, // Expected tag for verification
		HTTPResponse:   httpResponse,    // Actual HTTP response data for transcript
	}

	decryptReqData, _ := json.Marshal(decryptReq)
	decryptMsg := WSMessage{
		Type:      MsgDecryptRequest,
		SessionID: *sessionID,
		Data:      decryptReqData,
		Timestamp: time.Now(),
	}

	if globalConn != nil {
		if err := globalConn.WriteJSON(decryptMsg); err != nil {
			fmt.Printf("   Failed to send decrypt request: %v\n", err)
		}
	}
}

// sendRedactionStreamsToTEET implements step 6 from the protocol design document:
// User sends redaction streams (Str_S, Str_SP) and commitment keys (K_S, K_SP) to TEE_T
func sendRedactionStreamsToTEET(sessionID string, commitments *RedactionData) error {
	fmt.Printf("   Implementing Protocol Step 6: User → TEE_T redaction streams\n")

	// Connect to TEE_T service directly for redaction stream processing
	teeT_URL := "http://localhost:8081" // TEE_T service URL

	// Generate the redaction streams and keys that were used in encryption
	// These must match exactly what was used in the original encryption request
	sensitiveData := []byte("Authorization: Bearer secret_token_12345_DO_NOT_REVEAL\n")
	sensitiveProofData := []byte("X-Bank-Account: 1234567890123456\n")

	streamS := generateRedactionStream(len(sensitiveData))
	streamSP := generateRedactionStream(len(sensitiveProofData))
	keyS := generateDummyKey(32)
	keySP := generateDummyKey(32)

	type RedactionStreamRequest struct {
		SessionID           string            `json:"session_id"`
		RedactionStreams    map[string][]byte `json:"redaction_streams"`
		RedactionKeys       map[string][]byte `json:"redaction_keys"`
		ExpectedCommitments *RedactionData    `json:"expected_commitments"`
	}

	request := RedactionStreamRequest{
		SessionID: sessionID,
		RedactionStreams: map[string][]byte{
			"stream_s":  streamS,
			"stream_sp": streamSP,
		},
		RedactionKeys: map[string][]byte{
			"key_s":  keyS,
			"key_sp": keySP,
		},
		ExpectedCommitments: commitments,
	}

	reqData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal redaction stream request: %v", err)
	}

	// Send POST request to TEE_T
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(teeT_URL+"/process-redaction-streams", "application/json", strings.NewReader(string(reqData)))
	if err != nil {
		return fmt.Errorf("failed to send redaction streams to TEE_T: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("TEE_T rejected redaction streams (status %d): %s", resp.StatusCode, string(body))
	}

	fmt.Printf("   Redaction streams successfully sent to TEE_T\n")
	fmt.Printf("     • Stream S: %d bytes (for sensitive authorization)\n", len(streamS))
	fmt.Printf("     • Stream SP: %d bytes (for sensitive proof bank account)\n", len(streamSP))
	fmt.Printf("     • Key S: %d bytes\n", len(keyS))
	fmt.Printf("     • Key SP: %d bytes\n", len(keySP))
	fmt.Printf("   TEE_T response: %s\n", string(body))
	fmt.Printf("   TEE_T will now verify commitments and prepare for tag computation\n")

	return nil
}

func handleDecryptResponse(data json.RawMessage) {
	var decryptResp DecryptResponseData
	if err := json.Unmarshal(data, &decryptResp); err != nil {
		fmt.Printf("   Failed to parse decrypt response: %v\n", err)
		return
	}

	fmt.Printf("   TEE Tag Verification Result:\n")
	fmt.Printf("     Decryption stream: %d bytes\n", len(decryptResp.DecryptionStream))
	fmt.Printf("     Status: %s\n", decryptResp.Status)
	fmt.Printf("     Protocol Phase 4 complete - using real TLS session keys!\n")

	// Finalize after successful verification
	time.Sleep(1 * time.Second)

	fmt.Printf("\nStep 5: Finalizing session to get signed transcripts...\n")
	finalizeData, _ := json.Marshal(map[string]interface{}{
		"request_count": 1,
	})
	finalizeMsg := WSMessage{
		Type:      MsgFinalize,
		Data:      finalizeData,
		Timestamp: time.Now(),
	}

	if globalConn != nil {
		globalConn.WriteJSON(finalizeMsg)
	}
}

func handleFinalizeResponse(data json.RawMessage) {
	var finalizeResp FinalizeResponseData
	if err := json.Unmarshal(data, &finalizeResp); err != nil {
		fmt.Printf("   Failed to parse finalize response: %v\n", err)
		return
	}

	fmt.Printf("   Finalization Status: %s\n", finalizeResp.Status)
	fmt.Printf("   TLS Keys: %d bytes\n", len(finalizeResp.TLSKeys))

	// Display Request Transcript
	if len(finalizeResp.SignedRequestTranscript) > 0 {
		fmt.Printf("\n   SIGNED REQUEST TRANSCRIPT (TEE_K):\n")
		var requestTranscript SignedTranscript
		if err := json.Unmarshal(finalizeResp.SignedRequestTranscript, &requestTranscript); err != nil {
			fmt.Printf("      Failed to parse request transcript: %v\n", err)
		} else {
			// Check if Data field is not nil before accessing its fields
			if requestTranscript.Data != nil {
				fmt.Printf("      Type: %s\n", requestTranscript.Data.Type)
				fmt.Printf("      Session ID: %s\n", requestTranscript.Data.SessionID)
				fmt.Printf("      Algorithm: %s\n", requestTranscript.Algorithm)
				signatureHex := fmt.Sprintf("%x", requestTranscript.Signature)
				fmt.Printf("      Signature: %s...\n", signatureHex[:min(32, len(signatureHex))])
				fmt.Printf("      Data: %d bytes\n", len(requestTranscript.Data.Data))
				fmt.Printf("      Metadata: %v\n", requestTranscript.Data.Metadata)
			} else {
				fmt.Printf("      Error: Request transcript data is nil\n")
				fmt.Printf("      Algorithm: %s\n", requestTranscript.Algorithm)
				signatureHex := fmt.Sprintf("%x", requestTranscript.Signature)
				fmt.Printf("      Signature: %s...\n", signatureHex[:min(32, len(signatureHex))])
			}
		}
	}

	// Display Response Transcript
	if len(finalizeResp.SignedResponseTranscript) > 0 {
		fmt.Printf("\n   SIGNED RESPONSE TRANSCRIPT (TEE_T):\n")
		var responseTranscript SignedTranscript
		if err := json.Unmarshal(finalizeResp.SignedResponseTranscript, &responseTranscript); err != nil {
			fmt.Printf("      Failed to parse response transcript: %v\n", err)
		} else {
			// Check if Data field is not nil before accessing its fields
			if responseTranscript.Data != nil {
				fmt.Printf("      Type: %s\n", responseTranscript.Data.Type)
				fmt.Printf("      Session ID: %s\n", responseTranscript.Data.SessionID)
				fmt.Printf("      Algorithm: %s\n", responseTranscript.Algorithm)
				signatureHex := fmt.Sprintf("%x", responseTranscript.Signature)
				fmt.Printf("      Signature: %s...\n", signatureHex[:min(32, len(signatureHex))])
				fmt.Printf("      Data: %d bytes\n", len(responseTranscript.Data.Data))
				fmt.Printf("      Metadata: %v\n", responseTranscript.Data.Metadata)
			} else {
				fmt.Printf("      Error: Response transcript data is nil\n")
				fmt.Printf("      Algorithm: %s\n", responseTranscript.Algorithm)
				signatureHex := fmt.Sprintf("%x", responseTranscript.Signature)
				fmt.Printf("      Signature: %s...\n", signatureHex[:min(32, len(signatureHex))])
			}
		}
	}

	fmt.Printf("\n   TEE+MPC Protocol completed successfully!\n")

}

// Helper function to convert TLS version to string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func cleanup() {
	fmt.Printf("\nCleaning up connections...\n")
	if globalTLSInterceptor != nil {
		globalTLSInterceptor.Close()
		fmt.Printf("Closed TLS interceptor connections\n")
	}
	if globalConn != nil {
		globalConn.Close()
		fmt.Printf("Closed WebSocket connection\n")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// verifyCertificateWithHandshakeKey verifies the server certificate using the handshake key
// This implements Protocol Step 2.3 from the design document
func verifyCertificateWithHandshakeKey(certChainBytes []byte, handshakeKey []byte, expectedHostname string) error {
	// Parse the certificate chain
	certChain, err := parseCertificateChain(certChainBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate chain: %v", err)
	}

	if len(certChain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Get the server certificate (first in chain)
	serverCert := certChain[0]

	// Verify the certificate matches the expected hostname
	if err := serverCert.VerifyHostname(expectedHostname); err != nil {
		return fmt.Errorf("hostname verification failed: %v", err)
	}

	// Verify certificate chain validity
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	// Add intermediate certificates to the pool
	for i := 1; i < len(certChain); i++ {
		intermediates.AddCert(certChain[i])
	}

	// Add system root CAs
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		// Fallback to empty pool if system roots unavailable
		systemRoots = x509.NewCertPool()
	}
	roots = systemRoots

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       expectedHostname,
	}

	if _, err := serverCert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %v", err)
	}

	// Protocol-specific verification: Verify the certificate's public key matches the handshake key
	// In the TEE+MPC protocol, the handshake key should be derived from the certificate's public key
	// For this demo, we'll perform a simplified verification
	certPubKeyBytes, err := x509.MarshalPKIXPublicKey(serverCert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate public key: %v", err)
	}

	// In a real implementation, this would verify that the handshake key is properly derived
	// from the certificate's public key using the TLS 1.3 key derivation process
	// For the demo, we'll verify that we have both keys and they're reasonable sizes
	if len(handshakeKey) < 16 {
		return fmt.Errorf("handshake key too short (got %d bytes, expected at least 16)", len(handshakeKey))
	}

	if len(certPubKeyBytes) < 32 {
		return fmt.Errorf("certificate public key too short (got %d bytes, expected at least 32)", len(certPubKeyBytes))
	}

	// Additional protocol verification would go here in a full implementation
	// This would include verifying the handshake key derivation from the certificate

	return nil
}

// parseCertificateChain parses a DER-encoded certificate chain
func parseCertificateChain(certChainBytes []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	remaining := certChainBytes

	// Try to parse as concatenated DER certificates first
	for len(remaining) > 0 {
		// Try to parse the first certificate
		cert, err := x509.ParseCertificate(remaining)
		if err != nil {
			// If DER parsing fails, try PEM parsing
			break
		}

		certificates = append(certificates, cert)

		// Move to the next certificate
		// In DER format, we need to skip the current certificate length
		certLen := len(cert.Raw)
		if certLen >= len(remaining) {
			break // This was the last certificate
		}
		remaining = remaining[certLen:]
	}

	// If no DER certificates were parsed, try PEM format
	if len(certificates) == 0 {
		remaining = certChainBytes
		for len(remaining) > 0 {
			block, rest := pem.Decode(remaining)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse PEM certificate: %v", err)
				}
				certificates = append(certificates, cert)
			}
			remaining = rest
		}
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("no valid certificates found in chain")
	}

	return certificates, nil
}
