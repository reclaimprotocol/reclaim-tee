package main

import (
	"fmt"
	"time"

	"tee-mpc/minitls"
	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// performTLSHandshakeAndHTTPForSession performs TLS handshake for a specific session
func (t *TEEK) performTLSHandshakeAndHTTPForSession(sessionID string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get session for TLS handshake", zap.Error(err))
		return
	}

	// Get connection data
	reqData, ok := session.ConnectionData.(*shared.RequestConnectionData)
	if !ok {
		t.logger.WithSession(sessionID).Error("Missing connection data for TLS handshake")
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("missing connection data"), "Missing connection data")
		return
	}

	// Initialize TEE_K session state first
	initialState := &TEEKSessionState{
		HandshakeComplete: false,
		TCPReady:          make(chan bool, 1),
	}
	t.sessionManager.SetTEEKSessionState(sessionID, initialState)

	// Create session-specific TLS client
	wsConn := session.ClientConn.(*shared.WSConnection)
	tlsConn := &WebSocketConn{
		wsConn:      wsConn.GetWebSocketConn(),
		pendingData: make(chan []byte, 10),
		teek:        t,         // Add TEEK reference for transcript collection
		sessionID:   sessionID, // Add session ID for per-session transcript collection
	}

	// Initialize TLS client for this session
	tlsClient := minitls.NewClient(tlsConn)

	// Configure TLS version based on client request or server setting
	config := &minitls.Config{}

	// Prefer client-requested TLS version over server default
	effectiveTLSVersion := reqData.ForceTLSVersion
	if effectiveTLSVersion == "" {
		effectiveTLSVersion = t.forceTLSVersion
	}

	// Prefer client-requested cipher suite over server default
	effectiveCipherSuite := reqData.ForceCipherSuite
	if effectiveCipherSuite == "" {
		effectiveCipherSuite = t.forceCipherSuite
	}

	switch effectiveTLSVersion {
	case "1.2":
		config.MinVersion = minitls.VersionTLS12
		config.MaxVersion = minitls.VersionTLS12
		t.logger.WithSession(sessionID).Info("Forcing TLS 1.2")
	case "1.3":
		config.MinVersion = minitls.VersionTLS13
		config.MaxVersion = minitls.VersionTLS13
		t.logger.WithSession(sessionID).Info("Forcing TLS 1.3")
	default:
		// Auto-negotiate (default behavior)
		config.MinVersion = minitls.VersionTLS12
		config.MaxVersion = minitls.VersionTLS13
		t.logger.WithSession(sessionID).Info("TLS version auto-negotiation enabled")
	}

	// Configure cipher suite restrictions if specified
	if err := configureCipherSuites(config, effectiveCipherSuite, effectiveTLSVersion); err != nil {
		t.logger.WithSession(sessionID).Error("Cipher suite configuration error", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Invalid cipher suite configuration: %v", err))
		return
	}

	if effectiveCipherSuite != "" {
		t.logger.WithSession(sessionID).Info("Forcing cipher suite", zap.String("cipher_suite", effectiveCipherSuite))
	} else {
		t.logger.WithSession(sessionID).Info("Cipher suite auto-negotiation enabled")
	}

	tlsClient = minitls.NewClientWithConfig(tlsConn, config)

	// Store in session state instead of global fields
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get TLS state", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to get TLS state: %v", err))
		return
	}
	tlsState.TLSClient = tlsClient
	tlsState.WSConn2TLS = tlsConn
	tlsState.CurrentConn = wsConn.GetWebSocketConn()
	tlsState.CurrentRequest = reqData

	// Global state removed - using session state only

	if err := tlsClient.Handshake(reqData.Hostname); err != nil {
		t.logger.WithSession(sessionID).Error("TLS handshake failed", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("TLS handshake failed: %v", err))
		return
	}

	// Update TEE_K session state to mark handshake complete
	tlsState.HandshakeComplete = true

	// NEW: Extract certificate info from TLS client for structured storage
	session, sessionErr := t.sessionManager.GetSession(sessionID)
	if sessionErr == nil && tlsClient.GetCertificateInfo() != nil {
		session.CertificateInfo = tlsClient.GetCertificateInfo()
		t.logger.WithSession(sessionID).Info("Captured certificate info for structured verification",
			zap.String("common_name", session.CertificateInfo.CommonName),
			zap.String("issuer", session.CertificateInfo.IssuerCommonName))
	}

	// Store cipher suite for session
	cipherSuite := tlsClient.GetCipherSuite()
	tlsState.CipherSuite = cipherSuite

	// Certificate info is stored as structured data instead of raw handshake packets

	t.logger.WithSession(sessionID).Info("Handshake finished - ready for split AEAD")

	// Send handshake complete message
	envHandshake := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_HandshakeComplete{HandshakeComplete: &teeproto.HandshakeComplete{
			Success:     true,
			CipherSuite: uint32(cipherSuite), // Include cipher suite for consolidated verification
		}},
	}

	if err := t.sessionManager.RouteToClient(sessionID, envHandshake); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to send handshake complete", zap.Error(err))
	}

	t.logger.WithSession(sessionID).Info("TLS handshake complete",
		zap.Uint16("cipher_suite", cipherSuite))
	t.logger.WithSession(sessionID).Info("Ready for Phase 4 split AEAD response handling")
}

// getCipherSuiteAlgorithm maps TLS cipher suite numbers to algorithm names
func getCipherSuiteAlgorithm(cipherSuite uint16) string {
	return shared.GetAlgorithmName(cipherSuite)
}
