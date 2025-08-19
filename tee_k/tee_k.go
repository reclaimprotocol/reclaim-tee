package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// RedactionOperation represents a redaction to be applied to a specific sequence
type RedactionOperation struct {
	SeqNum uint64
	Start  int    // Start offset within the sequence
	End    int    // End offset within the sequence
	Bytes  []byte // Redaction bytes to apply
}

// TEEK is the main TEE_K service structure
type TEEK struct {
	port int

	// Session management
	sessionManager    *TEEKSessionManager
	sessionTerminator *shared.SessionTerminator

	// Logging
	logger *shared.Logger

	// TEE_T connection settings
	teetURL string

	// Shared persistent connection to TEE_T
	sharedTEETConn *websocket.Conn
	teetConnMutex  sync.RWMutex

	// TLS configuration
	forceTLSVersion  string // Force specific TLS version: "1.2", "1.3", or "" for auto
	forceCipherSuite string // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto

	// Single Session Mode: ECDSA signing keys
	signingKeyPair *shared.SigningKeyPair // ECDSA key pair for signing transcripts

	// Enclave manager for attestation generation
	enclaveManager *shared.EnclaveManager

	// Attestation caching for performance optimization
	cachedAttestation *teeproto.AttestationReport
	attestationMutex  sync.RWMutex
	attestationExpiry time.Time
}

// NewTEEKWithConfig creates a new TEEK instance with the provided configuration
func NewTEEKWithConfig(config *TEEKConfig) *TEEK {
	teek := NewTEEKWithEnclaveManager(config.Port, nil)
	teek.SetTEETURL(config.TEETURL)
	teek.SetForceTLSVersion(config.ForceTLSVersion)
	teek.SetForceCipherSuite(config.ForceCipherSuite)
	return teek
}

// NewTEEKWithEnclaveManager creates a new TEEK instance with optional enclave manager
func NewTEEKWithEnclaveManager(port int, enclaveManager *shared.EnclaveManager) *TEEK {
	// Generate ECDSA signing key pair
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		// Critical failure - cannot operate without signing capability
		log.Fatalf("[TEE_K] CRITICAL: Failed to generate signing key pair: %v", err)
	}

	// Get logger
	logger := shared.GetTEEKLogger()
	logger.Info("Generated ECDSA signing key pair")

	return &TEEK{
		port:              port,
		sessionManager:    NewTEEKSessionManager(),
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
		teetURL:           "ws://localhost:8081/teek", // Default TEE_T URL
		signingKeyPair:    signingKeyPair,
		enclaveManager:    enclaveManager,
	}
}

// SetTEETURL sets the TEE_T connection URL
func (t *TEEK) SetTEETURL(url string) {
	t.teetURL = url
}

// SetForceTLSVersion sets the forced TLS version
func (t *TEEK) SetForceTLSVersion(version string) {
	t.forceTLSVersion = version
}

// SetForceCipherSuite sets the forced cipher suite
func (t *TEEK) SetForceCipherSuite(cipherSuite string) {
	t.forceCipherSuite = cipherSuite
}

// Helper functions to access session state
func (t *TEEK) getSessionTLSState(sessionID string) (*TEEKSessionState, error) {
	return t.sessionManager.GetTEEKSessionState(sessionID)
}

func (t *TEEK) getSessionResponseState(sessionID string) (*shared.ResponseSessionState, error) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingResponses:          make(map[string][]byte),
			ResponseLengthBySeq:       make(map[uint64]int),
			ExplicitIVBySeq:           make(map[uint64][]byte),
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}
	return session.ResponseState, nil
}

// cleanupSession performs complete cleanup of session resources
func (t *TEEK) cleanupSession(sessionID string) {
	// Close the session in session manager (handles connections and state cleanup)
	if err := t.sessionManager.CloseSession(sessionID); err != nil {
		// Log cleanup failure but don't continue with broken session
		t.logger.WithSession(sessionID).Error("Failed to cleanup session", zap.Error(err))
	}

	// Cleanup session terminator tracking
	t.sessionTerminator.CleanupSession(sessionID)

	t.logger.WithSession(sessionID).Info("Session terminated and cleaned up")
}

// terminateSessionWithError terminates a session due to a critical error
func (t *TEEK) terminateSessionWithError(sessionID string, reason shared.TerminationReason, err error, message string) {
	// Send error message to client BEFORE terminating
	t.sendErrorToClient(sessionID, message, err)

	// Log the critical error and determine if session should terminate
	if t.sessionTerminator.ZeroToleranceError(sessionID, reason, err) {
		// Small delay to ensure error message is sent before connection closes
		time.Sleep(50 * time.Millisecond)
		// Cleanup session resources
		t.cleanupSession(sessionID)
	}
}

// sendErrorToClient sends an error message to the client before terminating
func (t *TEEK) sendErrorToClient(sessionID string, message string, err error) {
	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{
			Error: &teeproto.ErrorData{
				Message: errorMsg,
			},
		},
	}

	// Best effort to send error - don't fail if routing fails
	if routeErr := t.sessionManager.RouteToClient(sessionID, env); routeErr != nil {
		t.logger.WithSession(sessionID).Warn("Failed to send error to client")
	} else {
		t.logger.WithSession(sessionID).Info("Sent error message to client")
	}
}
