package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

var teetUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

// TEET represents the TEE_T (Execution Environment for Transcript generation)
type TEET struct {
	port int

	// Session management
	sessionManager *TEETSessionManager

	// Logging and error handling
	logger            *shared.Logger
	sessionTerminator *shared.SessionTerminator

	ready bool

	// Single Session Mode: ECDSA signing keys
	signingKeyPair *shared.SigningKeyPair // ECDSA key pair for signing transcripts

	// Enclave manager for attestation generation
	enclaveManager *shared.EnclaveManager

	// Attestation caching for performance optimization
	cachedAttestation *teeproto.AttestationReport
	attestationMutex  sync.RWMutex
	attestationExpiry time.Time
}

// NewTEETWithLogger creates a TEET with a specific logger
func NewTEETWithLogger(port int, logger *shared.Logger) *TEET {
	return NewTEETWithEnclaveManagerAndLogger(port, nil, logger)
}

// NewTEETWithEnclaveManagerAndLogger creates a TEET with enclave manager and logger
func NewTEETWithEnclaveManagerAndLogger(port int, enclaveManager *shared.EnclaveManager, logger *shared.Logger) *TEET {
	sessionTerminator := shared.NewSessionTerminator(logger)

	// Generate ECDSA signing key pair
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		// Critical failure - cannot operate without signing capability
		if logger != nil {
			logger.Fatal("CRITICAL: Failed to generate signing key pair", zap.Error(err))
		}
		// Fallback if logger is nil
		log.Fatalf("[TEE_T] CRITICAL: Failed to generate signing key pair: %v", err)
	}
	if logger != nil {
		logger.InfoIf("Generated ECDSA signing key pair", zap.String("curve", "P-256"))
	}

	return &TEET{
		port:              port,
		sessionManager:    NewTEETSessionManager(),
		logger:            logger,
		sessionTerminator: sessionTerminator,
		signingKeyPair:    signingKeyPair,
		enclaveManager:    enclaveManager,
	}
}

// Helper functions to access session state
func (t *TEET) getSessionRedactionState(sessionID string) (*shared.RedactionSessionState, error) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}
	return session.RedactionState, nil
}

func (t *TEET) getTEETSessionState(sessionID string) (*TEETSessionState, error) {
	return t.sessionManager.GetTEETSessionState(sessionID)
}

// Start method removed - now handled by main.go with proper graceful shutdown

// Handler methods
