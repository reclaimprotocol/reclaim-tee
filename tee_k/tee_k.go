package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

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

	// Per-session connection manager (control + per-session connections)
	connManager *TEETConnectionManager

	// TLS configuration
	forceTLSVersion  string                     // Force specific TLS version: "1.2", "1.3", or "" for auto
	forceCipherSuite string                     // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
	certFetcher      minitls.CertificateFetcher // Shared cached certificate fetcher

	// Single Session Mode: ECDSA signing keys
	signingKeyPair *shared.SigningKeyPair // ECDSA key pair for signing transcripts

	// Attestation caching for performance optimization
	cachedAttestation *teeproto.AttestationReport
	attestationMutex  sync.RWMutex
	attestationExpiry time.Time

	// Mutual attestation (managed by connection manager)
	teetAttestationVerified bool
	teetAttestationMutex    sync.RWMutex

	// Persistent OPRF key share (loaded from cloud storage)
	oprfKeyShare []byte

	// OT precomputation state for 2-round OPRF protocol
	otPrecomputeState *OTPrecomputeState

	// V2 router-mode wiring. Nil/zero in standalone mode; filled in by
	// NewTEEKForRouter when ROUTER_URL is set. The connection manager,
	// attestation code, and heartbeat goroutine all read these.
	ratls                   *shared.RATLSManager
	router                  *shared.RouterClient
	pairID                  string
	expectedPeerImageDigest string // sha256:... of TEE_T container image, for RA-TLS peer verification

	// Heartbeat observation state — written by the connection manager
	// (controlHealthy on peer connect/disconnect), OT precompute code
	// (otReady on pool ready/cleared), and the session manager
	// (activeSessions). Read by the router-heartbeat goroutine each tick.
	// Atomic so reads stay lock-free.
	controlHealthy atomic.Bool
	otReady        atomic.Bool
	activeSessions atomic.Int32
}

// NewTEEKWithConfig creates a new TEEK instance with the provided configuration
func NewTEEKWithConfig(config *TEEKConfig) *TEEK {
	teek := NewTEEK(config.Port)
	teek.SetTEETURL(config.TEETURL)
	teek.SetForceTLSVersion(config.ForceTLSVersion)
	teek.SetForceCipherSuite(config.ForceCipherSuite)
	return teek
}

// NewTEEKForRouter constructs a TEEK wired for the V2 router-mode path:
// RA-TLS instead of ACME-issued certs, router client for register +
// heartbeat, deterministic pair_id generated at boot. Used only when
// ROUTER_URL is set; standalone-mode boot continues to use NewTEEKWithConfig.
//
// Returns a fully-initialized TEEK with router-mode fields populated but
// no peer connection or HTTP server started yet — the caller wires those up.
func NewTEEKForRouter(
	config *TEEKConfig,
	ratls *shared.RATLSManager,
	router *shared.RouterClient,
	pairID string,
) *TEEK {
	teek := NewTEEK(config.Port)
	teek.ratls = ratls
	teek.router = router
	teek.pairID = pairID
	teek.expectedPeerImageDigest = config.ExpectedPeerImageDigest
	// In router mode the peer URL is derived from PEER_ADDR rather than
	// the legacy TEET_URL env var. /ws is the base path; the connection
	// manager extends it to /ws/control and /ws/session.
	teek.SetTEETURL("wss://" + config.PeerAddr + "/ws")
	teek.SetForceTLSVersion(config.ForceTLSVersion)
	teek.SetForceCipherSuite(config.ForceCipherSuite)
	return teek
}

// NewTEEK constructs a baseline TEEK on the given port. Higher-level
// constructors (NewTEEKWithConfig, NewTEEKForRouter) layer mode-specific
// wiring on top.
func NewTEEK(port int) *TEEK {
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		log.Fatalf("[TEE_K] CRITICAL: Failed to generate signing key pair: %v", err)
	}

	logger := shared.GetTEEKLogger()
	logger.Info("Generated ECDSA signing key pair")

	certFetcher, err := NewCertificateFetcher(logger)
	if err != nil {
		log.Fatalf("[TEE_K] CRITICAL: Failed to initialize certificate fetcher: %v", err)
	}
	logger.Info("Initialized cached certificate fetcher")

	oprfKeyShare := initializeOPRFKeyShare(logger)

	sessionManager := NewTEEKSessionManager()
	sessionManager.SetLogger(logger)

	return &TEEK{
		port:              port,
		sessionManager:    sessionManager,
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
		teetURL:           "ws://localhost:8081/teek", // Default TEE_T URL
		signingKeyPair:    signingKeyPair,
		certFetcher:       certFetcher,
		oprfKeyShare:      oprfKeyShare,
	}
}

// initializeOPRFKeyShare returns TEE_K's MPC OPRF key share. When
// KMS_ENCLAVE_DOMAIN_KEY is set the share is loaded from (or created in)
// GCP Secret Manager — same secret name + envelope format as the legacy
// EnclaveCache, so existing V1 shares are picked up unchanged. When the
// env var is empty (local dev / standalone), a hardcoded share is used.
func initializeOPRFKeyShare(logger *shared.Logger) []byte {
	deploymentKey := shared.GetEnvOrDefault("KMS_ENCLAVE_DOMAIN_KEY", "")
	if deploymentKey == "" {
		keyShare := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
		logger.Info("Using static OPRF key share (KMS_ENCLAVE_DOMAIN_KEY unset)")
		return keyShare
	}
	share, err := loadPersistentOPRFShare(deploymentKey, "tee_k", logger)
	if err != nil {
		log.Fatalf("[TEE_K] CRITICAL: load OPRF share: %v", err)
	}
	return share
}

// loadPersistentOPRFShare bridges initializeOPRFKeyShare to shared.SecretStore.
// Fails fatally if any of the supporting env vars are missing — operators
// must set all of them when KMS_ENCLAVE_DOMAIN_KEY is in use.
func loadPersistentOPRFShare(deploymentKey, role string, logger *shared.Logger) ([]byte, error) {
	projectID := shared.GetEnvOrDefault("GOOGLE_PROJECT_ID", "")
	kmsLocation := shared.GetEnvOrDefault("GOOGLE_KMS_LOCATION", "")
	kmsKeyRing := shared.GetEnvOrDefault("GOOGLE_KMS_KEYRING", "")
	kmsKey := shared.GetEnvOrDefault("GOOGLE_KMS_KEY", "")
	for name, v := range map[string]string{
		"GOOGLE_PROJECT_ID":   projectID,
		"GOOGLE_KMS_LOCATION": kmsLocation,
		"GOOGLE_KMS_KEYRING":  kmsKeyRing,
		"GOOGLE_KMS_KEY":      kmsKey,
	} {
		if v == "" {
			return nil, fmt.Errorf("%s required when KMS_ENCLAVE_DOMAIN_KEY is set", name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, err := shared.NewSecretStore(ctx, projectID, kmsLocation, kmsKeyRing, kmsKey)
	if err != nil {
		return nil, fmt.Errorf("new secret store: %w", err)
	}
	share, err := store.LoadOrCreateOPRFShare(ctx, role, deploymentKey)
	if err != nil {
		return nil, fmt.Errorf("LoadOrCreateOPRFShare: %w", err)
	}
	logger.Info("Loaded OPRF share from Secret Manager",
		zap.String("role", role),
		zap.String("deployment_key", deploymentKey))
	return share, nil
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
// This function is idempotent - safe to call multiple times for the same session
func (t *TEEK) cleanupSession(sessionID string) {
	// Close per-session connection to TEE_T
	if t.connManager != nil {
		t.connManager.CloseSessionConnection(sessionID, "session_cleanup")
	}

	// Close the session in session manager (handles connections and state cleanup)
	if err := t.sessionManager.CloseSession(sessionID); err != nil {
		// Session already cleaned up - expected when both sides close proactively
		t.logger.WithSession(sessionID).Debug("Session already cleaned up", zap.Error(err))
		return
	}

	// Cleanup session terminator tracking
	t.sessionTerminator.CleanupSession(sessionID)

	t.logger.WithSession(sessionID).Info("Session terminated and cleaned up")
}

// terminateSessionWithError terminates a session due to a critical error
// Sends error notification to both client and TEE_T, then cleans up session
// This function implements ZERO TOLERANCE - always terminates the session
func (t *TEEK) terminateSessionWithError(sessionID string, reason shared.TerminationReason, err error, message string) {
	// Check if session exists - if not, it's already been terminated
	if _, sessionErr := t.sessionManager.GetSession(sessionID); sessionErr != nil {
		t.logger.WithSession(sessionID).Warn("Session already terminated, skipping duplicate termination",
			zap.String("reason", string(reason)))
		return
	}

	t.logger.WithSession(sessionID).Error(message, zap.Error(err), zap.String("reason", string(reason)))

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

	// Send error to client
	if routeErr := t.sessionManager.RouteToClient(sessionID, env); routeErr != nil {
		t.logger.WithSession(sessionID).Warn("Failed to send error to client", zap.Error(routeErr))
	}

	// Send error to TEE_T
	if sendErr := t.sendEnvelopeToTEET(sessionID, env); sendErr != nil {
		t.logger.WithSession(sessionID).Warn("Failed to send error to TEE_T", zap.Error(sendErr))
	}

	// Small delay to ensure error messages are sent before connection closes
	time.Sleep(50 * time.Millisecond)

	// Cleanup session resources
	t.cleanupSession(sessionID)
}

// getEnvelopePayloadType returns a string describing the payload type for logging
func getEnvelopePayloadType(env *teeproto.Envelope) string {
	if env == nil {
		return "nil"
	}
	switch env.Payload.(type) {
	case *teeproto.Envelope_SessionCreated:
		return "SessionCreated"
	case *teeproto.Envelope_KeyShareRequest:
		return "KeyShareRequest"
	case *teeproto.Envelope_BatchedEncryptedRequest:
		return "BatchedEncryptedRequest"
	case *teeproto.Envelope_Finished:
		return "Finished"
	case *teeproto.Envelope_BatchedTagSecrets:
		return "BatchedTagSecrets"
	case *teeproto.Envelope_Error:
		return "Error"
	case *teeproto.Envelope_OtPrecomputeRequest:
		return "OtPrecomputeRequest"
	case *teeproto.Envelope_OtPrecomputeComplete:
		return "OtPrecomputeComplete"
	case *teeproto.Envelope_OprfOnlineFull:
		return "OprfOnlineFull"
	case *teeproto.Envelope_TeekAttestation:
		return "TeekAttestation"
	default:
		return fmt.Sprintf("Unknown(%T)", env.Payload)
	}
}

// sendToTEET sends a message to TEE_T, routing to control or session connection as appropriate
func (t *TEEK) sendToTEET(sessionID string, env *teeproto.Envelope) error {
	if t.connManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}

	// Check attestation via connection manager
	if !t.connManager.IsAttestationVerified() {
		err := fmt.Errorf("cannot send to TEE_T: attestation not verified")
		t.logger.WithSession(sessionID).Error("Attestation check failed", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonAttestationVerificationFailed, err,
			"TEE_T attestation not verified")
		return err
	}

	t.logger.WithSession(sessionID).Info("Sending to TEE_T",
		zap.String("type", getEnvelopePayloadType(env)))

	// Route control messages to control connection, session messages to session connection
	if isControlMessage(env) {
		return t.connManager.SendOnControl(env)
	}
	return t.connManager.SendOnSession(sessionID, env)
}
