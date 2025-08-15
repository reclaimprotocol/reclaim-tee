package clientlib

import (
	"crypto/ecdsa"
	"fmt"
	"tee-mpc/proto"
	"tee-mpc/shared"
	"time"
)

// ReclaimClient is the public interface for the Reclaim TEE+MPC client library
type ReclaimClient interface {
	Connect() error
	RequestHTTP(hostname string, port int) error
	SetRequestData(requestData []byte) error
	SetRequestRedactionRanges(ranges []shared.RequestRedactionRange)
	WaitForCompletion() <-chan struct{}
	Close() error
	SetResponseCallback(callback ResponseCallback)

	// 2-phase operation methods
	EnableTwoPhaseMode()
	WaitForPhase1Completion() <-chan struct{}
	ContinueToPhase2() error

	// Results access methods
	GetProtocolResult() (*ProtocolResult, error)
	GetTranscripts() (*TranscriptResults, error)
	GetValidationResults() (*ValidationResults, error)
	GetAttestationResults() (*AttestationResults, error)
	GetResponseResults() (*ResponseResults, error)
	BuildVerificationBundle(path string) error
	SubmitToAttestorCore(attestorURL string, privateKey *ecdsa.PrivateKey, params ClaimTeeBundleParams) (*teeproto.ProviderClaimData, error)
}

// ClientMode represents the operational mode of the client
type ClientMode int

const (
	ModeAuto ClientMode = iota // Auto-detect based on URLs
	ModeEnclave
	ModeStandalone
)

// ReclaimClientImpl is the internal implementation of ReclaimClient
type ReclaimClientImpl struct {
	Client *Client
	config ClientConfig
	logger *shared.Logger
}

// NewReclaimClient creates a new ReclaimClient with the given configuration
func NewReclaimClient(config ClientConfig) ReclaimClient {
	// Apply defaults if not specified
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Mode == ModeAuto {
		config.Mode = detectMode(config.TEEKURL, config.TEETURL)
	}

	// Create internal client with TEE_K URL
	client := NewClient(config.TEEKURL)

	// Configure TEE_T URL if provided
	if config.TEETURL != "" {
		client.SetTEETURL(config.TEETURL)
	}

	// Store config for later use
	client.forceTLSVersion = config.ForceTLSVersion
	client.forceCipherSuite = config.ForceCipherSuite
	client.SetMode(config.Mode)

	// Initialize logger
	logger, err := shared.NewLoggerFromEnv("client")
	if err != nil {
		// Fallback to basic logger if initialization fails
		logger, _ = shared.NewLogger(shared.LoggerConfig{
			ServiceName: "client",
			EnclaveMode: false,
			Development: true,
		})
	}

	return &ReclaimClientImpl{
		Client: client,
		config: config,
		logger: logger,
	}
}

// Connect establishes connections to both TEE_K and TEE_T
func (r *ReclaimClientImpl) Connect() error {
	// Connect to TEE_K
	if err := r.Client.ConnectToTEEK(); err != nil {
		return NewConnectionError("TEE_K", err)
	}

	// Connect to TEE_T
	if err := r.Client.ConnectToTEET(); err != nil {
		return NewConnectionError("TEE_T", err)
	}

	// Fetch and verify attestations (only in enclave mode)
	if r.config.Mode == ModeEnclave {
		if err := r.Client.fetchAndVerifyAttestations(); err != nil {
			return NewAttestationError(err)
		}
	} else {
		r.logger.Info("Skipping attestation verification in standalone mode")
	}

	return nil
}

// RequestHTTP initiates an HTTP request through the TEE+MPC protocol
func (r *ReclaimClientImpl) RequestHTTP(hostname string, port int) error {
	// Set response callback if provided
	if r.config.ResponseCallback != nil {
		r.Client.responseCallback = r.config.ResponseCallback
	}

	return r.Client.RequestHTTP(hostname, port)
}

// WaitForCompletion returns a channel that closes when the protocol is complete
func (r *ReclaimClientImpl) WaitForCompletion() <-chan struct{} {
	return r.Client.WaitForCompletion()
}

// Close closes the client connections
func (r *ReclaimClientImpl) Close() error {
	r.Client.Close()
	return nil
}

// SetResponseCallback sets the callback for handling response redactions
func (r *ReclaimClientImpl) SetResponseCallback(callback ResponseCallback) {
	r.config.ResponseCallback = callback
	if r.Client != nil {
		r.Client.responseCallback = callback
	}
}

// EnableTwoPhaseMode enables 2-phase operation mode
func (r *ReclaimClientImpl) EnableTwoPhaseMode() {
	if r.Client != nil {
		r.Client.EnableTwoPhaseMode()
	}
}

// WaitForPhase1Completion returns a channel that closes when phase 1 is complete
func (r *ReclaimClientImpl) WaitForPhase1Completion() <-chan struct{} {
	if r.Client != nil {
		return r.Client.WaitForPhase1Completion()
	}
	// Return a closed channel if client is nil
	ch := make(chan struct{})
	close(ch)
	return ch
}

// ContinueToPhase2 continues the protocol to phase 2
func (r *ReclaimClientImpl) ContinueToPhase2() error {
	if r.Client != nil {
		return r.Client.ContinueToPhase2()
	}
	return fmt.Errorf("client not initialized")
}

// GetProtocolResult returns the complete protocol execution results
func (r *ReclaimClientImpl) GetProtocolResult() (*ProtocolResult, error) {
	return r.Client.buildProtocolResult()
}

// GetTranscripts returns the signed transcripts from both TEE_K and TEE_T
func (r *ReclaimClientImpl) GetTranscripts() (*TranscriptResults, error) {
	return r.Client.buildTranscriptResults()
}

// GetValidationResults returns the validation results for transcripts and attestations
func (r *ReclaimClientImpl) GetValidationResults() (*ValidationResults, error) {
	return r.Client.buildValidationResults()
}

// GetAttestationResults returns the attestation verification results
func (r *ReclaimClientImpl) GetAttestationResults() (*AttestationResults, error) {
	return r.Client.buildAttestationResults()
}

// GetResponseResults returns the HTTP response data and proof claims
func (r *ReclaimClientImpl) GetResponseResults() (*ResponseResults, error) {
	return r.Client.buildResponseResults()
}

func (r *ReclaimClientImpl) BuildVerificationBundle(path string) error {
	return r.Client.BuildVerificationBundle(path)
}

func (r *ReclaimClientImpl) SetRequestData(requestData []byte) error {
	// Store the request data in the client for later use
	r.Client.requestData = requestData
	return nil
}

func (r *ReclaimClientImpl) SetRequestRedactionRanges(ranges []shared.RequestRedactionRange) {
	r.Client.SetRequestRedactionRanges(ranges)
}

func (r *ReclaimClientImpl) SubmitToAttestorCore(attestorURL string, privateKey *ecdsa.PrivateKey, params ClaimTeeBundleParams) (*teeproto.ProviderClaimData, error) {
	return r.Client.SubmitToAttestorCore(attestorURL, privateKey, params)
}

// detectMode automatically detects the client mode based on URLs
func detectMode(teekURL, teetURL string) ClientMode {
	if (teekURL != "" && teekURL[:4] == "wss:") || (teetURL != "" && teetURL[:4] == "wss:") {
		return ModeEnclave
	}
	return ModeStandalone
}
