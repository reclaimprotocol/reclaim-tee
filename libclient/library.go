package clientlib

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	teeproto "tee-mpc/proto"
	"tee-mpc/providers"
	"tee-mpc/shared"
	"time"
)

// ReclaimClient is the public interface for the Reclaim TEE+MPC client library
type ReclaimClient interface {
	// Single-call protocol execution
	StartProtocol(providerParamsJSON string) error

	// Legacy methods for backward compatibility
	Connect() error
	RequestHTTP() error
	WaitForCompletion() <-chan struct{}
	Close() error

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

	// Set provider params for automatic response redactions
	client.providerParams = config.ProviderParams
	client.providerSecretParams = config.ProviderSecretParams

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

// NewReclaimClientFromJSON creates a new ReclaimClient with JSON-encoded provider params
func NewReclaimClientFromJSON(teekURL, teetURL, providerParamsJSON string) (ReclaimClient, error) {
	// Parse provider params from JSON
	var providerData ProviderRequestData
	if err := json.Unmarshal([]byte(providerParamsJSON), &providerData); err != nil {
		return nil, fmt.Errorf("failed to parse provider params JSON: %v", err)
	}

	if providerData.Params == nil {
		return nil, fmt.Errorf("params required in provider params JSON")
	}

	// Validate provider params using production validation functions
	if err := providers.ValidateProviderParams(providerData.Name, providerData.Params); err != nil {
		return nil, fmt.Errorf("invalid provider params: %v", err)
	}

	if providerData.SecretParams != nil {
		if err := providers.ValidateProviderSecretParams(providerData.Name, providerData.SecretParams); err != nil {
			return nil, fmt.Errorf("invalid provider secret params: %v", err)
		}
	}

	// Create config with validated provider params
	config := ClientConfig{
		TEEKURL:              teekURL,
		TEETURL:              teetURL,
		Timeout:              30 * time.Second,
		Mode:                 ModeAuto,
		ProviderParams:       providerData.Params,
		ProviderSecretParams: providerData.SecretParams,
	}

	return NewReclaimClient(config), nil
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

	// Session coordination happens automatically in background via WebSocket messages
	r.logger.Info("Connection established - session coordination will happen naturally")

	return nil
}

// StartProtocol executes the complete TEE+MPC protocol with JSON-encoded provider params
func (r *ReclaimClientImpl) StartProtocol(providerParamsJSON string) error {
	// Parse provider params from JSON
	var providerData ProviderRequestData
	if err := json.Unmarshal([]byte(providerParamsJSON), &providerData); err != nil {
		return fmt.Errorf("failed to parse provider params JSON: %v", err)
	}

	if providerData.Params == nil {
		return fmt.Errorf("params required in provider params JSON")
	}

	// Validate provider params using production validation functions
	if err := providers.ValidateProviderParams(providerData.Name, providerData.Params); err != nil {
		return fmt.Errorf("invalid provider params: %v", err)
	}

	if providerData.SecretParams != nil {
		if err := providers.ValidateProviderSecretParams(providerData.Name, providerData.SecretParams); err != nil {
			return fmt.Errorf("invalid provider secret params: %v", err)
		}
	}

	// Update client with validated provider params
	r.Client.providerParams = providerData.Params
	r.Client.providerSecretParams = providerData.SecretParams

	// Execute the complete protocol: Connect -> RequestHTTP
	if err := r.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	if err := r.RequestHTTP(); err != nil {
		return fmt.Errorf("failed to request HTTP: %v", err)
	}

	return nil
}

// RequestHTTP initiates an HTTP request through the TEE+MPC protocol
func (r *ReclaimClientImpl) RequestHTTP() error {
	return r.Client.RequestHTTP()
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
