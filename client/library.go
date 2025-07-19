package main

import (
	"time"
)

// ReclaimClient is the public interface for the Reclaim TEE+MPC client library
type ReclaimClient interface {
	Connect() error
	RequestHTTP(hostname string, port int) error
	WaitForCompletion() <-chan struct{}
	Close() error
	SetResponseCallback(callback ResponseCallback)

	// Results access methods
	GetProtocolResult() (*ProtocolResult, error)
	GetTranscripts() (*TranscriptResults, error)
	GetValidationResults() (*ValidationResults, error)
	GetAttestationResults() (*AttestationResults, error)
	GetResponseResults() (*ResponseResults, error)
}

// ClientMode represents the operational mode of the client
type ClientMode int

const (
	ModeAuto ClientMode = iota // Auto-detect based on URLs
	ModeEnclave
	ModeStandalone
)

// reclaimClientImpl is the internal implementation of ReclaimClient
type reclaimClientImpl struct {
	client *Client
	config ClientConfig
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

	return &reclaimClientImpl{
		client: client,
		config: config,
	}
}

// Connect establishes connections to both TEE_K and TEE_T
func (r *reclaimClientImpl) Connect() error {
	// Connect to TEE_K
	if err := r.client.ConnectToTEEK(); err != nil {
		return NewConnectionError("TEE_K", err)
	}

	// Connect to TEE_T
	if err := r.client.ConnectToTEET(); err != nil {
		return NewConnectionError("TEE_T", err)
	}

	// Fetch and verify attestations (only in enclave mode)
	if err := r.client.fetchAndVerifyAttestations(); err != nil {
		return NewAttestationError(err)
	}

	return nil
}

// RequestHTTP initiates an HTTP request through the TEE+MPC protocol
func (r *reclaimClientImpl) RequestHTTP(hostname string, port int) error {
	// Apply request redactions from config to the client
	if len(r.config.RequestRedactions) > 0 {
		r.client.requestRedactions = r.config.RequestRedactions
	}

	// Set response callback if provided
	if r.config.ResponseCallback != nil {
		r.client.responseCallback = r.config.ResponseCallback
	}

	return r.client.RequestHTTP(hostname, port)
}

// WaitForCompletion returns a channel that closes when the protocol is complete
func (r *reclaimClientImpl) WaitForCompletion() <-chan struct{} {
	return r.client.WaitForCompletion()
}

// Close closes the client connections
func (r *reclaimClientImpl) Close() error {
	r.client.Close()
	return nil
}

// SetResponseCallback sets the callback for handling response redactions
func (r *reclaimClientImpl) SetResponseCallback(callback ResponseCallback) {
	r.config.ResponseCallback = callback
	if r.client != nil {
		r.client.responseCallback = callback
	}
}

// GetProtocolResult returns the complete protocol execution results
func (r *reclaimClientImpl) GetProtocolResult() (*ProtocolResult, error) {
	return r.client.buildProtocolResult()
}

// GetTranscripts returns the signed transcripts from both TEE_K and TEE_T
func (r *reclaimClientImpl) GetTranscripts() (*TranscriptResults, error) {
	return r.client.buildTranscriptResults()
}

// GetValidationResults returns the validation results for transcripts and attestations
func (r *reclaimClientImpl) GetValidationResults() (*ValidationResults, error) {
	return r.client.buildValidationResults()
}

// GetAttestationResults returns the attestation verification results
func (r *reclaimClientImpl) GetAttestationResults() (*AttestationResults, error) {
	return r.client.buildAttestationResults()
}

// GetResponseResults returns the HTTP response data and proof claims
func (r *reclaimClientImpl) GetResponseResults() (*ResponseResults, error) {
	return r.client.buildResponseResults()
}

// detectMode automatically detects the client mode based on URLs
func detectMode(teekURL, teetURL string) ClientMode {
	if (teekURL != "" && teekURL[:4] == "wss:") || (teetURL != "" && teetURL[:4] == "wss:") {
		return ModeEnclave
	}
	return ModeStandalone
}
