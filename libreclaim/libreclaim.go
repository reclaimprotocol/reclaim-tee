package libreclaim

import (
	"fmt"
	"os"
	"sync"
	"time"

	"tee-mpc/shared"
)

// StartProtocol initiates the TEE+MPC protocol and returns raw response data
// It accepts host, raw HTTP request and redaction ranges from the calling app
// Returns raw concatenated response data from 0x17 data packets (TLS 1.3 and 1.2)
func StartProtocol(host string, rawRequest []byte, requestRanges []shared.RedactionRange) (*ProtocolResult, error) {
	// Create protocol instance
	protocol := NewProtocol()

	// Start the protocol
	result, err := protocol.Start(host, rawRequest, requestRanges)
	if err != nil {
		return nil, fmt.Errorf("protocol start failed: %v", err)
	}

	return result, nil
}

// FinishProtocol completes the protocol with response redaction ranges
// It waits till response redaction ranges will be provided and returns Verification bundle
func FinishProtocol(protocolID string, responseRanges []shared.RedactionRange) (*FinishResult, error) {
	// Get protocol instance
	protocol := GetProtocol(protocolID)
	if protocol == nil {
		return nil, fmt.Errorf("protocol not found: %s", protocolID)
	}

	// Finish the protocol
	result, err := protocol.Finish(responseRanges)
	if err != nil {
		return nil, fmt.Errorf("protocol finish failed: %v", err)
	}

	return result, nil
}

// ProtocolResult represents the result of StartProtocol
type ProtocolResult struct {
	ProtocolID     string `json:"protocol_id"`
	RawResponse    []byte `json:"raw_response"`
	ResponseLength int    `json:"response_length"`
	Success        bool   `json:"success"`
	Error          string `json:"error,omitempty"`
}

// FinishResult represents the result of FinishProtocol
type FinishResult struct {
	VerificationBundle []byte `json:"verification_bundle"`
	BundleSize         int    `json:"bundle_size"`
	Success            bool   `json:"success"`
	Error              string `json:"error,omitempty"`
}

// Protocol manages a single TEE+MPC protocol session
type Protocol struct {
	ID           string
	client       Client
	responseData []byte
	completed    bool
	mutex        sync.Mutex
}

// Global protocol registry
var (
	protocols     = make(map[string]*Protocol)
	protocolMutex sync.RWMutex
	nextID        = 1
)

// NewProtocol creates a new protocol instance
func NewProtocol() *Protocol {
	protocolMutex.Lock()
	defer protocolMutex.Unlock()

	id := fmt.Sprintf("protocol_%d", nextID)
	nextID++

	protocol := &Protocol{
		ID: id,
	}

	protocols[id] = protocol
	return protocol
}

// GetProtocol retrieves a protocol instance by ID
func GetProtocol(id string) *Protocol {
	protocolMutex.RLock()
	defer protocolMutex.RUnlock()
	return protocols[id]
}

// Start initiates the TEE+MPC protocol
func (p *Protocol) Start(host string, rawRequest []byte, requestRanges []shared.RedactionRange) (*ProtocolResult, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.completed {
		return nil, fmt.Errorf("protocol already completed")
	}

	// Create client configuration
	config := &ClientConfig{
		TEEKURL:           "wss://tee-k.reclaimprotocol.org/ws", // Use remote TEEs like original client
		TEETURL:           "wss://tee-t.reclaimprotocol.org/ws",
		Timeout:           30 * time.Second,
		Mode:              ModeEnclave, // Use enclave mode for remote TEEs
		RequestRedactions: convertRangesToSpecs(requestRanges),
	}

	// Create client
	p.client = NewReclaimClient(config)

	// Connect to TEEs
	if err := p.client.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}

	// Set request data
	if err := p.client.SetRequestData(rawRequest); err != nil {
		return nil, fmt.Errorf("failed to set request data: %v", err)
	}

	// Extract hostname and port from host string
	hostname, port := parseHost(host)

	// Send HTTP request
	if err := p.client.RequestHTTP(hostname, port); err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %v", err)
	}

	// Wait for phase 1 completion (response decryption)
	select {
	case <-p.client.WaitForPhase1Completion():
		// Phase 1 completed, get response data
		responseResults, err := p.client.GetResponseResults()
		if err != nil {
			return nil, fmt.Errorf("failed to get response results: %v", err)
		}

		if responseResults.ResponseReceived && responseResults.DecryptionSuccessful {
			p.responseData = responseResults.DecryptedData
			return &ProtocolResult{
				ProtocolID:     p.ID,
				RawResponse:    p.responseData,
				ResponseLength: len(p.responseData),
				Success:        true,
			}, nil
		} else {
			return nil, fmt.Errorf("response processing failed")
		}

	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("protocol timeout")
	}
}

// Finish completes the protocol with response redaction ranges
func (p *Protocol) Finish(responseRanges []shared.RedactionRange) (*FinishResult, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.completed {
		return nil, fmt.Errorf("protocol already completed")
	}

	if p.client == nil {
		return nil, fmt.Errorf("protocol not started")
	}

	// Set response callback with the provided ranges
	callback := &ResponseCallbackImpl{
		Ranges: responseRanges,
	}
	p.client.SetResponseCallback(callback)

	// Continue to phase 2 (this will resume the protocol from PhaseWaitingForRedactionRanges)
	if err := p.client.ContinueToPhase2(); err != nil {
		return nil, fmt.Errorf("failed to continue to phase 2: %v", err)
	}

	// Wait for final completion
	select {
	case <-p.client.WaitForCompletion():
		// Build verification bundle
		tempPath := fmt.Sprintf("/tmp/verification_bundle_%s.json", p.ID)
		if err := p.client.BuildVerificationBundle(tempPath); err != nil {
			return nil, fmt.Errorf("failed to build verification bundle: %v", err)
		}

		// Read the bundle file
		bundleData, err := os.ReadFile(tempPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read verification bundle: %v", err)
		}

		// Clean up the temporary file
		os.Remove(tempPath)

		p.completed = true

		return &FinishResult{
			VerificationBundle: bundleData,
			BundleSize:         len(bundleData),
			Success:            true,
		}, nil

	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("finish timeout")
	}
}
