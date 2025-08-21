package main

// #cgo CFLAGS: -I.
/*
#include <stddef.h>

// Opaque handle for protocol session
typedef struct reclaim_protocol* reclaim_protocol_t;

// Error codes
typedef enum {
    RECLAIM_SUCCESS = 0,
    RECLAIM_ERROR_INVALID_ARGS = -1,
    RECLAIM_ERROR_CONNECTION_FAILED = -2,
    RECLAIM_ERROR_PROTOCOL_FAILED = -3,
    RECLAIM_ERROR_TIMEOUT = -4,
    RECLAIM_ERROR_MEMORY = -5,
    RECLAIM_ERROR_SESSION_NOT_FOUND = -6,
    RECLAIM_ERROR_ALREADY_COMPLETED = -7
} reclaim_error_t;
*/
import "C"
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	clientlib "tee-mpc/libclient"
	"tee-mpc/providers"

	"github.com/ethereum/go-ethereum/crypto"
)

// Library-wide constants
const ATTESTOR_URL = "ws://localhost:8001/ws"
const ATTESTOR_CONTEXT_PURPOSE = "demo"

// Global session registry with cleanup
var (
	sessions      = make(map[C.reclaim_protocol_t]*ProtocolSession)
	sessionMutex  sync.RWMutex
	nextSessionID = 1
	cleanupTicker *time.Ticker
	cleanupDone   chan bool
)

// ProtocolSession manages a single TEE+MPC protocol session
type ProtocolSession struct {
	ID           string
	Client       clientlib.ReclaimClient
	ResponseData []byte
	Completed    bool
	CleanupTime  time.Time
	Mutex        sync.Mutex
	CleanedUp    bool
	PublicParams *providers.HTTPProviderParams       // For automatic response redactions
	SecretParams *providers.HTTPProviderSecretParams // For automatic response redactions
}

// ProviderRequestData represents the JSON structure for provider-based request data
type ProviderRequestData struct {
	PublicParams *providers.HTTPProviderParams       `json:"public_params"`
	SecretParams *providers.HTTPProviderSecretParams `json:"secret_params"`
}

// ResponseData represents the JSON structure for response data
type ResponseData struct {
	ProtocolID     string `json:"protocol_id"`
	RawResponse    string `json:"raw_response"`
	ResponseLength int    `json:"response_length"`
	Success        bool   `json:"success"`
	Error          string `json:"error,omitempty"`
}

// VerificationBundleData represents the JSON structure for verification bundle data
type VerificationBundleData struct {
	VerificationBundle string `json:"verification_bundle"`
	BundleSize         int    `json:"bundle_size"`
	Success            bool   `json:"success"`
	Error              string `json:"error,omitempty"`
}

// Initialize cleanup goroutine
func init() {
	cleanupTicker = time.NewTicker(5 * time.Minute) // Check every 5 minutes
	cleanupDone = make(chan bool)

	go func() {
		for {
			select {
			case <-cleanupTicker.C:
				cleanupExpiredSessions()
			case <-cleanupDone:
				return
			}
		}
	}()
}

// cleanupExpiredSessions removes sessions that have been idle for too long
func cleanupExpiredSessions() {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	now := time.Now()
	expiredSessions := make([]C.reclaim_protocol_t, 0)

	for handle, session := range sessions {
		if now.Sub(session.CleanupTime) > 30*time.Minute { // 30 minute timeout
			expiredSessions = append(expiredSessions, handle)
		}
	}

	for _, handle := range expiredSessions {
		if session := sessions[handle]; session != nil {
			// Prevent double cleanup
			if !session.CleanedUp && session.Client != nil {
				// Use a goroutine to avoid blocking on WebSocket close
				go func() {
					defer func() {
						if r := recover(); r != nil {
							// Ignore panics from WebSocket close
						}
					}()
					session.Client.Close()
				}()
			}
		}
		delete(sessions, handle)
	}
}

// convertGoError converts Go error to C error code
func convertGoError(err error) C.reclaim_error_t {
	if err == nil {
		return C.RECLAIM_SUCCESS
	}

	errStr := err.Error()
	switch {
	case errStr == "protocol already completed":
		return C.RECLAIM_ERROR_ALREADY_COMPLETED
	case errStr == "protocol not found":
		return C.RECLAIM_ERROR_SESSION_NOT_FOUND
	case errStr == "protocol timeout":
		return C.RECLAIM_ERROR_TIMEOUT
	default:
		return C.RECLAIM_ERROR_PROTOCOL_FAILED
	}
}

//export reclaim_start_protocol
func reclaim_start_protocol(host *C.char, request_json *C.char, protocol_handle *C.reclaim_protocol_t) C.reclaim_error_t {
	if host == nil || request_json == nil || protocol_handle == nil {
		return C.RECLAIM_ERROR_INVALID_ARGS
	}

	goRequestJSON := C.GoString(request_json)

	// Parse provider-based format
	var providerData ProviderRequestData
	if err := json.Unmarshal([]byte(goRequestJSON), &providerData); err != nil || providerData.PublicParams == nil {
		return C.RECLAIM_ERROR_INVALID_ARGS
	}

	fmt.Printf("[Lib] Using provider-based request format\n")

	// Create new session
	sessionMutex.Lock()
	sessionID := fmt.Sprintf("session_%d", nextSessionID)
	nextSessionID++

	session := &ProtocolSession{
		ID:           sessionID,
		CleanupTime:  time.Now(),
		PublicParams: providerData.PublicParams,
		SecretParams: providerData.SecretParams,
	}

	// Create protocol handle (just use the session pointer as handle)
	handle := C.reclaim_protocol_t(unsafe.Pointer(session))
	sessions[handle] = session
	sessionMutex.Unlock()

	// Start the protocol
	session.Mutex.Lock()
	defer session.Mutex.Unlock()

	// Create client configuration with basic settings
	config := &clientlib.ClientConfig{
		TEEKURL: "wss://tee-k.reclaimprotocol.org/ws",
		TEETURL: "wss://tee-t.reclaimprotocol.org/ws",
		Timeout: 30 * time.Second,
		Mode:    clientlib.ModeEnclave,
	}

	// Create client
	session.Client = clientlib.NewReclaimClient(*config)

	// Enable 2-phase mode to allow manual control
	session.Client.EnableTwoPhaseMode()

	fmt.Printf("[Lib] Starting automatic protocol using provider params JSON\n")

	// Execute complete protocol with one call using JSON params!
	if err := session.Client.StartProtocol(goRequestJSON); err != nil {
		sessionMutex.Lock()
		delete(sessions, handle)
		sessionMutex.Unlock()
		return C.RECLAIM_ERROR_PROTOCOL_FAILED
	}

	// Wait for phase 1 completion (response decryption)
	select {
	case <-session.Client.WaitForPhase1Completion():
		// Phase 1 completed, get response data
		responseResults, err := session.Client.GetResponseResults()
		if err != nil {
			sessionMutex.Lock()
			delete(sessions, handle)
			sessionMutex.Unlock()
			return C.RECLAIM_ERROR_PROTOCOL_FAILED
		}

		if responseResults.ResponseReceived && responseResults.DecryptionSuccessful {
			// Get the decrypted data from the HTTP response
			if responseResults.HTTPResponse != nil {
				session.ResponseData = responseResults.HTTPResponse.FullResponse
			}
			session.CleanupTime = time.Now() // Update cleanup time
			*protocol_handle = handle
			return C.RECLAIM_SUCCESS
		} else {
			sessionMutex.Lock()
			delete(sessions, handle)
			sessionMutex.Unlock()
			return C.RECLAIM_ERROR_PROTOCOL_FAILED
		}

	case <-time.After(60 * time.Second):
		sessionMutex.Lock()
		delete(sessions, handle)
		sessionMutex.Unlock()
		return C.RECLAIM_ERROR_TIMEOUT
	}
}

//export reclaim_get_response
func reclaim_get_response(protocol_handle C.reclaim_protocol_t, response_json **C.char, response_length *C.int) C.reclaim_error_t {
	if response_json == nil || response_length == nil {
		return C.RECLAIM_ERROR_INVALID_ARGS
	}

	sessionMutex.RLock()
	session, exists := sessions[protocol_handle]
	sessionMutex.RUnlock()

	if !exists {
		return C.RECLAIM_ERROR_SESSION_NOT_FOUND
	}

	session.Mutex.Lock()
	defer session.Mutex.Unlock()

	if session.Completed {
		return C.RECLAIM_ERROR_ALREADY_COMPLETED
	}

	// Create response data
	responseData := ResponseData{
		ProtocolID:     session.ID,
		RawResponse:    string(session.ResponseData),
		ResponseLength: len(session.ResponseData),
		Success:        true,
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(responseData)
	if err != nil {
		return C.RECLAIM_ERROR_MEMORY
	}

	// Allocate C string
	cString := C.CString(string(jsonData))
	*response_json = cString
	*response_length = C.int(len(jsonData))

	return C.RECLAIM_SUCCESS
}

//export reclaim_finish_protocol
func reclaim_finish_protocol(protocol_handle C.reclaim_protocol_t, response_redaction_json *C.char, verification_bundle_json **C.char, bundle_length *C.int) C.reclaim_error_t {
	if response_redaction_json == nil || verification_bundle_json == nil || bundle_length == nil {
		return C.RECLAIM_ERROR_INVALID_ARGS
	}

	sessionMutex.RLock()
	session, exists := sessions[protocol_handle]
	sessionMutex.RUnlock()

	if !exists {
		return C.RECLAIM_ERROR_SESSION_NOT_FOUND
	}

	session.Mutex.Lock()
	defer session.Mutex.Unlock()

	if session.Completed {
		return C.RECLAIM_ERROR_ALREADY_COMPLETED
	}

	if session.Client == nil {
		return C.RECLAIM_ERROR_PROTOCOL_FAILED
	}

	// Provider params are already set in the client config, no need for callback setup
	fmt.Printf("[Lib] Using automatic provider-based response redactions\n")

	// Continue to phase 2 (this will resume the protocol from PhaseWaitingForRedactionRanges)
	if err := session.Client.ContinueToPhase2(); err != nil {
		return C.RECLAIM_ERROR_PROTOCOL_FAILED
	}

	// Wait for protocol completion before building verification bundle
	select {
	case <-session.Client.WaitForCompletion():
		// Protocol completed, now build verification bundle
	case <-time.After(30 * time.Second):
		return C.RECLAIM_ERROR_TIMEOUT
	}

	// Build verification bundle after protocol completion
	tempPath := fmt.Sprintf("/tmp/verification_bundle_%s.pb", session.ID)
	if err := session.Client.BuildVerificationBundle(tempPath); err != nil {
		return C.RECLAIM_ERROR_PROTOCOL_FAILED
	}

	// Read the bundle file
	bundleData, err := os.ReadFile(tempPath)
	if err != nil {
		os.Remove(tempPath)
		return C.RECLAIM_ERROR_PROTOCOL_FAILED
	}

	// Clean up the temporary file
	os.Remove(tempPath)

	// Create verification bundle data (keep as binary, encode as base64 for safe string transport)
	bundleResponse := VerificationBundleData{
		VerificationBundle: base64.StdEncoding.EncodeToString(bundleData),
		BundleSize:         len(bundleData),
		Success:            true,
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(bundleResponse)
	if err != nil {
		return C.RECLAIM_ERROR_MEMORY
	}

	// Allocate C string
	cString := C.CString(string(jsonData))
	*verification_bundle_json = cString
	*bundle_length = C.int(len(jsonData))

	session.Completed = true
	session.CleanupTime = time.Now()

	// Generate private key for attestor submission
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return C.RECLAIM_ERROR_PROTOCOL_FAILED
	}

	// Create proper claim params using stored provider data
	claimParams := clientlib.ClaimTeeBundleParams{
		Provider:   "http",               // Required for attestor compatibility
		Parameters: session.PublicParams, // Use stored provider params
		Context: map[string]interface{}{
			"purpose": ATTESTOR_CONTEXT_PURPOSE,
		},
	}

	// Submit to attestor with proper parameters
	claim, err := session.Client.SubmitToAttestorCore(ATTESTOR_URL, privateKey, claimParams)
	if err != nil {
		// Don't panic - return error code instead
		return C.RECLAIM_ERROR_PROTOCOL_FAILED
	}

	// Log successful attestor submission
	fmt.Printf("[Lib] Attestor submission successful: %s\n", claim.Identifier)

	return C.RECLAIM_SUCCESS
}

//export reclaim_cleanup
func reclaim_cleanup(protocol_handle C.reclaim_protocol_t) C.reclaim_error_t {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	session, exists := sessions[protocol_handle]
	if !exists {
		return C.RECLAIM_ERROR_SESSION_NOT_FOUND
	}

	// Prevent double cleanup
	if session.CleanedUp {
		delete(sessions, protocol_handle)
		return C.RECLAIM_SUCCESS
	}

	// Cleanup the session
	if session.Client != nil {
		// Use a goroutine to avoid blocking on WebSocket close
		go func() {
			defer func() {
				if r := recover(); r != nil {
					// Ignore panics from WebSocket close
				}
			}()
			session.Client.Close()
		}()
	}

	session.CleanedUp = true
	delete(sessions, protocol_handle)
	return C.RECLAIM_SUCCESS
}

//export reclaim_free_string
func reclaim_free_string(str *C.char) {
	if str != nil {
		// Use Go's memory management instead of C.free
		// The string will be garbage collected
	}
}

//export reclaim_get_error_message
func reclaim_get_error_message(error C.reclaim_error_t) *C.char {
	var message string
	switch error {
	case C.RECLAIM_SUCCESS:
		message = "Success"
	case C.RECLAIM_ERROR_INVALID_ARGS:
		message = "Invalid arguments"
	case C.RECLAIM_ERROR_CONNECTION_FAILED:
		message = "Connection failed"
	case C.RECLAIM_ERROR_PROTOCOL_FAILED:
		message = "Protocol failed"
	case C.RECLAIM_ERROR_TIMEOUT:
		message = "Operation timed out"
	case C.RECLAIM_ERROR_MEMORY:
		message = "Memory allocation failed"
	case C.RECLAIM_ERROR_SESSION_NOT_FOUND:
		message = "Session not found"
	case C.RECLAIM_ERROR_ALREADY_COMPLETED:
		message = "Protocol already completed"
	default:
		message = "Unknown error"
	}

	return C.CString(message)
}

//export reclaim_get_version
func reclaim_get_version() *C.char {
	return C.CString("1.0.0")
}

// Helper functions

func main() {
	// Required for CGO shared library
}
