package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"tee/enclave"
)

func main() {
	// Load environment variables first
	enclave.LoadEnvVariables()

	// Initialize NSM for crypto operations
	if err := enclave.InitializeNSM(); err != nil {
		log.Fatalf("Failed to initialize NSM: %v", err)
	}

	// Create server configuration with the business mux
	config := enclave.CreateServerConfig(createBusinessMux())

	// Start the server
	startServer(config)
}

func createBusinessMux() *http.ServeMux {
	mux := http.NewServeMux()

	// Root endpoint - business logic
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received %s request for %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		response := fmt.Sprintf("Hello from TEE_T service! I handle tag computation for Split AEAD. Received %s request for %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave", "Nitro")
		w.Header().Set("X-Service", "tee_t")
		fmt.Fprintln(w, response)
	})

	// Attestation endpoint - business logic
	mux.HandleFunc("/attest", createAttestHandler())

	// Split AEAD tag computation endpoint
	mux.HandleFunc("/compute-tag", handleComputeTag)

	// Tag verification endpoint
	mux.HandleFunc("/verify-tag", handleVerifyTag)

	// Redaction stream processing endpoint
	mux.HandleFunc("/process-redaction-streams", handleRedactionStreams)

	// TEE-to-TEE WebSocket communication endpoint
	teeCommServer := enclave.NewTEECommServer()
	mux.HandleFunc("/tee-comm", teeCommServer.HandleWebSocket)

	return mux
}

// TagComputeRequest represents a tag computation request from TEE_K
type TagComputeRequest struct {
	Ciphertext          []byte                    `json:"ciphertext"`
	TagSecrets          *enclave.TagSecrets       `json:"tag_secrets"`
	SessionID           string                    `json:"session_id,omitempty"`
	UseRedaction        bool                      `json:"use_redaction,omitempty"`
	RedactedCiphertext  []byte                    `json:"redacted_ciphertext,omitempty"`
	OriginalRequestInfo *enclave.RedactionRequest `json:"original_request_info,omitempty"`
}

// TagComputeResponse represents the response with computed tag
type TagComputeResponse struct {
	Tag    []byte `json:"tag"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// TagVerifyRequest represents a tag verification request
type TagVerifyRequest struct {
	Ciphertext  []byte              `json:"ciphertext"`
	ExpectedTag []byte              `json:"expected_tag"`
	TagSecrets  *enclave.TagSecrets `json:"tag_secrets"`
}

// TagVerifyResponse represents the tag verification response
type TagVerifyResponse struct {
	Verified bool   `json:"verified"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

// RedactionStreamRequest represents a request from a user to process redaction streams
type RedactionStreamRequest struct {
	SessionID           string                        `json:"session_id"`
	RedactionStreams    *enclave.RedactionStreams     `json:"redaction_streams"`
	RedactionKeys       *enclave.RedactionKeys        `json:"redaction_keys"`
	ExpectedCommitments *enclave.RedactionCommitments `json:"expected_commitments"`
}

// RedactionStreamResponse represents the response to a redaction stream request
type RedactionStreamResponse struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	Ready     bool   `json:"ready"`
}

// RedactionSessionData stores redaction information for a session
type RedactionSessionData struct {
	RedactionStreams    *enclave.RedactionStreams
	RedactionKeys       *enclave.RedactionKeys
	ExpectedCommitments *enclave.RedactionCommitments
	RedactionProcessor  *enclave.RedactionProcessor
	Verified            bool
}

// Global session store for redaction data
var redactionSessions = make(map[string]*RedactionSessionData)
var redactionSessionsMu sync.RWMutex

// handleComputeTag processes tag computation requests from TEE_K
func handleComputeTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("Received tag computation request from %s", r.RemoteAddr)

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse request
	var req TagComputeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("Failed to parse tag compute request: %v", err)
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.TagSecrets == nil {
		log.Printf("Tag secrets missing in request")
		http.Error(w, "Tag secrets required", http.StatusBadRequest)
		return
	}

	// Create tag computer
	tagComputer := enclave.NewSplitAEADTagComputer()

	var tag []byte

	if req.UseRedaction && req.SessionID != "" {
		// Handle redacted request
		tag, err = handleRedactedTagComputation(req)
	} else {
		// Standard tag computation
		tag, err = tagComputer.ComputeTag(req.Ciphertext, req.TagSecrets)
	}

	var response TagComputeResponse
	if err != nil {
		log.Printf("Tag computation failed: %v", err)
		response = TagComputeResponse{
			Status: "error",
			Error:  fmt.Sprintf("Tag computation failed: %v", err),
		}
	} else {
		log.Printf("Tag computation successful (%d bytes)", len(tag))
		response = TagComputeResponse{
			Tag:    tag,
			Status: "success",
		}
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Service", "tee_t")

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Write(responseJSON)
}

// handleVerifyTag processes tag verification requests
func handleVerifyTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("Received tag verification request from %s", r.RemoteAddr)

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse request
	var req TagVerifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("Failed to parse tag verify request: %v", err)
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.TagSecrets == nil {
		log.Printf("Tag secrets missing in request")
		http.Error(w, "Tag secrets required", http.StatusBadRequest)
		return
	}

	if len(req.ExpectedTag) == 0 {
		log.Printf("Expected tag missing in request")
		http.Error(w, "Expected tag required", http.StatusBadRequest)
		return
	}

	// Create tag computer
	tagComputer := enclave.NewSplitAEADTagComputer()

	// Verify tag
	err = tagComputer.VerifyTag(req.Ciphertext, req.ExpectedTag, req.TagSecrets)

	var response TagVerifyResponse
	if err != nil {
		log.Printf("Tag verification failed: %v", err)
		response = TagVerifyResponse{
			Verified: false,
			Status:   "failed",
			Error:    fmt.Sprintf("Tag verification failed: %v", err),
		}
	} else {
		log.Printf("Tag verification successful")
		response = TagVerifyResponse{
			Verified: true,
			Status:   "success",
		}
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Service", "tee_t")

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Write(responseJSON)
}

func createAttestHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received attestation request from %s", r.RemoteAddr)

		// We need to get the server config to access the cache
		// For now, we'll create a temporary cache instance
		// This is a limitation of the current architecture
		cache := enclave.NewMemoryCache()

		fingerprint, err := enclave.GetCertificateFingerprint(r.Context(), cache)
		if err != nil {
			log.Printf("Failed to get certificate fingerprint: %v", err)
			http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
			return
		}

		// Convert fingerprint to hex
		fingerprintHex := hex.EncodeToString(fingerprint)

		handle := enclave.MustGlobalHandle()
		attestationDoc, err := enclave.GenerateAttestation(handle, []byte(fingerprintHex))
		if err != nil {
			log.Printf("Failed to generate attestation: %v", err)
			http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
			return
		}

		encoded := base64.StdEncoding.EncodeToString(attestationDoc)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Service", "tee_t")
		fmt.Fprint(w, encoded)
	}
}

func startServer(serverConfig *enclave.ServerConfig) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpErrChan, httpsErrChan := enclave.StartListeners(ctx, serverConfig.HTTPServer, serverConfig.HTTPSServer)

	log.Printf("Attempting to load or issue certificate for %s", enclave.EnclaveDomain)
	_, err := serverConfig.Manager.GetCertificate(&tls.ClientHelloInfo{ServerName: enclave.EnclaveDomain})
	if err != nil {
		log.Printf("Failed to load or issue certificate on startup: %v", err)
	} else {
		log.Printf("Successfully loaded or issued certificate for %s", enclave.EnclaveDomain)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err = <-httpErrChan:
		if err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	case err = <-httpsErrChan:
		if err != nil {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	case <-sigChan:
		log.Println("Received shutdown signal, stopping TEE_T service...")
		cancel()

		// Gracefully close connection manager
		if manager := enclave.GetConnectionManager(); manager != nil {
			log.Println("Closing connection pool...")
			manager.Close()
		}

		_ = serverConfig.HTTPServer.Close()
		_ = serverConfig.HTTPSServer.Close()
	}
}

// handleRedactedTagComputation processes tag computation for redacted data
func handleRedactedTagComputation(req TagComputeRequest) ([]byte, error) {
	// Retrieve session data to verify it exists and is authenticated
	redactionSessionsMu.RLock()
	sessionData, exists := redactionSessions[req.SessionID]
	redactionSessionsMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no redaction session data found for session %s", req.SessionID)
	}

	if !sessionData.Verified {
		return nil, fmt.Errorf("redaction session %s not verified", req.SessionID)
	}

	// In the redaction protocol:
	// 1. User sends streams to TEE_T (already verified above)
	// 2. TEE_K applies redaction streams and sends recovered original ciphertext to TEE_T
	// 3. TEE_T computes tag on the original ciphertext from TEE_K
	if req.OriginalRequestInfo == nil {
		return nil, fmt.Errorf("original request info required for redaction processing")
	}

	// Compute tag on the original ciphertext provided by TEE_K
	tagComputer := enclave.NewSplitAEADTagComputer()
	tag, err := tagComputer.ComputeTag(req.Ciphertext, req.TagSecrets)
	if err != nil {
		return nil, fmt.Errorf("failed to compute tag on original data: %v", err)
	}

	log.Printf("Successfully computed tag for redacted session %s", req.SessionID)
	return tag, nil
}

// handleRedactionStreams processes redaction stream requests from users
func handleRedactionStreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("Received redaction stream request from %s", r.RemoteAddr)

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse request
	var req RedactionStreamRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("Failed to parse redaction stream request: %v", err)
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.SessionID == "" {
		log.Printf("Session ID missing in request")
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	if req.RedactionStreams == nil {
		log.Printf("Redaction streams missing in request")
		http.Error(w, "Redaction streams required", http.StatusBadRequest)
		return
	}

	if req.RedactionKeys == nil {
		log.Printf("Redaction keys missing in request")
		http.Error(w, "Redaction keys required", http.StatusBadRequest)
		return
	}

	if req.ExpectedCommitments == nil {
		log.Printf("Expected commitments missing in request")
		http.Error(w, "Expected commitments required", http.StatusBadRequest)
		return
	}

	// Create redaction processor
	processor := enclave.NewRedactionProcessor()

	// Verify commitments against streams and keys
	if err := processor.VerifyCommitments(req.RedactionStreams, req.RedactionKeys, req.ExpectedCommitments); err != nil {
		log.Printf("Commitment verification failed for session %s: %v", req.SessionID, err)
		response := RedactionStreamResponse{
			SessionID: req.SessionID,
			Status:    "error",
			Error:     fmt.Sprintf("Commitment verification failed: %v", err),
			Ready:     false,
		}
		sendRedactionStreamResponse(w, response)
		return
	}

	// Store session data for later use during tag computation
	sessionData := &RedactionSessionData{
		RedactionStreams:    req.RedactionStreams,
		RedactionKeys:       req.RedactionKeys,
		ExpectedCommitments: req.ExpectedCommitments,
		RedactionProcessor:  processor,
		Verified:            true,
	}

	redactionSessionsMu.Lock()
	redactionSessions[req.SessionID] = sessionData
	redactionSessionsMu.Unlock()

	// Send success response
	response := RedactionStreamResponse{
		SessionID: req.SessionID,
		Status:    "success",
		Ready:     true,
	}

	log.Printf("Redaction streams processed and verified for session %s", req.SessionID)
	sendRedactionStreamResponse(w, response)
}

// sendRedactionStreamResponse sends a JSON response for redaction stream requests
func sendRedactionStreamResponse(w http.ResponseWriter, response RedactionStreamResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Service", "tee_t")

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal redaction stream response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Write(responseJSON)
}
