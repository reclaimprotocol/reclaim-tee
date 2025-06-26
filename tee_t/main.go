package main

import (
	"context"
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
	log.Printf("Starting TEE_T service...")

	// Check for demo mode (PORT environment variable)
	if port := os.Getenv("PORT"); port != "" {
		log.Printf("Demo mode: Starting TEE_T on HTTP port %s", port)
		startDemoServer(port)
		return
	}

	// Load TEE_T specific configuration
	config, err := enclave.LoadTEETConfig()
	if err != nil {
		log.Fatalf("Failed to load TEE_T configuration: %v", err)
	}

	// Initialize NSM for crypto operations
	if err := enclave.InitializeNSM(); err != nil {
		log.Fatalf("Failed to initialize NSM: %v", err)
	}

	// Set up transcript integration
	enclave.GetResponseTranscriptForSession = GetSignedResponseTranscriptForSession

	// Create TEE server
	server, err := enclave.NewTEEServer(config)
	if err != nil {
		log.Fatalf("Failed to create TEE server: %v", err)
	}

	// Create the business logic mux
	businessMux := createBusinessMux()

	// Setup servers with business logic
	if err := server.SetupServers(businessMux); err != nil {
		log.Fatalf("Failed to setup servers: %v", err)
	}

	// Start the server
	startServer(server)
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

	// Attestation endpoint is now handled by common TEEServer infrastructure

	// Split AEAD tag computation endpoint
	mux.HandleFunc("/compute-tag", handleComputeTag)

	// Tag verification endpoint
	mux.HandleFunc("/verify-tag", handleVerifyTag)

	// Redaction stream processing endpoint
	mux.HandleFunc("/process-redaction-streams", handleRedactionStreams)

	// Response transcript finalization endpoint
	mux.HandleFunc("/finalize-response-transcript", handleFinalizeResponseTranscript)

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
	SessionID   string              `json:"session_id,omitempty"` // For transcript building
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
	RedactionStreams          *enclave.RedactionStreams
	RedactionKeys             *enclave.RedactionKeys
	ExpectedCommitments       *enclave.RedactionCommitments
	RedactionProcessor        *enclave.RedactionProcessor
	Verified                  bool
	TranscriptSigner          *enclave.TranscriptSigner          // Signer for response transcript
	ResponseTranscriptBuilder *enclave.ResponseTranscriptBuilder // Builder for response transcript
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

		// Capture encrypted response in transcript if session exists
		if req.SessionID != "" {
			redactionSessionsMu.RLock()
			sessionData, exists := redactionSessions[req.SessionID]
			redactionSessionsMu.RUnlock()

			if exists && sessionData.ResponseTranscriptBuilder != nil {
				sessionData.ResponseTranscriptBuilder.AddEncryptedResponse(req.Ciphertext)
				log.Printf("Added encrypted response to transcript for session %s (%d bytes)", req.SessionID, len(req.Ciphertext))
			}
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

func startServer(server *enclave.TEEServer) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start listeners
	httpErrChan, httpsErrChan := server.StartListeners(ctx)

	// Load or issue certificate
	if err := server.LoadOrIssueCertificate(); err != nil {
		log.Printf("Failed to load or issue certificate on startup: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-httpErrChan:
		if err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	case err := <-httpsErrChan:
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

		// Close server
		server.Close()
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

	// Create transcript signer for demo (generates random key)
	transcriptSigner, err := enclave.GenerateDemoKey()
	if err != nil {
		log.Printf("Failed to create transcript signer for session %s: %v", req.SessionID, err)
		response := RedactionStreamResponse{
			SessionID: req.SessionID,
			Status:    "error",
			Error:     fmt.Sprintf("Failed to create transcript signer: %v", err),
			Ready:     false,
		}
		sendRedactionStreamResponse(w, response)
		return
	}

	// Store session data for later use during tag computation
	sessionData := &RedactionSessionData{
		RedactionStreams:          req.RedactionStreams,
		RedactionKeys:             req.RedactionKeys,
		ExpectedCommitments:       req.ExpectedCommitments,
		RedactionProcessor:        processor,
		Verified:                  true,
		TranscriptSigner:          transcriptSigner,
		ResponseTranscriptBuilder: enclave.NewResponseTranscriptBuilder(req.SessionID),
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

// FinalizeTranscriptRequest represents a request to finalize and sign response transcript
type FinalizeTranscriptRequest struct {
	SessionID          string   `json:"session_id"`
	EncryptedResponses [][]byte `json:"encrypted_responses"`
}

// FinalizeTranscriptResponse represents the response with signed transcript
type FinalizeTranscriptResponse struct {
	SessionID        string `json:"session_id"`
	SignedTranscript []byte `json:"signed_transcript"`
	Status           string `json:"status"`
	Error            string `json:"error,omitempty"`
}

// handleFinalizeResponseTranscript finalizes and signs the response transcript
func handleFinalizeResponseTranscript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("Received response transcript finalization request from %s", r.RemoteAddr)

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse request
	var req FinalizeTranscriptRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("Failed to parse finalize transcript request: %v", err)
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.SessionID == "" {
		log.Printf("Session ID missing in request")
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	// Retrieve session data
	redactionSessionsMu.RLock()
	sessionData, exists := redactionSessions[req.SessionID]
	redactionSessionsMu.RUnlock()

	var response FinalizeTranscriptResponse
	response.SessionID = req.SessionID

	if !exists {
		log.Printf("No session data found for session %s", req.SessionID)
		response.Status = "error"
		response.Error = "Session not found"
	} else if sessionData.TranscriptSigner == nil || sessionData.ResponseTranscriptBuilder == nil {
		log.Printf("No transcript signer or builder available for session %s", req.SessionID)
		response.Status = "error"
		response.Error = "Transcript components not available"
	} else {
		// Add encrypted responses to transcript builder
		for _, encryptedResponse := range req.EncryptedResponses {
			sessionData.ResponseTranscriptBuilder.AddEncryptedResponse(encryptedResponse)
		}

		// Sign the response transcript
		signedTranscript, err := sessionData.ResponseTranscriptBuilder.Sign(sessionData.TranscriptSigner)
		if err != nil {
			log.Printf("Failed to sign response transcript for session %s: %v", req.SessionID, err)
			response.Status = "error"
			response.Error = fmt.Sprintf("Failed to sign transcript: %v", err)
		} else {
			// Serialize the signed transcript
			signedTranscriptBytes, err := json.Marshal(signedTranscript)
			if err != nil {
				log.Printf("Failed to serialize signed transcript for session %s: %v", req.SessionID, err)
				response.Status = "error"
				response.Error = fmt.Sprintf("Failed to serialize transcript: %v", err)
			} else {
				log.Printf("Response transcript signed for session %s (%d bytes, %s algorithm)",
					req.SessionID, len(signedTranscriptBytes), signedTranscript.Algorithm)
				response.SignedTranscript = signedTranscriptBytes
				response.Status = "success"
			}
		}
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Service", "tee_t")

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal finalize transcript response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Write(responseJSON)
}

// startDemoServer starts a simple HTTP server for demo purposes
// GetSignedResponseTranscriptForSession retrieves and signs the response transcript for a session
func GetSignedResponseTranscriptForSession(sessionID string) (*enclave.SignedTranscript, error) {
	redactionSessionsMu.RLock()
	sessionData, exists := redactionSessions[sessionID]
	redactionSessionsMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no session data found for session %s", sessionID)
	}

	if sessionData.ResponseTranscriptBuilder == nil {
		return nil, fmt.Errorf("no response transcript builder for session %s", sessionID)
	}

	if sessionData.TranscriptSigner == nil {
		return nil, fmt.Errorf("no transcript signer for session %s", sessionID)
	}

	// Sign the response transcript using the builder
	signedTranscript, err := sessionData.ResponseTranscriptBuilder.Sign(sessionData.TranscriptSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response transcript: %v", err)
	}

	log.Printf("Generated signed response transcript for session %s", sessionID)
	return signedTranscript, nil
}

func startDemoServer(port string) {
	mux := createBusinessMux()

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("TEE_T demo server starting on port %s", port)
	log.Printf("Available endpoints:")
	log.Printf("  POST /process-redaction-streams - Process redaction streams from users")
	log.Printf("  POST /compute-tag - Compute authentication tags")
	log.Printf("  POST /verify-tag - Verify authentication tags")
	log.Printf("  GET /attest - Get attestation document")

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Demo server failed: %v", err)
	}
}
