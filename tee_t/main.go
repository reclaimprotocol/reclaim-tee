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

	// TEE-to-TEE WebSocket communication endpoint (ALL TEE communication uses this)
	teeCommServer := enclave.NewTEECommServer()

	// Set up callbacks for WebSocket session management
	enclave.GetResponseTranscriptForSession = GetSignedResponseTranscriptForSession
	enclave.CreateSessionDataForWebSocket = CreateSessionDataForWebSocket
	enclave.CaptureEncryptedResponseForSession = CaptureEncryptedResponseForSession

	mux.HandleFunc("/tee-comm", teeCommServer.HandleWebSocket)

	// Redaction stream processing endpoint (for users, not TEEs)
	mux.HandleFunc("/process-redaction-streams", handleRedactionStreams)

	return mux
}

// TEE-to-TEE communication types are now handled by WebSocket protocol in enclave/tee_communication.go

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

// HTTP handlers for tag computation are replaced by WebSocket handlers in enclave/tee_communication.go

// HTTP handlers for tag verification are replaced by WebSocket handlers in enclave/tee_communication.go

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

// Redacted tag computation is now handled by WebSocket handlers in enclave/tee_communication.go

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

// Transcript finalization types are now handled by WebSocket protocol in enclave/tee_communication.go

// HTTP handlers for transcript finalization are replaced by WebSocket handlers in enclave/tee_communication.go

// startDemoServer starts a simple HTTP server for demo purposes
// CreateSessionDataForWebSocket creates session data for WebSocket sessions
func CreateSessionDataForWebSocket(sessionID string) error {
	// Create transcript signer for demo (generates random key)
	transcriptSigner, err := enclave.GenerateDemoKey()
	if err != nil {
		return fmt.Errorf("failed to create transcript signer: %v", err)
	}

	// Create session data for WebSocket sessions (without redaction)
	sessionData := &RedactionSessionData{
		RedactionStreams:          nil, // No redaction for WebSocket sessions
		RedactionKeys:             nil,
		ExpectedCommitments:       nil,
		RedactionProcessor:        nil,
		Verified:                  true, // WebSocket sessions are pre-verified
		TranscriptSigner:          transcriptSigner,
		ResponseTranscriptBuilder: enclave.NewResponseTranscriptBuilder(sessionID),
	}

	redactionSessionsMu.Lock()
	redactionSessions[sessionID] = sessionData
	redactionSessionsMu.Unlock()

	log.Printf("TEE_T: Created session data for WebSocket session %s", sessionID)
	return nil
}

// CaptureEncryptedResponseForSession captures encrypted responses for transcript building
func CaptureEncryptedResponseForSession(sessionID string, ciphertext []byte) error {
	redactionSessionsMu.RLock()
	sessionData, exists := redactionSessions[sessionID]
	redactionSessionsMu.RUnlock()

	if !exists {
		return fmt.Errorf("no session data found for session %s", sessionID)
	}

	if sessionData.ResponseTranscriptBuilder != nil {
		sessionData.ResponseTranscriptBuilder.AddEncryptedResponse(ciphertext)
		log.Printf("TEE_T: Added encrypted response to transcript for session %s (%d bytes)", sessionID, len(ciphertext))
	}

	return nil
}

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
	// Use the same business mux as production to ensure callbacks are set
	mux := createBusinessMux()

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("TEE_T demo server starting on port %s", port)
	log.Printf("Available endpoints:")
	log.Printf("  POST /process-redaction-streams - Process redaction streams from users")
	log.Printf("  WS /tee-comm - WebSocket endpoint for TEE-to-TEE communication")
	log.Printf("  GET /attest - Get attestation document")

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Demo server failed: %v", err)
	}
}
