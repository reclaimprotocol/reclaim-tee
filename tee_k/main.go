package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"tee/enclave"
	"time"
)

// SessionState will hold the state for a single user session.
type SessionState struct {
	ID           string
	TLSClient    *enclave.TLSClientState // TLS client state for handshake
	TLSKeys      *enclave.TLSSessionKeys // Extracted TLS session keys
	WebsiteURL   string                  // Target website
	Completed    bool
	RequestCount int // Number of requests processed
}

// Global session store (in-memory, not for production)
var (
	sessionStore = make(map[string]*SessionState)
	storeMutex   = &sync.RWMutex{}
)

func main() {
	// Load environment variables first
	enclave.LoadEnvVariables()

	// Initialize NSM for crypto operations
	if err := enclave.InitializeNSM(); err != nil {
		log.Fatalf("Failed to initialize NSM: %v", err)
	}

	// Create server configuration with the TEE_K business mux
	config := enclave.CreateServerConfig(createBusinessMux())

	// Start the server
	startServer(config)
}

func createBusinessMux() *http.ServeMux {
	mux := http.NewServeMux()

	// Root endpoint - basic status check
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received %s request for %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		response := fmt.Sprintf("Hello from TEE_K service! I am alive. Received %s request for %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave", "Nitro")
		w.Header().Set("X-Service", "tee_k")
		fmt.Fprintln(w, response)
	})

	// WebSocket endpoint for real-time MPC protocol
	mux.HandleFunc("/ws", handleWebSocket)

	// Protocol endpoints for TEE_K (HTTP fallback)
	mux.HandleFunc("/session/init", handleSessionInit)
	mux.HandleFunc("/encrypt", handleEncrypt)
	mux.HandleFunc("/decrypt-stream", handleDecryptStream)
	mux.HandleFunc("/finalize", handleFinalize)

	return mux
}

// SessionInitRequest holds the data needed to initialize a TLS session
type SessionInitRequest struct {
	Hostname      string   `json:"hostname"`
	Port          int      `json:"port"`
	SNI           string   `json:"sni"`
	ALPNProtocols []string `json:"alpn_protocols"`
}

// SessionInitResponse contains the Client Hello and session info
type SessionInitResponse struct {
	SessionID   string `json:"session_id"`
	ClientHello []byte `json:"client_hello"`
	Status      string `json:"status"`
}

// handleSessionInit initializes a new TLS session and generates Client Hello
func handleSessionInit(w http.ResponseWriter, r *http.Request) {
	var req SessionInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Hostname == "" {
		http.Error(w, "Hostname is required", http.StatusBadRequest)
		return
	}
	if req.Port == 0 {
		req.Port = 443 // Default HTTPS port
	}
	if req.SNI == "" {
		req.SNI = req.Hostname // Default SNI to hostname
	}

	// Create TLS client configuration
	tlsConfig := &enclave.TLSClientConfig{
		ServerName:    req.SNI,
		ALPNProtocols: req.ALPNProtocols,
		MaxVersion:    enclave.VersionTLS13,
	}

	// Initialize TLS client state
	tlsClient, err := enclave.NewTLSClientState(tlsConfig)
	if err != nil {
		log.Printf("Failed to create TLS client state: %v", err)
		http.Error(w, "Failed to initialize TLS client", http.StatusInternalServerError)
		return
	}

	// Generate Client Hello
	clientHello, err := tlsClient.GenerateClientHello()
	if err != nil {
		log.Printf("Failed to generate Client Hello: %v", err)
		http.Error(w, "Failed to generate Client Hello", http.StatusInternalServerError)
		return
	}

	// Create session
	sessionID := fmt.Sprintf("session-%d-%d", len(sessionStore)+1, time.Now().Unix())
	newState := &SessionState{
		ID:         sessionID,
		TLSClient:  tlsClient,
		WebsiteURL: fmt.Sprintf("%s:%d", req.Hostname, req.Port),
		Completed:  false,
	}

	storeMutex.Lock()
	sessionStore[sessionID] = newState
	storeMutex.Unlock()

	log.Printf("Initialized new TLS session: %s for %s", sessionID, req.Hostname)

	// Return Client Hello to user
	response := SessionInitResponse{
		SessionID:   sessionID,
		ClientHello: clientHello,
		Status:      "client_hello_ready",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleEncrypt is a placeholder for the request encryption logic.
func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement the split AEAD encryption.
	// 1. Receive R_red, comm_s, comm_sp from the User.
	// 2. Perform request verifications.
	// 3. Encrypt R_red using the derived TLS key to get R_red_Enc.
	// 4. Compute Tag Secrets for TEE_T.
	// 5. Send R_red_Enc to User and TEE_T.
	// 6. Send Tag Secrets and commitments to TEE_T.
	log.Println("Placeholder: /encrypt endpoint called")
	http.Error(w, "Not Implemented: Request encryption", http.StatusNotImplemented)
}

// handleDecryptStream is a placeholder for generating the decryption stream for the response.
func handleDecryptStream(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement response decryption stream generation.
	// 1. Receive the length of the response from the User.
	// 2. Wait for a "success" message from TEE_T (indicating tag verification passed).
	// 3. Compute the decryption keystream (Str_Dec).
	// 4. Send Str_Dec to the User.
	log.Println("Placeholder: /decrypt-stream endpoint called")
	http.Error(w, "Not Implemented: Decryption stream generation", http.StatusNotImplemented)
}

// handleFinalize is a placeholder for signing the transcript.
func handleFinalize(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement transcript finalization.
	// 1. Receive "final" message from the User.
	// 2. Concatenate redacted requests and commitments.
	// 3. Sign the concatenated transcript.
	// 4. Send the signed transcript and the *real* TLS keys to the User.
	log.Println("Placeholder: /finalize endpoint called")
	http.Error(w, "Not Implemented: Transcript finalization", http.StatusNotImplemented)
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
		log.Println("Received shutdown signal, stopping TEE_K service...")
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
