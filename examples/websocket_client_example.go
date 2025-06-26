package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket message types (matching TEE_K service)
type MessageType string

const (
	MsgSessionInit       MessageType = "session_init"
	MsgSessionInitResp   MessageType = "session_init_response"
	MsgServerHello       MessageType = "server_hello"
	MsgHandshakeComplete MessageType = "handshake_complete"
	MsgEncryptRequest    MessageType = "encrypt_request"
	MsgEncryptResponse   MessageType = "encrypt_response"
	MsgDecryptRequest    MessageType = "decrypt_request"
	MsgDecryptResponse   MessageType = "decrypt_response"
	MsgFinalize          MessageType = "finalize"
	MsgFinalizeResp      MessageType = "finalize_response"
	MsgError             MessageType = "error"
	MsgStatus            MessageType = "status"
)

// WebSocket message structure (matching TEE_K service)
type WSMessage struct {
	Type      MessageType     `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// Session initialization request
type SessionInitRequest struct {
	Hostname      string   `json:"hostname"`
	Port          int      `json:"port"`
	SNI           string   `json:"sni"`
	ALPNProtocols []string `json:"alpn_protocols"`
}

// Session initialization response
type SessionInitResponse struct {
	SessionID   string `json:"session_id"`
	ClientHello []byte `json:"client_hello"`
	Status      string `json:"status"`
}

func main() {
	// TEE_K service WebSocket endpoint
	// In production, this would be the actual TEE_K enclave endpoint
	teeKURL := "ws://localhost:8080/ws?client_type=user"

	fmt.Printf("WebSocket TEE_K Client Example\n")
	fmt.Printf("Connecting to: %s\n\n", teeKURL)

	// Parse URL
	u, err := url.Parse(teeKURL)
	if err != nil {
		log.Fatal("Invalid URL:", err)
	}

	// Connect to WebSocket
	fmt.Println("Connecting to TEE_K WebSocket...")
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("WebSocket connection failed:", err)
	}
	defer conn.Close()
	fmt.Println("Connected to TEE_K!")

	// Set up interrupt handler
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	// Channel for receiving messages
	done := make(chan struct{})

	// Start message reader goroutine
	go func() {
		defer close(done)
		for {
			var msg WSMessage
			err := conn.ReadJSON(&msg)
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket error: %v", err)
				}
				return
			}
			handleMessage(msg)
		}
	}()

	// Demo: Initialize a TLS session
	fmt.Println("\nStep 1: Initializing TLS session...")
	sessionInitReq := SessionInitRequest{
		Hostname:      "httpbin.org",
		Port:          443,
		SNI:           "httpbin.org",
		ALPNProtocols: []string{"h2", "http/1.1"},
	}

	sessionInitData, _ := json.Marshal(sessionInitReq)
	sessionInitMsg := WSMessage{
		Type:      MsgSessionInit,
		Data:      sessionInitData,
		Timestamp: time.Now(),
	}

	if err := conn.WriteJSON(sessionInitMsg); err != nil {
		log.Fatal("Failed to send session init:", err)
	}

	// Wait for a bit to see responses
	fmt.Println("Waiting for responses...")

	// Demo timer
	timer := time.NewTimer(10 * time.Second)

	select {
	case <-done:
		fmt.Println("Connection closed")
	case <-timer.C:
		fmt.Println("Demo timeout - closing connection")
	case <-interrupt:
		fmt.Println("Interrupt received - closing connection")

		// Send close message
		err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		if err != nil {
			log.Println("Write close:", err)
			return
		}

		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}

	fmt.Println("\nWebSocket client demo completed!")
}

// handleMessage processes incoming messages from TEE_K
func handleMessage(msg WSMessage) {
	fmt.Printf("Received message: %s", msg.Type)
	if msg.SessionID != "" {
		fmt.Printf(" (Session: %s)", msg.SessionID)
	}
	fmt.Println()

	switch msg.Type {
	case MsgSessionInitResp:
		var resp SessionInitResponse
		if err := json.Unmarshal(msg.Data, &resp); err != nil {
			fmt.Printf("Failed to parse session init response: %v\n", err)
			return
		}

		fmt.Printf("Session initialized!\n")
		fmt.Printf("   Session ID: %s\n", resp.SessionID)
		fmt.Printf("   Status: %s\n", resp.Status)
		fmt.Printf("   Client Hello: %d bytes\n", len(resp.ClientHello))
		fmt.Printf("   Client Hello (hex): %x...\n", resp.ClientHello[:min(32, len(resp.ClientHello))])

		// In a real implementation, you would now:
		// 1. Send the Client Hello to the target website
		// 2. Receive the Server Hello
		// 3. Send the Server Hello back to TEE_K via WebSocket
		fmt.Println("Next: Send Client Hello to website, then return Server Hello to TEE_K")

	case MsgHandshakeComplete:
		fmt.Printf("TLS handshake completed!\n")

		// In a real implementation, you would now be ready for split AEAD operations
		fmt.Println("Next: Ready for split AEAD encrypt/decrypt operations")

	case MsgEncryptResponse:
		fmt.Printf("Request encryption completed\n")

	case MsgDecryptResponse:
		fmt.Printf("Response decryption stream ready\n")

	case MsgFinalizeResp:
		fmt.Printf("📜 Transcript finalized and signed\n")

	case MsgError:
		fmt.Printf("Error: %s\n", msg.Error)

	case MsgStatus:
		fmt.Printf("Status update received\n")

	default:
		fmt.Printf("❓ Unknown message type: %s\n", msg.Type)
	}

	// Print raw data if present (truncated)
	if len(msg.Data) > 0 {
		fmt.Printf("   Data: %d bytes\n", len(msg.Data))
	}

	fmt.Println()
}

// Helper function for min (Go 1.21+)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
