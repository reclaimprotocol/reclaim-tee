package main

import (
	"github.com/gorilla/websocket"
)

// createEnclaveWebSocketDialer creates a custom WebSocket dialer for enclave mode
func createEnclaveWebSocketDialer() *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: DefaultWSHandshakeTimeout,
	}
}
