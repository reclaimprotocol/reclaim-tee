package client

import (
	"context"
	"net"

	"github.com/gorilla/websocket"
)

// createEnclaveWebSocketDialer creates a custom WebSocket dialer for enclave mode
func createEnclaveWebSocketDialer() *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: DefaultWSHandshakeTimeout,
	}
}

// createNativeNetworkDialer creates a WebSocket dialer that uses native networking
// for iOS VPN compatibility. The dialer uses a custom NetDialTLSContext that
// delegates connection establishment to the native iOS/Flutter layer.
func createNativeNetworkDialer(targetURL string, timeoutMs int) *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: DefaultWSHandshakeTimeout,
		// NetDialTLSContext is used for wss:// connections
		// When set, the Dialer assumes TLS handshake is done by this function
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return NativeDialWebSocket(targetURL, timeoutMs)
		},
		// NetDialContext is used for ws:// connections
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return NativeDialWebSocket(targetURL, timeoutMs)
		},
	}
}
