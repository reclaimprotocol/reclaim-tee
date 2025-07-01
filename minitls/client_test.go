package minitls

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// TestFullHandshakeAndHTTP runs a full handshake and a simple HTTP request
// against a real server for a variety of cipher suites.
func TestFullHandshakeAndHTTP(t *testing.T) {
	// Note: You must have an internet connection for these tests to run.
	testCases := []struct {
		name        string
		serverName  string
		cipherSuite uint16
	}{
		// Cloudflare is a good general-purpose server that supports all modern ciphers.
		{"AES256_GCM_SHA384_vs_Cloudflare", "cloudflare.com", TLS_AES_256_GCM_SHA384},
		{"AES128_GCM_SHA256_vs_Cloudflare", "cloudflare.com", TLS_AES_128_GCM_SHA256},
		{"CHACHA20_POLY1305_vs_Cloudflare", "cloudflare.com", TLS_CHACHA20_POLY1305_SHA256},
		// Google is another good test case.
		{"AES256_GCM_SHA384_vs_Google", "google.com", TLS_AES_256_GCM_SHA384},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr := tc.serverName + ":443"

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("Failed to connect to server %s: %v", addr, err)
			}
			defer conn.Close()

			// Create a client and override the supported cipher suites
			// to isolate the one we are testing.
			client := NewClient(conn)
			client.SupportedCipherSuites = []uint16{tc.cipherSuite}

			// Perform the handshake
			if err := client.Handshake(tc.serverName); err != nil {
				t.Fatalf("Handshake failed: %v", err)
			}
			fmt.Println(" Handshake completed successfully!")

			// Send an HTTP request
			if err := client.SendHTTPRequest("GET", "/", tc.serverName); err != nil {
				t.Fatalf("Failed to send HTTP request: %v", err)
			}

			// Read the response
			response, err := client.ReadHTTPResponse()
			if err != nil {
				t.Fatalf("Failed to read HTTP response: %v", err)
			}

			if len(response) == 0 {
				t.Error("Received an empty HTTP response.")
			}

			// A simple check to see if we got a valid HTTP response
			if !strings.HasPrefix(string(response), "HTTP/1.1") && !strings.HasPrefix(string(response), "HTTP/2") {
				t.Errorf("Response does not look like HTTP. Got: %s", string(response[:min_test(30, len(response))]))
			}

			fmt.Printf(" Successfully received HTTP response (%d bytes):\n", len(response))
			fmt.Printf("Response preview:\n%s\n", string(response[:min_test(200, len(response))]))
		})
	}
}

func min_test(a, b int) int {
	if a < b {
		return a
	}
	return b
}
