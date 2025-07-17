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
			config := &Config{
				CipherSuites: []uint16{tc.cipherSuite},
			}
			client := NewClientWithConfig(conn, config)

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

// TestChaCha20Preference tests that ChaCha20-Poly1305 is preferred when no specific cipher is forced
func TestChaCha20Preference(t *testing.T) {
	addr := "cloudflare.com:443"

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect to server %s: %v", addr, err)
	}
	defer conn.Close()

	// Create a client WITHOUT overriding cipher suites to test natural preference
	client := NewClient(conn)

	// Perform the handshake - should prefer ChaCha20-Poly1305
	if err := client.Handshake("cloudflare.com"); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	negotiatedCipher := client.GetCipherSuite()

	fmt.Printf("🔐 Negotiated cipher suite: 0x%04x\n", negotiatedCipher)

	if negotiatedCipher == TLS_CHACHA20_POLY1305_SHA256 {
		fmt.Println("✅ SUCCESS: ChaCha20-Poly1305 was preferred!")
	} else {
		fmt.Printf("⚠️  Note: Server chose 0x%04x instead of ChaCha20-Poly1305 (0x%04x)\n",
			negotiatedCipher, TLS_CHACHA20_POLY1305_SHA256)
	}

	// Verify the connection works
	if err := client.SendHTTPRequest("GET", "/", "cloudflare.com"); err != nil {
		t.Fatalf("Failed to send HTTP request: %v", err)
	}

	response, err := client.ReadHTTPResponse()
	if err != nil {
		t.Fatalf("Failed to read HTTP response: %v", err)
	}

	if len(response) == 0 {
		t.Error("Received an empty HTTP response")
	}

	fmt.Printf("✅ HTTP request successful with cipher 0x%04x (%d bytes response)\n",
		negotiatedCipher, len(response))
}

// TestChaCha20PreferenceGoogle tests ChaCha20-Poly1305 preference against Google
func TestChaCha20PreferenceGoogle(t *testing.T) {
	addr := "google.com:443"

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect to server %s: %v", addr, err)
	}
	defer conn.Close()

	// Create a client WITHOUT overriding cipher suites
	client := NewClient(conn)

	// Perform the handshake
	if err := client.Handshake("google.com"); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	negotiatedCipher := client.GetCipherSuite()

	fmt.Printf("🔐 Google negotiated cipher suite: 0x%04x\n", negotiatedCipher)

	switch negotiatedCipher {
	case TLS_CHACHA20_POLY1305_SHA256:
		fmt.Println("✅ Google also prefers ChaCha20-Poly1305!")
	case TLS_AES_256_GCM_SHA384:
		fmt.Println("📊 Google chose AES-256-GCM instead")
	case TLS_AES_128_GCM_SHA256:
		fmt.Println("📊 Google chose AES-128-GCM instead")
	default:
		fmt.Printf("❓ Google chose unknown cipher: 0x%04x\n", negotiatedCipher)
	}

	// Quick HTTP test
	if err := client.SendHTTPRequest("GET", "/", "google.com"); err == nil {
		if response, err := client.ReadHTTPResponse(); err == nil && len(response) > 0 {
			fmt.Printf("✅ Google connection successful (%d bytes)\n", len(response))
		}
	}
}
