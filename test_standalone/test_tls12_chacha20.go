package main

import (
	"fmt"
	"net"
	"os"
	"tee-mpc/minitls"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test_tls12_chacha20.go <hostname>")
		fmt.Println("Example: go run test_tls12_chacha20.go github.com")
		os.Exit(1)
	}

	hostname := os.Args[1]
	addr := hostname + ":443"

	fmt.Printf("=== Testing TLS 1.2 ChaCha20-Poly1305 against %s ===\n", hostname)

	// Connect to server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("❌ Failed to connect to %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("✅ TCP connection established to %s\n", addr)

	// Create TLS 1.2 only config with ChaCha20 cipher suites
	config := &minitls.Config{
		MinVersion: minitls.VersionTLS12,
		MaxVersion: minitls.VersionTLS12,
		CipherSuites: []uint16{
			minitls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // 0xcca9
			minitls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   // 0xcca8
		},
	}

	// Create client with TLS 1.2 configuration
	client := minitls.NewClientWithConfig(conn, config)

	fmt.Println("🔨 Starting TLS 1.2 handshake...")

	// Perform handshake
	if err := client.Handshake(hostname); err != nil {
		fmt.Printf("❌ TLS 1.2 handshake failed: %v\n", err)
		os.Exit(1)
	}

	// Get negotiated details
	negotiatedVersion := client.GetNegotiatedVersion()
	negotiatedCipher := client.GetCipherSuite()

	fmt.Printf("✅ TLS handshake successful!\n")
	fmt.Printf("   Version: 0x%04x (%s)\n", negotiatedVersion, versionString(negotiatedVersion))
	fmt.Printf("   Cipher: 0x%04x (%s)\n", negotiatedCipher, cipherString(negotiatedCipher))

	// Verify we got TLS 1.2 ChaCha20
	if negotiatedVersion != minitls.VersionTLS12 {
		fmt.Printf("⚠️  Expected TLS 1.2 (0x%04x), got 0x%04x\n", minitls.VersionTLS12, negotiatedVersion)
	}

	if negotiatedCipher != 0xcca9 && negotiatedCipher != 0xcca8 {
		fmt.Printf("⚠️  Expected ChaCha20 cipher (0xcca8 or 0xcca9), got 0x%04x\n", negotiatedCipher)
	}

	// Send HTTP request to test encryption/decryption
	fmt.Println("📤 Sending HTTP request...")

	if err := client.SendHTTPRequest("GET", "/", hostname); err != nil {
		fmt.Printf("❌ Failed to send HTTP request: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("📥 Reading HTTP response...")

	response, err := client.ReadHTTPResponse()
	if err != nil {
		fmt.Printf("❌ Failed to read HTTP response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ HTTP request/response successful!\n")
	fmt.Printf("   Response size: %d bytes\n", len(response))

	// Show first few lines of response
	if len(response) > 0 {
		lines := string(response[:min(200, len(response))])
		fmt.Printf("   Response preview:\n%s\n", lines)
		if len(response) > 200 {
			fmt.Printf("   ... (truncated)\n")
		}
	}

	fmt.Printf("\n🎉 TLS 1.2 ChaCha20-Poly1305 test completed successfully!\n")
}

func versionString(version uint16) string {
	switch version {
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func cipherString(cipher uint16) string {
	switch cipher {
	case 0xcca8:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case 0xcca9:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return "Unknown ChaCha20 variant"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
