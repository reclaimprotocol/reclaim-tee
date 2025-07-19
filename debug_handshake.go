package main

import (
	"fmt"
	"net"
	"tee-mpc/minitls"
)

func main() {
	fmt.Printf("=== MINITLS STANDALONE TLS 1.2 + HTTP TEST ===\n")

	config := &minitls.Config{
		MinVersion: minitls.VersionTLS12,
		MaxVersion: minitls.VersionTLS12,
	}

	conn, err := net.Dial("tcp", "httpbin.org:443")
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		return
	}
	defer conn.Close()

	client := minitls.NewClientWithConfig(conn, config)
	err = client.Handshake("httpbin.org")
	if err != nil {
		fmt.Printf("Handshake failed: %v\n", err)
		return
	}

	fmt.Printf("✅ Handshake: TLS %x, cipher %x\n",
		client.GetNegotiatedVersion(), client.GetCipherSuite())

	if aead := client.GetTLS12AEAD(); aead != nil {
		fmt.Printf("\n🔑 KEY MATERIAL:\n")
		fmt.Printf("  Read Key:  %x\n", aead.GetReadKey())
		fmt.Printf("  Read IV:   %x\n", aead.GetReadIV())
		fmt.Printf("  Write Key: %x\n", aead.GetWriteKey())
		fmt.Printf("  Write IV:  %x\n", aead.GetWriteIV())
		fmt.Printf("  Read Seq:  %d\n", aead.GetReadSequence())
		fmt.Printf("  Write Seq: %d\n", aead.GetWriteSequence())
	}

	// Test HTTP request/response to verify decryption works
	fmt.Printf("\n🌐 SENDING HTTP REQUEST...\n")
	err = client.SendHTTPRequest("GET", "/get", "httpbin.org")
	if err != nil {
		fmt.Printf("❌ HTTP request failed: %v\n", err)
		return
	}

	fmt.Printf("📨 READING HTTP RESPONSE...\n")
	response, err := client.ReadHTTPResponse()
	if err != nil {
		fmt.Printf("❌ HTTP response failed: %v\n", err)
		return
	}

	fmt.Printf("✅ HTTP RESPONSE RECEIVED:\n")
	if len(response) > 200 {
		fmt.Printf("Response preview (200 chars): %s...\n", response[:200])
	} else {
		fmt.Printf("Full response: %s\n", response)
	}

	fmt.Printf("\n✅ MINITLS TLS 1.2 WORKS CORRECTLY WITH HTTPBIN.ORG!\n")
}
