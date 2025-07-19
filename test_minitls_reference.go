package main

import (
	"fmt"
	"log"
	"net"
	"tee-mpc/minitls"
)

func main() {
	// Test TLS 1.2 AES-GCM with example.com to see reference behavior
	config := &minitls.Config{
		MinVersion: minitls.VersionTLS12,
		MaxVersion: minitls.VersionTLS12,
	}

	conn, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := minitls.NewClientWithConfig(conn, config)
	err = client.Handshake("example.com")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("✅ Handshake: TLS %x, cipher %x\n",
		client.GetNegotiatedVersion(), client.GetCipherSuite())

	// Send HTTP request
	err = client.SendHTTPRequest("GET", "/", "example.com")
	if err != nil {
		log.Fatal(err)
	}

	// Read response
	response, err := client.ReadHTTPResponse()
	if err != nil {
		log.Printf("Read error: %v", err)
	}

	fmt.Printf("✅ Received %d bytes response\n", len(response))
	fmt.Printf("Response preview: %.200s...\n", response[:min(200, len(response))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
