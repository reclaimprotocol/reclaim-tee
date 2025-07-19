package main

import (
	"fmt"
	"net"
	"tee-mpc/minitls"
)

func main() {
	config := &minitls.Config{
		MinVersion: minitls.VersionTLS12,
		MaxVersion: minitls.VersionTLS12,
	}

	conn, err := net.Dial("tcp", "github.com:443")
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		return
	}
	defer conn.Close()

	client := minitls.NewClientWithConfig(conn, config)
	err = client.Handshake("github.com")
	if err != nil {
		fmt.Printf("Handshake failed: %v\n", err)
		return
	}

	fmt.Printf("✅ Handshake: TLS %x, cipher %x\n",
		client.GetNegotiatedVersion(), client.GetCipherSuite())

	err = client.SendHTTPRequest("GET", "/", "github.com")
	if err != nil {
		fmt.Printf("❌ HTTP request failed: %v\n", err)
		return
	}

	response, err := client.ReadHTTPResponse()
	if err != nil {
		fmt.Printf("❌ HTTP response failed: %v\n", err)
		return
	}

	fmt.Printf("✅ HTTP RESPONSE RECEIVED: %d bytes\n", len(response))
	if len(response) > 200 {
		fmt.Printf("Response preview (200 chars): %s...\n", response[:200])
	} else {
		fmt.Printf("Full response: %s\n", response)
	}
}
