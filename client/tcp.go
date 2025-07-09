package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// parseAndCaptureHandshakeRecords parses TLS records from handshake data and stores them for transcript validation
func (c *Client) parseAndCaptureHandshakeRecords(data []byte) {
	offset := 0

	for offset < len(data) {
		// Need at least 5 bytes for TLS record header
		if offset+5 > len(data) {
			break
		}

		// Parse TLS record header: type (1) + version (2) + length (2)
		recordType := data[offset]
		recordLength := int(data[offset+3])<<8 | int(data[offset+4])
		totalRecordLength := 5 + recordLength

		// Check if we have the complete record
		if offset+totalRecordLength > len(data) {
			break
		}

		// Extract the complete record
		record := make([]byte, totalRecordLength)
		copy(record, data[offset:offset+totalRecordLength])

		// Store handshake and other relevant records for transcript validation
		if recordType == 0x16 || recordType == 0x17 || recordType == 0x15 || recordType == 0x14 {
			c.capturedTraffic = append(c.capturedTraffic, record)
			fmt.Printf("[Client] Captured handshake-phase TLS record: type 0x%02x, %d bytes\n", recordType, len(record))
		}

		offset += totalRecordLength
	}
}

// parseAndCaptureOutgoingRecords parses TLS records from outgoing data and stores them for transcript validation
func (c *Client) parseAndCaptureOutgoingRecords(data []byte) {
	offset := 0

	for offset < len(data) {
		// Need at least 5 bytes for TLS record header
		if offset+5 > len(data) {
			break
		}

		// Parse TLS record header: type (1) + version (2) + length (2)
		recordType := data[offset]
		recordLength := int(data[offset+3])<<8 | int(data[offset+4])
		totalRecordLength := 5 + recordLength

		// Check if we have the complete record
		if offset+totalRecordLength > len(data) {
			break
		}

		// Extract the complete record
		record := make([]byte, totalRecordLength)
		copy(record, data[offset:offset+totalRecordLength])

		// Store all outgoing TLS records for transcript validation
		if recordType == 0x16 || recordType == 0x17 || recordType == 0x15 || recordType == 0x14 {
			c.capturedTraffic = append(c.capturedTraffic, record)
			fmt.Printf("[Client] Captured outgoing TLS record: type 0x%02x, %d bytes\n", recordType, len(record))
		}

		offset += totalRecordLength
	}
}

// handleConnectionReady processes connection ready messages from TEE_K
func (c *Client) handleConnectionReady(msg *Message) {
	var readyData ConnectionReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		log.Printf("[Client] Failed to unmarshal connection ready data: %v", err)
		return
	}

	if readyData.Success {
		// In Phase 2 split AEAD protocol, Client waits for handshake disclosure
		// then sends plaintext data to TEE_K for encryption
		// No direct TCP connection is established until we have encrypted data to send

		// Send TCP ready confirmation to TEE_K so it can start the handshake
		c.sendTCPReady(true)
	}
}

// sendTCPReady establishes TCP connection and sends ready message to TEE_K
func (c *Client) sendTCPReady(success bool) {
	fmt.Printf("[Client] DEBUG: sendTCPReady called with success=%v\n", success)

	if success {
		// Establish TCP connection to website to act as proxy for TEE_K
		tcpAddr := fmt.Sprintf("%s:%d", c.targetHost, c.targetPort)
		fmt.Printf("[Client] DEBUG: Attempting TCP connection to %s\n", tcpAddr)

		tcpConn, err := net.Dial("tcp", tcpAddr)
		if err != nil {
			log.Printf("[Client] Failed to establish TCP connection to website: %v", err)
			fmt.Printf("[Client] DEBUG: TCP connection failed: %v\n", err)
			success = false
		} else {
			fmt.Printf("[Client] DEBUG: TCP connection established successfully to %s\n", tcpAddr)
			c.tcpConn = tcpConn
			fmt.Printf("[Client] DEBUG: c.tcpConn set to %p\n", c.tcpConn)

			// Start proxying data from website back to TEE_K
			fmt.Printf("[Client] DEBUG: Starting tcpToWebsocket goroutine\n")
			go c.tcpToWebsocket()
		}
	}

	fmt.Printf("[Client] DEBUG: Sending MsgTCPReady with success=%v\n", success)
	tcpReadyMsg, err := CreateMessage(MsgTCPReady, TCPReadyData{Success: success})
	if err != nil {
		log.Printf("[Client] Failed to create TCP ready message: %v", err)
		return
	}

	if err := c.sendMessage(tcpReadyMsg); err != nil {
		log.Printf("[Client] Failed to send TCP ready message: %v", err)
	}
	fmt.Printf("[Client] DEBUG: MsgTCPReady sent successfully\n")
}

// handleSendTCPData forwards TCP data from TEE_K to the website
func (c *Client) handleSendTCPData(msg *Message) {
	fmt.Printf("[Client] DEBUG: handleSendTCPData called\n")
	fmt.Printf("[Client] DEBUG: c.tcpConn = %p\n", c.tcpConn)

	var tcpData TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		log.Printf("[Client] Failed to unmarshal TCP data: %v", err)
		return
	}

	fmt.Printf("[Client] DEBUG: Received TCP data with %d bytes\n", len(tcpData.Data))

	// *** CAPTURE RAW TCP DATA EXACTLY AS TEE_K SEES IT ***
	// Don't parse into individual TLS records - capture the raw TCP chunk
	rawTCPData := make([]byte, len(tcpData.Data))
	copy(rawTCPData, tcpData.Data)
	c.capturedTraffic = append(c.capturedTraffic, rawTCPData)
	fmt.Printf("[Client] Captured outgoing raw TCP chunk: %d bytes\n", len(rawTCPData))
	fmt.Printf("[Client] Total captured chunks now: %d\n", len(c.capturedTraffic))

	// Forward TLS data from TEE_K to website via our TCP connection
	conn := c.tcpConn

	if conn == nil {
		fmt.Printf("[Client] DEBUG: TCP connection is nil!\n")
		fmt.Printf("[Client] DEBUG: c.isClosing = %v\n", c.isClosing)
		fmt.Printf("[Client] DEBUG: c.targetHost = %s, c.targetPort = %d\n", c.targetHost, c.targetPort)
		log.Printf("[Client] No TCP connection to website available")
		return
	}

	fmt.Printf("[Client] DEBUG: TCP connection available, forwarding %d bytes\n", len(tcpData.Data))
	// Forward TLS data to website
	_, err := conn.Write(tcpData.Data)
	if err != nil {
		log.Printf("[Client] Failed to forward TLS data to website: %v", err)
		return
	}
	fmt.Printf("[Client] DEBUG: Successfully forwarded %d bytes to website\n", len(tcpData.Data))
}

// tcpToWebsocket reads from TCP connection and processes data
func (c *Client) tcpToWebsocket() {
	fmt.Printf("[Client] DEBUG: tcpToWebsocket goroutine started\n")
	fmt.Printf("[Client] DEBUG: c.tcpConn = %p\n", c.tcpConn)

	defer func() {
		fmt.Printf("[Client] DEBUG: tcpToWebsocket defer called\n")
		if c.isClosing && c.tcpConn != nil {
			fmt.Printf("[Client] DEBUG: Closing TCP connection on shutdown\n")
			c.tcpConn.Close()
			c.tcpConn = nil
		} else {
			fmt.Printf("[Client] DEBUG: Not closing TCP connection (isClosing=%v, tcpConn=%p)\n", c.isClosing, c.tcpConn)
		}
	}()

	buffer := make([]byte, 4096)
	var pending []byte // Buffer for incomplete TLS packets

	for {
		if c.isClosing {
			fmt.Printf("[Client] DEBUG: tcpToWebsocket exiting because c.isClosing=true\n")
			break
		}

		if c.tcpConn != nil {
			c.tcpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		}

		n, err := c.tcpConn.Read(buffer)

		if err != nil {
			if err == io.EOF {
				fmt.Printf("[Client] TCP connection closed by server (EOF)\n")
				atomic.StoreInt64(&c.eofReached, 1)
				fmt.Printf("[Client] EOF reached, checking for protocol completion...\n")
				break
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			} else if !isClientNetworkShutdownError(err) {
				fmt.Printf("[Client] TCP read error: %v\n", err)
				fmt.Printf("[Client] DEBUG: Real TCP error, exiting tcpToWebsocket\n")
				break
			} else {
				fmt.Printf("[Client] DEBUG: Network shutdown error, exiting tcpToWebsocket\n")
				break
			}
		}

		if c.tcpConn != nil {
			c.tcpConn.SetReadDeadline(time.Time{})
		}

		// Append new data to any pending data
		data := append(pending, buffer[:n]...)
		pending = nil
		offset := 0

		// Process complete TLS packets
		for offset < len(data) {
			// Need at least 5 bytes for TLS record header
			if offset+5 > len(data) {
				pending = data[offset:]
				break
			}

			// Get packet length from TLS header
			length := int(data[offset+3])<<8 | int(data[offset+4])
			fullLength := length + 5

			// Check if we have the complete packet
			if offset+fullLength > len(data) {
				pending = data[offset:]
				break
			}

			// Extract the complete TLS packet
			packet := make([]byte, fullLength)
			copy(packet, data[offset:offset+fullLength])
			c.capturedTraffic = append(c.capturedTraffic, packet)
			fmt.Printf("[Client] Captured TLS packet: type=0x%02x, length=%d\n", packet[0], length)

			if !c.handshakeComplete {
				// During handshake: Forward to TEE_K
				tcpDataMsg, err := CreateMessage(MsgTCPData, TCPData{Data: packet})
				if err != nil {
					log.Printf("[Client] Failed to create TCP data message: %v", err)
					continue
				}

				if err := c.sendMessage(tcpDataMsg); err != nil {
					if !isClientNetworkShutdownError(err) {
						log.Printf("[Client] Failed to send TCP data to TEE_K: %v", err)
					}
					break
				}
			} else {
				// After handshake: Process for split AEAD
				c.processTLSRecordFromData(packet)
			}

			offset += fullLength
		}
	}

	log.Printf("[Client] TCP read loop finished, performing final completion check...")
	c.checkProtocolCompletion("TCP connection closed")
}

// Helper function to detect network errors that occur during normal shutdown
func isClientNetworkShutdownError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe")
}
