package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"tee-mpc/shared"
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
func (c *Client) handleConnectionReady(msg *shared.Message) {
	var readyData shared.ConnectionReadyData
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
	if success {
		// Establish TCP connection to website to act as proxy for TEE_K
		tcpAddr := fmt.Sprintf("%s:%d", c.targetHost, c.targetPort)

		tcpConn, err := net.Dial("tcp", tcpAddr)
		if err != nil {
			log.Printf("[Client] Failed to establish TCP connection to website: %v", err)
			success = false
		} else {
			c.tcpConn = tcpConn

			// Start proxying data from website back to TEE_K
			go c.tcpToWebsocket()
		}
	}

	tcpReadyMsg := shared.CreateMessage(shared.MsgTCPReady, shared.TCPReadyData{Success: success})

	if err := c.sendMessage(tcpReadyMsg); err != nil {
		log.Printf("[Client] Failed to send TCP ready message: %v", err)
	}
}

// handleSendTCPData processes send TCP data messages from TEE_K
func (c *Client) handleSendTCPData(msg *shared.Message) {
	var tcpData shared.TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		log.Printf("[Client] Failed to unmarshal TCP data: %v", err)
		return
	}

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
		log.Printf("[Client] No TCP connection to website available")
		return
	}

	// Forward TLS data to website
	_, err := conn.Write(tcpData.Data)
	if err != nil {
		log.Printf("[Client] Failed to forward TLS data to website: %v", err)
		return
	}
}

// tcpToWebsocket reads from TCP connection and processes data
func (c *Client) tcpToWebsocket() {
	defer func() {
		if c.isClosing && c.tcpConn != nil {
			c.tcpConn.Close()
			c.tcpConn = nil
		}
	}()

	buffer := make([]byte, TCPBufferSize)
	var pending []byte // Buffer for incomplete TLS packets

	for {
		if c.isClosing {
			break
		}

		if c.tcpConn != nil {
			c.tcpConn.SetReadDeadline(time.Now().Add(DefaultTCPReadTimeout))
		}

		n, err := c.tcpConn.Read(buffer)

		// Process any received data before handling EOF
		eofReceived := false
		if err != nil {
			if err == io.EOF {
				fmt.Printf("[Client] TCP connection closed by server (EOF)\n")
				atomic.StoreInt64(&c.eofReached, 1)
				fmt.Printf("[Client] EOF reached, but checking for final data first...\n")
				eofReceived = true // Mark EOF but continue to process any final data
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			} else if !isClientNetworkShutdownError(err) {
				fmt.Printf("[Client] TCP read error: %v\n", err)

				break
			} else {

				break
			}
		}

		// If we got data (n > 0), process it even if EOF was also received
		if n > 0 {
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
					tcpDataMsg := shared.CreateMessage(shared.MsgTCPData, shared.TCPData{Data: packet})

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
		} // Close the "if n > 0" block

		// After processing any final data, break if EOF was received
		if eofReceived {
			fmt.Printf("[Client] EOF reached, checking for protocol completion...\n")

			// Send batched responses if any were collected
			if err := c.sendBatchedResponses(); err != nil {
				log.Printf("[Client] Failed to send batched responses on EOF: %v", err)
			}

			break
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
