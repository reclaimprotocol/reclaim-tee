package clientlib

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"tee-mpc/shared"
	"time"

	"go.uber.org/zap"
)

// handleConnectionReady processes connection ready messages from TEE_K
func (c *Client) handleConnectionReady(msg *shared.Message) {
	var readyData shared.ConnectionReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		c.logger.Error("Failed to unmarshal connection ready data", zap.Error(err))
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
			c.logger.Error("Failed to establish TCP connection to website", zap.Error(err))
			success = false
		} else {
			c.tcpConn = tcpConn

			// Start proxying data from website back to TEE_K
			go c.tcpToWebsocket()
		}
	}

	tcpReadyMsg := shared.CreateMessage(shared.MsgTCPReady, shared.TCPReadyData{Success: success})

	if err := c.sendMessage(tcpReadyMsg); err != nil {
		c.logger.Error("Failed to send TCP ready message", zap.Error(err))
	}
}

// handleSendTCPData processes send TCP data messages from TEE_K
func (c *Client) handleSendTCPData(msg *shared.Message) {
	var tcpData shared.TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		c.logger.Error("Failed to unmarshal TCP data", zap.Error(err))
		return
	}

	// Don't parse into individual TLS records - capture the raw TCP chunk
	rawTCPData := make([]byte, len(tcpData.Data))
	copy(rawTCPData, tcpData.Data)
	c.capturedTraffic = append(c.capturedTraffic, rawTCPData)
	c.logger.Info("Captured outgoing raw TCP chunk", zap.Int("bytes", len(rawTCPData)))
	c.logger.Info("Total captured chunks now", zap.Int("count", len(c.capturedTraffic)))

	// Forward TLS data from TEE_K to website via our TCP connection
	conn := c.tcpConn

	if conn == nil {
		c.logger.Error("No TCP connection to website available")
		return
	}

	// Forward TLS data to website
	_, err := conn.Write(tcpData.Data)
	if err != nil {
		c.logger.Error("Failed to forward TLS data to website", zap.Error(err))
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
				c.logger.Info("TCP connection closed by server (EOF)")
				c.setBatchCollectionComplete()
				c.logger.Info("EOF reached, but checking for final data first...")
				eofReceived = true // Mark EOF but continue to process any final data
			} else {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				} else if !isClientNetworkShutdownError(err) {
					c.logger.Error("TCP read error", zap.Error(err))

					break
				} else {
					break
				}
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
				// fmt.Printf("[Client] Captured TLS packet: type=0x%02x, length=%d\n", packet[0], length)

				if !c.handshakeComplete {
					// During handshake: Forward to TEE_K
					tcpDataMsg := shared.CreateMessage(shared.MsgTCPData, shared.TCPData{Data: packet})

					if err := c.sendMessage(tcpDataMsg); err != nil {
						if !isClientNetworkShutdownError(err) {
							c.logger.Error("Failed to send TCP data to TEE_K", zap.Error(err))
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
			c.logger.Info("EOF reached, checking for protocol completion...")

			// Send batched responses if any were collected
			if err := c.sendBatchedResponses(); err != nil {
				c.logger.Error("Failed to send batched responses on EOF", zap.Error(err))
			}

			break
		}
	}

	c.logger.Info("TCP read loop finished, performing final completion check...")
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
