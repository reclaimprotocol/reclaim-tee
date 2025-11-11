package client

import "time"

// Timeout and Duration Constants
const (
	DefaultConnectionTimeout  = 30 * time.Second // Default WebSocket connection timeout
	DefaultProcessingTimeout  = 30 * time.Second // Default processing completion timeout
	DefaultTCPReadTimeout     = 1 * time.Second  // TCP connection read timeout
	DefaultWSHandshakeTimeout = 30 * time.Second // WebSocket handshake timeout
)

// Buffer and Processing Constants
const (
	TCPBufferSize             = 4096 // TCP read buffer size
	HTTPResponsePreviewLength = 200  // HTTP response preview length for logging
	AsteriskCollapseThreshold = 100  // Number of consecutive asterisks before collapsing
)

// Display and Formatting Constants
const (
	CollapsedAsteriskPattern = "*********" // Pattern used for collapsed asterisks display
)
