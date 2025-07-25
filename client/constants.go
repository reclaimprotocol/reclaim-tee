package main

import "time"

// Timeout and Duration Constants
const (
	DefaultConnectionTimeout  = 30 * time.Second       // Default WebSocket connection timeout
	DefaultProcessingTimeout  = 30 * time.Second       // Default processing completion timeout
	DefaultTCPReadTimeout     = 1 * time.Second        // TCP connection read timeout
	DefaultWSHandshakeTimeout = 30 * time.Second       // WebSocket handshake timeout
	DefaultRetryInterval      = 100 * time.Millisecond // Retry interval for polling operations
)

// TLS and Crypto Constants
const (
	TLS12ExplicitIVSize = 8     // TLS 1.2 explicit IV size in bytes
	AESGCMTagSize       = 16    // AES-GCM authentication tag size
	TLSRecordHeaderSize = 5     // TLS record header size (type + version + length)
	MaxTLSRecordSize    = 16384 // Maximum TLS record payload size
)

// Buffer and Processing Constants
const (
	TCPBufferSize             = 4096 // TCP read buffer size
	HTTPResponsePreviewLength = 200  // HTTP response preview length for logging
	AsteriskCollapseThreshold = 100  // Number of consecutive asterisks before collapsing
	MaxFileReadLines          = 1500 // Maximum lines to read from files at once
)

// Display and Formatting Constants
const (
	CollapsedAsteriskPattern = "*********..." // Pattern used for collapsed asterisks display
	MinAsteriskCollapseCount = 9              // Minimum asterisks in collapsed pattern
)

// Network and Connection Constants
const (
	DefaultTCPKeepAliveDisabled = true // Whether to disable TCP keep-alive by default
)
