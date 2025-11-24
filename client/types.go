package client

import "tee-mpc/shared"

// TLSToHTTPMapping tracks the relationship between TLS and HTTP positions
type TLSToHTTPMapping struct {
	SeqNum       uint64
	HTTPPos      int    // Position within HTTP content (stripped)
	TLSPos       int    // Position within TLS stream (consolidated, with padding)
	Length       int    // Length of HTTP data inside this TLS packet (stripped)
	OriginalLen  int    // Original length including TLS 1.3 padding
	PaddingBytes int    // Number of padding bytes (TLS 1.3 content type + padding)
	Ciphertext   []byte // Original ciphertext for this segment
}

// TLSAnalysisResult contains the results of analyzing TLS records
type TLSAnalysisResult struct {
	ProtocolRedactions []shared.ResponseRedactionRange // Session tickets, alerts, etc.
	HTTPMappings       []TLSToHTTPMapping              // HTTP content mappings
	AllHTTPContent     []byte                          // Concatenated HTTP content
	TotalTLSOffset     int                             // Final offset in TLS stream after all records
}
