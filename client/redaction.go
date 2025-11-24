package client

import (
	"fmt"
	"sort"
	"tee-mpc/minitls"
	teeproto "tee-mpc/proto"
	"tee-mpc/shared"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// analyzeResponseRedaction is the main entry point for response redaction analysis
func (c *Client) analyzeResponseRedaction() (shared.ResponseRedactionSpec, error) {
	// Step 1: Analyze TLS records and build mappings
	tlsAnalysis := c.analyzeTLSRecords(c.getSortedSequenceNumbers())

	// Step 2: Process HTTP content redactions if present
	httpRedactions, err := c.analyzeHTTPContent(tlsAnalysis.HTTPMappings, tlsAnalysis.AllHTTPContent)
	if err != nil {
		return shared.ResponseRedactionSpec{}, fmt.Errorf("failed to analyze HTTP content: %w", err)
	}

	// Step 3: Combine all redaction ranges
	responseRedactionRanges := append(tlsAnalysis.ProtocolRedactions, httpRedactions...)

	// Step 4: Consolidate and finalize
	spec := c.finalizeRedactionSpec(responseRedactionRanges)

	// Calculate total response size and redacted bytes
	totalResponseBytes := 0
	for _, parsed := range c.parsedResponseBySeq {
		if parsed != nil {
			totalResponseBytes += len(parsed.ActualContent)
		}
	}

	// Calculate total redacted bytes from consolidated ranges
	totalRedactedBytes := 0
	for _, r := range spec.Ranges {
		totalRedactedBytes += r.Length
	}

	// Calculate revealed bytes
	revealedBytes := totalResponseBytes - totalRedactedBytes

	// Log statistics - single line with revealed bytes and OPRF redaction count
	logFields := []zap.Field{
		zap.Int("revealed_bytes", revealedBytes),
		zap.Int("oprf_redactions", len(c.oprfRedactionRanges)),
	}
	if c.requestId != "" {
		logFields = append(logFields, zap.String("requestId", c.requestId))
	}
	c.logger.Info("Response redaction analysis complete", logFields...)

	return spec, nil
}

// getSortedSequenceNumbers returns sequence numbers in sorted order
func (c *Client) getSortedSequenceNumbers() []uint64 {
	seqNums := make([]uint64, 0, len(c.parsedResponseBySeq))
	for seqNum := range c.parsedResponseBySeq {
		seqNums = append(seqNums, seqNum)
	}
	sort.Slice(seqNums, func(i, j int) bool {
		return seqNums[i] < seqNums[j]
	})
	return seqNums
}

// analyzeTLSRecords processes all TLS records and categorizes them
func (c *Client) analyzeTLSRecords(seqNums []uint64) *TLSAnalysisResult {
	result := &TLSAnalysisResult{
		ProtocolRedactions: make([]shared.ResponseRedactionRange, 0),
		HTTPMappings:       make([]TLSToHTTPMapping, 0),
		AllHTTPContent:     make([]byte, 0),
	}

	for _, seqNum := range seqNums {
		c.processSingleTLSRecord(seqNum, result)
	}

	// Store mappings for OPRF use
	c.httpToTlsMapping = result.HTTPMappings

	return result
}

// processSingleTLSRecord processes one TLS record based on its content type
func (c *Client) processSingleTLSRecord(seqNum uint64, result *TLSAnalysisResult) {
	parsed := c.parsedResponseBySeq[seqNum]
	if parsed == nil {
		c.terminateConnectionWithError("No parsed data found for sequence", fmt.Errorf("invalid sequence number %d", seqNum))
		return
	}

	// Verify ciphertext exists
	ciphertext, exists := c.ciphertextBySeq[seqNum]
	if !exists {
		c.terminateConnectionWithError("No ciphertext found for sequence", fmt.Errorf("invalid sequence number %d", seqNum))
		return
	}

	if len(ciphertext) != len(parsed.ActualContent) {
		panic("ciphertext and actual content length do not match")
	}

	c.logger.Info("[REDACTION DEBUG] Processing TLS record",
		zap.Uint64("seq_num", seqNum),
		zap.Int("total_offset", result.TotalTLSOffset),
		zap.Uint8("content_type", parsed.ContentType),
		zap.Int("content_length", len(parsed.ActualContent)))

	// Calculate padding bytes (TLS 1.3: originalLen includes content + content_type_byte + padding)
	paddingBytes := parsed.OriginalLen - len(parsed.ActualContent)

	switch parsed.ContentType {
	case minitls.RecordTypeApplicationData:
		// Create mapping for this segment
		mapping := TLSToHTTPMapping{
			SeqNum:       seqNum,
			HTTPPos:      len(result.AllHTTPContent),
			TLSPos:       result.TotalTLSOffset,
			Length:       len(parsed.ActualContent),
			OriginalLen:  parsed.OriginalLen,
			PaddingBytes: paddingBytes,
			Ciphertext:   ciphertext,
		}

		result.HTTPMappings = append(result.HTTPMappings, mapping)
		result.AllHTTPContent = append(result.AllHTTPContent, parsed.ActualContent...)
	default:
		// redact everything except app data - use original length for TLS position
		result.ProtocolRedactions = append(result.ProtocolRedactions,
			shared.ResponseRedactionRange{
				Start:  result.TotalTLSOffset,
				Length: parsed.OriginalLen, // Use original length (with padding)
			})
	}

	// CRITICAL: Increment by ORIGINAL length to match consolidated stream positions
	result.TotalTLSOffset += parsed.OriginalLen // Use original length including padding
}

// analyzeHTTPContent analyzes HTTP content and returns redaction ranges
func (c *Client) analyzeHTTPContent(mappings []TLSToHTTPMapping, httpContent []byte) ([]shared.ResponseRedactionRange, error) {
	if len(httpContent) == 0 || len(mappings) == 0 {
		return nil, nil
	}
	// Parse HTTP response
	httpResponse := c.parseHTTPResponse(httpContent)
	c.lastResponseData = httpResponse

	// Get automatic redactions from provider if configured
	httpRedactions, err := c.getAutomaticHTTPRedactions(httpResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to get automatic HTTP redactions: %w", err)
	}

	// Convert HTTP positions to TLS positions
	return c.mapHTTPToTLSRedactions(httpRedactions, mappings), nil
}

// getAutomaticHTTPRedactions gets provider-specific redactions
func (c *Client) getAutomaticHTTPRedactions(httpResponse *HTTPResponse) ([]shared.ResponseRedactionRange, error) {
	if len(c.lastRedactionRanges) == 0 {
		c.logger.Info("Getting automatic response redactions", zap.Int("response_bytes", len(httpResponse.FullResponse)))

		// Log if response uses chunked encoding
		if len(httpResponse.Headers) > 0 {
			if te, ok := httpResponse.Headers["Transfer-Encoding"]; ok {
				c.logger.Info("⚠️ Response uses Transfer-Encoding",
					zap.String("transfer_encoding", te))
			}
			if ce, ok := httpResponse.Headers["Content-Encoding"]; ok {
				c.logger.Info("Response uses Content-Encoding",
					zap.String("content_encoding", ce))
			}
		}

		ranges, err := c.getResponseRedactions(httpResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to get response redactions: %w", err)
		}

		c.logger.Info("Automatic response redactions generated",
			zap.Int("redaction_ranges", len(ranges)))
		c.lastRedactionRanges = ranges
	} else {
		c.logger.Info("Response redactions already generated",
			zap.Int("cached_ranges", len(c.lastRedactionRanges)))
	}

	return c.lastRedactionRanges, nil
}

// mapHTTPToTLSRedactions converts HTTP position ranges to TLS stream positions
func (c *Client) mapHTTPToTLSRedactions(httpRanges []shared.ResponseRedactionRange, mappings []TLSToHTTPMapping) []shared.ResponseRedactionRange {
	tlsRanges := make([]shared.ResponseRedactionRange, 0)

	for _, httpRange := range httpRanges {
		tlsPositions := c.findTLSPositions(httpRange.Start, httpRange.Length, mappings)
		tlsRanges = append(tlsRanges, tlsPositions...)
	}

	return tlsRanges
}

// findTLSPositions converts an HTTP range to TLS positions
// CRITICAL: HTTP positions are in stripped content, TLS positions are in consolidated stream (with padding)
func (c *Client) findTLSPositions(httpStart int, httpLength int, mappings []TLSToHTTPMapping) []shared.ResponseRedactionRange {
	ranges := make([]shared.ResponseRedactionRange, 0)
	httpEnd := httpStart + httpLength

	for _, mapping := range mappings {
		mappingHTTPEnd := mapping.HTTPPos + mapping.Length

		// Check if this mapping overlaps with the HTTP range
		if mapping.HTTPPos < httpEnd && mappingHTTPEnd > httpStart {
			// Calculate the overlap in HTTP (stripped) space
			overlapStart := max(mapping.HTTPPos, httpStart)
			overlapEnd := min(mappingHTTPEnd, httpEnd)

			// Convert to TLS positions (with padding)
			// mapping.TLSPos already accounts for cumulative padding from previous records
			tlsStart := mapping.TLSPos + (overlapStart - mapping.HTTPPos)
			tlsLength := overlapEnd - overlapStart

			c.logger.Debug("Mapping HTTP to TLS",
				zap.Int("http_start", httpStart),
				zap.Int("http_length", httpLength),
				zap.Int("mapping_http_pos", mapping.HTTPPos),
				zap.Int("mapping_tls_pos", mapping.TLSPos),
				zap.Int("mapping_padding", mapping.PaddingBytes),
				zap.Int("tls_start", tlsStart),
				zap.Int("tls_length", tlsLength))

			ranges = append(ranges, shared.ResponseRedactionRange{
				Start:  tlsStart,
				Length: tlsLength,
			})
		}
	}

	return ranges
}

// finalizeRedactionSpec consolidates ranges and creates the final spec
func (c *Client) finalizeRedactionSpec(ranges []shared.ResponseRedactionRange) shared.ResponseRedactionSpec {
	// Log individual ranges if needed (debug)
	c.logRedactionRanges("Pre-consolidation", ranges)

	// Consolidate overlapping ranges
	consolidated := shared.ConsolidateResponseRedactionRanges(ranges)

	c.logger.Info("✅ [REDACTION] Final redaction spec generated",
		zap.Int("original_count", len(ranges)),
		zap.Int("consolidated_count", len(consolidated)))

	return shared.ResponseRedactionSpec{
		Ranges: consolidated,
	}
}

// logRedactionRanges logs redaction ranges for debugging
func (c *Client) logRedactionRanges(context string, ranges []shared.ResponseRedactionRange) {
	for i, r := range ranges {
		c.logger.Debug(fmt.Sprintf("[REDACTION] %s range", context),
			zap.Int("index", i),
			zap.Int("start", r.Start),
			zap.Int("length", r.Length),
			zap.Int("end", r.Start+r.Length-1))
	}
}

// applyRedactionRangesToContent applies redaction ranges to a content segment
func (c *Client) applyRedactionRangesToContent(content []byte, baseOffset int, ranges []shared.ResponseRedactionRange) []byte {
	result := make([]byte, len(content))
	copy(result, content)

	// Apply each redaction range that overlaps with this content
	for _, r := range ranges {
		rangeStart := r.Start
		rangeEnd := r.Start + r.Length
		contentStart := baseOffset
		contentEnd := baseOffset + len(content)

		// Check for overlap
		overlapStart := max(rangeStart, contentStart)
		overlapEnd := min(rangeEnd, contentEnd)

		if overlapStart < overlapEnd {
			// Apply redaction (replace with asterisks)
			localStart := overlapStart - contentStart
			localEnd := overlapEnd - contentStart
			for i := localStart; i < localEnd; i++ {
				result[i] = '*'
			}
		}
	}

	return result
}

// logRedactedResponseWithAsterisks reconstructs the full response and logs it with redacted parts as asterisks
func (c *Client) logRedactedResponseWithAsterisks(ranges []shared.ResponseRedactionRange) {
	// Get sorted sequence numbers
	seqNums := c.getSortedSequenceNumbers()

	// Reconstruct full TLS stream WITH PADDING to match consolidated stream
	var fullTLSStream []byte
	totalOffset := 0
	totalPadding := 0

	c.logger.Info("=== RECONSTRUCTING FULL TLS STREAM (with padding to match attestor) ===")

	for _, seqNum := range seqNums {
		parsed := c.parsedResponseBySeq[seqNum]
		if parsed == nil {
			continue
		}

		paddingBytes := parsed.OriginalLen - len(parsed.ActualContent)
		totalPadding += paddingBytes

		c.logger.Info("TLS Record",
			zap.Uint64("seq_num", seqNum),
			zap.Int("offset", totalOffset),
			zap.Int("stripped_length", len(parsed.ActualContent)),
			zap.Int("original_length", parsed.OriginalLen),
			zap.Int("padding_bytes", paddingBytes),
			zap.Uint8("content_type", parsed.ContentType))

		// Add actual content
		fullTLSStream = append(fullTLSStream, parsed.ActualContent...)
		// Add padding to match what attestor will see
		if paddingBytes > 0 {
			padding := make([]byte, paddingBytes)
			// TLS 1.3: last byte is content type, rest is 0x00
			fullTLSStream = append(fullTLSStream, padding...)
		}
		totalOffset += parsed.OriginalLen
	}

	c.logger.Info("Full TLS stream reconstructed (with padding)",
		zap.Int("total_bytes", len(fullTLSStream)),
		zap.Int("total_padding", totalPadding))

	// Apply redactions (replace with asterisks)
	redactedStream := c.applyRedactionRangesToContent(fullTLSStream, 0, ranges)

	// Log statistics
	totalRedacted := 0
	for _, r := range ranges {
		totalRedacted += r.Length
	}
	totalRevealed := len(fullTLSStream) - totalRedacted

	c.logger.Info("=== REDACTION STATISTICS ===",
		zap.Int("total_bytes", len(fullTLSStream)),
		zap.Int("redacted_bytes", totalRedacted),
		zap.Int("revealed_bytes", totalRevealed),
		zap.Int("num_ranges", len(ranges)))

	// Log each range
	for i, r := range ranges {
		c.logger.Info("Redaction Range",
			zap.Int("index", i),
			zap.Int("start", r.Start),
			zap.Int("length", r.Length),
			zap.Int("end", r.Start+r.Length))
	}

	// Log the full redacted response (convert to string for readability)
	c.logger.Info("=== FULL REDACTED RESPONSE (asterisks show redacted parts) ===")
	c.logger.Info(string(redactedStream))
	c.logger.Info("=== END REDACTED RESPONSE ===")
}

// sendRedactionSpec sends redaction specification to TEE_K
func (c *Client) sendRedactionSpec() error {
	c.logger.Info("🚀 [REDACTION] Generating and sending redaction specification to TEE_K")

	// Analyze response content to identify redaction ranges
	redactionSpec, err := c.analyzeResponseRedaction()
	if err != nil {
		c.terminateConnectionWithError("Failed to analyze response redaction", err)
		return fmt.Errorf("failed to analyze response redaction: %w", err)
	}

	// Log the full redacted response for debugging
	c.logRedactedResponseWithAsterisks(redactionSpec.Ranges)

	// Send redaction spec to TEE_K using protobuf envelope
	if c.wsConn == nil {
		return fmt.Errorf("no websocket connection to TEE_K")
	}

	// Map ranges
	pr := make([]*teeproto.ResponseRedactionRange, 0, len(redactionSpec.Ranges))
	for _, r := range redactionSpec.Ranges {
		pr = append(pr, &teeproto.ResponseRedactionRange{Start: int32(r.Start), Length: int32(r.Length)})
	}

	env := &teeproto.Envelope{SessionId: c.sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_ResponseRedactionSpec{ResponseRedactionSpec: &teeproto.ResponseRedactionSpec{Ranges: pr}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal redaction spec envelope: %v", err)
	}
	if err := c.wsConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("failed to send redaction spec: %v", err)
	}

	c.logger.Info("Sent redaction specification to TEE_K", zap.Int("consolidated_ranges", len(redactionSpec.Ranges)))
	c.logger.Info("Redaction specification sent successfully")

	c.advanceToPhase(PhaseReceivingRedacted)

	c.logger.Info("Entering redacted receiving phase - waiting for TEE_K to send 'finished' to TEE_T")
	return nil
}
