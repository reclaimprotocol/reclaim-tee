package client

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/providers"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// The TCP reader owns counters, framing, and response maps until freeze.
// mu only protects the expected WebSocket replies and their publication.
type incrementalResponseState struct {
	mu                  sync.Mutex
	binding             []byte
	prefix              []byte
	batchCount          uint64
	recordCount         uint64
	bytes               int
	framer              *providers.HTTPResponseFramer
	closeNotify         bool
	pending             *teeproto.ResponseBatchMetadata
	pendingRecords      []shared.EncryptedResponseData
	streams             chan *teeproto.BatchedDecryptionStreams
	finalize            *teeproto.FinalizeResponse
	frozen              chan *teeproto.ResponseFrozen
	frozenReceived      bool
	captureRequested    bool
	captureAcknowledged bool
	captureReady        chan struct{}
}

func parseResponseMode(mode string) (teeproto.ResponseMode, error) {
	switch mode {
	case "", "incremental":
		return teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1, nil
	case "legacy":
		return teeproto.ResponseMode_RESPONSE_MODE_LEGACY_EOF, nil
	default:
		return 0, fmt.Errorf("invalid response mode %q: use incremental or legacy", mode)
	}
}

// SelectedResponseMode returns legacy until handshake negotiation is published.
func (c *Client) SelectedResponseMode() teeproto.ResponseMode {
	if !c.handshakeComplete.Load() {
		return teeproto.ResponseMode_RESPONSE_MODE_LEGACY_EOF
	}
	return c.selectedResponseMode
}

func (c *Client) incrementalResponseEnabled() bool {
	return c.SelectedResponseMode() == teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1
}

func (c *Client) configureResponseMode(data shared.HandshakeCompleteData) error {
	switch data.SelectedResponseMode {
	case teeproto.ResponseMode_RESPONSE_MODE_LEGACY_EOF:
		if len(data.ResponseBinding) != 0 {
			return fmt.Errorf("legacy response mode includes a binding")
		}
	case teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1:
		if c.requestedResponseMode != data.SelectedResponseMode || minitls.IsTLS12CBCCipherSuite(data.CipherSuite) {
			return fmt.Errorf("unrequested or unsupported incremental response mode")
		}
		prefix, err := shared.ResponseInitialCommitment(c.sessionID, data.ResponseBinding)
		if err != nil {
			return err
		}
		method, _, ok := bytes.Cut(c.requestData, []byte(" "))
		if !ok || len(method) == 0 {
			return fmt.Errorf("HTTP request method unavailable for response framing")
		}
		c.incrementalResponse = &incrementalResponseState{
			binding: bytes.Clone(data.ResponseBinding), prefix: prefix,
			framer:       providers.NewHTTPResponseFramer(string(method)),
			streams:      make(chan *teeproto.BatchedDecryptionStreams, 1),
			frozen:       make(chan *teeproto.ResponseFrozen, 1),
			captureReady: make(chan struct{}, 1),
		}
	default:
		return fmt.Errorf("unknown selected response mode %d", data.SelectedResponseMode)
	}
	c.selectedResponseMode = data.SelectedResponseMode
	c.logger.Info("Response mode selected", zap.String("response_mode", data.SelectedResponseMode.String()))
	return nil
}

// establishResponseCapture runs on the TCP owner after all of its earlier
// TCPData sends. The ordered K connection seals the handshake-forwarding nonce
// offset before a response batch can arrive through the separate T connection.
func (c *Client) establishResponseCapture() error {
	s := c.incrementalResponse
	s.mu.Lock()
	if s.captureAcknowledged {
		s.mu.Unlock()
		return nil
	}
	if s.captureRequested {
		s.mu.Unlock()
		return fmt.Errorf("response capture barrier is already outstanding")
	}
	s.captureRequested = true
	s.mu.Unlock()
	if err := c.sendEnvelope(&teeproto.Envelope{TimestampMs: time.Now().UnixMilli(), Payload: &teeproto.Envelope_ResponseCaptureReady{ResponseCaptureReady: &teeproto.ResponseCaptureReady{SessionBinding: bytes.Clone(s.binding)}}}); err != nil {
		return fmt.Errorf("send response capture barrier: %w", err)
	}
	select {
	case <-s.captureReady:
	case <-c.coreProtocolDone:
		return fmt.Errorf("protocol ended while establishing response capture")
	case <-c.watchdogStop:
		return fmt.Errorf("client closed while establishing response capture")
	}
	if c.isClosing.Load() {
		return fmt.Errorf("client closed while establishing response capture")
	}
	return nil
}

func (c *Client) receiveResponseCaptureReady(sessionID string, ready *teeproto.ResponseCaptureReady) error {
	if !c.incrementalResponseEnabled() || ready == nil {
		return fmt.Errorf("unexpected response capture acknowledgment")
	}
	s := c.incrementalResponse
	s.mu.Lock()
	defer s.mu.Unlock()
	if sessionID != c.sessionID || !ready.GetAcknowledged() || !s.captureRequested || s.captureAcknowledged || !bytes.Equal(s.binding, ready.GetSessionBinding()) {
		return fmt.Errorf("response capture acknowledgment mismatch or duplicate")
	}
	s.captureAcknowledged = true
	s.captureReady <- struct{}{}
	return nil
}

// receiveIncrementalDecryption runs on the TEE_K WebSocket reader. Validate the
// entire reply before publishing it; no ciphertext map is modified here.
func (c *Client) receiveIncrementalDecryption(sessionID string, batch *teeproto.BatchedDecryptionStreams) error {
	s := c.incrementalResponse
	if s == nil || !c.incrementalResponseEnabled() {
		return fmt.Errorf("incremental response mode is not active")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sessionID != c.sessionID || batch.GetSessionId() != c.sessionID {
		return fmt.Errorf("decryption batch session mismatch")
	}
	if s.pending == nil || !shared.EqualResponseBatchMetadata(s.pending, batch.GetMetadata()) {
		return fmt.Errorf("unexpected decryption batch metadata")
	}
	streams := batch.GetDecryptionStreams()
	if len(streams) != len(s.pendingRecords) || int(batch.GetTotalCount()) != len(streams) {
		return fmt.Errorf("decryption batch count mismatch")
	}
	for i, stream := range streams {
		record := s.pendingRecords[i]
		if stream == nil || stream.GetSeqNum() != record.SeqNum || len(stream.GetDecryptionStream()) != len(record.EncryptedData) || int(stream.GetLength()) != len(record.EncryptedData) {
			return fmt.Errorf("invalid decryption stream at batch position %d", i)
		}
	}
	select {
	case s.streams <- proto.Clone(batch).(*teeproto.BatchedDecryptionStreams):
		s.pending = nil
		s.pendingRecords = nil
		return nil
	default:
		return fmt.Errorf("duplicate decryption batch reply")
	}
}

// authenticateIncrementalBatch runs only on the TCP reader and permits one
// outstanding batch. It waits without holding any mutex; the watchdog cancels it.
func (c *Client) authenticateIncrementalBatch() error {
	if len(c.batchedResponses) == 0 {
		return nil
	}
	s := c.incrementalResponse
	records := c.batchedResponses
	if len(records) > shared.MaxIncrementalBatchRecords || s.recordCount+uint64(len(records)) > shared.MaxIncrementalResponseRecords {
		return fmt.Errorf("incremental response record limit exceeded")
	}
	newBytes := 0
	for i, record := range records {
		initialSeq := uint64(0)
		if !minitls.IsTLS13CipherSuite(c.cipherSuite) {
			initialSeq = 1
		}
		if err := shared.ValidateIncrementalRecordShape(len(record.EncryptedData), record.RecordHeader, record.ExplicitIV, record.SeqNum, initialSeq+s.recordCount+uint64(i), minitls.IsTLS13CipherSuite(c.cipherSuite), minitls.IsTLS12AESGCMCipherSuite(c.cipherSuite)); err != nil {
			return err
		}
		if len(record.Tag) != 16 {
			return fmt.Errorf("invalid response authentication tag length")
		}
		newBytes += len(record.RecordHeader) + len(record.ExplicitIV) + len(record.EncryptedData) + len(record.Tag)
	}
	if newBytes > shared.MaxIncrementalResponseBytes-s.bytes {
		return fmt.Errorf("incremental response byte limit exceeded")
	}
	if err := c.establishResponseCapture(); err != nil {
		return err
	}
	metadata, err := shared.BuildResponseBatchMetadata(c.sessionID, s.binding, s.prefix, s.batchCount, s.recordCount, records)
	if err != nil {
		return err
	}
	responses := make([]*teeproto.EncryptedResponseData, 0, len(records))
	for _, record := range records {
		responses = append(responses, &teeproto.EncryptedResponseData{EncryptedData: record.EncryptedData, Tag: record.Tag, RecordHeader: record.RecordHeader, SeqNum: record.SeqNum, ExplicitIv: record.ExplicitIV})
	}
	s.mu.Lock()
	if s.pending != nil || s.finalize != nil {
		s.mu.Unlock()
		return fmt.Errorf("response batch already outstanding or frozen")
	}
	s.pending = proto.Clone(metadata).(*teeproto.ResponseBatchMetadata)
	s.pendingRecords = records
	s.mu.Unlock()
	if err := c.sendEnvelopeToTEET(&teeproto.Envelope{TimestampMs: time.Now().UnixMilli(), Payload: &teeproto.Envelope_BatchedEncryptedResponses{BatchedEncryptedResponses: &teeproto.BatchedEncryptedResponses{
		SessionId: c.sessionID, Responses: responses, TotalCount: int32(len(responses)), Metadata: metadata,
	}}}); err != nil {
		return err
	}
	var batch *teeproto.BatchedDecryptionStreams
	select {
	case batch = <-s.streams:
	case <-c.coreProtocolDone:
		return fmt.Errorf("protocol ended while authenticating response")
	case <-c.watchdogStop:
		return fmt.Errorf("client closed while authenticating response")
	}
	if c.isClosing.Load() {
		return fmt.Errorf("client closed while authenticating response")
	}
	if err := c.decryptIncrementalBatch(records, batch); err != nil {
		return err
	}
	s.prefix = bytes.Clone(metadata.GetPrefixCommitment())
	s.batchCount++
	s.recordCount += uint64(len(records))
	s.bytes += newBytes
	c.expectedRedactedStreams = int(s.recordCount)
	c.batchedResponses = nil
	c.logger.Info("Incremental response batch authenticated", zap.Uint64("batch_id", metadata.GetBatchId()), zap.Uint64("record_count", s.recordCount), zap.Bool("http_complete", s.framer.Complete()))
	return nil
}

func (c *Client) decryptIncrementalBatch(records []shared.EncryptedResponseData, batch *teeproto.BatchedDecryptionStreams) error {
	s := c.incrementalResponse
	// Decode all records before publishing or trimming ciphertext. Each stream
	// must match the current immutable record and can be applied only once.
	parsed := make([]*TLSResponseData, len(records))
	for i, record := range records {
		stream := batch.GetDecryptionStreams()[i].GetDecryptionStream()
		plaintext := make([]byte, len(record.EncryptedData))
		for j := range plaintext {
			plaintext[j] = record.EncryptedData[j] ^ stream[j]
		}
		content, contentType := c.removeTLSPadding(plaintext)
		if !minitls.IsTLS13CipherSuite(c.cipherSuite) {
			contentType = record.RecordHeader[0]
		}
		if s.closeNotify {
			return fmt.Errorf("TLS record follows authenticated close_notify")
		}
		switch contentType {
		case minitls.RecordTypeApplicationData:
			if err := s.framer.OnChunk(content); err != nil {
				return fmt.Errorf("HTTP response framing: %w", err)
			}
		case minitls.RecordTypeHandshake:
			// A KeyUpdate changes the traffic secret. This protocol has no
			// negotiated key-update transition and must not reuse the old key.
			if len(content) > 0 && content[0] == 24 {
				return fmt.Errorf("TLS KeyUpdate is unsupported")
			}
		case minitls.RecordTypeAlert:
			if len(content) != 2 || content[1] != 0 {
				return fmt.Errorf("unexpected authenticated TLS alert")
			}
			s.closeNotify = true
			if err := s.framer.StreamEnded(); err != nil {
				return fmt.Errorf("TLS close_notify before complete HTTP response: %w", err)
			}
		default:
			return fmt.Errorf("invalid authenticated TLS content type %d", contentType)
		}
		parsed[i] = &TLSResponseData{ActualContent: content, ContentType: contentType, OriginalLen: len(plaintext)}
	}
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()
	for _, record := range records {
		if _, exists := c.parsedResponseBySeq[record.SeqNum]; exists {
			return fmt.Errorf("duplicate authenticated TLS sequence %d", record.SeqNum)
		}
		if !bytes.Equal(c.ciphertextBySeq[record.SeqNum], record.EncryptedData) {
			return fmt.Errorf("response ciphertext changed before authentication")
		}
	}
	for i, record := range records {
		length := len(record.EncryptedData)
		if minitls.IsTLS13CipherSuite(c.cipherSuite) {
			length--
		}
		if length < 0 {
			return fmt.Errorf("empty TLS 1.3 plaintext")
		}
		c.ciphertextBySeq[record.SeqNum] = bytes.Clone(record.EncryptedData[:length])
		c.decryptionStreamBySeq[record.SeqNum] = bytes.Clone(batch.GetDecryptionStreams()[i].GetDecryptionStream())
		c.parsedResponseBySeq[record.SeqNum] = parsed[i]
	}
	return nil
}

func (c *Client) receiveResponseFrozen(sessionID string, frozen *teeproto.ResponseFrozen) error {
	if !c.incrementalResponseEnabled() || frozen == nil {
		return fmt.Errorf("unexpected response freeze acknowledgment")
	}
	s := c.incrementalResponse
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.finalize
	if sessionID != c.sessionID || f == nil || s.frozenReceived || !bytes.Equal(f.GetSessionBinding(), frozen.GetSessionBinding()) ||
		f.GetBatchCount() != frozen.GetBatchCount() || f.GetRecordCount() != frozen.GetRecordCount() || !bytes.Equal(f.GetPrefixCommitment(), frozen.GetPrefixCommitment()) {
		return fmt.Errorf("response freeze prefix mismatch or duplicate")
	}
	s.frozenReceived = true
	s.frozen <- proto.Clone(frozen).(*teeproto.ResponseFrozen)
	return nil
}

func (c *Client) finalizeIncrementalResponse(eof bool) error {
	s := c.incrementalResponse
	if eof {
		if err := s.framer.StreamEnded(); err != nil {
			return fmt.Errorf("HTTP response incomplete at EOF: %w", err)
		}
	}
	if !s.framer.Complete() || s.recordCount == 0 {
		return fmt.Errorf("HTTP response is not complete")
	}
	// Stop capture before asking both TEEs to freeze the selected prefix.
	if c.tcpConn != nil {
		_ = c.tcpConn.Close()
	}
	f := &teeproto.FinalizeResponse{SessionBinding: bytes.Clone(s.binding), BatchCount: s.batchCount, RecordCount: s.recordCount, PrefixCommitment: bytes.Clone(s.prefix)}
	s.mu.Lock()
	if s.pending != nil || s.finalize != nil {
		s.mu.Unlock()
		return fmt.Errorf("response cannot be finalized in the current state")
	}
	s.finalize = proto.Clone(f).(*teeproto.FinalizeResponse)
	s.mu.Unlock()
	if err := c.sendEnvelope(&teeproto.Envelope{TimestampMs: time.Now().UnixMilli(), Payload: &teeproto.Envelope_FinalizeResponse{FinalizeResponse: f}}); err != nil {
		return err
	}
	select {
	case <-s.frozen:
	case <-c.coreProtocolDone:
		return fmt.Errorf("protocol ended while freezing response")
	case <-c.watchdogStop:
		return fmt.Errorf("client closed while freezing response")
	}
	if c.isClosing.Load() {
		return fmt.Errorf("client closed while freezing response")
	}
	if err := c.reconstructHTTPResponseFromDecryptedData(); err != nil {
		return err
	}
	c.responseReconstructed = true
	c.advanceToPhase(PhaseSendingRedaction)
	c.logger.Info("Incremental response frozen by both TEEs", zap.Uint64("record_count", s.recordCount))
	return c.sendRedactionSpec()
}
