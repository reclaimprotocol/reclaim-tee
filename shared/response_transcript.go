package shared

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"google.golang.org/protobuf/proto"
)

const (
	MaxIncrementalResponseRecords = 65536
	MaxIncrementalResponseBytes   = 30 * 1024 * 1024
	MaxIncrementalBatchRecords    = 64
)

// ResponseInitialCommitment binds the append-only response to one session generation.
func ResponseInitialCommitment(sessionID string, binding []byte) ([]byte, error) {
	if sessionID == "" || len(binding) != sha256.Size {
		return nil, fmt.Errorf("invalid response session binding")
	}
	data := []byte("reclaim-tee/response/v1/initial\x00")
	data = appendResponseBytes(data, []byte(sessionID))
	data = append(data, binding...)
	digest := sha256.Sum256(data)
	return digest[:], nil
}

func appendResponseBytes(dst, value []byte) []byte {
	dst = binary.BigEndian.AppendUint64(dst, uint64(len(value)))
	return append(dst, value...)
}

// BuildResponseBatchMetadata commits full wire records in their received order.
// TEE_K receives this commitment from TEE_T; it never receives the ciphertext.
func BuildResponseBatchMetadata(sessionID string, binding, previous []byte, batchID, firstRecord uint64, responses []EncryptedResponseData) (*teeproto.ResponseBatchMetadata, error) {
	if _, err := ResponseInitialCommitment(sessionID, binding); err != nil {
		return nil, err
	}
	if len(previous) != sha256.Size || len(responses) == 0 || len(responses) > MaxIncrementalBatchRecords {
		return nil, fmt.Errorf("invalid response commitment or batch size")
	}
	data := []byte("reclaim-tee/response/v1/batch\x00")
	data = appendResponseBytes(data, []byte(sessionID))
	data = append(data, binding...)
	data = append(data, previous...)
	data = binary.BigEndian.AppendUint64(data, batchID)
	data = binary.BigEndian.AppendUint64(data, firstRecord)
	data = binary.BigEndian.AppendUint32(data, uint32(len(responses)))
	for _, record := range responses {
		data = binary.BigEndian.AppendUint64(data, record.SeqNum)
		data = appendResponseBytes(data, record.RecordHeader)
		data = appendResponseBytes(data, record.ExplicitIV)
		data = appendResponseBytes(data, record.EncryptedData)
		data = appendResponseBytes(data, record.Tag)
	}
	digest := sha256.Sum256(data)
	return &teeproto.ResponseBatchMetadata{SessionBinding: bytes.Clone(binding), BatchId: batchID, FirstRecord: firstRecord, RecordCount: uint32(len(responses)), PrefixCommitment: digest[:]}, nil
}

func EqualResponseBatchMetadata(a, b *teeproto.ResponseBatchMetadata) bool {
	return a != nil && b != nil && a.BatchId == b.BatchId && a.FirstRecord == b.FirstRecord && a.RecordCount == b.RecordCount && bytes.Equal(a.SessionBinding, b.SessionBinding) && bytes.Equal(a.PrefixCommitment, b.PrefixCommitment)
}

func CloneEncryptedResponse(record EncryptedResponseData) EncryptedResponseData {
	record.EncryptedData = bytes.Clone(record.EncryptedData)
	record.Tag = bytes.Clone(record.Tag)
	record.RecordHeader = bytes.Clone(record.RecordHeader)
	record.ExplicitIV = bytes.Clone(record.ExplicitIV)
	return record
}

// ValidateIncrementalRecordShape validates metadata before any nonce or key release.
func ValidateIncrementalRecordShape(length int, header, explicitIV []byte, seq, expectedSeq uint64, tls13, explicitGCM bool) error {
	if seq != expectedSeq || length < 0 || length > 16384+256 || len(header) != 5 || header[1] != 3 || header[2] != 3 {
		return fmt.Errorf("invalid incremental response record metadata")
	}
	if tls13 {
		if header[0] != 23 || length < 1 || len(explicitIV) != 0 {
			return fmt.Errorf("invalid TLS 1.3 response record")
		}
	} else {
		if length > 16384 || (header[0] != 21 && header[0] != 22 && header[0] != 23) {
			return fmt.Errorf("invalid TLS 1.2 response record")
		}
		expectedIV := 0
		if explicitGCM {
			expectedIV = 8
		}
		if len(explicitIV) != expectedIV {
			return fmt.Errorf("invalid TLS 1.2 explicit IV")
		}
	}
	if int(binary.BigEndian.Uint16(header[3:])) != length+16+len(explicitIV) {
		return fmt.Errorf("TLS response record length mismatch")
	}
	return nil
}

type responseTranscriptPhase uint8

const (
	responseOpen responseTranscriptPhase = iota
	responsePending
	responseAuthenticating
	responseFreezing
	responseFrozen
)

// ResponseTranscript serializes acceptance and finalization. Zero value is legacy.
// Invalid transitions have no effect; callers must terminate the owning session.
// No method performs I/O or releases cryptographic material.
type ResponseTranscript struct {
	mu                  sync.Mutex
	enabled             bool
	legacyStarted       bool
	sessionID           string
	binding             []byte
	commitment          []byte
	initialSeq          uint64
	nextBatch           uint64
	recordCount         uint64
	totalBytes          uint64
	phase               responseTranscriptPhase
	pending             *teeproto.ResponseBatchMetadata
	finalizationStarted bool
}

func (s *ResponseTranscript) Configure(sessionID string, binding []byte, initialSeq uint64) error {
	initial, err := ResponseInitialCommitment(sessionID, binding)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enabled || s.legacyStarted {
		return fmt.Errorf("response protocol already started")
	}
	s.enabled = true
	s.sessionID = sessionID
	s.binding = bytes.Clone(binding)
	s.commitment = initial
	s.initialSeq = initialSeq
	return nil
}
func (s *ResponseTranscript) Active() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.enabled }
func (s *ResponseTranscript) StartLegacy() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enabled {
		return fmt.Errorf("legacy response batch in incremental session")
	}
	s.legacyStarted = true
	return nil
}
func (s *ResponseTranscript) Snapshot() *teeproto.FinalizeResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}
func (s *ResponseTranscript) snapshotLocked() *teeproto.FinalizeResponse {
	return &teeproto.FinalizeResponse{SessionBinding: bytes.Clone(s.binding), BatchCount: s.nextBatch, RecordCount: s.recordCount, PrefixCommitment: bytes.Clone(s.commitment)}
}
func (s *ResponseTranscript) ExpectedSequence(firstRecord uint64) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initialSeq + firstRecord
}
func (s *ResponseTranscript) Accept(meta *teeproto.ResponseBatchMetadata, totalBytes uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acceptLocked(meta, totalBytes)
}

// AcceptRecords checks the full ciphertext commitment and reserves its prefix
// under the same lock. Authentication of the previous batch cannot change the
// chain between taking its snapshot and accepting this batch.
func (s *ResponseTranscript) AcceptRecords(meta *teeproto.ResponseBatchMetadata, records []EncryptedResponseData, totalBytes uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if meta == nil {
		return fmt.Errorf("missing response batch metadata")
	}
	computed, err := BuildResponseBatchMetadata(s.sessionID, s.binding, s.commitment, meta.BatchId, meta.FirstRecord, records)
	if err != nil {
		return err
	}
	if !EqualResponseBatchMetadata(computed, meta) {
		return fmt.Errorf("response ciphertext commitment mismatch")
	}
	return s.acceptLocked(meta, totalBytes)
}

func (s *ResponseTranscript) acceptLocked(meta *teeproto.ResponseBatchMetadata, totalBytes uint64) error {
	if !s.enabled || s.phase != responseOpen || meta == nil || len(meta.PrefixCommitment) != sha256.Size || !bytes.Equal(meta.SessionBinding, s.binding) || meta.BatchId != s.nextBatch || meta.FirstRecord != s.recordCount || meta.RecordCount == 0 || meta.RecordCount > MaxIncrementalBatchRecords {
		return fmt.Errorf("unexpected incremental response batch")
	}
	if uint64(meta.RecordCount) > MaxIncrementalResponseRecords-s.recordCount || totalBytes > MaxIncrementalResponseBytes-s.totalBytes {
		return fmt.Errorf("incremental response limit exceeded")
	}
	s.pending = proto.Clone(meta).(*teeproto.ResponseBatchMetadata)
	s.totalBytes += totalBytes
	s.phase = responsePending
	return nil
}
func (s *ResponseTranscript) CheckPending(meta *teeproto.ResponseBatchMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled || s.phase != responsePending || !EqualResponseBatchMetadata(s.pending, meta) {
		return fmt.Errorf("response acknowledgment does not match pending batch")
	}
	return nil
}
func (s *ResponseTranscript) ClaimPending(meta *teeproto.ResponseBatchMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled || s.phase != responsePending || !EqualResponseBatchMetadata(s.pending, meta) {
		return fmt.Errorf("response batch authentication already started or mismatched")
	}
	s.phase = responseAuthenticating
	return nil
}
func (s *ResponseTranscript) Complete(meta *teeproto.ResponseBatchMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled || s.phase != responseAuthenticating || !EqualResponseBatchMetadata(s.pending, meta) {
		return fmt.Errorf("response completion does not match pending batch")
	}
	s.nextBatch++
	s.recordCount += uint64(meta.RecordCount)
	s.commitment = bytes.Clone(meta.PrefixCommitment)
	s.pending = nil
	s.phase = responseOpen
	return nil
}
func (s *ResponseTranscript) BeginFreeze(req *teeproto.FinalizeResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled || s.phase != responseOpen || s.recordCount == 0 || req == nil || !proto.Equal(s.snapshotLocked(), req) {
		return fmt.Errorf("response freeze does not match authenticated prefix")
	}
	s.phase = responseFreezing
	return nil
}
func (s *ResponseTranscript) FinishFreeze(ack *teeproto.ResponseFrozen) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled || s.phase != responseFreezing || ack == nil || ack.BatchCount != s.nextBatch || ack.RecordCount != s.recordCount || !bytes.Equal(ack.SessionBinding, s.binding) || !bytes.Equal(ack.PrefixCommitment, s.commitment) {
		return fmt.Errorf("response freeze acknowledgment mismatch")
	}
	s.phase = responseFrozen
	return nil
}
func (s *ResponseTranscript) Frozen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled && s.phase == responseFrozen
}
func (s *ResponseTranscript) RequireFrozen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enabled && s.phase != responseFrozen {
		return fmt.Errorf("response transcript is not frozen")
	}
	return nil
}
func (s *ResponseTranscript) BeginRedaction() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled {
		s.legacyStarted = true
		return nil
	}
	if s.phase != responseFrozen || s.finalizationStarted {
		return fmt.Errorf("response redaction requires one frozen transcript")
	}
	s.finalizationStarted = true
	return nil
}

// RequireFrozenForInput reserves legacy ordering for actual finalization inputs.
// Negotiation cannot reinterpret inputs accepted under legacy semantics.
func (s *ResponseTranscript) RequireFrozenForInput() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled {
		s.legacyStarted = true
		return nil
	}
	if s.phase != responseFrozen {
		return fmt.Errorf("response transcript is not frozen")
	}
	return nil
}
