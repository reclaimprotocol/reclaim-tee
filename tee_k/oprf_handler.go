package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/oprfmpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// handleOPRFRangesFromClient handles OPRFRangesSubmission from client
func (t *TEEK) handleOPRFRangesFromClient(sessionID string, msg *teeproto.OPRFRangesSubmission) error {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	t.logger.WithSession(sessionID).Info("Received OPRF ranges from client",
		zap.Int("range_count", len(msg.GetRanges())))

	// If no ranges, mark OPRF as not needed
	if len(msg.GetRanges()) == 0 {
		teekState.OPRFState = shared.OPRFStateNone
		t.logger.WithSession(sessionID).Info("No OPRF ranges - skipping MPC OPRF")
		// Check if we can send signature now
		t.checkAndSendSignatureIfReady(sessionID)
		return nil
	}

	// Initialize OPRF state
	teekState.OPRFRanges = msg.GetRanges()
	teekState.ClientRangesReceived = true
	teekState.OPRFState = shared.OPRFStateInProgress
	teekState.OPRFExpectedCount = len(msg.GetRanges())
	teekState.GarblerSessions = make(map[int]*oprfmpc.CMACGarblerSession)
	teekState.OPRFResults = make(map[int]*shared.OPRFResult)

	// Generate OPRF key share if not already set
	if len(teekState.OPRFKeyShare) == 0 {
		teekState.OPRFKeyShare = make([]byte, 16)
		if _, err := rand.Read(teekState.OPRFKeyShare); err != nil {
			return fmt.Errorf("failed to generate OPRF key share: %w", err)
		}
	}

	// If keystream not yet available, processing will happen later
	// when processQueuedOPRFRanges is called after keystream is set
	if len(teekState.ConsolidatedKeystream) == 0 {
		t.logger.WithSession(sessionID).Info("Keystream not yet available, OPRF will be initiated after redaction processing")
		return nil
	}

	// Keystream available, process immediately
	return t.processQueuedOPRFRanges(sessionID, teekState)
}

// processQueuedOPRFRanges processes OPRF ranges that were waiting for keystream
func (t *TEEK) processQueuedOPRFRanges(sessionID string, teekState *TEEKSessionState) error {
	if !teekState.ClientRangesReceived || len(teekState.OPRFRanges) == 0 {
		return nil // No ranges to process
	}
	if teekState.OPRFState != shared.OPRFStateInProgress {
		return nil // Already processed or not needed
	}
	if len(teekState.GarblerSessions) > 0 {
		return nil // Already initiated
	}

	t.logger.WithSession(sessionID).Info("Processing queued OPRF ranges",
		zap.Int("count", len(teekState.OPRFRanges)))

	// Validate ranges and initiate MPC for each
	for i, r := range teekState.OPRFRanges {
		if r.TlsStart < 0 || r.TlsLength <= 0 || r.TlsLength > 64 {
			return fmt.Errorf("invalid range %d: start=%d length=%d", i, r.TlsStart, r.TlsLength)
		}
		if int(r.TlsStart+r.TlsLength) > len(teekState.ConsolidatedKeystream) {
			return fmt.Errorf("range %d exceeds keystream (end=%d, keystream_len=%d)",
				i, r.TlsStart+r.TlsLength, len(teekState.ConsolidatedKeystream))
		}

		if err := t.initiateOPRFForRange(sessionID, teekState, i, r); err != nil {
			return fmt.Errorf("failed to initiate OPRF for range %d: %w", i, err)
		}
	}

	return nil
}

// initiateOPRFForRange starts MPC OPRF for a single range
func (t *TEEK) initiateOPRFForRange(sessionID string, teekState *TEEKSessionState, rangeIndex int, r *teeproto.OPRFRangeSpec) error {
	// Generate Round1 (no input needed at this stage)
	round1, garblerState, err := oprfmpc.CMACGarblerRound1(rand.Reader, elliptic.P256())
	if err != nil {
		return fmt.Errorf("CMACGarblerRound1 failed: %w", err)
	}

	teekState.GarblerSessions[rangeIndex] = garblerState

	// Compute TLS session hash for replay protection
	tlsSessionHash := t.computeTLSSessionHash(sessionID)

	t.logger.WithSession(sessionID).Info("Sending MPC OPRF Round1 to TEE_T",
		zap.Int("range_index", rangeIndex),
		zap.Int32("tls_start", r.TlsStart),
		zap.Int32("tls_length", r.TlsLength))

	// Serialize Round1 payload
	round1Bytes := oprfmpc.SerializeRound1(round1)

	// Send Round1 to TEE_T
	return t.sendMPCOPRFRound1ToTEET(sessionID, &teeproto.MPCOPRFRound1{
		SessionId:      sessionID,
		OprfSessionId:  garblerState.SessionID,
		OtSetup:        round1Bytes,
		RangeIndex:     int32(rangeIndex),
		TlsStart:       r.TlsStart,
		TlsLength:      r.TlsLength,
		TlsSessionHash: tlsSessionHash,
	})
}

// handleOPRFRound2 handles Round2 response from TEE_T
func (t *TEEK) handleOPRFRound2(sessionID string, msg *teeproto.MPCOPRFRound2) error {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	// Find garbler session by OPRF session ID
	var rangeIndex int = -1
	var garblerSession *oprfmpc.CMACGarblerSession
	for idx, gs := range teekState.GarblerSessions {
		if gs.SessionID == msg.OprfSessionId {
			rangeIndex = idx
			garblerSession = gs
			break
		}
	}

	if rangeIndex < 0 {
		return fmt.Errorf("no garbler session found for OPRF session %d", msg.OprfSessionId)
	}

	t.logger.WithSession(sessionID).Info("Received MPC OPRF Round2 from TEE_T",
		zap.Int("range_index", rangeIndex),
		zap.Uint64("oprf_session_id", msg.OprfSessionId))

	// Extract keystream for range and build garbler input
	r := teekState.OPRFRanges[rangeIndex]
	keystream := teekState.ConsolidatedKeystream[r.TlsStart : r.TlsStart+r.TlsLength]
	paddedKeystream, _ := oprfmpc.PadZeros64(keystream, int(r.TlsLength))

	var garblerInput [80]byte
	copy(garblerInput[:64], paddedKeystream[:])
	copy(garblerInput[64:], teekState.OPRFKeyShare)

	// Deserialize Round2 payload
	round2, err := oprfmpc.DeserializeRound2(msg.OtChoices)
	if err != nil {
		return fmt.Errorf("failed to deserialize Round2: %w", err)
	}

	// Generate Round3
	round3, err := oprfmpc.CMACGarblerRound3(rand.Reader, elliptic.P256(), garblerSession, garblerInput, round2)
	if err != nil {
		return fmt.Errorf("CMACGarblerRound3 failed: %w", err)
	}

	// Serialize Round3 payload
	round3Bytes := oprfmpc.SerializeRound3(round3)

	// Send Round3 to TEE_T
	return t.sendMPCOPRFRound3ToTEET(sessionID, &teeproto.MPCOPRFRound3{
		SessionId:      sessionID,
		OprfSessionId:  msg.OprfSessionId,
		GarbledCircuit: round3Bytes, // Full serialized payload
		GarblerInputs:  nil,         // Included in serialized payload
		OtCiphertexts:  nil,         // Included in serialized payload
		OutputHints:    nil,         // Included in serialized payload
	})
}

// handleOPRFResult handles the final OPRF result from TEE_T
func (t *TEEK) handleOPRFResult(sessionID string, msg *teeproto.MPCOPRFResult) error {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	rangeIndex := int(msg.RangeIndex)
	if rangeIndex < 0 || rangeIndex >= len(teekState.OPRFRanges) {
		return fmt.Errorf("invalid range index %d", rangeIndex)
	}

	r := teekState.OPRFRanges[rangeIndex]

	t.logger.WithSession(sessionID).Info("Received MPC OPRF result from TEE_T",
		zap.Int("range_index", rangeIndex),
		zap.Int("cmac_len", len(msg.CmacOutput)),
		zap.Int("hash_len", len(msg.HashOutput)))

	// Store the result
	var cmacOutput [16]byte
	var hashOutput [32]byte
	copy(cmacOutput[:], msg.CmacOutput)
	copy(hashOutput[:], msg.HashOutput)

	teekState.OPRFResults[rangeIndex] = &shared.OPRFResult{
		RangeIndex: rangeIndex,
		TLSStart:   int(r.TlsStart),
		TLSLength:  int(r.TlsLength),
		CMACOutput: cmacOutput,
		HashOutput: hashOutput,
	}

	// Check if all OPRF computations are complete
	if len(teekState.OPRFResults) >= teekState.OPRFExpectedCount {
		teekState.OPRFState = shared.OPRFStateComplete
		t.logger.WithSession(sessionID).Info("All MPC OPRF computations complete",
			zap.Int("count", len(teekState.OPRFResults)))

		// Check if we can send signature now
		t.checkAndSendSignatureIfReady(sessionID)
	}

	return nil
}

// computeTLSSessionHash computes a hash of TLS session parameters for replay protection
func (t *TEEK) computeTLSSessionHash(sessionID string) []byte {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return nil
	}

	// Include session-specific data that can't be replayed
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write(teekState.ClientHello)
	h.Write(teekState.ServerHello)
	return h.Sum(nil)
}

// sendMPCOPRFRound1ToTEET sends Round1 message to TEE_T
func (t *TEEK) sendMPCOPRFRound1ToTEET(sessionID string, round1 *teeproto.MPCOPRFRound1) error {
	conn := t.getSharedTEETConnection()
	if conn == nil {
		return fmt.Errorf("no shared TEE_T connection available")
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_MpcOprfRound1{
			MpcOprfRound1: round1,
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal Round1: %w", err)
	}

	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// sendMPCOPRFRound3ToTEET sends Round3 message to TEE_T
func (t *TEEK) sendMPCOPRFRound3ToTEET(sessionID string, round3 *teeproto.MPCOPRFRound3) error {
	conn := t.getSharedTEETConnection()
	if conn == nil {
		return fmt.Errorf("no shared TEE_T connection available")
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_MpcOprfRound3{
			MpcOprfRound3: round3,
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal Round3: %w", err)
	}

	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// buildOPRFOutputsForSigning builds OPRF outputs for inclusion in signed payload
// IMPORTANT: Iterates over OPRFRanges slice (not OPRFResults map) for deterministic ordering
func (t *TEEK) buildOPRFOutputsForSigning(teekState *TEEKSessionState) []*teeproto.OPRFOutput {
	if teekState.OPRFState != shared.OPRFStateComplete || len(teekState.OPRFResults) == 0 {
		return nil
	}

	var outputs []*teeproto.OPRFOutput

	// Iterate over ranges slice for deterministic ordering
	for i, r := range teekState.OPRFRanges {
		result, ok := teekState.OPRFResults[i]
		if !ok {
			continue
		}
		outputs = append(outputs, &teeproto.OPRFOutput{
			TlsStart:   r.TlsStart,
			TlsLength:  r.TlsLength,
			CmacOutput: result.CMACOutput[:],
			HashOutput: result.HashOutput[:],
		})
	}

	return outputs
}

// isOPRFReady checks if OPRF processing is complete or not needed
// ZERO ERROR POLICY: Failed state is NOT ready - session should have been terminated
func isOPRFReady(state shared.OPRFSessionState) bool {
	return state == shared.OPRFStateNone ||
		state == shared.OPRFStateComplete
}

// handleCiphertextReady verifies ciphertext length matches keystream
func (t *TEEK) handleCiphertextReady(sessionID string, msg *teeproto.CiphertextReady) error {
	teekState, err := t.sessionManager.GetTEEKSessionState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TEE_K session state: %w", err)
	}

	keystreamLen := len(teekState.ConsolidatedKeystream)
	ciphertextLen := int(msg.TotalLength)

	if keystreamLen != ciphertextLen {
		return fmt.Errorf("keystream length %d != ciphertext length %d", keystreamLen, ciphertextLen)
	}

	t.logger.WithSession(sessionID).Info("Ciphertext ready confirmed",
		zap.Int("length", ciphertextLen))

	return nil
}

// sendCiphertextReadyToTEET notifies TEE_T that ciphertext consolidation is complete
func (t *TEEK) sendCiphertextReadyToTEET(sessionID string, totalLength int) error {
	conn := t.getSharedTEETConnection()
	if conn == nil {
		return fmt.Errorf("no shared TEE_T connection available")
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_CiphertextReady{
			CiphertextReady: &teeproto.CiphertextReady{
				SessionId:   sessionID,
				TotalLength: int32(totalLength),
			},
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal CiphertextReady: %w", err)
	}

	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// Ensure bytes import is used
var _ = bytes.Equal
