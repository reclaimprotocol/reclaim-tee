package main

import (
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// sendEnvelopeToTEET sends a protobuf envelope directly to TEE_T with attestation check
func (t *TEEK) sendEnvelopeToTEET(sessionID string, env *teeproto.Envelope) error {
	// Ensure session ID is set
	if env.GetSessionId() == "" {
		env.SessionId = sessionID
	}

	// Use sendToTEET which includes attestation verification
	return t.sendToTEET(sessionID, env)
}

// sendEncryptedRequestToTEET sends encrypted request data and tag secrets to TEE_T
func (t *TEEK) sendEncryptedRequestToTEET(sessionID string, encryptedData, tagSecrets []byte, cipherSuite uint16, seqNum uint64, redactionRanges []shared.RequestRedactionRange, commitments [][]byte) error {
	t.logger.WithSession(sessionID).Info("Sending encrypted request to TEE_T",
		zap.Int("bytes", len(encryptedData)),
		zap.Int("ranges", len(redactionRanges)),
		zap.Int("commitments", len(commitments)))

	// Convert redaction ranges to protobuf format
	var pbRanges []*teeproto.RequestRedactionRange
	for _, r := range redactionRanges {
		pbRanges = append(pbRanges, &teeproto.RequestRedactionRange{
			Start:  int32(r.Start),
			Length: int32(r.Length),
			Type:   r.Type,
		})
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_EncryptedRequest{
			EncryptedRequest: &teeproto.EncryptedRequest{
				EncryptedData:   encryptedData,
				TagSecrets:      tagSecrets,
				Commitments:     commitments,
				CipherSuite:     uint32(cipherSuite),
				SeqNum:          seqNum,
				RedactionRanges: pbRanges,
			},
		},
	}
	return t.sendEnvelopeToTEET(sessionID, env)
}
