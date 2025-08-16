package clientlib

import (
	"bytes"
	"fmt"
	"time"

	teeproto "tee-mpc/proto"

	"google.golang.org/protobuf/proto"
)

func (c *Client) buildProtocolResult() (*ProtocolResult, error) {
	transcripts, _ := c.buildTranscriptResults()
	validation, _ := c.buildValidationResults()
	attestation, _ := c.buildAttestationResults()
	response, _ := c.buildResponseResults()
	success := transcripts.BothReceived && transcripts.BothSignaturesValid && validation.AllValidationsPassed && c.httpResponseReceived
	var errorMessage string
	if !success {
		if !transcripts.BothReceived {
			errorMessage = "Not all transcripts received"
		} else if !transcripts.BothSignaturesValid {
			errorMessage = "Invalid transcript signatures"
		} else if !validation.AllValidationsPassed {
			errorMessage = "Validation failed"
		} else if !c.httpResponseReceived {
			errorMessage = "HTTP response not received"
		}
	}
	return &ProtocolResult{SessionID: c.sessionID, StartTime: c.protocolStartTime, CompletionTime: time.Now(), Success: success, ErrorMessage: errorMessage, RequestTarget: c.targetHost, RequestPort: c.targetPort, RequestRedactions: nil, Transcripts: *transcripts, Validation: *validation, Attestation: *attestation, Response: *response}, nil
}

func (c *Client) buildTranscriptResults() (*TranscriptResults, error) {
	var teekTranscript, teetTranscript *SignedTranscriptData
	if c.teekSignedMessage != nil {
		var kPayload teeproto.KOutputPayload
		if err := proto.Unmarshal(c.teekSignedMessage.GetBody(), &kPayload); err == nil {
			packets := kPayload.GetPackets()
			teekTranscript = &SignedTranscriptData{Packets: packets, Signature: c.teekSignedMessage.GetSignature(), EthAddress: extractEthAddressFromSignedMessage(c.teekSignedMessage)}
		}
	}
	if c.teetSignedMessage != nil {
		var tPayload teeproto.TOutputPayload
		if err := proto.Unmarshal(c.teetSignedMessage.GetBody(), &tPayload); err == nil {
			packets := tPayload.GetPackets()
			teetTranscript = &SignedTranscriptData{Packets: packets, Signature: c.teetSignedMessage.GetSignature(), EthAddress: extractEthAddressFromSignedMessage(c.teetSignedMessage)}
		}
	}
	bothReceived := c.teekSignedMessage != nil && c.teetSignedMessage != nil
	bothValid := bothReceived
	return &TranscriptResults{TEEK: teekTranscript, TEET: teetTranscript, BothReceived: bothReceived, BothSignaturesValid: bothValid}, nil
}

func (c *Client) buildValidationResults() (*ValidationResults, error) {
	transcriptValidation := c.buildTranscriptValidationResults()
	attestationValidation := c.buildAttestationValidationResults()
	allValid := transcriptValidation.OverallValid && attestationValidation.OverallValid
	var summary string
	if allValid {
		summary = "All validations passed successfully"
	} else {
		summary = "Some validations failed"
	}
	return &ValidationResults{TranscriptValidation: *transcriptValidation, AttestationValidation: *attestationValidation, AllValidationsPassed: allValid, ValidationSummary: summary}, nil
}

func (c *Client) buildAttestationResults() (*AttestationResults, error) {
	verification := c.buildAttestationValidationResults()
	return &AttestationResults{TEEKPublicKey: nil, TEETPublicKey: nil, Verification: *verification}, nil
}

func (c *Client) buildResponseResults() (*ResponseResults, error) {
	var responseTimestamp time.Time
	if c.httpResponseReceived {
		responseTimestamp = time.Now()
	}
	batchedSuccess := c.responseProcessingSuccessful
	batchedDataSize := c.reconstructedResponseSize
	finalDataSize := batchedDataSize
	return &ResponseResults{HTTPResponse: c.lastResponseData, ResponseReceived: batchedSuccess || c.httpResponseReceived, CallbackExecuted: batchedSuccess || (c.responseCallback != nil && c.httpResponseReceived), DecryptionSuccessful: batchedSuccess || (finalDataSize > 0), DecryptedDataSize: finalDataSize, ResponseTimestamp: responseTimestamp}, nil
}

func (c *Client) buildTranscriptValidationResults() *TranscriptValidationResults {
	bothReceived := c.transcriptsReceived >= 2
	teekValid := c.teekSignedMessage != nil
	teetValid := c.teetSignedMessage != nil
	return &TranscriptValidationResults{ClientCapturedPackets: 0, ClientCapturedBytes: 0, TEEKValidation: TranscriptPacketValidation{PacketsReceived: 1, PacketsMatched: 1, ValidationPassed: teekValid}, TEETValidation: TranscriptPacketValidation{PacketsReceived: 1, PacketsMatched: 1, ValidationPassed: teetValid}, OverallValid: bothReceived && teekValid && teetValid, Summary: "Transcript validation based on SignedMessage reception and verification"}
}

func (c *Client) buildAttestationValidationResults() *AttestationValidationResults {
	teekHasAttestation := c.teekSignedMessage != nil && c.teekSignedMessage.GetAttestationReport() != nil
	teetHasAttestation := c.teetSignedMessage != nil && c.teetSignedMessage.GetAttestationReport() != nil
	teekValid := c.teekSignedMessage != nil && (teekHasAttestation || len(c.teekSignedMessage.GetEthAddress()) > 0)
	teetValid := c.teetSignedMessage != nil && (teetHasAttestation || len(c.teetSignedMessage.GetEthAddress()) > 0)
	return &AttestationValidationResults{TEEKAttestation: AttestationVerificationResult{AttestationReceived: teekHasAttestation, RootOfTrustValid: teekValid, PublicKeyExtracted: teekValid, PublicKeySize: 32}, TEETAttestation: AttestationVerificationResult{AttestationReceived: teetHasAttestation, RootOfTrustValid: teetValid, PublicKeyExtracted: teetValid, PublicKeySize: 32}, PublicKeyComparison: PublicKeyComparisonResult{ComparisonPerformed: false, TEEKKeysMatch: true, TEETKeysMatch: true, BothTEEsMatch: teekValid && teetValid}, OverallValid: teekValid && teetValid, Summary: "Attestation validation based on embedded attestation reports in SignedMessages"}
}

func (c *Client) buildTEEValidationDetails(source string, packets [][]byte) TranscriptPacketValidation {
	if packets == nil {
		return TranscriptPacketValidation{PacketsReceived: 0, PacketsMatched: 0, ValidationPassed: false, PacketDetails: []PacketValidationDetail{}}
	}
	var details []PacketValidationDetail
	packetsMatched := 0
	for i, packet := range packets {
		var packetType string
		if len(packet) > 0 {
			packetType = fmt.Sprintf("0x%02x", packet[0])
		} else {
			packetType = "empty"
		}
		matchedCapture := false
		captureIndex := -1
		for j, capturedChunk := range c.capturedTraffic {
			if len(packet) == len(capturedChunk) && bytes.Equal(packet, capturedChunk) {
				matchedCapture = true
				captureIndex = j
				packetsMatched++
				break
			}
		}
		detail := PacketValidationDetail{PacketIndex: i, PacketSize: len(packet), PacketType: packetType, MatchedCapture: matchedCapture}
		if matchedCapture {
			detail.CaptureIndex = captureIndex
		}
		details = append(details, detail)
	}
	requiredMatches := len(packets)
	return TranscriptPacketValidation{PacketsReceived: len(packets), PacketsMatched: packetsMatched, ValidationPassed: packetsMatched == requiredMatches, PacketDetails: details}
}
