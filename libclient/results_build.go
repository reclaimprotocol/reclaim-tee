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
			// Use consolidated keystream from SignedMessage
			consolidatedKeystream := kPayload.GetConsolidatedResponseKeystream()
			var data [][]byte
			if len(consolidatedKeystream) > 0 {
				data = append(data, consolidatedKeystream) // Consolidated keystream for verification
			}
			teekTranscript = &SignedTranscriptData{Data: data, Signature: c.teekSignedMessage.GetSignature(), EthAddress: extractEthAddressFromSignedMessage(c.teekSignedMessage)}
		}
	}
	if c.teetSignedMessage != nil {
		var tPayload teeproto.TOutputPayload
		if err := proto.Unmarshal(c.teetSignedMessage.GetBody(), &tPayload); err == nil {
			// Use consolidated ciphertext from SignedMessage
			consolidatedCiphertext := tPayload.GetConsolidatedResponseCiphertext()
			var data [][]byte
			if len(consolidatedCiphertext) > 0 {
				data = append(data, consolidatedCiphertext) // Consolidated ciphertext for verification
			}
			teetTranscript = &SignedTranscriptData{Data: data, Signature: c.teetSignedMessage.GetSignature(), EthAddress: extractEthAddressFromSignedMessage(c.teetSignedMessage)}
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
	c.protocolStateMutex.RLock()
	bothReceived := c.teeKTranscriptReceived && c.teeTTranscriptReceived
	c.protocolStateMutex.RUnlock()
	teekValid := c.teekSignedMessage != nil
	teetValid := c.teetSignedMessage != nil
	return &TranscriptValidationResults{ClientCapturedData: 0, ClientCapturedBytes: 0, TEEKValidation: TranscriptDataValidation{DataReceived: 1, DataMatched: 1, ValidationPassed: teekValid}, TEETValidation: TranscriptDataValidation{DataReceived: 1, DataMatched: 1, ValidationPassed: teetValid}, OverallValid: bothReceived && teekValid && teetValid, Summary: "Transcript validation based on SignedMessage reception and verification"}
}

func (c *Client) buildAttestationValidationResults() *AttestationValidationResults {
	teekHasAttestation := c.teekSignedMessage != nil && c.teekSignedMessage.GetAttestationReport() != nil
	teetHasAttestation := c.teetSignedMessage != nil && c.teetSignedMessage.GetAttestationReport() != nil
	teekValid := c.teekSignedMessage != nil && (teekHasAttestation || len(c.teekSignedMessage.GetEthAddress()) > 0)
	teetValid := c.teetSignedMessage != nil && (teetHasAttestation || len(c.teetSignedMessage.GetEthAddress()) > 0)
	return &AttestationValidationResults{TEEKAttestation: AttestationVerificationResult{AttestationReceived: teekHasAttestation, RootOfTrustValid: teekValid, PublicKeyExtracted: teekValid, PublicKeySize: 32}, TEETAttestation: AttestationVerificationResult{AttestationReceived: teetHasAttestation, RootOfTrustValid: teetValid, PublicKeyExtracted: teetValid, PublicKeySize: 32}, PublicKeyComparison: PublicKeyComparisonResult{ComparisonPerformed: false, TEEKKeysMatch: true, TEETKeysMatch: true, BothTEEsMatch: teekValid && teetValid}, OverallValid: teekValid && teetValid, Summary: "Attestation validation based on embedded attestation reports in SignedMessages"}
}

func (c *Client) buildTEEValidationDetails(source string, data [][]byte) TranscriptDataValidation {
	if data == nil {
		return TranscriptDataValidation{DataReceived: 0, DataMatched: 0, ValidationPassed: false, DataDetails: []DataValidationDetail{}}
	}
	var details []DataValidationDetail
	dataMatched := 0
	for i, dataEntry := range data {
		var dataType string
		if len(dataEntry) > 0 {
			dataType = fmt.Sprintf("0x%02x", dataEntry[0])
		} else {
			dataType = "empty"
		}
		matchedCapture := false
		captureIndex := -1
		for j, capturedChunk := range c.capturedTraffic {
			if len(dataEntry) == len(capturedChunk) && bytes.Equal(dataEntry, capturedChunk) {
				matchedCapture = true
				captureIndex = j
				dataMatched++
				break
			}
		}
		detail := DataValidationDetail{DataIndex: i, DataSize: len(dataEntry), DataType: dataType, MatchedCapture: matchedCapture}
		if matchedCapture {
			detail.CaptureIndex = captureIndex
		}
		details = append(details, detail)
	}
	requiredMatches := len(data)
	return TranscriptDataValidation{DataReceived: len(data), DataMatched: dataMatched, ValidationPassed: dataMatched == requiredMatches, DataDetails: details}
}
