# Single Session Mode Implementation Plan

## Overview
Transform the existing multi-session TEE+MPC protocol to support single response-request TLS sessions. The key changes involve implementing immediate transcript signing after response processing and response redaction capabilities.

## Current State Analysis
- ✅ **Request redaction system**: Already implemented with R_S redaction
- ✅ **Split AEAD protocol**: Working for both requests and responses  
- ✅ **TLS handshake and communication**: Functional
- ✅ **Basic response processing**: Tag verification and decryption streams work
- ❌ **"Finished" command protocol**: Not implemented
- ❌ **Transcript signing**: Not implemented
- ❌ **Response redaction**: Not implemented
- ❌ **Redacted decryption streams**: Not implemented

## Implementation Tasks

### 1. Implement "Finished" Command Protocol
**Files to modify:** `tee_k/tee_k.go`, `tee_t/tee_t.go`, `client/client.go`, `shared/types.go`

#### Client (`client/client.go`)
- Add `sendFinished()` method to signal completion to both TEE_K and TEE_T
- Add handler for final signed transcripts and redacted streams
- Trigger finished after HTTP response is fully processed

#### TEE_K (`tee_k/tee_k.go`)
- Add `handleFinished()` method for finished coordination with TEE_T
- Add coordination logic as per tee+mpc.md (send "finished" to TEE_T, wait for response)
- Trigger transcript signing and redacted stream generation after coordination

#### TEE_T (`tee_t/tee_t.go`)
- Add `handleFinished()` method for finished coordination with TEE_K
- Respond with "finished" if already received from client, "not finished" otherwise
- Trigger transcript signing after coordination

#### Shared (`shared/types.go`)
- Add `MsgFinished` message type
- Add finished coordination message structures

### 2. Implement Transcript Collection and Signing
**Files to modify:** `tee_k/tee_k.go`, `tee_t/tee_t.go`, `shared/types.go`

#### TEE_K Transcript Collection
- Collect all handshake packets during TLS handshake
- Collect all request packets during request processing
- Store packets in chronological order
- Sign complete transcript after "finished" command

#### TEE_T Transcript Collection  
- Collect all response packets during response processing
- Store packets in chronological order
- Sign complete transcript after "finished" command

#### Cryptographic Signing
- Implement signing using enclave keys (integrate with existing KMS system)
- Create signed transcript message structures
- Add signature verification capabilities

### 3. Implement Response Redaction System
**Files to modify:** `client/client.go`, `tee_k/tee_k.go`, `shared/types.go`

#### Client Response Analysis
- Parse HTTP response to identify sensitive data ranges
- **Demo targets**: 
  - Content inside "h1" tags (page title)
  - "Etag" header values
  - Session ticket packets (always redacted)
- Send redaction specification to TEE_K

#### TEE_K Redacted Stream Generation
- Generate `Str_Dec_Red` where sensitive ranges are replaced with "*"
- Always redact session ticket packets completely
- Apply client-specified redaction ranges
- Sign the redacted decryption streams

### 4. Add New Message Types
**Files to modify:** `shared/types.go`, `client/messages.go`

#### New Message Types
```go
MsgFinished                    MessageType = "finished"
MsgSignedTranscript           MessageType = "signed_transcript"  
MsgRedactionSpec              MessageType = "redaction_spec"
MsgSignedRedactedDecryptionStream MessageType = "signed_redacted_decryption_stream"
```

#### New Data Structures
```go
type FinishedMessage struct {
    Source string `json:"source"` // "client", "tee_k", "tee_t"
}

type SignedTranscript struct {
    Packets   [][]byte `json:"packets"`
    Signature []byte   `json:"signature"`
    Source    string   `json:"source"` // "tee_k" or "tee_t"
}

type RedactionSpec struct {
    Ranges []RedactionRange `json:"ranges"`
    AlwaysRedactSessionTickets bool `json:"always_redact_session_tickets"`
}

type SignedRedactedDecryptionStream struct {
    RedactedStream []byte `json:"redacted_stream"`
    Signature      []byte `json:"signature"`
    SeqNum         uint64 `json:"seq_num"`
}
```

### 5. Modify Existing Response Processing
**Files to modify:** `tee_k/tee_k.go`, `tee_t/tee_t.go`, `client/client.go`

#### TEE_T Response Processing
- **Current**: `handleEncryptedResponse()` processes and stores response
- **Add**: Collect response packets for transcript
- **Modify**: After tag verification, prepare for transcript signing (don't sign immediately)

#### TEE_K Response Processing  
- **Current**: `generateAndSendDecryptionStream()` sends normal decryption stream
- **Add**: Collect request packets for transcript
- **Modify**: After sending decryption stream, prepare for transcript signing

#### Client Response Processing
- **Current**: `processTLSRecord()` handles response decryption
- **Add**: Parse decrypted response to identify redaction targets
- **Add**: Send redaction specification before "finished" command

### 6. Session Ticket Handling
**Files to modify:** `client/client.go`, `tee_k/tee_k.go`

#### Session Ticket Detection
- Identify TLS NewSessionTicket messages in response stream
- Mark these packets for complete redaction
- Handle in both transcript collection and redacted stream generation

### 7. Demo-Specific Implementation
**Files to modify:** `client/client.go`

#### HTML/HTTP Parsing
- Parse HTTP response to find "h1" tags and extract content ranges
- Parse HTTP headers to find "Etag" header and extract value range
- Create redaction specification for these ranges

#### Example Implementation
```go
func (c *Client) identifyRedactionRanges(httpResponse []byte) []RedactionRange {
    ranges := []RedactionRange{}
    
    // Find h1 tag content
    h1Regex := regexp.MustCompile(`<h1[^>]*>([^<]*)</h1>`)
    matches := h1Regex.FindAllIndex(httpResponse, -1)
    for _, match := range matches {
        ranges = append(ranges, RedactionRange{
            Start: match[0],
            Length: match[1] - match[0],
        })
    }
    
    // Find Etag header
    etagRegex := regexp.MustCompile(`Etag:\s*([^\r\n]*)`)
    matches = etagRegex.FindAllIndex(httpResponse, -1)
    for _, match := range matches {
        ranges = append(ranges, RedactionRange{
            Start: match[0],
            Length: match[1] - match[0],
        })
    }
    
    return ranges
}
```

## Implementation Order

1. **Phase 1**: Add new message types and data structures
2. **Phase 2**: Implement transcript collection in TEE_K and TEE_T
3. **Phase 3**: Implement cryptographic signing infrastructure
4. **Phase 4**: Implement "finished" command protocol
5. **Phase 5**: Implement response redaction system
6. **Phase 6**: Add demo-specific redaction logic
7. **Phase 7**: Integration testing and validation

## Expected Output

After implementing this plan, running the protocol should produce:

1. **Signed packets from TEE_K**: All handshake and request packets, cryptographically signed
2. **Signed packets from TEE_T**: All response packets, cryptographically signed  
3. **Signed redacted decryption streams**: For all packets, with:
   - Session ticket packets always fully redacted
   - Client-specified sensitive data (h1 content, Etag headers) redacted with "*"
   - R_S parts from requests redacted (already implemented)

## Key Considerations

- **Request redaction**: Already implemented, ensure R_S parts remain redacted
- **Backward compatibility**: Maintain existing multi-session capability if needed
- **Security**: All signing must use enclave-based keys with proper attestation
- **Performance**: Transcript collection should not impact protocol performance
- **Testing**: Verify redaction doesn't break response structure for XPath verification 