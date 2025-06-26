# TEE+MPC Protocol Implementation

A secure Multi-Party Computation (MPC) protocol implementation using Trusted Execution Environments (TEEs) for privacy-preserving TLS transcript verification.

## Architecture

The protocol involves four main entities:
- **User**: Initiates TLS sessions with websites
- **TEE_K**: Holds TLS keys and performs encryption/decryption
- **TEE_T**: Assists in tag computation without access to TLS keys  
- **Website**: Target website (e.g., example.com)

## Key Features

- **Split AEAD**: Encryption and MAC computation are separated between TEE_K and TEE_T
- **Transcript Signing**: Both TEEs sign transcripts proving authentic request/response handling
- **Privacy Preservation**: Sensitive data is redacted while maintaining verifiability
- **Third-Party Verification**: Independent verifiers can validate signed transcripts

## Quick Start

### 1. Start TEE Services

```bash
# Terminal 1: Start TEE_T
PORT=8081 go run ./tee_t

# Terminal 2: Start TEE_K  
PORT=8080 go run ./tee_k
```

### 2. Run Demo

```bash
# Terminal 3: Run the demo client
go run demo.go "ws://localhost:8080/ws?client_type=user"
```

The demo will:
1. Connect to TEE_K via WebSocket
2. Initialize a TLS session with example.com
3. Process the TLS handshake
4. Generate and display signed transcripts

## Protocol Flow

1. **Session Initialization**: User establishes secure channels with both TEEs
2. **TLS Handshake**: TEE_K performs handshake with target website  
3. **Request Processing**: User sends redacted requests, TEE_K encrypts, TEE_T computes tags
4. **Response Processing**: TEE_T verifies response tags, TEE_K provides decryption keys
5. **Transcript Signing**: Both TEEs sign their respective transcripts
6. **Verification**: Third parties can verify transcript authenticity

## Signed Transcripts

- **Request Transcript** (TEE_K): Contains redacted requests + commitments
- **Response Transcript** (TEE_T): Contains encrypted response data
- Both transcripts include cryptographic signatures for verification

## Testing

```bash
# Run all tests
go test ./...

# Run transcript signing tests specifically  
go test ./enclave -v -run TestTranscript
```

## Security Model

- TEEs cannot collude with each other or cloud providers
- Standard cryptographic assumptions apply
- MPC protocol is provably 1-private against honest-but-curious adversaries
- TLS transcript authenticity and integrity are maintained
