# Reclaim TEE - Split AEAD Implementation

A Trusted Execution Environment (TEE) implementation for secure TLS transcript generation using Multi-Party Computation (MPC) principles.

## Architecture

This implementation follows the design research document for TEE + MPC, providing a split AEAD (Authenticated Encryption with Associated Data) system that separates encryption and authentication tag computation across two independent TEEs.

### Components

- **TEE_K** (`tee_k/`): Key Management TEE
  - Holds TLS session keys
  - Performs encryption operations
  - Generates tag computation secrets
  - Provides WebSocket API for real-time coordination

- **TEE_T** (`tee_t/`): Tag Computation TEE  
  - Computes authentication tags using secrets from TEE_K
  - Verifies message authenticity
  - Independent from TEE_K to prevent collusion
  - Provides HTTP API for tag operations

- **Enclave** (`enclave/`): Core cryptographic library
  - Split AEAD implementation (AES-GCM and ChaCha20-Poly1305)
  - TLS 1.3 handshake and key derivation
  - AWS Nitro Enclave integration
  - Certificate management with ACME

- **Proxy** (`proxy/`): Traffic routing and coordination

## Split AEAD Protocol

The implementation enables secure TLS transcript generation by:

1. **TEE_K** encrypts plaintext and generates tag secrets
2. **TEE_T** computes authentication tags using the secrets
3. Both TEEs operate independently to ensure 1-private MPC security
4. Results are cryptographically identical to standard AEAD

### Supported Cipher Suites

- **AES-128-GCM** / **AES-256-GCM**: Using GHASH authentication
- **ChaCha20-Poly1305**: Using Poly1305 authentication

## TEE Communication Protocol

The system implements a comprehensive WebSocket-based communication protocol between TEE_K and TEE_T for Split AEAD operations, following the design research document specifications:

### Protocol Overview
- **Transport**: Secure WebSocket (WSS) connections for real-time bidirectional communication
- **Security**: TLS-encrypted TEE-to-TEE communication with protocol validation
- **Session Management**: Multi-session support with proper lifecycle management
- **Error Handling**: Comprehensive error handling and recovery mechanisms

### Message Types
- **Session Management**: `session_start`, `session_end` 
- **Split AEAD Operations**: `tag_compute`, `tag_verify`
- **Protocol Control**: `ping`/`pong`, `error`, `status`

### Communication Flow
1. **Connection Establishment**: TEE_K connects to TEE_T via secure WebSocket (`wss://tee-t/tee-comm`)
2. **TLS Handshake**: Full TLS encryption established between TEEs (terminated inside TEEs)
3. **Session Initialization**: TEE_K starts Split AEAD session with cipher suite negotiation
4. **Tag Operations**: 
   - **Encryption**: TEE_K → ciphertext + tag secrets → TEE_T → computed tag
   - **Decryption**: TEE_K → ciphertext + expected tag → TEE_T → verification result
5. **Session Termination**: Clean session end with resource cleanup
6. **Connection Management**: Automatic reconnection and keepalive mechanisms

### Integration Points
- **TEE_K Service**: Integrated WebSocket client for TEE_T coordination
- **TEE_T Service**: WebSocket server handling multiple concurrent TEE_K connections
- **Split AEAD Engine**: Seamless integration with tag computation/verification
- **Session State**: Proper session lifecycle management across both TEEs

## Building and Running

### Prerequisites

- Go 1.24+
- AWS Nitro Enclaves SDK (for production deployment)

### Build Services

```bash
# Build TEE_K (Key Management)
go build -o bin/tee_k ./tee_k

# Build TEE_T (Tag Computation)  
go build -o bin/tee_t ./tee_t

# Build Proxy
go build -o bin/proxy ./proxy
```

### Run Services

```bash
# Start TEE_K service
./bin/tee_k

# Start TEE_T service (in separate terminal)
./bin/tee_t

# Start Proxy (in separate terminal)
./bin/proxy
```

#### Production Configuration

For production deployment with TLS encryption:

```bash
# Set environment variable for secure TEE communication
export TEE_T_URL="https://tee-t.your-domain.com"

# Start services (will use HTTPS/WSS automatically)
./bin/tee_k
./bin/tee_t
```

### Demo

```bash
# Run interactive demo showing TEE communication
go run demo_tee_communication.go
```

This demo showcases:
- WebSocket-based TEE_K ↔ TEE_T communication (HTTP for local dev)
- Split AEAD encryption with both AES-GCM and ChaCha20-Poly1305
- Authentication tag computation and verification
- Security validation (tampered tag detection)
- Proper session management and cleanup

**Note**: The demo uses HTTP for local development. In production, set `TEE_T_URL` environment variable to use HTTPS/WSS.

### Docker Deployment

```bash
# Build TEE_T container
docker build -t reclaim-tee-t .

# Run container
docker run -p 8443:8443 reclaim-tee-t
```

## API Endpoints

### TEE_K Service (Port 8080)
- `ws://localhost:8080/ws` - User WebSocket API for TLS coordination
- `POST /session/init` - Initialize TLS session
- `POST /encrypt` - Request encryption operations
- `POST /decrypt-stream` - Generate decryption stream
- `POST /finalize` - Finalize transcript with signatures

### TEE_T Service (Port 8081)
- `ws://localhost:8081/tee-comm` - TEE-to-TEE WebSocket communication (dev)
- `wss://tee-t.domain.com/tee-comm` - TEE-to-TEE secure WebSocket (production)
- `POST /compute-tag` - Compute authentication tag (HTTP fallback)
- `POST /verify-tag` - Verify authentication tag (HTTP fallback)
- `GET /attest` - Generate attestation document

### Communication Patterns
- **User ↔ TEE_K**: WebSocket for real-time TLS protocol coordination
- **TEE_K ↔ TEE_T**: WebSocket for Split AEAD tag operations
- **User ↔ TEE_T**: Direct HTTP for verification (in some flows)

## Testing

```bash
# Run all tests
go test ./...

# Run Split AEAD tests specifically
go test ./enclave -v -run TestSplitAEAD

# Run TEE communication tests
go test ./enclave -v -run TestTEECommunication

# Run integration tests
go test ./enclave -v -run TestSplitAEADIntegration

# Run with coverage
go test ./enclave -cover
```

### Test Coverage
- **Split AEAD Engine**: 100% compatibility with Go's standard crypto
- **TEE Communication**: WebSocket protocol validation and error handling
- **Concurrency**: Multi-client scenarios with proper isolation
- **Integration**: Full protocol flows from encryption to verification
- **Edge Cases**: Invalid inputs, network failures, and security boundaries

## Security Features

- **Cryptographic Isolation**: Keys never leave TEE_K
- **Independent Computation**: TEE_T operates without key access
- **TLS-Encrypted Communication**: All TEE-to-TEE communication uses TLS 1.2/1.3
- **Memory Security**: Automatic secure zeroing of sensitive data
- **Side-Channel Resistance**: Uses Go's constant-time implementations
- **Attestation Support**: AWS Nitro Enclave attestation documents
- **Certificate Management**: Automatic ACME certificate provisioning and renewal

## Protocol Compliance

- **TLS 1.3**: RFC 8446 compliant handshake and key derivation
- **AEAD Compatibility**: 100% compatible with Go's standard crypto implementations
- **MPC Security**: Provably 1-private against honest-but-curious adversaries

## Development

The codebase is structured for easy extension and testing:

- Comprehensive unit tests with 100% compatibility verification
- Integration tests simulating full protocol flows
- Concurrency tests for production readiness
- Edge case and security tests for robustness

## License

[Add your license information here]
