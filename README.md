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

### Docker Deployment

```bash
# Build TEE_T container
docker build -t reclaim-tee-t .

# Run container
docker run -p 8443:8443 reclaim-tee-t
```

## API Endpoints

### TEE_K WebSocket API
- `ws://localhost:8080/ws` - Real-time TLS coordination
- Message types: `handshake_init`, `encrypt_request`, `decrypt_request`

### TEE_T HTTP API
- `POST /compute-tag` - Compute authentication tag
- `POST /verify-tag` - Verify authentication tag
- `GET /attest` - Generate attestation document

## Testing

```bash
# Run all tests
go test ./...

# Run Split AEAD tests specifically
go test ./enclave -v -run TestSplitAEAD

# Run integration tests
go test ./enclave -v -run TestSplitAEADIntegration
```

## Security Features

- **Cryptographic Isolation**: Keys never leave TEE_K
- **Independent Computation**: TEE_T operates without key access
- **Memory Security**: Automatic secure zeroing of sensitive data
- **Side-Channel Resistance**: Uses Go's constant-time implementations
- **Attestation Support**: AWS Nitro Enclave attestation documents

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
