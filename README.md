# TEE + MPC Protocol Implementation

This is a structured implementation of the TEE + MPC protocol for secure TLS communication with split AEAD processing.

## Project Structure

The codebase has been organized into separate folders for better maintainability:

```
tee-mpc/
├── tee_k/          # TEE_K service implementation
│   ├── main.go     # TEE_K service entry point
│   ├── tee_k.go    # TEE_K implementation
│   └── messages.go # Shared message types
├── tee_t/          # TEE_T service implementation
│   ├── main.go     # TEE_T service entry point
│   ├── tee_t.go    # TEE_T implementation
│   └── messages.go # Shared message types
├── client/         # Client implementation
│   ├── main.go     # Client entry point
│   ├── client.go   # Client implementation
│   └── messages.go # Shared message types
├── minitls/        # Shared TLS implementation
├── bin/            # Compiled executables (created by build.sh)
│   ├── tee_k       # TEE_K executable
│   ├── tee_t       # TEE_T executable
│   └── client      # Client executable
├── main.go         # Demo orchestrator
├── demo.sh         # Bash script for running demo
├── build.sh        # Build script for all services
├── go.mod          # Go module configuration
├── go.sum          # Go module dependencies  
└── README.md       # This file
```

## Usage

### Building the Services

First, build all services (recommended for better process control):

```bash
./build.sh
```

This creates compiled executables in the `bin/` folder.

### Running the Demo

The demo can be started in two ways:

#### Option 1: Using Go (builds and runs automatically)
```bash
go run . demo
```

#### Option 2: Using the bash script (recommended)
```bash
./demo.sh
```

Both methods will:
1. Build all services (if needed)
2. Start TEE_K service on port 8080  
3. Start TEE_T service on port 8081
4. Run the Client which connects to both services
5. Execute the full TEE + MPC protocol with example.com
6. Shut down all services gracefully with proper cleanup

### Running Individual Services

Each service can be run independently:

#### Option A: Using compiled executables (recommended)
```bash
./bin/tee_k [port]       # Default port: 8080
./bin/tee_t [port]       # Default port: 8081  
./bin/client [teek_url]  # Default: ws://localhost:8080/ws
```

#### Option B: Using go run from service folders
```bash
cd tee_k && go run . [port]          # Default port: 8080
cd tee_t && go run . [port]          # Default port: 8081
cd client && go run . [teek_url]     # Default: ws://localhost:8080/ws
```

## Protocol Overview

This implementation follows the TEE + MPC protocol as described in `tee+mpc.md`:

1. **Pre-initialization**: Establish secure channels between TEE_K, TEE_T, and Client
2. **TLS Handshake**: TEE_K establishes TLS connection with target website
3. **Request Handling**: Client sends redacted requests with split AEAD processing
4. **Response Handling**: Split AEAD verification and decryption of responses
5. **Transcript Generation**: Final transcript creation for proof verification

## Key Features

- **Split AEAD**: Encryption and authentication tag computation are separated between TEE_K and TEE_T
- **Request Redaction**: Sensitive data in requests can be redacted with XOR streams
- **Tag Verification**: Authentication tags are verified by TEE_T before decryption
- **Secure Channels**: WebSocket connections provide secure communication between components
- **Graceful Shutdown**: All services handle shutdown signals properly

## Dependencies

- Go 1.24.2 or later
- github.com/gorilla/websocket v1.5.3
- golang.org/x/crypto v0.39.0

## Development

The codebase maintains all original functionality while providing better organization:

- Each service is self-contained with its own entry point
- Shared dependencies (messages, minitls) are referenced from the root module
- Single go.mod file manages all dependencies 
- The original `go run . demo` command continues to work as expected

## Testing

To test the system:

```bash
# Build all services
./build.sh

# Test individual executables 
./bin/tee_k --help    # Should show usage
./bin/tee_t --help    # Should show usage
./bin/client --help   # Should show usage

# Test full demo
./demo.sh
# or
go run . demo
``` 