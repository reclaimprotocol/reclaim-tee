# TEE_K WebSocket API Documentation

## Overview

The TEE_K service provides a WebSocket API for real-time coordination of the TEE MPC protocol. This API enables secure communication between the User, TEE_K, and TEE_T services for TLS handshake coordination and split AEAD operations.

## WebSocket Endpoint

```
ws://[tee-k-host]:[port]/ws?client_type=[user|tee_t]&session_id=[optional]
```

**Query Parameters:**
- `client_type`: Either "user" or "tee_t" to identify the client type
- `session_id`: Optional session identifier (auto-generated if not provided)

## Message Format

All WebSocket messages use the following JSON structure:

```json
{
  "type": "message_type",
  "session_id": "session_identifier",
  "data": { /* message-specific payload */ },
  "error": "error_message_if_any",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Message Types

### Session Management

#### `session_init`
**Direction:** User → TEE_K  
**Purpose:** Initialize a new TLS session and generate Client Hello

**Request Data:**
```json
{
  "hostname": "example.com",
  "port": 443,
  "sni": "example.com",
  "alpn_protocols": ["h2", "http/1.1"]
}
```

**Response:** `session_init_response`
```json
{
  "session_id": "session-123-456",
  "client_hello": [/* Client Hello bytes */],
  "status": "client_hello_ready"
}
```

### TLS Handshake Coordination

#### `server_hello`
**Direction:** User → TEE_K  
**Purpose:** Provide Server Hello response from website to complete TLS handshake

**Request Data:**
```json
{
  "server_hello_record": [/* Server Hello TLS record bytes */]
}
```

**Response:** `handshake_complete`
```json
{
  "status": "handshake_complete",
  "cipher_suite": 4865,
  "keys_ready": true
}
```

### Split AEAD Operations

#### `encrypt_request`
**Direction:** User → TEE_K  
**Purpose:** Request encryption of HTTP request data using split AEAD

**Request Data:**
```json
{
  "request_data": [/* HTTP request bytes */],
  "commitments": {
    "commitment_s": [/* commitment bytes */],
    "commitment_sp": [/* commitment prime bytes */]
  }
}
```

**Response:** `encrypt_response`
```json
{
  "encrypted_data": [/* encrypted request bytes */],
  "tag_secrets": [/* secrets for TEE_T tag computation */],
  "status": "encryption_ready"
}
```

#### `decrypt_request`
**Direction:** User → TEE_K  
**Purpose:** Request decryption stream for HTTP response

**Request Data:**
```json
{
  "response_length": 1024,
  "encrypted_data": [/* encrypted response bytes */]
}
```

**Response:** `decrypt_response`
```json
{
  "decryption_stream": [/* decryption keystream bytes */],
  "status": "decryption_ready"
}
```

### TEE_T Coordination

#### `tag_verify`
**Direction:** TEE_T → TEE_K  
**Purpose:** Report tag verification results

**Request Data:**
```json
{
  "verified": true,
  "error": "optional_error_message"
}
```

### Transcript Finalization

#### `finalize`
**Direction:** User → TEE_K  
**Purpose:** Finalize session and sign transcript

**Request Data:**
```json
{
  "request_count": 3
}
```

**Response:** `finalize_response`
```json
{
  "signed_transcript": [/* signed transcript bytes */],
  "tls_keys": {
    "client_write_key": [/* key bytes */],
    "server_write_key": [/* key bytes */],
    "client_write_iv": [/* IV bytes */],
    "server_write_iv": [/* IV bytes */],
    "cipher_suite": 4865
  },
  "status": "finalized"
}
```

### Error Handling

#### `error`
**Direction:** TEE_K → User/TEE_T  
**Purpose:** Report errors

```json
{
  "type": "error",
  "session_id": "session-123",
  "error": "Detailed error message",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Protocol Flow

### 1. Session Initialization
```
User → TEE_K: session_init
TEE_K → User: session_init_response (with Client Hello)
```

### 2. TLS Handshake
```
User → Website: Client Hello
Website → User: Server Hello
User → TEE_K: server_hello
TEE_K → User: handshake_complete
```

### 3. Request Processing
```
User → TEE_K: encrypt_request
TEE_K → User: encrypt_response
TEE_K → TEE_T: tag_request (internal)
TEE_T → TEE_K: tag_response (internal)
```

### 4. Response Processing
```
User → TEE_K: decrypt_request
TEE_T → TEE_K: tag_verify
TEE_K → User: decrypt_response
```

### 5. Finalization
```
User → TEE_K: finalize
TEE_K → User: finalize_response (with signed transcript)
```

## Connection Management

### Connection Lifecycle
1. **Establish:** Client connects to WebSocket endpoint
2. **Register:** Connection is registered with session ID
3. **Communicate:** Bidirectional message exchange
4. **Cleanup:** Connection is cleaned up on disconnect

### Connection Types
- **User Connections:** Handle TLS proxy and coordination
- **TEE_T Connections:** Handle tag computation coordination

### Heartbeat
- **Ping/Pong:** Automatic every 54 seconds
- **Timeout:** 60 seconds read deadline
- **Reconnection:** Client responsibility

## Security Considerations

### Message Validation
- All incoming messages are validated for structure and content
- Session IDs are verified against active sessions
- Data payloads are validated for required fields

### Connection Security
- WebSocket connections should use WSS (TLS) in production
- Origin checking should be implemented for production deployments
- Rate limiting should be applied to prevent abuse

### Key Material Handling
- TLS keys are only exposed during finalization
- Tag secrets are securely transmitted to TEE_T
- All sensitive data is zeroed after use

## Example Usage

See `examples/websocket_client_example.go` for a complete client implementation.

### Basic Connection
```go
conn, _, err := websocket.DefaultDialer.Dial("ws://localhost:8080/ws?client_type=user", nil)
if err != nil {
    log.Fatal("Connection failed:", err)
}
defer conn.Close()
```

### Send Message
```go
msg := WSMessage{
    Type: "session_init",
    Data: sessionInitData,
    Timestamp: time.Now(),
}
err := conn.WriteJSON(msg)
```

### Receive Message
```go
var msg WSMessage
err := conn.ReadJSON(&msg)
if err != nil {
    log.Printf("Read error: %v", err)
    return
}
```

## Error Codes

| Error | Description |
|-------|-------------|
| `invalid_message_format` | JSON parsing failed |
| `unknown_message_type` | Unsupported message type |
| `session_not_found` | Session ID not found |
| `session_not_ready` | Session not in correct state |
| `invalid_data_format` | Message data validation failed |
| `tls_handshake_failed` | TLS handshake error |
| `encryption_failed` | Split AEAD encryption error |
| `decryption_failed` | Split AEAD decryption error |

## Future Enhancements

- **Authentication:** JWT-based client authentication
- **Rate Limiting:** Per-connection message rate limits
- **Metrics:** Connection and message metrics
- **Load Balancing:** Multi-instance TEE_K coordination
- **Compression:** Message compression for large payloads 