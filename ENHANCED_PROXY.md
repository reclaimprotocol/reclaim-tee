# Enhanced Proxy with Domain Routing

The proxy has been enhanced to support multi-domain routing without breaking existing functionality.

## Features

### Domain-Based Routing
- **HTTP Routing**: Inspects `Host` header to route requests
- **HTTPS Routing**: Uses SNI (Server Name Indication) extraction from TLS ClientHello
- **Configurable**: Domain mappings configured via environment variables

### Supported Services
- **TEE_K Service**: `tee-k.reclaimprotocol.org`
  - Enclave CID: Configurable via `TEE_K_CID` (default: 16)
  - HTTP: vsock port 8000
  - HTTPS: vsock port 8001
- **TEE_T Service**: `tee-t.reclaimprotocol.org`
  - Enclave CID: Configurable via `TEE_T_CID` (default: 17)
  - HTTP: vsock port 8002
  - HTTPS: vsock port 8003

### Backward Compatibility
- Existing vsock proxy functionality preserved
- Default routing to original ports when no domain match
- All existing tests pass

## Architecture

### Network Flow
```
Internet → EC2:443 → Enhanced Proxy → SNI Router → {
  tee-k.reclaimprotocol.org → CID 16:8001 (TEE_K HTTPS)
  tee-t.reclaimprotocol.org → CID 17:8003 (TEE_T HTTPS)
}

Internet → EC2:80 → Enhanced Proxy → Host Router → {
  tee-k.reclaimprotocol.org → CID 16:8000 (TEE_K HTTP)
  tee-t.reclaimprotocol.org → CID 17:8002 (TEE_T HTTP)
}
```

### Components
- **DomainRouter**: Maps domains to vsock ports
- **SNIExtractor**: Extracts domain from TLS ClientHello
- **ConnectionRouter**: Routes HTTPS connections based on SNI
- **BufferedConnection**: Replays peeked TLS data

## Usage

### Configuration
Set environment variables:
```bash
export TEE_K_DOMAIN="tee-k.reclaimprotocol.org"
export TEE_T_DOMAIN="tee-t.reclaimprotocol.org"
export TEE_K_CID=16  # Set to your TEE_K enclave CID
export TEE_T_CID=17  # Set to your TEE_T enclave CID
```

### Running
```bash
# Use the convenience script
./run_enhanced_proxy.sh

# Or run directly
cd proxy && go run .
```

### Building
```bash
cd proxy && go build -o enhanced-proxy .
```

## Implementation Details

### SNI Extraction
- Parses TLS ClientHello packet structure
- Extracts Server Name Indication extension (type 0x00)
- Handles variable-length fields properly
- Falls back gracefully if SNI not present

### Connection Handling
- Peeks at connection data without consuming it
- Creates wrapper connections that replay buffered data
- Maintains full compatibility with existing connection handling

### HTTP Host Routing
- Parses HTTP headers to find Host field
- Strips port numbers from domain names
- Case-insensitive header matching
- Preserves all request data through buffered readers

## Files Modified/Added

### New Files
- `proxy/domain_router.go` - Domain routing functionality
- `run_enhanced_proxy.sh` - Convenience runner script

### Modified Files
- `proxy/proxy.go` - Enhanced with domain routing
  - Added domain router initialization
  - New HTTP/HTTPS connection handlers
  - Domain-aware routing logic

## Testing

All existing tests pass:
```bash
go test ./...
```

The enhanced proxy maintains full backward compatibility while adding multi-domain support. 