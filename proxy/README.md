# TEE+MPC Unified Proxy

The unified proxy service routes traffic between external clients and AWS Nitro enclaves running TEE_K and TEE_T services. It provides secure, domain-based routing and supports ACME certificate challenges.

## Architecture

### Components

1. **HTTP Router** (Port 80) - Routes HTTP traffic based on Host header for ACME challenges
2. **HTTPS Router** (Port 443) - Routes HTTPS traffic based on SNI for client connections  
3. **KMS Proxy** (Port 5000) - Forwards KMS requests from enclaves to AWS KMS
4. **Internet Proxy** (Port 8444) - Allows enclaves to make outbound connections

### Domain Routing

- `tee-k.reclaimprotocol.org` → TEE_K Enclave (CID 16)
- `tee-t.reclaimprotocol.org` → TEE_T Enclave (CID 17)

### Port Mapping

#### External Ports (Proxy)
- `:80` - HTTP traffic (ACME challenges)
- `:443` - HTTPS traffic (client connections + inter-TEE communication)
- `:5000` - KMS proxy (VSock listener for enclaves)
- `:8444` - Internet proxy (VSock listener for enclaves)

#### Enclave Ports (Both TEE_K and TEE_T)
- `8080` - HTTP server (ACME challenges)
- `8443` - HTTPS server (client traffic)
- `5000` - KMS client (outbound to proxy)
- `8444` - Internet client (outbound to proxy)

## Configuration

### Environment Variables

- `PROXY_CONFIG` - Path to configuration file (default: `proxy-config.json`)
- `TEE_K_KMS_KEY` - KMS key ARN for TEE_K enclave
- `TEE_T_KMS_KEY` - KMS key ARN for TEE_T enclave
- `AWS_REGION` - AWS region (default: `ap-south-1`)

### Configuration File Format

```json
{
  "domains": {
    "tee-k.reclaimprotocol.org": {
      "cid": 16,
      "kms_key": "arn:aws:kms:region:account:key/tee-k-key"
    },
    "tee-t.reclaimprotocol.org": {
      "cid": 17,
      "kms_key": "arn:aws:kms:region:account:key/tee-t-key"
    }
  },
  "aws": {
    "region": "ap-south-1"
  },
  "ports": {
    "http": 80,
    "https": 443,
    "kms": 5000,
    "internet": 8444
  }
}
```

## Traffic Flow

### ACME Certificate Challenge
```
Let's Encrypt → Proxy:80 → Host Header → TEE_K/TEE_T:8080
```

### Client HTTPS Connection
```
Client → Proxy:443 → SNI → TEE_K:8443
```

### Inter-TEE Communication
```
TEE_K → Proxy:8444 → Internet → Proxy:443 → SNI → TEE_T:8443
```

### KMS Request
```
TEE_K/TEE_T:5000 → Proxy:5000 → AWS KMS
```

## Building and Running

### Build Locally
```bash
cd proxy
go build -o proxy .
```

### Build with Docker
```bash
cd proxy
docker build -t tee-proxy .
```

### Run
```bash
# Local
./proxy

# Docker
docker run -p 80:80 -p 443:443 -p 5000:5000 -p 8444:8444 \
  -v $(pwd)/proxy-config.json:/root/proxy-config.json \
  tee-proxy
```

## Security Features

1. **Domain Isolation** - Each enclave only handles its own domain
2. **KMS Key Separation** - TEE_K and TEE_T use different KMS keys
3. **SNI-based Routing** - Secure HTTPS routing without terminating TLS
4. **Timeout Protection** - Reasonable timeouts for all connections
5. **Connection Validation** - Validates target addresses and formats

## Monitoring

The proxy logs all routing decisions and connection events:

- HTTP/HTTPS routing decisions with domain/SNI information
- KMS operations with operation types and success/failure
- Internet proxy connections with target addresses
- Connection timeouts and errors

## Troubleshooting

### Common Issues

1. **VSock Connection Failed** - Check that enclaves are running and CIDs are correct
2. **SNI Extraction Failed** - Verify TLS ClientHello contains SNI extension
3. **KMS Operation Failed** - Check AWS credentials and KMS key permissions
4. **Domain Not Found** - Verify domain configuration matches requests

### Debug Logging

Set log level to debug for verbose connection information:
```bash
PROXY_LOG_LEVEL=debug ./proxy
```

## Integration with Enclaves

The proxy expects enclaves to:

1. **Listen on Standard Ports** - Port 8080 (HTTP) and 8443 (HTTPS)
2. **Use KMS Proxy** - Connect to VSock port 5000 for KMS operations
3. **Use Internet Proxy** - Connect to VSock port 8444 for outbound connections
4. **Send Target Address** - For internet proxy, send "hostname:port\n" format

### Example Enclave Code

```go
// KMS request
conn, err := vsock.Dial(3, 5000, nil)
kmsRequest := KMSRequest{Operation: "GenerateDataKey", Input: input}
json.NewEncoder(conn).Encode(kmsRequest)

// Internet connection
conn, err := vsock.Dial(3, 8444, nil)
fmt.Fprintf(conn, "%s\n", "tee-t.reclaimprotocol.org:443")
``` 