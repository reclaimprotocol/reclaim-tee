#!/bin/bash

# Enhanced Proxy Runner
# This script runs the enhanced proxy with domain routing support

echo "Starting Enhanced Proxy with Domain Routing..."

# Set domain routing environment variables
export TEE_K_DOMAIN="tee-k.reclaimprotocol.org"
export TEE_T_DOMAIN="tee-t.reclaimprotocol.org"

# Set enclave CIDs (you'll set these based on your enclave deployment)
export TEE_K_CID=16  # Default CID for TEE_K enclave
export TEE_T_CID=17  # Default CID for TEE_T enclave

# Set other proxy configuration
export VSOCK_PORT=5000
export PROXY_TIMEOUT=30s
export MAX_REQUEST_SIZE=40960

# Display configuration
echo "Configuration:"
echo "  TEE_K Domain: $TEE_K_DOMAIN -> CID $TEE_K_CID, ports 8000 (HTTP), 8001 (HTTPS)"
echo "  TEE_T Domain: $TEE_T_DOMAIN -> CID $TEE_T_CID, ports 8002 (HTTP), 8003 (HTTPS)"
echo "  Listening on: :80 (HTTP), :443 (HTTPS)"
echo "  VSock proxy: port 5000"
echo ""

# Build if needed
if [ ! -f proxy/enhanced-proxy ]; then
    echo "Building enhanced proxy..."
    cd proxy && go build -o enhanced-proxy . && cd ..
fi

# Run the enhanced proxy
echo "Starting proxy..."
exec proxy/enhanced-proxy 