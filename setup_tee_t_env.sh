#!/bin/bash

# TEE_T Environment Configuration Script
# This script sets up the environment variables for TEE_T service
# with its own domain and KMS key separate from TEE_K

echo "Setting up TEE_T environment variables..."

# TEE_T specific configuration
export TEE_T_DOMAIN="tee-t.reclaimprotocol.org"
export TEE_T_KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/your-tee-t-kms-key-id"

# ACME configuration (shared with TEE_K)
export ACME_URL="https://acme-v02.api.letsencrypt.org/directory"

# TEE_T specific vsock configuration
export TEE_T_VSOCK_PARENT_CID="3"
export TEE_T_VSOCK_PORT="8002"
export TEE_T_VSOCK_FORWARD_PORT="8003"

# TEE_T HTTP server ports
export TEE_T_HTTP_PORT="8081"
export TEE_T_HTTPS_PORT="8444"

# TEE_K configuration (for reference)
export ENCLAVE_DOMAIN="tee-k.reclaimprotocol.org"
export KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/your-tee-k-kms-key-id"

# TEE_K specific vsock configuration
export ENCLAVE_VSOCK_PARENT_CID="3"
export ENCLAVE_VSOCK_PORT="8000"
export ENCLAVE_VSOCK_FORWARD_PORT="8001"

# TEE_K HTTP server ports
export HTTP_PORT="8080"
export HTTPS_PORT="8443"

echo "Environment variables set:"
echo "TEE_T Domain: $TEE_T_DOMAIN"
echo "TEE_T KMS Key: $TEE_T_KMS_KEY_ID"
echo "TEE_T HTTP Port: $TEE_T_HTTP_PORT"
echo "TEE_T HTTPS Port: $TEE_T_HTTPS_PORT"
echo "TEE_T Vsock Port: $TEE_T_VSOCK_PORT"
echo ""
echo "TEE_K Domain: $ENCLAVE_DOMAIN"
echo "TEE_K KMS Key: $KMS_KEY_ID"
echo "TEE_K HTTP Port: $HTTP_PORT"
echo "TEE_K HTTPS Port: $HTTPS_PORT"
echo "TEE_K Vsock Port: $ENCLAVE_VSOCK_PORT"
echo ""
echo "ACME URL: $ACME_URL"
echo ""
echo "Configuration complete. You can now run:"
echo "  ./bin/tee_k    # Starts TEE_K service"
echo "  ./bin/tee_t    # Starts TEE_T service" 