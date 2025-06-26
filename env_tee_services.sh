#!/bin/bash

# TEE Services Environment Configuration
# This script sets up environment variables for both TEE_K and TEE_T services
# Each service has its own domain and KMS key

echo "Setting up TEE services environment variables..."

# Common ACME configuration
export ACME_URL="https://acme-v02.api.letsencrypt.org/directory"

# TEE_K Configuration
export ENCLAVE_DOMAIN="tee-k.reclaimprotocol.org"
export KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/tee-k-kms-key-id"
export ENCLAVE_VSOCK_PARENT_CID="3"
export ENCLAVE_VSOCK_PORT="8000"
export ENCLAVE_VSOCK_FORWARD_PORT="8001"
export HTTP_PORT="8080"
export HTTPS_PORT="8443"

# TEE_T Configuration (separate domain and KMS key)
export TEE_T_DOMAIN="tee-t.reclaimprotocol.org"
export TEE_T_KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/tee-t-kms-key-id"
export TEE_T_VSOCK_PARENT_CID="3"
export TEE_T_VSOCK_PORT="8002"
export TEE_T_VSOCK_FORWARD_PORT="8003"
export TEE_T_HTTP_PORT="8081"
export TEE_T_HTTPS_PORT="8444"

# Communication between TEE services
export TEE_T_URL="https://tee-t.reclaimprotocol.org"

echo ""
echo "Environment variables configured:"
echo ""
echo "TEE_K Service:"
echo "  Domain: $ENCLAVE_DOMAIN"
echo "  KMS Key: $KMS_KEY_ID"
echo "  HTTP Port: $HTTP_PORT"
echo "  HTTPS Port: $HTTPS_PORT"
echo "  Vsock Port: $ENCLAVE_VSOCK_PORT"
echo ""
echo "TEE_T Service:"
echo "  Domain: $TEE_T_DOMAIN"  
echo "  KMS Key: $TEE_T_KMS_KEY_ID"
echo "  HTTP Port: $TEE_T_HTTP_PORT"
echo "  HTTPS Port: $TEE_T_HTTPS_PORT"
echo "  Vsock Port: $TEE_T_VSOCK_PORT"
echo ""
echo "Shared:"
echo "  ACME URL: $ACME_URL"
echo "  TEE_T Communication URL: $TEE_T_URL"
echo ""
echo "Ready to start services:"
echo "  ./bin/tee_k    # TEE_K on $ENCLAVE_DOMAIN"
echo "  ./bin/tee_t    # TEE_T on $TEE_T_DOMAIN" 