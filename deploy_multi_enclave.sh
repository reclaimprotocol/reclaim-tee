#!/bin/bash

# Multi-Enclave TEE Deployment Script
# Production-ready script for deploying TEE_K and TEE_T on different enclaves

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_info "Starting Multi-Enclave TEE Deployment"

# Validate environment
if [ ! -f "go.mod" ]; then
    log_error "Not in reclaim-tee root directory"
    exit 1
fi

# Configuration - Override these in environment
TEE_K_DOMAIN="${TEE_K_DOMAIN:-tee-k.reclaimprotocol.org}"
TEE_T_DOMAIN="${TEE_T_DOMAIN:-tee-t.reclaimprotocol.org}"
TEE_K_CID="${TEE_K_CID:-16}"
TEE_T_CID="${TEE_T_CID:-17}"
KMS_REGION="${KMS_REGION:-us-east-1}"

# Build all components
log_info "Building TEE services and enhanced proxy..."

# Build TEE_K service
if ! go build -o bin/tee_k ./tee_k; then
    log_error "Failed to build TEE_K service"
    exit 1
fi
log_success "TEE_K service built successfully"

# Build TEE_T service
if ! go build -o bin/tee_t ./tee_t; then
    log_error "Failed to build TEE_T service"
    exit 1
fi
log_success "TEE_T service built successfully"

# Build enhanced proxy
if ! (cd proxy && go build -o ../bin/enhanced-proxy .); then
    log_error "Failed to build enhanced proxy"
    exit 1
fi
log_success "Enhanced proxy built successfully"

# Build demo clients
if ! go build -o bin/demo-client ./cmd/demo-client; then
    log_error "Failed to build demo client"
    exit 1
fi

if ! go build -o bin/test-demo ./cmd/test-demo; then
    log_error "Failed to build test demo"
    exit 1
fi
log_success "Demo clients built successfully"

# Create configuration files
log_info "Creating configuration files..."

# Enhanced proxy configuration
cat > config/enhanced_proxy.env << EOF
# Enhanced Proxy Configuration for Multi-Enclave Setup

# Domain routing
TEE_K_DOMAIN=${TEE_K_DOMAIN}
TEE_T_DOMAIN=${TEE_T_DOMAIN}

# Enclave CIDs (set these to your actual enclave CIDs)
TEE_K_CID=${TEE_K_CID}
TEE_T_CID=${TEE_T_CID}

# Proxy configuration
VSOCK_PORT=5000
PROXY_TIMEOUT=30s
MAX_REQUEST_SIZE=40960

# AWS configuration
AWS_REGION=${KMS_REGION}
EOF

# TEE_K configuration
cat > config/tee_k.env << EOF
# TEE_K Service Configuration

# Service identity
ENCLAVE_DOMAIN=${TEE_K_DOMAIN}
KMS_KEY_ID=${TEE_K_KMS_KEY_ID:-arn:aws:kms:${KMS_REGION}:123456789012:key/tee-k-key-id}

# Network configuration
ENCLAVE_VSOCK_PARENT_CID=3
ENCLAVE_VSOCK_PORT=8000
ENCLAVE_VSOCK_FORWARD_PORT=8001

# Server ports
HTTP_PORT=8080
HTTPS_PORT=8443

# ACME configuration
ACME_URL=https://acme-v02.api.letsencrypt.org/directory

# TEE_T coordination
TEE_T_URL=https://${TEE_T_DOMAIN}
EOF

# TEE_T configuration
cat > config/tee_t.env << EOF
# TEE_T Service Configuration

# Service identity
TEE_T_DOMAIN=${TEE_T_DOMAIN}
TEE_T_KMS_KEY_ID=${TEE_T_KMS_KEY_ID:-arn:aws:kms:${KMS_REGION}:123456789012:key/tee-t-key-id}

# Network configuration
TEE_T_VSOCK_PARENT_CID=3
TEE_T_VSOCK_PORT=8002
TEE_T_VSOCK_FORWARD_PORT=8003

# Server ports
TEE_T_HTTP_PORT=8081
TEE_T_HTTPS_PORT=8444

# ACME configuration
ACME_URL=https://acme-v02.api.letsencrypt.org/directory
EOF

log_success "Configuration files created in config/ directory"

# Create deployment scripts
log_info "Creating deployment scripts..."

# Enhanced proxy runner
cat > scripts/run_enhanced_proxy.sh << 'EOF'
#!/bin/bash
set -euo pipefail

source config/enhanced_proxy.env

echo "Starting Enhanced Proxy with Multi-Enclave Support"
echo "TEE_K: ${TEE_K_DOMAIN} -> CID ${TEE_K_CID} (HTTP:8000, HTTPS:8001)"
echo "TEE_T: ${TEE_T_DOMAIN} -> CID ${TEE_T_CID} (HTTP:8002, HTTPS:8003)"
echo "Listening on: :80 (HTTP), :443 (HTTPS)"

exec bin/enhanced-proxy
EOF

# TEE_K runner
cat > scripts/run_tee_k.sh << 'EOF'
#!/bin/bash
set -euo pipefail

source config/tee_k.env

echo "Starting TEE_K service on ${ENCLAVE_DOMAIN}"
echo "Enclave vsock ports: ${ENCLAVE_VSOCK_PORT} (HTTP), ${ENCLAVE_VSOCK_FORWARD_PORT} (HTTPS)"

exec bin/tee_k
EOF

# TEE_T runner
cat > scripts/run_tee_t.sh << 'EOF'
#!/bin/bash
set -euo pipefail

source config/tee_t.env

echo "Starting TEE_T service on ${TEE_T_DOMAIN}"
echo "Enclave vsock ports: ${TEE_T_VSOCK_PORT} (HTTP), ${TEE_T_VSOCK_FORWARD_PORT} (HTTPS)"

exec bin/tee_t
EOF

# Make scripts executable
chmod +x scripts/*.sh

log_success "Deployment scripts created in scripts/ directory"

# Create production checklist
cat > DEPLOYMENT_CHECKLIST.md << EOF
# Multi-Enclave TEE Deployment Checklist

## Pre-deployment Requirements

### 1. AWS Infrastructure
- [ ] KMS keys created for TEE_K and TEE_T
- [ ] IAM roles configured with KMS permissions
- [ ] Security groups allowing port 80/443
- [ ] DNS records pointing to EC2 instance

### 2. Enclave Setup
- [ ] TEE_K enclave launched with CID ${TEE_K_CID}
- [ ] TEE_T enclave launched with CID ${TEE_T_CID}
- [ ] Vsock communication verified between parent and enclaves

### 3. Certificate Configuration
- [ ] ACME challenges will be routed correctly
- [ ] Domain validation can reach appropriate enclaves
- [ ] Certificate storage configured in enclaves

## Deployment Steps

### 1. Deploy Enhanced Proxy (on EC2 parent)
\`\`\`bash
# Set actual enclave CIDs
export TEE_K_CID=<actual_tee_k_cid>
export TEE_T_CID=<actual_tee_t_cid>

# Set KMS key ARNs
export TEE_K_KMS_KEY_ID=<actual_tee_k_kms_key_arn>
export TEE_T_KMS_KEY_ID=<actual_tee_t_kms_key_arn>

# Start enhanced proxy
scripts/run_enhanced_proxy.sh
\`\`\`

### 2. Deploy TEE_K Service (in TEE_K enclave)
\`\`\`bash
scripts/run_tee_k.sh
\`\`\`

### 3. Deploy TEE_T Service (in TEE_T enclave)
\`\`\`bash
scripts/run_tee_t.sh
\`\`\`

## Verification Steps

### 1. Service Health Checks
\`\`\`bash
# Check TEE_K health
curl https://${TEE_K_DOMAIN}/status

# Check TEE_T health
curl https://${TEE_T_DOMAIN}/status

# Check TEE_K metrics
curl https://${TEE_K_DOMAIN}/metrics

# Check TEE_T metrics
curl https://${TEE_T_DOMAIN}/metrics
\`\`\`

### 2. Certificate Verification
\`\`\`bash
# Verify TEE_K certificate
openssl s_client -connect ${TEE_K_DOMAIN}:443 -servername ${TEE_K_DOMAIN}

# Verify TEE_T certificate
openssl s_client -connect ${TEE_T_DOMAIN}:443 -servername ${TEE_T_DOMAIN}
\`\`\`

### 3. Redaction Protocol Test
\`\`\`bash
# Run demo clients
bin/demo-client
bin/test-demo
\`\`\`

## Security Considerations

- [ ] KMS keys have proper access policies
- [ ] Enclave measurements verified
- [ ] TLS certificates are properly validated
- [ ] Inter-enclave communication is authenticated
- [ ] Logs are properly configured and monitored

## Monitoring

- [ ] CloudWatch logs configured
- [ ] Metrics collection enabled
- [ ] Alerting set up for service failures
- [ ] Certificate expiration monitoring

## Configuration Files

- \`config/enhanced_proxy.env\` - Proxy configuration
- \`config/tee_k.env\` - TEE_K service configuration
- \`config/tee_t.env\` - TEE_T service configuration

## Deployment Scripts

- \`scripts/run_enhanced_proxy.sh\` - Start enhanced proxy
- \`scripts/run_tee_k.sh\` - Start TEE_K service
- \`scripts/run_tee_t.sh\` - Start TEE_T service
EOF

log_success "Deployment checklist created: DEPLOYMENT_CHECKLIST.md"

# Summary
log_info "Deployment Summary:"
echo "  📦 Built Services:"
echo "    - TEE_K service (bin/tee_k)"
echo "    - TEE_T service (bin/tee_t)"
echo "    - Enhanced proxy (bin/enhanced-proxy)"
echo "    - Demo clients (bin/demo-client, bin/test-demo)"
echo ""
echo "  ⚙️  Configuration:"
echo "    - TEE_K Domain: ${TEE_K_DOMAIN} -> CID ${TEE_K_CID}"
echo "    - TEE_T Domain: ${TEE_T_DOMAIN} -> CID ${TEE_T_CID}"
echo ""
echo "  📁 Created Files:"
echo "    - config/enhanced_proxy.env"
echo "    - config/tee_k.env"
echo "    - config/tee_t.env"
echo "    - scripts/run_*.sh"
echo "    - DEPLOYMENT_CHECKLIST.md"
echo ""

log_success "Multi-enclave deployment preparation complete!"
log_info "Next steps:"
echo "  1. Review DEPLOYMENT_CHECKLIST.md"
echo "  2. Set actual KMS key ARNs and enclave CIDs"
echo "  3. Deploy enhanced proxy on EC2 parent"
echo "  4. Deploy services in respective enclaves"
echo "  5. Run verification tests"
</rewritten_file> 