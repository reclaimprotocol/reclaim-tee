#!/bin/bash

set -euo pipefail

echo "🔨 Building TEE + MPC services..."

# Create bin directory
mkdir -p bin

# Generate Go code from protobufs
echo "  Generating Go protobufs..."
protoc -I proto --go_out=proto/ --go_opt=paths=source_relative proto/*.proto || { echo "protoc failed"; exit 1; }

# Build all services
echo "  Building TEE_K..."
cd tee_k && go build -o ../bin/tee_k . && cd ..

echo "  Building TEE_T..."
cd tee_t && go build -o ../bin/tee_t . && cd ..

echo "  Building Client..."
cd demo && go build -o ../bin/client . && cd ..

echo "  Building Proxy..."
cd proxy && go mod download && go build -o ../bin/proxy . && cd ..

echo " All services built successfully!"
echo ""
echo "Executables available in bin/:"
ls -la bin/ 