#!/bin/bash

echo "🔨 Building TEE + MPC services..."

# Create bin directory
mkdir -p bin

# Build all services
echo "  Building TEE_K..."
cd tee_k && go build -o ../bin/tee_k . && cd ..

echo "  Building TEE_T..."
cd tee_t && go build -o ../bin/tee_t . && cd ..

echo "  Building Client..."
cd client && go build -o ../bin/client . && cd ..

echo "  Building Proxy..."
cd proxy && go build -o ../bin/proxy . && cd ..

echo " All services built successfully!"
echo ""
echo "Executables available in bin/:"
ls -la bin/ 