#!/bin/bash

echo "=== TEE + MPC Protocol - Demo Script ==="
echo ""
echo "This will start TEE_K and TEE_T services in standalone mode, then connect a Client to both."
echo "The Client will request TEE_K to make a TLS connection with split AEAD protocol."
echo ""

# Build all services first
echo "🔨 Building services..."
./build.sh
if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi
echo " All services built successfully"
echo ""

# Function to cleanup processes
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    if [ ! -z "$TEEK_PID" ] && kill -0 $TEEK_PID 2>/dev/null; then
        kill $TEEK_PID 2>/dev/null
        wait $TEEK_PID 2>/dev/null
    fi
    if [ ! -z "$TEET_PID" ] && kill -0 $TEET_PID 2>/dev/null; then
        kill $TEET_PID 2>/dev/null
        wait $TEET_PID 2>/dev/null
    fi
    echo " Demo completed"
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start TEE_K service in standalone mode
echo "🚀 Starting TEE_K service (standalone mode, port 8080)..."
ENCLAVE_MODE=false ./bin/tee_k > /tmp/demo_teek.log 2>&1 &
TEEK_PID=$!

# Start TEE_T service in standalone mode
echo "🚀 Starting TEE_T service (standalone mode, port 8081)..."
ENCLAVE_MODE=false ./bin/tee_t > /tmp/demo_teet.log 2>&1 &
TEET_PID=$!

# Wait for services to start
echo "⏳ Waiting for services to initialize..."
sleep 3

# Check if services are still running
if ! kill -0 $TEEK_PID 2>/dev/null; then
    echo "❌ TEE_K service failed to start"
    echo "TEE_K log:"
    cat /tmp/demo_teek.log
    cleanup
    exit 1
fi

if ! kill -0 $TEET_PID 2>/dev/null; then
    echo "❌ TEE_T service failed to start"
    echo "TEE_T log:"
    cat /tmp/demo_teet.log
    cleanup
    exit 1
fi

echo " Services are ready"
echo "   TEE_K running on port 8080 (PID: $TEEK_PID)"
echo "   TEE_T running on port 8081 (PID: $TEET_PID)"
echo ""

# Start Client and wait for completion
echo "🚀 Starting Client..."
echo "   Connecting to TEE_K at ws://localhost:8080/ws"
echo ""
./bin/client ws://localhost:8080/ws
CLIENT_EXIT_CODE=$?

echo ""
echo "🎯 Client finished with exit code: $CLIENT_EXIT_CODE"

# Show service logs if client failed
if [ $CLIENT_EXIT_CODE -ne 0 ]; then
    echo ""
    echo "📋 Service logs for debugging:"
    echo "--- TEE_K log ---"
    cat /tmp/demo_teek.log
    echo ""
    echo "--- TEE_T log ---"
    cat /tmp/demo_teet.log
fi

# Client completed, cleanup and exit
cleanup

# Clean up log files
rm -f /tmp/demo_*.log

exit $CLIENT_EXIT_CODE
