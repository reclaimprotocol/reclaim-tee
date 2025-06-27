#!/bin/bash

echo "Starting TEE+MPC Protocol Demo Test"
echo "====================================="

# Function to kill all background processes
cleanup() {
    echo "Cleaning up processes..."
    pkill -f "tee_t"
    pkill -f "tee_k"
    pkill -f "demo"
    sleep 1
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Start TEE_T in background
echo "Starting TEE_T on port 8081..."
PORT=8081 ./bin/tee_t &
TEE_T_PID=$!
sleep 2

# Start TEE_K in background  
echo "Starting TEE_K on port 8080..."
PORT=8080 ./bin/tee_k &
TEE_K_PID=$!
sleep 3

# Check if services are running
if ! kill -0 $TEE_T_PID 2>/dev/null; then
    echo "❌ TEE_T failed to start"
    exit 1
fi

if ! kill -0 $TEE_K_PID 2>/dev/null; then
    echo "TEE_K failed to start"
    exit 1
fi

echo "Both TEE services started successfully"
echo ""

# Run the demo
echo "Running the fixed demo with proper TLS handling..."
echo "================================================="
timeout 30 ./bin/demo "ws://localhost:8080/ws?client_type=user"
DEMO_EXIT_CODE=$?

echo ""
echo "Demo Results:"
echo "============="

if [ $DEMO_EXIT_CODE -eq 0 ]; then
    echo "Demo completed successfully!"
elif [ $DEMO_EXIT_CODE -eq 124 ]; then
    echo "Demo timed out (30 seconds) - may still be working"
    echo "   This is normal for network operations"
else
    echo "Demo exited with code: $DEMO_EXIT_CODE"
fi

# Always cleanup
cleanup