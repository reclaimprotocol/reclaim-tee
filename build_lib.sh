#!/bin/bash

echo "🔨 Building libreclaim shared library and sample application..."

# Create bin directory
mkdir -p bin

# Build the shared library
echo "  Building libreclaim library..."
cd libreclaim && go build -o ../bin/libreclaim.a . && cd ..

# Build the sample application
echo "  Building sample application..."
cd sample_app && go build -o ../bin/sample_app . && cd ..

echo " All components built successfully!"
echo ""
echo "Executables available in bin/:"
ls -la bin/
echo ""
echo "To run the sample application:"
echo "  ./bin/sample_app"
echo ""
echo "Note: The library currently contains placeholder implementations."
echo "To integrate with the actual client code, you'll need to:"
echo "  1. Import the client package in libreclaim"
echo "  2. Replace placeholder implementations with actual client calls"
echo "  3. Handle the protocol state management properly" 