#!/bin/bash

set -e

echo "Building libreclaim shared library..."

# Build the shared library
cd ../lib
make clean
make all

echo "Shared library built successfully!"

# Build the sample application
cd ../sample_app_cgo
echo "Building sample application..."

# Set environment variables for CGO
export CGO_ENABLED=1
export CGO_CFLAGS="-I../lib"
export CGO_LDFLAGS="-L../lib -lreclaim"

# Build the application
go build -o sample_app_cgo main.go

echo "Sample application built successfully!"
echo "Run with: ./sample_app_cgo" 