#!/bin/bash

set -e

echo "Building sample application with shared library..."

# Set environment variables for CGO
export CGO_ENABLED=1
export CGO_CFLAGS="-I."
export CGO_LDFLAGS="-L../lib -lreclaim"

# Build the application
go build -o sample_app_shared main.go

echo "Sample application built successfully!"
echo "Run with: ./sample_app_shared" 