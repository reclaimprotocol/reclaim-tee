# TEE Redaction Protocol Demo Makefile

.PHONY: build test test-demo help clean

# Build all components
build:
	@echo "Building TEE components..."
	go build -o bin/tee_k ./tee_k
	go build -o bin/tee_t ./tee_t  
	go build -o bin/demo-client ./cmd/demo-client
	go build -o bin/test-demo ./cmd/test-demo
	@echo "Build complete"

# Run comprehensive tests
test:
	@echo "Running comprehensive tests..."
	go test ./enclave -v
	go test ./tee_k -v  
	go test ./tee_t -v
	@echo "Tests complete"

# Run the local redaction logic test
test-demo:
	@echo "Running redaction protocol test..."
	@go run ./cmd/test-demo
	@echo "Protocol test complete"

# Clean up build artifacts
clean:
	@echo "Cleaning up..."
	@rm -rf bin/
	@echo "Cleanup complete"

# Help
help:
	@echo "TEE Redaction Protocol Demo"
	@echo ""
	@echo "Available targets:"
	@echo "  build      - Build all components"
	@echo "  test       - Run all unit tests"
	@echo "  test-demo  - Run redaction protocol logic test"
	@echo "  clean      - Clean up build artifacts"
	@echo ""
	@echo "Manual Demo Steps:"
	@echo "  1. Terminal 1: PORT=8080 go run ./tee_k"
	@echo "  2. Terminal 2: PORT=8081 go run ./tee_t"
	@echo "  3. Terminal 3: go run ./cmd/demo-client"
	@echo ""
	@echo "Individual service targets:"
	@echo "  PORT=8080 go run ./tee_k  - Start TEE_K on :8080 (demo mode)"
	@echo "  PORT=8081 go run ./tee_t  - Start TEE_T on :8081 (demo mode)" 