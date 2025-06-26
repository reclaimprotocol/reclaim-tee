# TEE+MPC Protocol Implementation Makefile

.PHONY: build test demo help clean

# Build all components
build:
	@echo "Building TEE components..."
	go build -o bin/tee_k ./tee_k
	go build -o bin/tee_t ./tee_t  
	go build -o bin/demo ./demo.go
	@echo "Build complete"

# Run comprehensive tests
test:
	@echo "Running comprehensive tests..."
	go test ./enclave -v
	go test ./tee_k -v  
	go test ./tee_t -v
	@echo "Tests complete"

# Run the demo
demo:
	@echo "Running TEE+MPC Protocol Demo..."
	@echo "Please start services first:"
	@echo "  Terminal 1: PORT=8081 go run ./tee_t"
	@echo "  Terminal 2: PORT=8080 go run ./tee_k"
	@echo "  Terminal 3: go run demo.go \"ws://localhost:8080/ws?client_type=user\""
	@echo ""

# Clean up build artifacts
clean:
	@echo "Cleaning up..."
	@rm -rf bin/
	@echo "Cleanup complete"

# Help
help:
	@echo "TEE+MPC Protocol Implementation"
	@echo ""
	@echo "Available targets:"
	@echo "  build      - Build all components"
	@echo "  test       - Run all unit tests"
	@echo "  demo       - Show demo instructions"
	@echo "  clean      - Clean up build artifacts"
	@echo ""
	@echo "Quick Start:"
	@echo "  1. Terminal 1: PORT=8081 go run ./tee_t"
	@echo "  2. Terminal 2: PORT=8080 go run ./tee_k"
	@echo "  3. Terminal 3: go run demo.go \"ws://localhost:8080/ws?client_type=user\""
	@echo ""
	@echo "Testing:"
	@echo "  make test                     - Run all tests"
	@echo "  go test ./enclave -v          - Run enclave tests"
	@echo "  go test ./enclave -run TestTranscript -v  - Run transcript tests" 