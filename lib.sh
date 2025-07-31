#!/bin/bash

# TEE+MPC Shared Library Build and Run Script
# This script automates the complete build and run process for the shared library and sample app

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LIB_DIR="lib"
SAMPLE_APP_DIR="sample_app_shared"
LIB_NAME="libreclaim.so"
SAMPLE_APP_NAME="sample_app_shared"
BUILD_DIR="build"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check dependencies
check_dependencies() {
    print_status "Checking dependencies..."
    
    local missing_deps=()
    
    if ! command_exists go; then
        missing_deps+=("go")
    fi
    
    if ! command_exists gcc; then
        missing_deps+=("gcc")
    fi
    
    if ! command_exists make; then
        missing_deps+=("make")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_error "Please install the missing dependencies and try again."
        exit 1
    fi
    
    print_success "All dependencies found"
}

# Function to clean previous builds
clean_builds() {
    print_status "Cleaning previous builds..."
    
    # Clean lib build
    if [ -d "$LIB_DIR" ]; then
        cd "$LIB_DIR"
        make clean >/dev/null 2>&1 || true
        cd ..
    fi
    
    # Clean sample app build
    if [ -f "$SAMPLE_APP_DIR/$SAMPLE_APP_NAME" ]; then
        rm -f "$SAMPLE_APP_DIR/$SAMPLE_APP_NAME"
    fi
    
    # Clean build directory
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
    
    print_success "Cleanup completed"
}

# Function to build the shared library
build_library() {
    print_status "Building shared library..."
    
    if [ ! -d "$LIB_DIR" ]; then
        print_error "Library directory '$LIB_DIR' not found"
        exit 1
    fi
    
    cd "$LIB_DIR"
    
    # Build the library
    if make all; then
        print_success "Shared library built successfully"
        
        # Verify the library was created
        if [ -f "$LIB_NAME" ]; then
            print_status "Library file: $(pwd)/$LIB_NAME"
            print_status "Library size: $(du -h "$LIB_NAME" | cut -f1)"
        else
            print_error "Library file not found after build"
            exit 1
        fi
    else
        print_error "Failed to build shared library"
        exit 1
    fi
    
    cd ..
}

# Function to build the sample application
build_sample_app() {
    print_status "Building sample application..."
    
    if [ ! -d "$SAMPLE_APP_DIR" ]; then
        print_error "Sample app directory '$SAMPLE_APP_DIR' not found"
        exit 1
    fi
    
    cd "$SAMPLE_APP_DIR"
    
    # Set environment variables for CGO
    export CGO_ENABLED=1
    export CGO_CFLAGS="-I."
    export CGO_LDFLAGS="-L../lib -lreclaim"
    
    print_status "CGO Environment:"
    print_status "  CGO_ENABLED=$CGO_ENABLED"
    print_status "  CGO_CFLAGS=$CGO_CFLAGS"
    print_status "  CGO_LDFLAGS=$CGO_LDFLAGS"
    
    # Build the application
    if go build -o "$SAMPLE_APP_NAME" main.go; then
        print_success "Sample application built successfully"
        
        # Verify the app was created
        if [ -f "$SAMPLE_APP_NAME" ]; then
            print_status "Application file: $(pwd)/$SAMPLE_APP_NAME"
            print_status "Application size: $(du -h "$SAMPLE_APP_NAME" | cut -f1)"
        else
            print_error "Application file not found after build"
            exit 1
        fi
    else
        print_error "Failed to build sample application"
        exit 1
    fi
    
    cd ..
}

# Function to run the sample application
run_sample_app() {
    print_status "Running sample application..."
    
    if [ ! -f "$SAMPLE_APP_DIR/$SAMPLE_APP_NAME" ]; then
        print_error "Sample application not found. Please build first."
        exit 1
    fi
    
    # Set library path
    export LD_LIBRARY_PATH="$LIB_DIR:$LD_LIBRARY_PATH"
    
    print_status "Library path: $LD_LIBRARY_PATH"
    
    # Run the application
    cd "$SAMPLE_APP_DIR"
    
    print_status "Starting sample application..."
    echo "=========================================="
    
    if ./"$SAMPLE_APP_NAME"; then
        echo "=========================================="
        print_success "Sample application completed successfully"
    else
        echo "=========================================="
        print_error "Sample application failed"
        exit 1
    fi
    
    cd ..
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  build     Build the shared library and sample application"
    echo "  run       Run the sample application (builds if needed)"
    echo "  clean     Clean all build artifacts"
    echo "  install   Install the shared library to system directories"
    echo "  test      Run tests for the shared library"
    echo "  info      Show information about the built library"
    echo "  all       Build and run (default if no option provided)"
    echo "  help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0          # Build and run"
    echo "  $0 build    # Build only"
    echo "  $0 run      # Run only (builds if needed)"
    echo "  $0 clean    # Clean builds"
}

# Function to install library
install_library() {
    print_status "Installing shared library..."
    
    if [ ! -f "$LIB_DIR/$LIB_NAME" ]; then
        print_error "Library not found. Please build first."
        exit 1
    fi
    
    cd "$LIB_DIR"
    
    if make install; then
        print_success "Library installed successfully"
    else
        print_error "Failed to install library"
        exit 1
    fi
    
    cd ..
}

# Function to run tests
run_tests() {
    print_status "Running library tests..."
    
    if [ ! -f "$LIB_DIR/$LIB_NAME" ]; then
        print_error "Library not found. Please build first."
        exit 1
    fi
    
    cd "$LIB_DIR"
    
    if make test; then
        print_success "Tests completed successfully"
    else
        print_error "Tests failed"
        exit 1
    fi
    
    cd ..
}

# Function to show library info
show_info() {
    print_status "Library information..."
    
    if [ ! -f "$LIB_DIR/$LIB_NAME" ]; then
        print_error "Library not found. Please build first."
        exit 1
    fi
    
    cd "$LIB_DIR"
    
    if make info; then
        print_success "Library information displayed"
    else
        print_error "Failed to get library information"
        exit 1
    fi
    
    cd ..
}

# Main script logic
main() {
    local action="${1:-all}"
    
    case "$action" in
        "build")
            check_dependencies
            clean_builds
            build_library
            build_sample_app
            print_success "Build completed successfully"
            ;;
        "run")
            check_dependencies
            # Build if needed
            if [ ! -f "$SAMPLE_APP_DIR/$SAMPLE_APP_NAME" ] || [ ! -f "$LIB_DIR/$LIB_NAME" ]; then
                print_warning "Build artifacts not found, building first..."
                clean_builds
                build_library
                build_sample_app
            fi
            run_sample_app
            ;;
        "clean")
            clean_builds
            print_success "Cleanup completed"
            ;;
        "install")
            check_dependencies
            install_library
            ;;
        "test")
            check_dependencies
            run_tests
            ;;
        "info")
            check_dependencies
            show_info
            ;;
        "all")
            check_dependencies
            clean_builds
            build_library
            build_sample_app
            run_sample_app
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            print_error "Unknown option: $action"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@" 