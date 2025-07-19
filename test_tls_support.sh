#!/bin/bash

# TLS Support Testing Script
# Tests TLS versions and cipher suites against a target website
# Usage: ./test_tls_support.sh <hostname> [port]

#set -e

# Cleanup function to kill background processes
cleanup() {
    echo -e "\n${YELLOW}Script interrupted. Cleaning up...${NC}"
    # Kill any remaining child processes
    pkill -P $$ 2>/dev/null || true
    # Also kill any openssl or timeout processes that might be orphaned
    pkill -f "openssl.*${HOSTNAME}" 2>/dev/null || true
    pkill -f "timeout.*openssl" 2>/dev/null || true
    exit 130  # Standard exit code for CTRL+C
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_PORT=443
TIMEOUT=3

# Help function
show_help() {
    echo "TLS Support Testing Script"
    echo ""
    echo "Usage: $0 <hostname> [port]"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 google.com 443"
    echo "  $0 localhost 8080"
    echo ""
    echo "This script tests what TLS versions and cipher suites are supported"
    echo "by the target server using OpenSSL."
}

# Parse arguments
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_help
    exit 0
fi

HOSTNAME="$1"
PORT="${2:-$DEFAULT_PORT}"

# Function to run openssl with signal awareness
run_openssl_test() {
    local cmd="$*"
    echo -n | timeout $TIMEOUT openssl $cmd 2>&1
}

echo -e "${BLUE}=== TLS Support Test for ${HOSTNAME}:${PORT} ===${NC}"
echo ""

# Test basic connectivity
echo -e "${YELLOW}Testing basic connectivity...${NC}"
result=$(run_openssl_test s_client -connect "${HOSTNAME}:${PORT}" -brief)
if echo "$result" | grep -q "CONNECTION ESTABLISHED"; then
    echo -e "${GREEN}✅ Basic connectivity OK${NC}"
else
    echo -e "${RED}❌ Cannot connect to ${HOSTNAME}:${PORT}${NC}"
    exit 1
fi
echo ""

# TLS versions to test
declare -A TLS_VERSIONS=(
    ["tls1_2"]="TLS 1.2"
    ["tls1_3"]="TLS 1.3"
)

# TLS 1.2 cipher suites to test
declare -A TLS12_CIPHERS=(
    ["ECDHE-RSA-AES128-GCM-SHA256"]="0xc02f"
    ["ECDHE-ECDSA-AES128-GCM-SHA256"]="0xc02b"
    ["ECDHE-RSA-AES256-GCM-SHA384"]="0xc030"
    ["ECDHE-ECDSA-AES256-GCM-SHA384"]="0xc02c"
    ["ECDHE-RSA-CHACHA20-POLY1305"]="0xcca8"
    ["ECDHE-ECDSA-CHACHA20-POLY1305"]="0xcca9"
)

# TLS 1.3 cipher suites to test
declare -A TLS13_CIPHERS=(
    ["TLS_AES_128_GCM_SHA256"]="0x1301"
    ["TLS_AES_256_GCM_SHA384"]="0x1302"
    ["TLS_CHACHA20_POLY1305_SHA256"]="0x1303"
)

# Function to test TLS version
test_tls_version() {
    local tls_flag="$1"
    local display_name="$2"
    
    echo -e "${YELLOW}Testing ${display_name}...${NC}"
    
    result=$(run_openssl_test s_client -connect "${HOSTNAME}:${PORT}" -${tls_flag} -brief)
    if echo "$result" | grep -q "CONNECTION ESTABLISHED"; then
        local protocol=$(echo "$result" | grep "Protocol" | head -1 | cut -d: -f2 | tr -d ' ')
        local cipher=$(echo "$result" | grep "Cipher" | head -1 | cut -d: -f2 | tr -d ' ')
        echo -e "${GREEN}✅ ${display_name} supported - Protocol: ${protocol}, Cipher: ${cipher}${NC}"
        return 0
    fi
    echo -e "${RED}❌ ${display_name} not supported${NC}"
    return 1
}

# Function to test specific cipher suite
test_cipher_suite() {
    local tls_flag="$1"
    local cipher_name="$2"
    local is_tls13="$3"
    
    if [ "$is_tls13" = "true" ]; then
        # TLS 1.3 uses -ciphersuites
        run_openssl_test s_client -connect "${HOSTNAME}:${PORT}" -${tls_flag} -ciphersuites "${cipher_name}" -brief | grep -q "CONNECTION ESTABLISHED"
    else
        # TLS 1.2 uses -cipher
        run_openssl_test s_client -connect "${HOSTNAME}:${PORT}" -${tls_flag} -cipher "${cipher_name}" -brief | grep -q "CONNECTION ESTABLISHED"
    fi
}

# Test TLS versions first
echo -e "${BLUE}=== TLS Version Support ===${NC}"
TLS12_SUPPORTED=false
TLS13_SUPPORTED=false

for tls_flag in "${!TLS_VERSIONS[@]}"; do
    display_name="${TLS_VERSIONS[$tls_flag]}"
    if test_tls_version "$tls_flag" "$display_name"; then
        if [ "$tls_flag" = "tls1_2" ]; then
            TLS12_SUPPORTED=true
        elif [ "$tls_flag" = "tls1_3" ]; then
            TLS13_SUPPORTED=true
        fi
    fi
done

echo ""

# Test cipher suites
echo -e "${BLUE}=== Cipher Suite Support ===${NC}"
echo ""

# Create table header
printf "%-40s %-12s %-10s %-10s\n" "Cipher Suite" "Hex ID" "TLS 1.2" "TLS 1.3"
printf "%-40s %-12s %-10s %-10s\n" "----------------------------------------" "------------" "----------" "----------"

# Test TLS 1.2 cipher suites
for cipher_name in "${!TLS12_CIPHERS[@]}"; do
    cipher_hex="${TLS12_CIPHERS[$cipher_name]}"
    
    # Test TLS 1.2
    tls12_result="N/A"
    if [ "$TLS12_SUPPORTED" = true ]; then
        if test_cipher_suite "tls1_2" "$cipher_name" "false"; then
            tls12_result="✅"
        else
            tls12_result="❌"
        fi
    else
        tls12_result="N/A"
    fi
    
    # TLS 1.2 ciphers don't work with TLS 1.3
    tls13_result="N/A"
    
    printf "%-40s %-12s %-10s %-10s\n" "$cipher_name" "$cipher_hex" "$tls12_result" "$tls13_result"
done

# Test TLS 1.3 cipher suites
for cipher_name in "${!TLS13_CIPHERS[@]}"; do
    cipher_hex="${TLS13_CIPHERS[$cipher_name]}"
    
    # TLS 1.3 ciphers don't work with TLS 1.2
    tls12_result="N/A"
    
    # Test TLS 1.3
    tls13_result="N/A"
    if [ "$TLS13_SUPPORTED" = true ]; then
        if test_cipher_suite "tls1_3" "$cipher_name" "true"; then
            tls13_result="✅"
        else
            tls13_result="❌"
        fi
    else
        tls13_result="N/A"
    fi
    
    printf "%-40s %-12s %-10s %-10s\n" "$cipher_name" "$cipher_hex" "$tls12_result" "$tls13_result"
done

echo ""

# Summary
echo -e "${BLUE}=== Summary ===${NC}"
echo "Tested against: ${HOSTNAME}:${PORT}"
echo -n "TLS 1.2 Support: "
[ "$TLS12_SUPPORTED" = true ] && echo -e "${GREEN}✅ Yes${NC}" || echo -e "${RED}❌ No${NC}"
echo -n "TLS 1.3 Support: "
[ "$TLS13_SUPPORTED" = true ] && echo -e "${GREEN}✅ Yes${NC}" || echo -e "${RED}❌ No${NC}"

# Count supported cipher suites
tls12_count=0
tls13_count=0

if [ "$TLS12_SUPPORTED" = true ]; then
    for cipher_name in "${!TLS12_CIPHERS[@]}"; do
        if test_cipher_suite "tls1_2" "$cipher_name" "false" >/dev/null 2>&1; then
            ((tls12_count++))
        fi
    done
fi

if [ "$TLS13_SUPPORTED" = true ]; then
    for cipher_name in "${!TLS13_CIPHERS[@]}"; do
        if test_cipher_suite "tls1_3" "$cipher_name" "true" >/dev/null 2>&1; then
            ((tls13_count++))
        fi
    done
fi

echo "Supported TLS 1.2 Cipher Suites: ${tls12_count}/${#TLS12_CIPHERS[@]}"
echo "Supported TLS 1.3 Cipher Suites: ${tls13_count}/${#TLS13_CIPHERS[@]}"

echo ""
echo -e "${BLUE}=== Recommendations for Testing ===${NC}"

if [ "$TLS12_SUPPORTED" = true ]; then
    echo -e "${GREEN}TLS 1.2 Testing:${NC}"
    for cipher_name in "${!TLS12_CIPHERS[@]}"; do
        cipher_hex="${TLS12_CIPHERS[$cipher_name]}"
        if test_cipher_suite "tls1_2" "$cipher_name" "false" >/dev/null 2>&1; then
            echo "  ./demo.sh 1.2 $cipher_hex  # $cipher_name"
        fi
    done
    echo ""
fi

if [ "$TLS13_SUPPORTED" = true ]; then
    echo -e "${GREEN}TLS 1.3 Testing:${NC}"
    for cipher_name in "${!TLS13_CIPHERS[@]}"; do
        cipher_hex="${TLS13_CIPHERS[$cipher_name]}"
        if test_cipher_suite "tls1_3" "$cipher_name" "true" >/dev/null 2>&1; then
            echo "  ./demo.sh 1.3 $cipher_hex  # $cipher_name"
        fi
    done
fi
