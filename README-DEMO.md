# 🚀 TEE Redaction Protocol - End-to-End Demo

This demo showcases the complete redaction protocol implementation with a real HTTP request to example.com, demonstrating both request and response redaction capabilities.

## 📋 What This Demo Shows

### **Scenario**: HTTP Request to example.com with Redaction
- **Request Redaction**: Hides a sensitive "Auth" header from the HTTP request
- **Response Redaction**: Extracts only "Example Domain" from the full HTML response
- **Full Protocol**: Complete TEE_T ↔ TEE_K coordination using the redaction protocol

### **Protocol Flow Demonstrated**
1. **Client** creates HTTP request with sensitive "Auth" header
2. **Client** separates request into non-sensitive and sensitive parts
3. **Client** generates redaction streams and commitments (HMAC-SHA256)
4. **Client** → **TEE_T**: Sends streams for verification and storage
5. **Client** → **TEE_K**: Sends redacted request
6. **TEE_K** verifies commitments and recovers original request
7. **TEE_K** makes actual HTTP call to example.com
8. **TEE_K** applies response redaction (extracts only "Example Domain")
9. **Client** receives redacted result

## 🛠 Prerequisites

- Go 1.21+ installed
- Internet connection (for example.com request)
- Two terminal windows

## 🚀 Quick Start

### Option 1: Using Makefile (Recommended)
```bash
# Run complete demo (builds, starts services, runs demo, cleans up)
make demo

# Or run individual steps:
make build          # Build all components
make demo-setup     # Start TEE_K and TEE_T
make demo-run       # Run the demo client
make clean          # Clean up processes and build artifacts
```

### Option 2: Manual Setup

#### Terminal 1 - Start TEE_K
```bash
cd /path/to/reclaim-tee
go run ./tee_k
# TEE_K will start on :8080
```

#### Terminal 2 - Start TEE_T  
```bash
cd /path/to/reclaim-tee
PORT=8081 go run ./tee_t
# TEE_T will start on :8081
```

#### Terminal 3 - Run Demo
```bash
cd /path/to/reclaim-tee
go run ./cmd/demo-client
```

## 📊 Expected Output

```
🚀 TEE Redaction Protocol - End-to-End Demo
==================================================

📋 Demo Configuration:
   Target URL: http://example.com
   Session ID: demo-session-1234567890
   Auth Header: Bearer secret-token-12345 (will be redacted)

📝 Step 1: Creating HTTP request to example.com
   Original Request:
     Method: GET
     URL: http://example.com
     Headers:
       Host: example.com
       User-Agent: TEE-Demo-Client/1.0
       Accept: text/html,application/xhtml+xml
       Accept-Language: en-US,en;q=0.9
       Auth: Bearer secret-token-12345 (🔒 SENSITIVE)
       Connection: close

🔒 Step 2: Separating sensitive data for redaction
   Redaction Breakdown:
     Non-sensitive data: 156 bytes
     Sensitive data: 32 bytes (Auth header)
     Sensitive proof data: 0 bytes
     Total: 188 bytes

🎲 Step 3: Generating redaction streams and commitments
   Generated streams: S=32 bytes, SP=0 bytes
   Generated commitments: S=32 bytes, SP=32 bytes

📡 Step 4: Sending redaction streams to TEE_T
   ✅ TEE_T verified commitments and stored session data

🔀 Step 5: Applying redaction and sending to TEE_K

📋 Step 6: Processing results
   🎉 Redaction Protocol Results:
     Status: success
     Original response size: 1256 bytes
     Redacted response size: 14 bytes
     Redacted content: "Example Domain"
     ✅ Auth header successfully redacted from request
     ✅ Response successfully redacted to show only target text

✅ Demo completed successfully!
```

## 🔍 What's Being Demonstrated

### **Security Features**
- **Commitment Verification**: HMAC-SHA256 commitments ensure streams haven't been tampered with
- **Session Management**: Secure session storage and verification 
- **Data Separation**: Clear separation of sensitive vs non-sensitive data
- **Secure Memory**: Automatic secure zeroing of sensitive data after use

### **Protocol Compliance**
- **TEE_T Stream Processing**: Verifies commitments and stores session data
- **TEE_K Request Handling**: Recovers original data and makes external requests
- **Response Redaction**: Selective extraction of data from responses
- **End-to-End Security**: Complete protocol flow with proper verification

### **Real-World Applicability**
- **Actual HTTP Requests**: Real network calls to example.com
- **Header Redaction**: Practical example of hiding authentication data
- **Response Filtering**: Demonstrating selective response data extraction
- **Client Reference**: Complete example for TypeScript client development

## 🧪 Technical Details

### **Data Structures**
- `RedactionRequest`: Splits data into non-sensitive, sensitive, and sensitive-proof parts
- `RedactionStreams`: Random XOR streams for redaction
- `RedactionCommitments`: HMAC commitments to verify stream integrity
- `RedactionKeys`: Keys used for HMAC computation

### **Endpoints Used**
- `TEE_T /process-redaction-streams`: Accepts and verifies redaction streams
- `TEE_K /demo-redacted-request`: Processes redacted requests and makes HTTP calls

### **Cryptographic Operations**
- **HMAC-SHA256**: For commitment computation and verification
- **XOR Redaction**: For reversible data hiding
- **Secure Random**: Cryptographically secure stream generation

## 🔧 Customization

You can modify the demo by editing `cmd/demo-client/main.go`:

```go
config := DemoConfig{
    TargetURL:    "http://your-target.com",     // Change target URL
    AuthHeader:   "Your-Secret-Header-Value",   // Change what gets redacted
    SessionID:    "your-session-id",            // Customize session ID
    ShowDetailed: true,                         // Show/hide detailed output
}
```

## 🐛 Troubleshooting

### **Connection Errors**
- Ensure TEE_K is running on :8080
- Ensure TEE_T is running on :8081  
- Check firewall settings

### **Demo Failures**
- Verify internet connection for example.com access
- Check that both TEE services started successfully
- Review logs in TEE service terminals

### **Port Conflicts**
- Change ports in demo client if needed:
```go
const (
    TEE_K_URL = "http://localhost:8080"  // Change if port 8080 is busy
    TEE_T_URL = "http://localhost:8081"  // Change if port 8081 is busy  
)
```

## 📝 Next Steps

This demo serves as a reference implementation for:
- **TypeScript Client Development**: Shows complete protocol flow
- **Integration Testing**: Demonstrates end-to-end functionality  
- **Protocol Validation**: Verifies correct implementation
- **Performance Analysis**: Baseline for optimization work

For production deployment, consider:
- Proper TLS/mTLS between components
- Enhanced session management and cleanup
- Rate limiting and DoS protection
- Comprehensive logging and monitoring 