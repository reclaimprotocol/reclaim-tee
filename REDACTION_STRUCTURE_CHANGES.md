# TEE Redaction Structure Changes

## Overview
Modified the demo redaction structure according to the TEE + MPC protocol design to implement the three-part redaction:

1. **R_NS** (Non-sensitive): Domain, URL, and all public headers - goes as plaintext
2. **R_S** (Sensitive): Secret auth header - sensitive but not used in proof
3. **R_SP** (Sensitive Proof): Bank account header - sensitive and used in proof

## Changes Made

### 1. Main Demo Client (`cmd/demo-client/main.go`)

**Added Bank Account Header:**
```go
"X-Bank-Account": "ACC-123456789-DEMO-BANK", // This will go in R_SP (sensitive proof)
```

**Modified `createRedactionRequest()` function:**
- **R_NS**: Contains domain, URL, and all public headers (Host, User-Agent, Accept, Accept-Language, Connection)
- **R_S**: Contains only the Auth header (sensitive but not used in proof)
- **R_SP**: Contains the X-Bank-Account header (sensitive and used in proof)

**Updated Print Functions:**
- Shows which part each header belongs to: `(R_NS - PUBLIC)`, `(R_S - SENSITIVE)`, `(R_SP - SENSITIVE PROOF)`
- Enhanced redaction breakdown display

### 2. Test Demo Client (`cmd/test-demo/main.go`)

**Added Bank Account Header:**
```go
"X-Bank-Account": "ACC-987654321-TEST-BANK", // R_SP - sensitive proof
```

**Modified Functions:**
- `createRedactionRequest()`: Same three-part structure as main demo
- `reconstructHTTPRequest()`: Now handles all three parts (R_NS, R_S, R_SP)
- Updated print functions to show redaction part classifications

### 3. Protocol Implementation

The core redaction logic in `enclave/redaction.go` already supported three parts:
- `NonSensitive` (R_NS)
- `Sensitive` (R_S) 
- `SensitiveProof` (R_SP)

No changes were needed to the core protocol implementation.

## Demo Structure

### Before:
- R_NS: Everything except Auth header
- R_S: Auth header only
- R_SP: Empty (unused)

### After:
- **R_NS**: Domain + URL + public headers (Host, User-Agent, Accept, Accept-Language, Connection)
- **R_S**: Auth header (Bearer token)
- **R_SP**: Bank account header (ACC-123456789-DEMO-BANK)

## Testing

Both demo clients work correctly:
- `go run cmd/test-demo/main.go` - Local test without network calls
- `go run cmd/demo-client/main.go` - Full demo with TEE_K and TEE_T services

The redaction protocol successfully:
1. Separates data into three categories
2. Applies different streams to R_S and R_SP
3. Keeps R_NS as plaintext
4. Verifies commitments and reconstructs data correctly

## Usage

All three parts are now functional and visible in the demo output, clearly showing:
- What data goes where (R_NS/R_S/R_SP)
- Different treatment of sensitive vs sensitive-proof data
- Complete end-to-end redaction workflow

This implementation now fully demonstrates the TEE + MPC protocol design from the research document. 