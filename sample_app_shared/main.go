package main

// #cgo CFLAGS: -I.
// #cgo LDFLAGS: -L../lib -lreclaim
/*
#include <stddef.h>

// Opaque handle for protocol session
typedef struct reclaim_protocol* reclaim_protocol_t;

// Error codes
typedef enum {
    RECLAIM_SUCCESS = 0,
    RECLAIM_ERROR_INVALID_ARGS = -1,
    RECLAIM_ERROR_CONNECTION_FAILED = -2,
    RECLAIM_ERROR_PROTOCOL_FAILED = -3,
    RECLAIM_ERROR_TIMEOUT = -4,
    RECLAIM_ERROR_MEMORY = -5,
    RECLAIM_ERROR_SESSION_NOT_FOUND = -6,
    RECLAIM_ERROR_ALREADY_COMPLETED = -7
} reclaim_error_t;

// Function declarations
reclaim_error_t reclaim_start_protocol(char* host, char* request_json, reclaim_protocol_t* protocol_handle);
reclaim_error_t reclaim_get_response(reclaim_protocol_t protocol_handle, char** response_json, int* response_length);
reclaim_error_t reclaim_finish_protocol(reclaim_protocol_t protocol_handle, char* response_redaction_json, char** verification_bundle_json, int* bundle_length);
reclaim_error_t reclaim_cleanup(reclaim_protocol_t protocol_handle);
void reclaim_free_string(char* str);
char* reclaim_get_error_message(reclaim_error_t error);
char* reclaim_get_version(void);
*/
import "C"
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"tee-mpc/proofverifier"
)

func main() {
	fmt.Println("=== Sample Application using libreclaim Shared Library ===")

	// Use provider-based request format (same as main demo)
	providerData := map[string]interface{}{
		"public_params": map[string]interface{}{
			"url":    "https://vpic.nhtsa.dot.gov/api/vehicles/getallmanufacturers?format=json",
			"method": "GET",
			"responseMatches": []map[string]interface{}{
				{
					"value": "TESLA, INC.",
					"type":  "contains",
				},
			},
			"responseRedactions": []map[string]interface{}{
				{
					"jsonPath": "$.Results[*].Mfr_Name",
				},
			},
		},
		"secret_params": map[string]interface{}{
			"headers": map[string]interface{}{
				"accept": "application/json, text/plain, */*",
			},
		},
	}

	requestJSON, err := json.Marshal(providerData)
	if err != nil {
		log.Fatalf("Failed to marshal provider request JSON: %v", err)
	}

	// Note: host parameter is not used - actual host/port extracted from provider URL
	dummyHost := "unused"
	fmt.Printf("Using provider-based request format\n")
	fmt.Printf("URL: %s\n", providerData["public_params"].(map[string]interface{})["url"])
	fmt.Printf("Host will be automatically extracted from provider URL using GetHostPort\n")

	// Step 1: Start the protocol
	cRequestJSON := C.CString(string(requestJSON))
	defer C.reclaim_free_string(cRequestJSON)

	var protocolHandle C.reclaim_protocol_t
	result := C.reclaim_start_protocol(C.CString(dummyHost), cRequestJSON, &protocolHandle)
	if result != C.RECLAIM_SUCCESS {
		errorMsg := C.reclaim_get_error_message(result)
		log.Fatalf("Failed to start protocol: %s", C.GoString(errorMsg))
	}
	defer C.reclaim_cleanup(protocolHandle)

	fmt.Printf("Protocol started successfully!\n")

	// Step 2: Get response data
	var responseJSON *C.char
	var responseLength C.int
	result = C.reclaim_get_response(protocolHandle, &responseJSON, &responseLength)
	if result != C.RECLAIM_SUCCESS {
		errorMsg := C.reclaim_get_error_message(result)
		log.Fatalf("Failed to get response: %s", C.GoString(errorMsg))
	}
	defer C.reclaim_free_string(responseJSON)

	// Parse response data
	responseDataStr := C.GoStringN(responseJSON, responseLength)
	var responseData map[string]interface{}
	if err := json.Unmarshal([]byte(responseDataStr), &responseData); err != nil {
		log.Fatalf("Failed to parse response JSON: %v", err)
	}

	protocolID := responseData["protocol_id"].(string)
	responseLengthInt := int(responseData["response_length"].(float64))

	fmt.Printf("Protocol ID: %s\n", protocolID)
	fmt.Printf("Response received: %d bytes\n", responseLengthInt)
	fmt.Printf("Success: %v\n", responseData["success"])

	// Step 3: Finish the protocol (response redactions are automatic via provider config)
	fmt.Printf("Response redactions will be generated automatically from provider config\n")

	// The response_redaction_json parameter is ignored by the library for provider format
	dummyResponseRedactionJSON := "{}"
	cResponseRedactionJSON := C.CString(dummyResponseRedactionJSON)
	defer C.reclaim_free_string(cResponseRedactionJSON)

	// Step 4: Finish the protocol
	var bundleJSON *C.char
	var bundleLength C.int
	result = C.reclaim_finish_protocol(protocolHandle, cResponseRedactionJSON, &bundleJSON, &bundleLength)
	if result != C.RECLAIM_SUCCESS {
		errorMsg := C.reclaim_get_error_message(result)
		log.Fatalf("Failed to finish protocol: %s", C.GoString(errorMsg))
	}
	defer C.reclaim_free_string(bundleJSON)

	// Parse verification bundle data
	bundleDataStr := C.GoStringN(bundleJSON, bundleLength)
	var bundleData map[string]interface{}
	if err := json.Unmarshal([]byte(bundleDataStr), &bundleData); err != nil {
		log.Fatalf("Failed to parse bundle JSON: %v", err)
	}

	bundleSize := int(bundleData["bundle_size"].(float64))
	verificationBundle := bundleData["verification_bundle"].(string)

	fmt.Printf("Protocol finished successfully!\n")
	fmt.Printf("Verification bundle size: %d bytes\n", bundleSize)
	fmt.Printf("Success: %v\n", bundleData["success"])

	// Display some information about the verification bundle
	if len(verificationBundle) > 0 {
		previewLength := 50
		if len(verificationBundle) < previewLength {
			previewLength = len(verificationBundle)
		}
		fmt.Printf("Verification bundle preview: %s...\n",
			verificationBundle[:previewLength])
	}

	// Save verification bundle to file for offline verification
	// The verification bundle from the shared library is base64-encoded protobuf data
	bundlePath := fmt.Sprintf("/tmp/verification_bundle_%s.pb", protocolID)
	if err := writeVerificationBundleProtobuf(bundlePath, verificationBundle); err != nil {
		log.Printf("Failed to write verification bundle: %v", err)
	} else {
		fmt.Printf("Verification bundle saved to: %s\n", bundlePath)
	}

	// Run offline verification to display the final redacted response
	fmt.Println("\n🔍 Running offline verification to display final redacted response...")
	if err := proofverifier.Validate(bundlePath); err != nil {
		log.Printf("🔴 Offline verification failed: %v", err)
	} else {
		fmt.Println("✅ Offline verification succeeded")
	}

	fmt.Println("Sample application completed successfully!")

}

// writeVerificationBundleProtobuf decodes base64-encoded protobuf bundle and writes to file
func writeVerificationBundleProtobuf(path string, base64Data string) error {
	// Decode base64 data back to protobuf binary
	bundleData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return fmt.Errorf("failed to decode base64 bundle data: %v", err)
	}

	return os.WriteFile(path, bundleData, 0644)
}
