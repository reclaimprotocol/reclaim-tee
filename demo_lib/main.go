package main

// #cgo CFLAGS: -I.
// #cgo LDFLAGS: -L../lib -lreclaim
/*
#include <stddef.h>
#include <stdint.h>

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

// Go types for CGO
typedef struct { void *data; ptrdiff_t len; ptrdiff_t cap; } GoSlice;

// Function declarations
reclaim_error_t reclaim_execute_protocol(char* request_json, char* config_json, char** claim_json, int* claim_length);
void reclaim_free_string(char* str);
char* reclaim_get_error_message(reclaim_error_t error);
char* reclaim_get_version(void);
uint8_t InitAlgorithm(uint8_t algorithmID, GoSlice provingKey, GoSlice r1cs);
void Free(void* pointer);

// New extraction functions
typedef struct { void *p; ptrdiff_t n; } ExtractResult;
ExtractResult ExtractHTMLElementsIndexes(GoSlice params);
ExtractResult ExtractJSONValueIndexes(GoSlice params);
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"unsafe"
)

// initializeZKCircuits initializes the ZK circuits for OPRF algorithms
func initializeZKCircuits() error {
	fmt.Println("🔧 Initializing ZK circuits for OPRF algorithms...")

	// Algorithm IDs from gnark library
	const (
		CHACHA20_OPRF = 3
		AES_128_OPRF  = 4
		AES_256_OPRF  = 5
	)

	type circuitConfig struct {
		algorithmID   uint8
		pkFile        string
		r1csFile      string
		algorithmName string
	}

	circuits := []circuitConfig{
		{
			algorithmID:   CHACHA20_OPRF,
			pkFile:        "pk.chacha20_oprf",
			r1csFile:      "r1cs.chacha20_oprf",
			algorithmName: "CHACHA20_OPRF",
		},
		{
			algorithmID:   AES_128_OPRF,
			pkFile:        "pk.aes128_oprf",
			r1csFile:      "r1cs.aes128_oprf",
			algorithmName: "AES_128_OPRF",
		},
		{
			algorithmID:   AES_256_OPRF,
			pkFile:        "pk.aes256_oprf",
			r1csFile:      "r1cs.aes256_oprf",
			algorithmName: "AES_256_OPRF",
		},
	}

	// Search for circuits directory
	possiblePaths := []string{
		"circuits",
		"../circuits",
		"../../circuits",
	}

	var circuitsPath string
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			circuitsPath = path
			break
		}
	}

	if circuitsPath == "" {
		return fmt.Errorf("circuits directory not found in any of the expected locations")
	}

	fmt.Printf("📁 Found circuits directory at: %s\n", circuitsPath)

	// Initialize each circuit
	for _, circuit := range circuits {
		pkPath := filepath.Join(circuitsPath, circuit.pkFile)
		r1csPath := filepath.Join(circuitsPath, circuit.r1csFile)

		// Read proving key
		pkData, err := os.ReadFile(pkPath)
		if err != nil {
			return fmt.Errorf("failed to read proving key %s: %v", pkPath, err)
		}

		// Read R1CS
		r1csData, err := os.ReadFile(r1csPath)
		if err != nil {
			return fmt.Errorf("failed to read R1CS %s: %v", r1csPath, err)
		}

		// Create GoSlice structures for CGO
		pkSlice := C.GoSlice{
			data: unsafe.Pointer(&pkData[0]),
			len:  C.ptrdiff_t(len(pkData)),
			cap:  C.ptrdiff_t(len(pkData)),
		}

		r1csSlice := C.GoSlice{
			data: unsafe.Pointer(&r1csData[0]),
			len:  C.ptrdiff_t(len(r1csData)),
			cap:  C.ptrdiff_t(len(r1csData)),
		}

		// Call InitAlgorithm through the shared library
		success := C.InitAlgorithm(C.uint8_t(circuit.algorithmID), pkSlice, r1csSlice)
		if success == 0 {
			return fmt.Errorf("failed to initialize %s circuit", circuit.algorithmName)
		}

		fmt.Printf("  ✅ Initialized %s (ID: %d)\n", circuit.algorithmName, circuit.algorithmID)
	}

	fmt.Println("✅ All ZK circuits initialized successfully")
	return nil
}

func main() {
	fmt.Println("=== Sample Application using libreclaim Shared Library ===")

	// Initialize ZK circuits first
	if err := initializeZKCircuits(); err != nil {
		log.Printf("Warning: Failed to initialize ZK circuits: %v", err)
		log.Println("Continuing without ZK circuit initialization...")
	}

	// Create the provider data with optional context
	providerData := map[string]interface{}{
		"name": "http",
		"params": map[string]interface{}{
			"url":    "https://vpic.nhtsa.dot.gov/",
			"method": "GET",
			"responseMatches": []map[string]interface{}{
				{
					"value": "{{addr}}",
					"type":  "contains",
				},
			},
			"responseRedactions": []map[string]interface{}{
				{
					"xPath": "/html/body/footer/div[2]/div/div[1]/ul[3]/li[2]/a",
					"regex": "href=\"https://(?<addr>www.trafficsafetymarketing.gov)/\"",
					"hash":  "oprf",
				},
			},
			"paramValues": map[string]string{
				"addr": "www.trafficsafetymarketing.gov",
			},
		},
		"secretParams": map[string]interface{}{
			"headers": map[string]interface{}{
				"accept": "application/json, text/plain, */*",
			},
		},
		// Optional context that will be included in the claim (JSON string)
		"context": "{\"purpose\":\"demo\",\"version\":\"1.0\"}",
	}

	// Create config separately with optional TEE URLs
	// All URLs are optional - if not provided, defaults will be used:
	// - teekUrl: wss://tee-k.reclaimprotocol.org/ws (enclave mode)
	// - teetUrl: wss://tee-t.reclaimprotocol.org/ws (enclave mode)
	// - attestorUrl: ws://localhost:8001/ws
	configData := map[string]interface{}{
		"attestorUrl": "wss://attestor.reclaimprotocol.org:444/ws", // Attestor WebSocket URL
		"teekUrl":     "wss://tee-k.reclaimprotocol.org/ws",
		"teetUrl":     "wss://tee-t-gcp.reclaimprotocol.org/ws",
	}

	providerJSON, err := json.Marshal(providerData)
	if err != nil {
		log.Fatalf("Failed to marshal provider JSON: %v", err)
	}

	configJSON, err := json.Marshal(configData)
	if err != nil {
		log.Fatalf("Failed to marshal config JSON: %v", err)
	}

	// fmt.Printf("URL: %s\n", providerData["params"].(map[string]interface{})["url"])
	fmt.Printf("Config: %v\n", configData)

	cProviderJSON := C.CString(string(providerJSON))
	defer C.reclaim_free_string(cProviderJSON)

	cConfigJSON := C.CString(string(configJSON))
	defer C.reclaim_free_string(cConfigJSON)

	fmt.Printf("Starting protocol...\n")

	var claimJSON *C.char
	var claimLength C.int
	result := C.reclaim_execute_protocol(cProviderJSON, cConfigJSON, &claimJSON, &claimLength)
	if result != C.RECLAIM_SUCCESS {
		errorMsg := C.reclaim_get_error_message(result)
		log.Fatalf("Failed to execute protocol: %s", C.GoString(errorMsg))
	}
	defer C.reclaim_free_string(claimJSON)

	claimDataStr := C.GoStringN(claimJSON, claimLength)
	var claimData map[string]interface{}
	if err := json.Unmarshal([]byte(claimDataStr), &claimData); err != nil {
		log.Fatalf("Failed to parse claim JSON: %v", err)
	}

	// Print full JSON for debugging/integration
	fmt.Println("\nFull Claim JSON:")
	prettyJSON, err := json.MarshalIndent(claimData, "", "  ")
	if err != nil {
		fmt.Printf("Error formatting JSON: %v\n", err)
		fmt.Println(claimDataStr)
	} else {
		fmt.Println(string(prettyJSON))
	}

	fmt.Println("Sample application completed successfully!")

}
