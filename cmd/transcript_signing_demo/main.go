package main

import (
	"encoding/json"
	"fmt"
	"log"
	"tee/enclave"
)

func main() {
	fmt.Println("=== TEE+MPC Transcript Signing Demo ===")
	fmt.Println()

	// Demo 1: Request Transcript Signing (TEE_K)
	fmt.Println("📝 Demo 1: TEE_K Request Transcript Signing")
	demoRequestTranscriptSigning()
	fmt.Println()

	// Demo 2: Response Transcript Signing (TEE_T)
	fmt.Println("📝 Demo 2: TEE_T Response Transcript Signing")
	demoResponseTranscriptSigning()
	fmt.Println()

	// Demo 3: Full Protocol Flow Simulation
	fmt.Println("📝 Demo 3: Full Protocol Flow Simulation")
	demoFullProtocolFlow()
	fmt.Println()

	// Demo 4: Verification
	fmt.Println("📝 Demo 4: Transcript Verification")
	demoTranscriptVerification()
}

func demoRequestTranscriptSigning() {
	// Create demo signer for TEE_K
	signer, err := enclave.GenerateDemoKey()
	if err != nil {
		log.Fatalf("Failed to generate demo key: %v", err)
	}

	fmt.Printf("✅ Generated demo signing key (Algorithm: %s)\n", signer.GetAlgorithm())

	// Create request transcript builder
	sessionID := "demo-session-001"
	builder := enclave.NewRequestTranscriptBuilder(sessionID)

	// Simulate redacted HTTP requests
	requests := [][]byte{
		[]byte("GET /api/balance HTTP/1.1\r\nHost: bank.example.com\r\nAuthorization: [REDACTED]\r\n\r\n"),
		[]byte("POST /api/transfer HTTP/1.1\r\nHost: bank.example.com\r\nAuthorization: [REDACTED]\r\nContent-Type: application/json\r\n\r\n{\"amount\":100,\"to\":\"[REDACTED]\"}"),
	}

	// Add requests to transcript
	for i, request := range requests {
		builder.AddRequest(request)
		fmt.Printf("📄 Added request %d (%d bytes)\n", i+1, len(request))
	}

	// Add commitments (as per TEE+MPC protocol)
	commitmentSP := []byte("commitment_sp_demo_data_for_sensitive_proof")
	builder.AddCommitment("commitment_sp", commitmentSP)
	fmt.Printf("🔒 Added commitment_sp (%d bytes)\n", len(commitmentSP))

	// Sign the transcript
	signedTranscript, err := builder.Sign(signer)
	if err != nil {
		log.Fatalf("Failed to sign request transcript: %v", err)
	}

	fmt.Printf("✍️  Request transcript signed successfully\n")
	fmt.Printf("   Session ID: %s\n", signedTranscript.Data.SessionID)
	fmt.Printf("   Type: %s\n", signedTranscript.Data.Type)
	fmt.Printf("   Request Count: %v\n", signedTranscript.Data.Metadata["request_count"])
	fmt.Printf("   Total Data Size: %v bytes\n", signedTranscript.Data.Metadata["total_size"])
	fmt.Printf("   Signature: %d bytes\n", len(signedTranscript.Signature))
	fmt.Printf("   Algorithm: %s\n", signedTranscript.Algorithm)
}

func demoResponseTranscriptSigning() {
	// Create demo signer for TEE_T
	signer, err := enclave.GenerateDemoKey()
	if err != nil {
		log.Fatalf("Failed to generate demo key: %v", err)
	}

	fmt.Printf("✅ Generated demo signing key (Algorithm: %s)\n", signer.GetAlgorithm())

	// Create response transcript builder
	sessionID := "demo-session-002"
	builder := enclave.NewResponseTranscriptBuilder(sessionID)

	// Simulate encrypted responses
	encryptedResponses := [][]byte{
		[]byte("encrypted_balance_response_data_abc123"),
		[]byte("encrypted_transfer_confirmation_def456"),
		[]byte("encrypted_final_balance_ghi789"),
	}

	// Add encrypted responses to transcript
	for i, response := range encryptedResponses {
		builder.AddEncryptedResponse(response)
		fmt.Printf("🔐 Added encrypted response %d (%d bytes)\n", i+1, len(response))
	}

	// Sign the transcript
	signedTranscript, err := builder.Sign(signer)
	if err != nil {
		log.Fatalf("Failed to sign response transcript: %v", err)
	}

	fmt.Printf("✍️  Response transcript signed successfully\n")
	fmt.Printf("   Session ID: %s\n", signedTranscript.Data.SessionID)
	fmt.Printf("   Type: %s\n", signedTranscript.Data.Type)
	fmt.Printf("   Response Count: %v\n", signedTranscript.Data.Metadata["response_count"])
	fmt.Printf("   Total Data Size: %v bytes\n", signedTranscript.Data.Metadata["total_size"])
	fmt.Printf("   Signature: %d bytes\n", len(signedTranscript.Signature))
	fmt.Printf("   Algorithm: %s\n", signedTranscript.Algorithm)
}

func demoFullProtocolFlow() {
	sessionID := "demo-session-full-flow"

	// Step 1: TEE_K creates request transcript
	fmt.Println("🔄 Step 1: TEE_K processes requests and creates transcript")
	teeKSigner, err := enclave.GenerateDemoKey()
	if err != nil {
		log.Fatalf("Failed to generate TEE_K key: %v", err)
	}

	requestBuilder := enclave.NewRequestTranscriptBuilder(sessionID)

	// Simulate the protocol flow with redacted requests
	redactedRequests := [][]byte{
		[]byte("GET /profile HTTP/1.1\r\nHost: social.example.com\r\nAuthorization: [REDACTED]\r\n\r\n"),
		[]byte("POST /message HTTP/1.1\r\nHost: social.example.com\r\nAuthorization: [REDACTED]\r\n\r\n{\"message\":\"[REDACTED]\",\"to\":[\"user123\"]}"),
	}

	for _, req := range redactedRequests {
		requestBuilder.AddRequest(req)
	}

	// Add commitment for sensitive proof data
	requestBuilder.AddCommitment("commitment_sp", []byte("commitment_data_for_proof"))

	requestTranscript, err := requestBuilder.Sign(teeKSigner)
	if err != nil {
		log.Fatalf("Failed to sign request transcript: %v", err)
	}

	fmt.Printf("   ✅ TEE_K signed request transcript (%s, %d requests)\n",
		requestTranscript.Algorithm, requestTranscript.Data.Metadata["request_count"])

	// Step 2: TEE_T creates response transcript
	fmt.Println("🔄 Step 2: TEE_T processes encrypted responses and creates transcript")
	teeTSigner, err := enclave.GenerateDemoKey()
	if err != nil {
		log.Fatalf("Failed to generate TEE_T key: %v", err)
	}

	responseBuilder := enclave.NewResponseTranscriptBuilder(sessionID)

	// Simulate encrypted responses from the website
	encryptedResponses := [][]byte{
		[]byte("encrypted_profile_data_xyz789"),
		[]byte("encrypted_message_confirmation_abc123"),
	}

	for _, resp := range encryptedResponses {
		responseBuilder.AddEncryptedResponse(resp)
	}

	responseTranscript, err := responseBuilder.Sign(teeTSigner)
	if err != nil {
		log.Fatalf("Failed to sign response transcript: %v", err)
	}

	fmt.Printf("   ✅ TEE_T signed response transcript (%s, %d responses)\n",
		responseTranscript.Algorithm, responseTranscript.Data.Metadata["response_count"])

	// Step 3: Simulate user receiving both transcripts
	fmt.Println("🔄 Step 3: User receives signed transcripts from both TEEs")

	// Serialize transcripts (as they would be sent over the network)
	requestJSON, _ := json.Marshal(requestTranscript)
	responseJSON, _ := json.Marshal(responseTranscript)

	fmt.Printf("   📦 Request transcript: %d bytes\n", len(requestJSON))
	fmt.Printf("   📦 Response transcript: %d bytes\n", len(responseJSON))

	// Step 4: Simulate transcript verification by verifier
	fmt.Println("🔄 Step 4: Verifier validates transcript authenticity")

	// Verify request transcript
	err = enclave.VerifyTranscript(requestTranscript)
	if err != nil {
		log.Fatalf("Request transcript verification failed: %v", err)
	}
	fmt.Printf("   ✅ Request transcript verification passed\n")

	// Verify response transcript
	err = enclave.VerifyTranscript(responseTranscript)
	if err != nil {
		log.Fatalf("Response transcript verification failed: %v", err)
	}
	fmt.Printf("   ✅ Response transcript verification passed\n")

	fmt.Println("🎉 Full protocol flow completed successfully!")
}

func demoTranscriptVerification() {
	// Create a valid transcript
	signer, err := enclave.GenerateDemoKey()
	if err != nil {
		log.Fatalf("Failed to generate demo key: %v", err)
	}

	sessionID := "verification-demo"
	requests := [][]byte{
		[]byte("Valid request data for verification test"),
	}

	signedTranscript, err := signer.SignRequestTranscript(sessionID, requests, nil)
	if err != nil {
		log.Fatalf("Failed to sign transcript: %v", err)
	}

	fmt.Println("✅ Valid Transcript Verification:")
	err = enclave.VerifyTranscript(signedTranscript)
	if err != nil {
		fmt.Printf("   ❌ Verification failed: %v\n", err)
	} else {
		fmt.Printf("   ✅ Verification passed\n")
	}

	fmt.Println()
	fmt.Println("❌ Invalid Transcript Verification (corrupted signature):")

	// Create a corrupted copy
	corruptedTranscript := *signedTranscript
	corruptedTranscript.Signature = []byte("this_is_a_corrupted_signature")

	err = enclave.VerifyTranscript(&corruptedTranscript)
	if err != nil {
		fmt.Printf("   ✅ Correctly rejected corrupted transcript: %v\n", err)
	} else {
		fmt.Printf("   ❌ Should have rejected corrupted transcript\n")
	}

	fmt.Println()
	fmt.Println("💡 Summary:")
	fmt.Println("   • Transcript signing ensures authenticity and integrity")
	fmt.Println("   • TEE_K signs request transcripts with commitments")
	fmt.Println("   • TEE_T signs response transcripts with encrypted data")
	fmt.Println("   • Verifiers can validate both transcripts independently")
	fmt.Println("   • Supports both RSA-PSS and ECDSA signing algorithms")
}
