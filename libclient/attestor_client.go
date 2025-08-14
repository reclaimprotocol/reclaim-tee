package clientlib

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/proto/attestor"
	"tee-mpc/shared"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// AttestorClient handles communication with attestor-core for TEE bundle submission
type AttestorClient struct {
	url        string
	conn       *websocket.Conn
	privateKey *ecdsa.PrivateKey
	address    common.Address
	logger     *shared.Logger
}

// NewAttestorClient creates a new client for communicating with attestor-core
func NewAttestorClient(attestorURL string, privateKey *ecdsa.PrivateKey, logger *shared.Logger) *AttestorClient {
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	return &AttestorClient{
		url:        attestorURL,
		privateKey: privateKey,
		address:    address,
		logger:     logger,
	}
}

// Connect establishes WebSocket connection to attestor-core and initializes it
func (ac *AttestorClient) Connect() error {
	u, err := url.Parse(ac.url)
	if err != nil {
		return fmt.Errorf("failed to parse attestor URL: %v", err)
	}

	ac.logger.Info("Connecting to attestor-core WebSocket", zap.String("url", ac.url))

	// Connect to attestor-core
	var conn *websocket.Conn
	if strings.HasPrefix(ac.url, "wss://") {
		// Production environment
		ac.logger.Info("Using WSS connection")
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	} else {
		// Local development
		ac.logger.Info("Using WS connection")
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to attestor-core: %v", err)
	}

	ac.conn = conn
	ac.logger.Info("WebSocket connection established, starting initialization")

	// Initialize the connection with an InitRequest
	if err := ac.initializeConnection(); err != nil {
		ac.conn.Close()
		return fmt.Errorf("failed to initialize connection: %v", err)
	}

	ac.logger.Info("AttestorClient connection and initialization complete")
	return nil
}

// initializeConnection sends the required InitRequest to attestor-core
func (ac *AttestorClient) initializeConnection() error {
	ac.logger.Info("Creating InitRequest")

	// Create InitRequest
	initRequest := &attestor.InitRequest{
		ClientVersion: attestor.AttestorVersion_ATTESTOR_VERSION_2_0_1, // Latest version
		SignatureType: attestor.ServiceSignatureType_SERVICE_SIGNATURE_TYPE_ETH,
		Auth:          nil, // No authentication for now
	}

	ac.logger.Info("InitRequest created",
		zap.String("client_version", "ATTESTOR_VERSION_2_0_1"),
		zap.String("signature_type", "SERVICE_SIGNATURE_TYPE_ETH"))

	// Wrap in RPCMessage
	rpcMessage := &attestor.RPCMessage{
		Id: 1,
		Message: &attestor.RPCMessage_InitRequest{
			InitRequest: initRequest,
		},
	}

	ac.logger.Info("Marshaling InitRequest into RPCMessage")

	// Wrap in RPCMessages array as expected by attestor-core
	rpcMessages := &attestor.RPCMessages{
		Messages: []*attestor.RPCMessage{rpcMessage},
	}

	// Send the init request
	messageBytes, err := proto.Marshal(rpcMessages)
	if err != nil {
		return fmt.Errorf("failed to marshal init request: %v", err)
	}

	ac.logger.Info("Sending InitRequest over WebSocket",
		zap.Int("message_size", len(messageBytes)),
		zap.Uint64("rpc_id", rpcMessage.Id))

	if err := ac.conn.WriteMessage(websocket.BinaryMessage, messageBytes); err != nil {
		return fmt.Errorf("failed to send init request: %v", err)
	}

	ac.logger.Info("InitRequest sent, waiting for response...")

	// Read the init response
	_, responseBytes, err := ac.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read init response: %v", err)
	}

	ac.logger.Info("Received init response", zap.Int("response_size", len(responseBytes)))

	// Parse init response - attestor sends RPCMessages array
	var responseMessages attestor.RPCMessages
	if err := proto.Unmarshal(responseBytes, &responseMessages); err != nil {
		return fmt.Errorf("failed to unmarshal init response: %v", err)
	}

	if len(responseMessages.Messages) == 0 {
		return fmt.Errorf("received empty RPCMessages array")
	}

	responseMessage := responseMessages.Messages[0]

	ac.logger.Info("Parsed init response",
		zap.Uint64("response_id", responseMessage.Id),
		zap.Bool("has_error", responseMessage.GetRequestError() != nil),
		zap.Bool("has_init_response", responseMessage.GetInitResponse() != nil))

	// Check for error in response
	if responseMessage.GetRequestError() != nil {
		ac.logger.Error("Init request failed",
			zap.Int32("error_code", int32(responseMessage.GetRequestError().Code)),
			zap.String("error_message", responseMessage.GetRequestError().Message))
		return fmt.Errorf("init request failed: %s", responseMessage.GetRequestError().Message)
	}

	// Verify we got an init response
	if responseMessage.GetInitResponse() == nil {
		ac.logger.Error("Unexpected response type - expected init response")
		return fmt.Errorf("expected init response, got different message type")
	}

	ac.logger.Info("InitRequest completed successfully")
	return nil
}

// Close closes the WebSocket connection
func (ac *AttestorClient) Close() error {
	if ac.conn != nil {
		return ac.conn.Close()
	}
	return nil
}

// ClaimTeeBundleParams contains parameters for claim submission
type ClaimTeeBundleParams struct {
	Provider   string                 // Provider name (e.g., "http", "github")
	Parameters map[string]interface{} // Provider-specific parameters
	Context    map[string]interface{} // Optional context
}

// SubmitTeeBundle submits a TEE verification bundle to attestor-core for claim validation
func (ac *AttestorClient) SubmitTeeBundle(verificationBundle *teeproto.VerificationBundle, params ClaimTeeBundleParams) (*attestor.ProviderClaimData, error) {
	// 1. Serialize the verification bundle
	bundleBytes, err := proto.Marshal(verificationBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verification bundle: %v", err)
	}

	// 2. Prepare parameters and context as JSON
	parametersJson, err := json.Marshal(params.Parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal parameters: %v", err)
	}

	contextJson := "{}"
	if params.Context != nil {
		contextBytes, err := json.Marshal(params.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal context: %v", err)
		}
		contextJson = string(contextBytes)
	}

	// 3. Create claim request data with consistent timestamp
	timestamp := uint32(time.Now().Unix())
	claimData := &attestor.ClaimRequestData{
		Provider:   params.Provider,
		Parameters: string(parametersJson),
		Owner:      ac.address.Hex(),
		TimestampS: timestamp,
		Context:    contextJson,
	}

	// 4. Create ClaimTunnelRequest from TEE bundle data
	claimTunnelRequest, err := ac.createClaimTunnelRequestFromTeeBundle(verificationBundle, claimData)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClaimTunnelRequest: %v", err)
	}

	// 5. Create request without signatures for signing
	request := &attestor.ClaimTeeBundleRequest{
		VerificationBundle: bundleBytes,
		Data:               claimData,
		ClaimTunnelRequest: claimTunnelRequest,
		Signatures:         nil, // Will be added after signing
	}

	// 6. Sign the request
	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request for signing: %v", err)
	}

	// ===== TEE BUNDLE SIGNATURE DEBUG LOGGING =====
	hasher := sha256.New()
	hasher.Write(requestBytes)
	serializedHash := hex.EncodeToString(hasher.Sum(nil))

	// Verify the owner address matches the private key
	address := crypto.PubkeyToAddress(ac.privateKey.PublicKey)

	ac.logger.Info("TEE Bundle signature creation debug",
		zap.String("owner", claimData.Owner),
		zap.String("privateKeyAddress", address.Hex()),
		zap.Bool("addressesMatch", strings.EqualFold(claimData.Owner, address.Hex())),
		zap.Int("serializedLength", len(requestBytes)),
		zap.String("serializedHash", serializedHash),
		zap.String("serializedPreview", hex.EncodeToString(requestBytes[:min(200, len(requestBytes))])),
		zap.String("signatureType", "ETH"),
		zap.Uint32("timestampS", claimData.TimestampS),
		zap.String("provider", claimData.Provider),
		zap.Int("parametersLength", len(claimData.Parameters)),
		zap.Int("contextLength", len(claimData.Context)),
		zap.Int("bundleLength", len(bundleBytes)),
	)
	// ===== END TEE BUNDLE DEBUG LOGGING =====

	// Use personal_sign compatible signature (same as ethers.js wallet.signMessage)
	signature, err := crypto.Sign(accounts.TextHash(requestBytes), ac.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %v", err)
	}

	// Log signature creation details
	ac.logger.Info("TEE Bundle signature details",
		zap.Int("signatureLength", len(signature)),
		zap.String("signatureHex", hex.EncodeToString(signature[:min(10, len(signature))])+"..."),
		zap.String("textHashHex", hex.EncodeToString(accounts.TextHash(requestBytes))),
		zap.String("recoveryId", fmt.Sprintf("%d", signature[64])),
	)

	// Convert to ethers.js compatible format: add 27 to recovery ID for ethers.js
	if len(signature) == 65 {
		signature[64] += 27
		ac.logger.Info("Converted signature for ethers.js compatibility",
			zap.String("newRecoveryId", fmt.Sprintf("%d", signature[64])),
		)
	}

	// 7. Add signature to request
	request.Signatures = &attestor.ClaimTeeBundleRequest_Signatures{
		RequestSignature: signature,
	}

	ac.logger.Info("Added signature to request",
		zap.Int("signature_length", len(signature)),
		zap.String("signature_hex", fmt.Sprintf("0x%x...", signature[:10])),
		zap.String("owner_address", ac.address.Hex()))

	ac.logger.Info("Sending TEE bundle claim request",
		zap.String("provider", params.Provider),
		zap.String("owner", ac.address.Hex()),
		zap.Int("bundle_bytes", len(bundleBytes)),
		zap.Int("signature_bytes", len(signature)))

	// 8. Send the request
	ac.logger.Info("Sending ClaimTeeBundleRequest")
	response, err := ac.sendRPCMessage(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	ac.logger.Info("Received ClaimTeeBundleResponse")

	// 9. Process the response
	if response.GetError() != nil {
		return nil, fmt.Errorf("claim failed: %s - %s", response.GetError().Code, response.GetError().Message)
	}

	if response.GetClaim() == nil {
		return nil, fmt.Errorf("no claim returned in response")
	}

	claim := response.GetClaim()
	ac.logger.Info("TEE bundle claim successful",
		zap.String("claim_id", claim.Identifier),
		zap.String("provider", claim.Provider),
		zap.String("owner", claim.Owner))

	// 10. Verify attestor signatures (optional but recommended)
	if response.Signatures != nil {
		ac.logger.Info("Attestor signatures received",
			zap.String("attestor_address", response.Signatures.AttestorAddress),
			zap.Int("claim_signature_bytes", len(response.Signatures.ClaimSignature)),
			zap.Int("result_signature_bytes", len(response.Signatures.ResultSignature)))
	}

	return response.GetClaim(), nil
}

// createClaimTunnelRequestFromTeeBundle creates a ClaimTunnelRequest from TEE bundle data
// This allows the attestor to use existing validation logic
func (ac *AttestorClient) createClaimTunnelRequestFromTeeBundle(bundle *teeproto.VerificationBundle, claimData *attestor.ClaimRequestData) (*attestor.ClaimTunnelRequest, error) {
	// 1. Reconstruct transcript exactly like attestor will do
	transcript, err := ReconstructTranscriptForClaimTunnel(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct transcript: %v", err)
	}

	// 2. Extract host from bundle
	host := ExtractHostFromBundle(bundle)

	// 3. Create complete ClaimTunnelRequest with reconstructed transcript
	claimTunnelRequest := &attestor.ClaimTunnelRequest{
		Request: &attestor.CreateTunnelRequest{
			Id:          0, // Synthetic tunnel ID
			Host:        host,
			Port:        443, // Default HTTPS port
			GeoLocation: "",  // Not applicable for TEE mode
		},
		Data:          claimData,
		Transcript:    transcript, // ✅ NOW INCLUDES RECONSTRUCTED TRANSCRIPT
		ZkEngine:      0,          // ✅ TEE mode (use 0, not ZK_ENGINE_SNARKJS)
		FixedServerIV: []byte{},   // ✅ Empty for TEE mode
		FixedClientIV: []byte{},   // ✅ Empty for TEE mode
		Signatures:    nil,        // Will be added after signing
	}

	// 4. Marshal for signing (same as attestor does)
	claimTunnelBytes, err := proto.Marshal(claimTunnelRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ClaimTunnelRequest for signing: %v", err)
	}

	// 5. Sign using Ethereum personal_sign
	signature, err := crypto.Sign(accounts.TextHash(claimTunnelBytes), ac.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign ClaimTunnelRequest: %v", err)
	}

	// Log signature info
	ac.logger.Info("TEE signature creation",
		zap.Int("signatureLength", len(signature)),
		zap.String("signatureHex", hex.EncodeToString(signature[:min(10, len(signature))])+"..."),
		zap.String("textHashHex", hex.EncodeToString(accounts.TextHash(claimTunnelBytes))),
	)

	// 6. Add signature to the request
	claimTunnelRequest.Signatures = &attestor.ClaimTunnelRequest_Signatures{
		RequestSignature: signature,
	}

	ac.logger.Info("Created complete ClaimTunnelRequest with reconstructed transcript",
		zap.String("host", host),
		zap.Int("transcript_messages", len(transcript)),
		zap.Int("signature_length", len(signature)),
		zap.String("signature_hex", fmt.Sprintf("0x%x...", signature[:10])))

	return claimTunnelRequest, nil
}

// sendRPCMessage sends an RPC message and waits for response
func (ac *AttestorClient) sendRPCMessage(request *attestor.ClaimTeeBundleRequest) (*attestor.ClaimTeeBundleResponse, error) {
	ac.logger.Info("Creating ClaimTeeBundleRequest RPC message")

	// Wrap in RPC message envelope with incrementing ID
	rpcMessage := &attestor.RPCMessage{
		Id: 2, // Use ID 2 since init used ID 1
		Message: &attestor.RPCMessage_ClaimTeeBundleRequest{
			ClaimTeeBundleRequest: request,
		},
	}

	ac.logger.Info("Marshaling ClaimTeeBundleRequest")

	// Wrap in RPCMessages array as expected by attestor-core
	rpcMessages := &attestor.RPCMessages{
		Messages: []*attestor.RPCMessage{rpcMessage},
	}

	// Serialize and send
	messageBytes, err := proto.Marshal(rpcMessages)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RPC message: %v", err)
	}

	ac.logger.Info("Sending ClaimTeeBundleRequest over WebSocket",
		zap.Int("message_size", len(messageBytes)),
		zap.Uint64("rpc_id", rpcMessage.Id))

	if err := ac.conn.WriteMessage(websocket.BinaryMessage, messageBytes); err != nil {
		return nil, fmt.Errorf("failed to send message: %v", err)
	}

	ac.logger.Info("ClaimTeeBundleRequest sent, waiting for response...")

	// Read response
	_, responseBytes, err := ac.conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	ac.logger.Info("Received ClaimTeeBundleResponse", zap.Int("response_size", len(responseBytes)))

	// Parse response - attestor sends RPCMessages array
	var responseMessages attestor.RPCMessages
	if err := proto.Unmarshal(responseBytes, &responseMessages); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if len(responseMessages.Messages) == 0 {
		return nil, fmt.Errorf("received empty RPCMessages array")
	}

	responseMessage := responseMessages.Messages[0]

	ac.logger.Info("Parsed ClaimTeeBundleResponse",
		zap.Uint64("response_id", responseMessage.Id),
		zap.Bool("has_error", responseMessage.GetRequestError() != nil),
		zap.Bool("has_claim_response", responseMessage.GetClaimTeeBundleResponse() != nil))

	// Check for error in response
	if responseMessage.GetRequestError() != nil {
		ac.logger.Error("ClaimTeeBundleRequest failed",
			zap.Int32("error_code", int32(responseMessage.GetRequestError().Code)),
			zap.String("error_message", responseMessage.GetRequestError().Message))
		return nil, fmt.Errorf("RPC request failed: %s", responseMessage.GetRequestError().Message)
	}

	// Extract the specific response
	response := responseMessage.GetClaimTeeBundleResponse()
	if response == nil {
		ac.logger.Error("Unexpected response type - expected ClaimTeeBundleResponse")
		return nil, fmt.Errorf("expected ClaimTeeBundleResponse, got different message type")
	}

	ac.logger.Info("ClaimTeeBundleRequest completed successfully")
	return response, nil
}

// HTTPProviderParams creates parameters for HTTP provider claims
func HTTPProviderParams(url, method string, headers map[string]string, body string, responseMatches []map[string]string, responseRedactions []map[string]string) map[string]interface{} {
	params := map[string]interface{}{
		"url":    url,
		"method": method,
	}

	if headers != nil {
		params["headers"] = headers
	}

	if body != "" {
		params["body"] = body
	}

	if responseMatches != nil {
		params["responseMatches"] = responseMatches
	}

	if responseRedactions != nil {
		params["responseRedactions"] = responseRedactions
	}

	return params
}

// Helper functions for debug hashing
func hashRequestOnly(req *attestor.ClaimTunnelRequest) string {
	tempReq := &attestor.ClaimTunnelRequest{
		Request:       req.Request,
		ZkEngine:      req.ZkEngine,
		FixedServerIV: req.FixedServerIV,
		FixedClientIV: req.FixedClientIV,
	}
	bytes, _ := proto.Marshal(tempReq)
	hasher := sha256.New()
	hasher.Write(bytes)
	return hex.EncodeToString(hasher.Sum(nil))
}

func hashDataOnly(req *attestor.ClaimTunnelRequest) string {
	tempReq := &attestor.ClaimTunnelRequest{
		Data: req.Data,
	}
	bytes, _ := proto.Marshal(tempReq)
	hasher := sha256.New()
	hasher.Write(bytes)
	return hex.EncodeToString(hasher.Sum(nil))
}

func hashTranscriptOnly(req *attestor.ClaimTunnelRequest) string {
	if req.Transcript == nil || len(req.Transcript) == 0 {
		return "empty"
	}
	tempReq := &attestor.ClaimTunnelRequest{
		Transcript: req.Transcript,
	}
	bytes, _ := proto.Marshal(tempReq)
	hasher := sha256.New()
	hasher.Write(bytes)
	return hex.EncodeToString(hasher.Sum(nil))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
