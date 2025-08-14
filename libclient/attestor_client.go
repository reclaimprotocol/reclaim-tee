package clientlib

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	teeproto "tee-mpc/proto"
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
	initRequest := &teeproto.InitRequest{
		ClientVersion: teeproto.AttestorVersion_ATTESTOR_VERSION_2_0_1, // Latest version
		SignatureType: teeproto.ServiceSignatureType_SERVICE_SIGNATURE_TYPE_ETH,
		Auth:          nil, // No authentication for now
	}

	ac.logger.Info("InitRequest created",
		zap.String("client_version", "ATTESTOR_VERSION_2_0_1"),
		zap.String("signature_type", "SERVICE_SIGNATURE_TYPE_ETH"))

	// Wrap in RPCMessage
	rpcMessage := &teeproto.RPCMessage{
		Id: 1,
		Message: &teeproto.RPCMessage_InitRequest{
			InitRequest: initRequest,
		},
	}

	ac.logger.Info("Marshaling InitRequest into RPCMessage")

	// Wrap in RPCMessages array as expected by attestor-core
	rpcMessages := &teeproto.RPCMessages{
		Messages: []*teeproto.RPCMessage{rpcMessage},
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
	var responseMessages teeproto.RPCMessages
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
func (ac *AttestorClient) SubmitTeeBundle(verificationBundle *teeproto.VerificationBundle, params ClaimTeeBundleParams) (*teeproto.ProviderClaimData, error) {
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
	claimData := &teeproto.ClaimRequestData{
		Provider:   params.Provider,
		Parameters: string(parametersJson),
		Owner:      ac.address.Hex(),
		TimestampS: timestamp,
		Context:    contextJson,
	}

	// 5. Create request without signatures for signing
	request := &teeproto.ClaimTeeBundleRequest{
		VerificationBundle: bundleBytes,
		Data:               claimData,
	}

	// 6. Sign the request
	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request for signing: %v", err)
	}

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

// sendRPCMessage sends an RPC message and waits for response
func (ac *AttestorClient) sendRPCMessage(request *teeproto.ClaimTeeBundleRequest) (*teeproto.ClaimTeeBundleResponse, error) {
	ac.logger.Info("Creating ClaimTeeBundleRequest RPC message")

	// Wrap in RPC message envelope with incrementing ID
	rpcMessage := &teeproto.RPCMessage{
		Id: 2, // Use ID 2 since init used ID 1
		Message: &teeproto.RPCMessage_ClaimTeeBundleRequest{
			ClaimTeeBundleRequest: request,
		},
	}

	ac.logger.Info("Marshaling ClaimTeeBundleRequest")

	// Wrap in RPCMessages array as expected by attestor-core
	rpcMessages := &teeproto.RPCMessages{
		Messages: []*teeproto.RPCMessage{rpcMessage},
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
	var responseMessages teeproto.RPCMessages
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
