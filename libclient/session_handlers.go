package clientlib

import (
	"fmt"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// handleSessionReady processes session ready messages from TEE_K
func (c *Client) handleSessionReady(msg *shared.Message) {
	var sessionData shared.SessionReadyData
	if err := msg.UnmarshalData(&sessionData); err != nil {
		c.logger.Error("Failed to unmarshal session ready data", zap.Error(err))
		return
	}

	c.sessionID = sessionData.SessionID
	c.logger.Info("Received session ID", zap.String("session_id", c.sessionID))

	// Send pending connection request if we have one
	if c.connectionRequestPending && c.pendingConnectionRequest != nil {
		if err := c.sendPendingConnectionRequest(); err != nil {
			c.logger.Error("Failed to send pending connection request", zap.Error(err))
		}
	}
}

// handleError handles error messages from TEE_K (fail-fast implementation)
func (c *Client) handleError(msg *shared.Message) {
	var errorData shared.ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		c.terminateConnectionWithError("Failed to unmarshal error data from TEE_K", err)
		return
	}

	// Any error from TEE_K should terminate the session immediately
	c.terminateConnectionWithError("Received error from TEE_K", fmt.Errorf("TEE_K error: %s", errorData.Message))
}

// handleHTTPResponse handles HTTP response messages from TEE_K
func (c *Client) handleHTTPResponse(msg *shared.Message) {
	var responseData shared.HTTPResponseData
	if err := msg.UnmarshalData(&responseData); err != nil {
		c.logger.Error("Failed to unmarshal HTTP response data", zap.Error(err))
		return
	}

	if responseData.Success {
	} else {
		fmt.Println(" TEE_K reported HTTP request failed")
	}
}

// handleTEETReady handles TEE_T ready confirmation
func (c *Client) handleTEETReady(msg *shared.Message) {
	var readyData shared.TEETReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		c.logger.Error("Failed to unmarshal TEE_T ready data", zap.Error(err))
		return
	}

}

// handleTEETError handles error messages from TEE_T (fail-fast implementation)
func (c *Client) handleTEETError(msg *shared.Message) {
	var errorData shared.ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		c.terminateConnectionWithError("Failed to unmarshal TEE_T error", err)
		return
	}

	// Any error from TEE_T should terminate the session immediately
	c.terminateConnectionWithError("Received error from TEE_T", fmt.Errorf("TEE_T error: %s", errorData.Message))
}
