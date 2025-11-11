package client

import (
	"go.uber.org/zap"
)

// WaitForCompletion returns a channel that signals when the protocol is complete
// The channel will receive nil for success or an error if the protocol failed
func (c *Client) WaitForCompletion() <-chan error {
	return c.completionChan
}

// checkProtocolCompletion checks if all conditions are met and signals completion if so
func (c *Client) checkProtocolCompletion(reason string) {
	currentPhase := c.getCurrentPhase()

	c.logger.Info("Checking completion", zap.String("reason", reason), zap.String("current_phase", currentPhase.String()))

	if currentPhase == PhaseComplete {
		c.logger.Info("Protocol already complete")
		return
	}

	// For debugging: show where we are in the process
	switch currentPhase {
	case PhaseHandshaking:
		c.logger.Info("Handshaking in progress")
	case PhaseCollectingResponses:
		collectionComplete, _, _ := c.getBatchState()
		if collectionComplete {
			c.logger.Info("Responses collected, batch will be sent automatically")
		} else {
			c.logger.Info("Still collecting responses")
		}
	case PhaseReceivingDecryption:
		c.logger.Info("Waiting for batched decryption streams")
	case PhaseSendingRedaction:
		c.logger.Info("Redaction phase - specs will be sent automatically")
	case PhaseReceivingRedacted:
		c.logger.Info("Waiting for redacted streams")
	default:
		c.logger.Info("No completion action for current phase")
	}
}
