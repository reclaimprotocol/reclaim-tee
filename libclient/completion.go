package clientlib

import (
	"go.uber.org/zap"
)

// WaitForCompletion returns a channel that closes when the protocol is complete
func (c *Client) WaitForCompletion() <-chan struct{} {
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
	case PhaseSendingBatch:
		c.logger.Info("Sending batch of responses to TEE_T")
	case PhaseReceivingDecryption:
		c.logger.Info("Waiting for batched decryption streams")
	case PhaseWaitingForRedactionRanges:
		c.logger.Info("Waiting for response redaction ranges from application")
	case PhaseSendingRedaction:
		c.logger.Info("Redaction phase - specs will be sent automatically")
	case PhaseReceivingRedacted:
		c.logger.Info("Waiting for redacted streams")
	case PhaseReceivingTranscripts:
		phase, count := c.getProtocolState()
		c.logger.Info("Waiting for transcripts", zap.Int("received", count), zap.String("phase", phase.String()))
	default:
		c.logger.Info("No completion action for current phase")
	}
}
