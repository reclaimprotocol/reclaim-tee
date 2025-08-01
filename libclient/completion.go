package clientlib

import (
	"log"
)

// WaitForCompletion returns a channel that closes when the protocol is complete
func (c *Client) WaitForCompletion() <-chan struct{} {
	return c.completionChan
}

// checkProtocolCompletion checks if all conditions are met and signals completion if so
func (c *Client) checkProtocolCompletion(reason string) {
	currentPhase := c.getCurrentPhase()

	log.Printf("[Client] Checking completion: %s (current phase: %s)", reason, currentPhase)

	if currentPhase == PhaseComplete {
		log.Printf("[Client] Protocol already complete")
		return
	}

	// For debugging: show where we are in the process
	switch currentPhase {
	case PhaseHandshaking:
		log.Printf("[Client] Still in handshaking phase")
	case PhaseCollectingResponses:
		collectionComplete, _, _ := c.getBatchState()
		if collectionComplete {
			log.Printf("[Client] Responses collected, batch will be sent automatically")
		} else {
			log.Printf("[Client] Still collecting responses")
		}
	case PhaseReceivingDecryption:
		log.Printf("[Client] Waiting for batched decryption streams")
	case PhaseWaitingForRedactionRanges:
		log.Printf("[Client] Waiting for response redaction ranges from application")
	case PhaseSendingRedaction:
		log.Printf("[Client] Redaction phase - specs will be sent automatically")
	case PhaseReceivingRedacted:
		log.Printf("[Client] Waiting for redacted streams")
	case PhaseReceivingTranscripts:
		phase, count := c.getProtocolState()
		log.Printf("[Client] Waiting for transcripts: %d/2 received (phase: %s)", count, phase)
	default:
		panic("unhandled default case")
	}
}

// Protocol flow: TEE_K sends 'finished' to TEE_T after processing redaction specification
// TEE_T then signs transcript and sends it to client
// No client finished messages are required in single session mode
