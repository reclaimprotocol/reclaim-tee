package main

import (
	"fmt"
	"log"
	"tee-mpc/shared"
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

// sendFinishedCommand sends "finished" message to both TEE_K and TEE_T
func (c *Client) sendFinishedCommand() error {
	log.Printf("[Client] Sending finished command to both TEE_K and TEE_T")

	finishedMsg := shared.FinishedMessage{}

	// Send to TEE_K
	msg := shared.CreateSessionMessage(shared.MsgFinished, c.sessionID, finishedMsg)
	if err := c.wsConn.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send finished to TEE_K: %v", err)
	}
	log.Printf("[Client] Sent finished command to TEE_K")

	// Send to TEE_T
	if err := c.teetConn.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send finished to TEE_T: %v", err)
	}
	log.Printf("[Client] Sent finished command to TEE_T")

	log.Printf("[Client] Now waiting for signed transcripts from both TEE_K and TEE_T...")

	return nil
}

// isTLS12AESGCMCipher checks if the current connection is using TLS 1.2 AES-GCM
func (c *Client) isTLS12AESGCMCipher() bool {
	if c.handshakeDisclosure == nil {
		return false
	}

	cipherSuite := c.handshakeDisclosure.CipherSuite
	return cipherSuite == 0xc02f || // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		cipherSuite == 0xc02b || // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		cipherSuite == 0xc030 || // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		cipherSuite == 0xc02c // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
}
