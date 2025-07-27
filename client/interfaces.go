package main

import (
	"tee-mpc/shared"
)

// MessageHandler defines the interface for handling different types of messages
type MessageHandler interface {
	HandleMessage(msg *Message) error
}

// RedactionProcessor defines the interface for processing redaction-related operations
type RedactionProcessor interface {
	ProcessRedactionVerification(msg *Message) error
	ProcessSignedRedactedDecryptionStream(msg *Message) error
}

// ResponseProcessor defines the interface for processing response data
type ResponseProcessor interface {
	ProcessHTTPResponse(msg *Message) error
	ProcessSessionReady(msg *Message) error
}

// TranscriptValidator defines the interface for transcript validation
type TranscriptValidator interface {
	ValidateSignedTranscript(transcript *shared.SignedTranscript) error
}
