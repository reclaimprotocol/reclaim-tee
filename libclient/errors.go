package clientlib

import (
	"fmt"
)

// ReclaimError is the base error type for all library errors
type ReclaimError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Cause   error  `json:"cause,omitempty"`
}

// Error implements the error interface
func (e *ReclaimError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap implements the error unwrapping interface
func (e *ReclaimError) Unwrap() error {
	return e.Cause
}

// ConnectionError represents connection-related errors
type ConnectionError struct {
	*ReclaimError
	Target string `json:"target"` // Which service failed (TEE_K, TEE_T, etc.)
}

// NewConnectionError creates a new connection error
func NewConnectionError(target string, cause error) *ConnectionError {
	return &ConnectionError{
		ReclaimError: &ReclaimError{
			Type:    "connection_error",
			Message: fmt.Sprintf("Failed to connect to %s", target),
			Cause:   cause,
		},
		Target: target,
	}
}

// AttestationError represents attestation verification errors
type AttestationError struct {
	*ReclaimError
}

// NewAttestationError creates a new attestation error
func NewAttestationError(cause error) *AttestationError {
	return &AttestationError{
		ReclaimError: &ReclaimError{
			Type:    "attestation_error",
			Message: "Failed to verify TEE attestation",
			Cause:   cause,
		},
	}
}

// ProtocolError represents protocol-related errors
type ProtocolError struct {
	*ReclaimError
	Phase string `json:"phase"` // Which protocol phase failed
}

// NewProtocolError creates a new protocol error
func NewProtocolError(phase string, message string, cause error) *ProtocolError {
	return &ProtocolError{
		ReclaimError: &ReclaimError{
			Type:    "protocol_error",
			Message: fmt.Sprintf("Protocol error in %s: %s", phase, message),
			Cause:   cause,
		},
		Phase: phase,
	}
}

// RedactionError represents redaction-related errors
type RedactionError struct {
	*ReclaimError
	RedactionType string `json:"redaction_type"` // "request" or "response"
}

// NewRedactionError creates a new redaction error
func NewRedactionError(redactionType string, message string, cause error) *RedactionError {
	return &RedactionError{
		ReclaimError: &ReclaimError{
			Type:    "redaction_error",
			Message: fmt.Sprintf("Redaction error (%s): %s", redactionType, message),
			Cause:   cause,
		},
		RedactionType: redactionType,
	}
}

// ConfigurationError represents configuration-related errors
type ConfigurationError struct {
	*ReclaimError
	Field string `json:"field"` // Which configuration field is invalid
}

// NewConfigurationError creates a new configuration error
func NewConfigurationError(field string, message string) *ConfigurationError {
	return &ConfigurationError{
		ReclaimError: &ReclaimError{
			Type:    "configuration_error",
			Message: fmt.Sprintf("Configuration error in field '%s': %s", field, message),
		},
		Field: field,
	}
}

// ValidationError represents validation errors
type ValidationError struct {
	*ReclaimError
	Field string      `json:"field"` // Field that failed validation
	Value interface{} `json:"value"` // Invalid value
}

// NewValidationError creates a new validation error
func NewValidationError(field string, value interface{}, message string) *ValidationError {
	return &ValidationError{
		ReclaimError: &ReclaimError{
			Type:    "validation_error",
			Message: fmt.Sprintf("Validation error for field '%s': %s", field, message),
		},
		Field: field,
		Value: value,
	}
}
