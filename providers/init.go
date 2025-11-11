package providers

import (
	"go.uber.org/zap"
)

var (
	// Package-level logger for providers - use this directly
	logger *zap.Logger
)

func init() {
	// Initialize with a basic production logger
	// This will be replaced by SetLogger if the main package provides one
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		// Fallback to nop logger if production logger fails
		logger = zap.NewNop()
	}
}

// SetLogger allows the main package to inject its configured logger
func SetLogger(l *zap.Logger) {
	if l != nil {
		logger = l.With(zap.String("package", "providers"))
	}
}

// SetSharedLogger allows the shared library to inject its Flutter-enabled logger
// This maintains compatibility with the existing libreclaim.go integration
func SetSharedLogger(l *zap.Logger) {
	if l != nil {
		logger = l
	}
}
