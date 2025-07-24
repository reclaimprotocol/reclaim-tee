package shared

import (
	"go.uber.org/zap"
)

// LoggerConfig holds the configuration for the logger
type LoggerConfig struct {
	ServiceName string // "tee_t" or "tee_k"
	EnclaveMode bool   // true if running in enclave
	Development bool   // true for development mode
}

// Logger wraps zap.Logger with additional context
type Logger struct {
	*zap.Logger
	serviceName string
	enclaveMode bool
}

// NewLogger creates a new logger instance based on the configuration
func NewLogger(config LoggerConfig) (*Logger, error) {
	var zapLogger *zap.Logger
	var err error

	if config.EnclaveMode {
		// In enclave mode, use minimal logging (error-only) or no-op for security
		// This reduces attack surface and prevents information leakage
		zapConfig := zap.NewProductionConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
		zapConfig.DisableCaller = true
		zapConfig.DisableStacktrace = true
		zapLogger, err = zapConfig.Build()
	} else if config.Development {
		// Development mode: console logging with debug level
		zapConfig := zap.NewDevelopmentConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		zapLogger, err = zapConfig.Build()
	} else {
		// Standalone production mode: structured JSON logging
		zapConfig := zap.NewProductionConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		zapLogger, err = zapConfig.Build()
	}

	if err != nil {
		return nil, err
	}

	// Add service-specific fields
	zapLogger = zapLogger.With(
		zap.String("service", config.ServiceName),
		zap.Bool("enclave_mode", config.EnclaveMode),
	)

	return &Logger{
		Logger:      zapLogger,
		serviceName: config.ServiceName,
		enclaveMode: config.EnclaveMode,
	}, nil
}

// NewLoggerFromEnv creates a logger using environment variables
func NewLoggerFromEnv(serviceName string) (*Logger, error) {
	config := LoggerConfig{
		ServiceName: serviceName,
		EnclaveMode: GetEnvOrDefault("ENCLAVE_MODE", "false") == "true",
		Development: GetEnvOrDefault("DEVELOPMENT", "false") == "true",
	}
	return NewLogger(config)
}

// Session-aware logging methods
func (l *Logger) WithSession(sessionID string) *zap.Logger {
	if sessionID == "" {
		return l.Logger
	}
	return l.Logger.With(zap.String("session_id", sessionID))
}

// Connection-aware logging methods
func (l *Logger) WithConnection(remoteAddr string) *zap.Logger {
	if remoteAddr == "" {
		return l.Logger
	}
	return l.Logger.With(zap.String("remote_addr", remoteAddr))
}

// Protocol-aware logging methods
func (l *Logger) WithMessageType(msgType string) *zap.Logger {
	if msgType == "" {
		return l.Logger
	}
	return l.Logger.With(zap.String("message_type", msgType))
}

// Crypto-aware logging methods
func (l *Logger) WithCryptoOp(operation string) *zap.Logger {
	return l.Logger.With(zap.String("crypto_operation", operation))
}

// Critical error logging - always logs even in enclave mode
func (l *Logger) Critical(msg string, fields ...zap.Field) {
	// Critical errors are always logged regardless of mode
	l.Logger.Error(msg, append(fields, zap.Bool("critical", true))...)
}

// Security event logging - for security-relevant events
func (l *Logger) Security(msg string, fields ...zap.Field) {
	// Security events are always logged regardless of mode
	l.Logger.Warn(msg, append(fields, zap.Bool("security_event", true))...)
}

// Session termination logging
func (l *Logger) SessionTerminated(sessionID string, reason string, fields ...zap.Field) {
	baseFields := []zap.Field{
		zap.String("session_id", sessionID),
		zap.String("termination_reason", reason),
		zap.Bool("session_terminated", true),
	}
	l.Logger.Error("Session terminated", append(baseFields, fields...)...)
}

// Conditional debug logging - only logs in non-enclave mode
func (l *Logger) DebugIf(msg string, fields ...zap.Field) {
	if !l.enclaveMode {
		l.Logger.Debug(msg, fields...)
	}
}

// Conditional info logging - respects enclave mode settings
func (l *Logger) InfoIf(msg string, fields ...zap.Field) {
	if !l.enclaveMode {
		l.Logger.Info(msg, fields...)
	}
}

// Conditional warning logging - respects enclave mode settings
func (l *Logger) WarnIf(msg string, fields ...zap.Field) {
	if !l.enclaveMode {
		l.Logger.Warn(msg, fields...)
	}
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.Logger.Sync()
}

// Close closes the logger and flushes any buffered entries
func (l *Logger) Close() error {
	return l.Logger.Sync()
}

// Global logger instances for backward compatibility during migration
var (
	DefaultTEETLogger *Logger
	DefaultTEEKLogger *Logger
)

// InitializeGlobalLoggers initializes the global logger instances
// This is called during application startup
func InitializeGlobalLoggers() error {
	var err error

	DefaultTEETLogger, err = NewLoggerFromEnv("tee_t")
	if err != nil {
		return err
	}

	DefaultTEEKLogger, err = NewLoggerFromEnv("tee_k")
	if err != nil {
		return err
	}

	return nil
}

// GetTEETLogger returns the default TEE_T logger
func GetTEETLogger() *Logger {
	if DefaultTEETLogger == nil {
		// Fallback: create a basic logger if not initialized
		logger, _ := NewLoggerFromEnv("tee_t")
		return logger
	}
	return DefaultTEETLogger
}

// GetTEEKLogger returns the default TEE_K logger
func GetTEEKLogger() *Logger {
	if DefaultTEEKLogger == nil {
		// Fallback: create a basic logger if not initialized
		logger, _ := NewLoggerFromEnv("tee_k")
		return logger
	}
	return DefaultTEEKLogger
}

// LogLevel constants for consistency
const (
	DebugLevel = "debug"
	InfoLevel  = "info"
	WarnLevel  = "warn"
	ErrorLevel = "error"
)
