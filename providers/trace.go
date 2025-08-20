package providers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// TraceLevel defines the verbosity of trace logging
type TraceLevel int

const (
	TraceLevelOff TraceLevel = iota
	TraceLevelError
	TraceLevelWarn
	TraceLevelInfo
	TraceLevelDebug
	TraceLevelVerbose
)

var traceLevelNames = map[TraceLevel]string{
	TraceLevelOff:     "OFF",
	TraceLevelError:   "ERROR",
	TraceLevelWarn:    "WARN",
	TraceLevelInfo:    "INFO",
	TraceLevelDebug:   "DEBUG",
	TraceLevelVerbose: "VERBOSE",
}

// TraceConfig holds the configuration for trace logging
type TraceConfig struct {
	Level        TraceLevel
	EnableColors bool
	ShowTimestamp bool
	ShowCaller   bool
	MaxDataSize  int // Maximum size of data to log (in bytes)
}

var (
	traceConfig = TraceConfig{
		Level:         TraceLevelOff,
		EnableColors:  true,
		ShowTimestamp: true,
		ShowCaller:    true,
		MaxDataSize:   1024, // 1KB default
	}
	traceMutex sync.RWMutex
)

// Color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGreen  = "\033[32m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

// InitTrace initializes the trace system from environment variables
func InitTrace() {
	level := os.Getenv("RECLAIM_TRACE_LEVEL")
	switch strings.ToUpper(level) {
	case "ERROR":
		traceConfig.Level = TraceLevelError
	case "WARN":
		traceConfig.Level = TraceLevelWarn
	case "INFO":
		traceConfig.Level = TraceLevelInfo
	case "DEBUG":
		traceConfig.Level = TraceLevelDebug
	case "VERBOSE":
		traceConfig.Level = TraceLevelVerbose
	default:
		traceConfig.Level = TraceLevelOff
	}

	if os.Getenv("RECLAIM_TRACE_NO_COLOR") != "" {
		traceConfig.EnableColors = false
	}
	
	if os.Getenv("RECLAIM_TRACE_NO_TIMESTAMP") != "" {
		traceConfig.ShowTimestamp = false
	}
}

// SetTraceLevel sets the trace level programmatically
func SetTraceLevel(level TraceLevel) {
	traceMutex.Lock()
	traceConfig.Level = level
	traceMutex.Unlock()
}

// GetTraceLevel returns the current trace level
func GetTraceLevel() TraceLevel {
	traceMutex.RLock()
	defer traceMutex.RUnlock()
	return traceConfig.Level
}

// IsTraceEnabled checks if tracing is enabled for the given level
func IsTraceEnabled(level TraceLevel) bool {
	traceMutex.RLock()
	defer traceMutex.RUnlock()
	return traceConfig.Level >= level
}

// formatMessage formats a trace message with colors and metadata
func formatMessage(level TraceLevel, component, operation, message string) string {
	var color string
	if traceConfig.EnableColors {
		switch level {
		case TraceLevelError:
			color = colorRed
		case TraceLevelWarn:
			color = colorYellow
		case TraceLevelInfo:
			color = colorBlue
		case TraceLevelDebug:
			color = colorGreen
		case TraceLevelVerbose:
			color = colorPurple
		}
	}

	var parts []string
	
	if traceConfig.ShowTimestamp {
		parts = append(parts, fmt.Sprintf("%s[%s]%s", colorGray, time.Now().Format("15:04:05.000"), colorReset))
	}
	
	levelStr := traceLevelNames[level]
	parts = append(parts, fmt.Sprintf("%s[%s]%s", color, levelStr, colorReset))
	
	parts = append(parts, fmt.Sprintf("%s[%s:%s]%s", colorCyan, component, operation, colorReset))
	parts = append(parts, message)

	return strings.Join(parts, " ")
}

// truncateData truncates data to maximum allowed size for logging
func truncateData(data string) string {
	if len(data) <= traceConfig.MaxDataSize {
		return data
	}
	return data[:traceConfig.MaxDataSize] + fmt.Sprintf("... [truncated, total: %d bytes]", len(data))
}

// TraceError logs an error message
func TraceError(component, operation, format string, args ...interface{}) {
	if !IsTraceEnabled(TraceLevelError) {
		return
	}
	message := fmt.Sprintf(format, args...)
	fmt.Println(formatMessage(TraceLevelError, component, operation, message))
}

// TraceWarn logs a warning message
func TraceWarn(component, operation, format string, args ...interface{}) {
	if !IsTraceEnabled(TraceLevelWarn) {
		return
	}
	message := fmt.Sprintf(format, args...)
	fmt.Println(formatMessage(TraceLevelWarn, component, operation, message))
}

// TraceInfo logs an informational message
func TraceInfo(component, operation, format string, args ...interface{}) {
	if !IsTraceEnabled(TraceLevelInfo) {
		return
	}
	message := fmt.Sprintf(format, args...)
	fmt.Println(formatMessage(TraceLevelInfo, component, operation, message))
}

// TraceDebug logs a debug message
func TraceDebug(component, operation, format string, args ...interface{}) {
	if !IsTraceEnabled(TraceLevelDebug) {
		return
	}
	message := fmt.Sprintf(format, args...)
	fmt.Println(formatMessage(TraceLevelDebug, component, operation, message))
}

// TraceVerbose logs a verbose debug message
func TraceVerbose(component, operation, format string, args ...interface{}) {
	if !IsTraceEnabled(TraceLevelVerbose) {
		return
	}
	message := fmt.Sprintf(format, args...)
	fmt.Println(formatMessage(TraceLevelVerbose, component, operation, message))
}

// TraceData logs structured data (JSON format) at debug level
func TraceData(component, operation string, label string, data interface{}) {
	if !IsTraceEnabled(TraceLevelDebug) {
		return
	}
	
	var dataStr string
	switch v := data.(type) {
	case string:
		dataStr = truncateData(v)
	case []byte:
		dataStr = truncateData(string(v))
	default:
		if jsonData, err := json.MarshalIndent(data, "", "  "); err == nil {
			dataStr = truncateData(string(jsonData))
		} else {
			dataStr = fmt.Sprintf("%+v", data)
		}
	}
	
	message := fmt.Sprintf("%s:\n%s", label, dataStr)
	fmt.Println(formatMessage(TraceLevelDebug, component, operation, message))
}

// TraceStep logs a step in a multi-step process
func TraceStep(component, operation string, step int, total int, description string) {
	if !IsTraceEnabled(TraceLevelInfo) {
		return
	}
	message := fmt.Sprintf("Step %d/%d: %s", step, total, description)
	fmt.Println(formatMessage(TraceLevelInfo, component, operation, message))
}

// TraceStart logs the start of an operation
func TraceStart(component, operation string, args ...interface{}) {
	if !IsTraceEnabled(TraceLevelInfo) {
		return
	}
	var message string
	if len(args) > 0 {
		message = fmt.Sprintf("Starting %s with: %v", operation, args)
	} else {
		message = fmt.Sprintf("Starting %s", operation)
	}
	fmt.Println(formatMessage(TraceLevelInfo, component, operation, message))
}

// TraceEnd logs the end of an operation with duration
func TraceEnd(component, operation string, startTime time.Time, err error) {
	if !IsTraceEnabled(TraceLevelInfo) {
		return
	}
	duration := time.Since(startTime)
	if err != nil {
		message := fmt.Sprintf("Completed %s in %v with error: %v", operation, duration, err)
		fmt.Println(formatMessage(TraceLevelError, component, operation, message))
	} else {
		message := fmt.Sprintf("Completed %s in %v", operation, duration)
		fmt.Println(formatMessage(TraceLevelInfo, component, operation, message))
	}
}

// TraceResult logs the result of an operation
func TraceResult(component, operation string, result interface{}, err error) {
	if err != nil {
		TraceError(component, operation, "Operation failed: %v", err)
		return
	}
	
	if IsTraceEnabled(TraceLevelDebug) {
		TraceData(component, operation, "Result", result)
	} else if IsTraceEnabled(TraceLevelInfo) {
		TraceInfo(component, operation, "Operation succeeded")
	}
}

// TraceBinary logs binary data in a readable format
func TraceBinary(component, operation, label string, data []byte, maxBytes int) {
	if !IsTraceEnabled(TraceLevelVerbose) {
		return
	}
	
	if maxBytes == 0 {
		maxBytes = 256 // Default to 256 bytes
	}
	
	displayData := data
	if len(data) > maxBytes {
		displayData = data[:maxBytes]
	}
	
	var hexStr strings.Builder
	var asciiStr strings.Builder
	
	for i, b := range displayData {
		if i > 0 && i%16 == 0 {
			hexStr.WriteString("\n")
			asciiStr.WriteString("\n")
		} else if i > 0 && i%8 == 0 {
			hexStr.WriteString("  ")
		} else if i > 0 {
			hexStr.WriteString(" ")
		}
		
		hexStr.WriteString(fmt.Sprintf("%02x", b))
		
		if b >= 32 && b <= 126 {
			asciiStr.WriteByte(b)
		} else {
			asciiStr.WriteByte('.')
		}
	}
	
	message := fmt.Sprintf("%s (%d bytes):\nHex: %s\nASCII: %s", 
		label, len(data), hexStr.String(), asciiStr.String())
	
	if len(data) > maxBytes {
		message += fmt.Sprintf("\n... [truncated, showing first %d of %d bytes]", maxBytes, len(data))
	}
	
	fmt.Println(formatMessage(TraceLevelVerbose, component, operation, message))
}

// Initialize trace system on package import
func init() {
	InitTrace()
}