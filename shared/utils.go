package shared

import "runtime"

// getStackTrace returns a string containing the current goroutine's stack trace
func getStackTrace() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}
