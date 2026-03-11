package main

/*
#include <stdlib.h>
#include <stdbool.h>

// Native connection handle - opaque pointer managed by iOS/Flutter
typedef void* native_conn_handle_t;

// Connection types
typedef enum {
    CONN_TYPE_WEBSOCKET = 1,
    CONN_TYPE_TCP = 2
} connection_type_t;

// Error codes for native network operations
typedef enum {
    NATIVE_NET_SUCCESS = 0,
    NATIVE_NET_ERROR_UNKNOWN = -1,
    NATIVE_NET_ERROR_TIMEOUT = -2,
    NATIVE_NET_ERROR_EOF = -3,
    NATIVE_NET_ERROR_CLOSED = -4,
    NATIVE_NET_ERROR_CONNECT_FAILED = -5
} native_net_error_t;

// Result of a connection attempt
typedef struct {
    native_conn_handle_t handle;
    int error_code;
    const char* error_message;
} connection_result_t;

// Result of a read operation
typedef struct {
    const unsigned char* data;
    int length;
    int error_code;
} read_result_t;

// Callback function types
typedef connection_result_t (*native_connect_cb_t)(int conn_type, const char* url, int timeout_ms);
typedef read_result_t (*native_read_cb_t)(native_conn_handle_t handle, int max_bytes, int timeout_ms);
typedef int (*native_write_cb_t)(native_conn_handle_t handle, const unsigned char* data, int length);
typedef void (*native_close_cb_t)(native_conn_handle_t handle);

// Global callback storage
static native_connect_cb_t g_native_connect_cb = NULL;
static native_read_cb_t g_native_read_cb = NULL;
static native_write_cb_t g_native_write_cb = NULL;
static native_close_cb_t g_native_close_cb = NULL;

// Store callbacks
static inline void store_native_connect_cb(native_connect_cb_t cb) {
    g_native_connect_cb = cb;
}
static inline void store_native_read_cb(native_read_cb_t cb) {
    g_native_read_cb = cb;
}
static inline void store_native_write_cb(native_write_cb_t cb) {
    g_native_write_cb = cb;
}
static inline void store_native_close_cb(native_close_cb_t cb) {
    g_native_close_cb = cb;
}

// Call the connect callback
static inline connection_result_t call_native_connect(int conn_type, const char* url, int timeout_ms) {
    connection_result_t result = {NULL, NATIVE_NET_ERROR_UNKNOWN, "callback not registered"};
    if (g_native_connect_cb != NULL) {
        result = g_native_connect_cb(conn_type, url, timeout_ms);
    }
    return result;
}

// Call the read callback
static inline read_result_t call_native_read(native_conn_handle_t handle, int max_bytes, int timeout_ms) {
    read_result_t result = {NULL, 0, NATIVE_NET_ERROR_UNKNOWN};
    if (g_native_read_cb != NULL) {
        result = g_native_read_cb(handle, max_bytes, timeout_ms);
    }
    return result;
}

// Call the write callback
static inline int call_native_write(native_conn_handle_t handle, const unsigned char* data, int length) {
    if (g_native_write_cb != NULL) {
        return g_native_write_cb(handle, data, length);
    }
    return NATIVE_NET_ERROR_UNKNOWN;
}

// Call the close callback
static inline void call_native_close(native_conn_handle_t handle) {
    if (g_native_close_cb != NULL) {
        g_native_close_cb(handle);
    }
}
*/
import "C"
import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/reclaimprotocol/reclaim-tee/client"
	"go.uber.org/zap"
)

// Error variables for native network operations
var (
	ErrNativeNetworkNotEnabled = errors.New("native networking not enabled")
	ErrNativeConnectionClosed  = errors.New("native connection closed")
	ErrNativeNetworkTimeout    = errors.New("native network operation timed out")
	ErrNativeConnectFailed     = errors.New("native connection failed")
)

// Thread-safe state for native networking (following flutter_logger.go pattern)
var (
	nativeNetworkMutex   sync.RWMutex
	nativeNetworkEnabled bool = false
)

// DelegatedConn wraps a native connection handle and implements net.Conn
type DelegatedConn struct {
	handle     C.native_conn_handle_t
	connType   C.connection_type_t
	remoteAddr string
	localAddr  string

	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closed     int32 // atomic flag

	// Buffered read data for partial reads
	readBuffer []byte
}

// Ensure DelegatedConn implements net.Conn
var _ net.Conn = (*DelegatedConn)(nil)

// newDelegatedConn creates a new DelegatedConn wrapping a native handle
func newDelegatedConn(handle C.native_conn_handle_t, connType C.connection_type_t, remoteAddr string) *DelegatedConn {
	return &DelegatedConn{
		handle:     handle,
		connType:   connType,
		remoteAddr: remoteAddr,
		localAddr:  "native:0",
	}
}

// Read implements net.Conn.Read
func (c *DelegatedConn) Read(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, ErrNativeConnectionClosed
	}

	// Handle zero-length buffer per io.Reader semantics
	if len(b) == 0 {
		return 0, nil
	}

	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	// Return buffered data first if available
	if len(c.readBuffer) > 0 {
		n := copy(b, c.readBuffer)
		c.readBuffer = c.readBuffer[n:]
		return n, nil
	}

	// Call native read callback
	// Use a reasonable timeout (30 seconds) for read operations
	result := C.call_native_read(c.handle, C.int(len(b)), C.int(30000))

	switch result.error_code {
	case C.NATIVE_NET_SUCCESS:
		if result.length <= 0 {
			return 0, io.EOF
		}
		// Copy data from C buffer to Go slice
		data := C.GoBytes(unsafe.Pointer(result.data), result.length)
		n := copy(b, data)
		// Buffer any remaining data
		if n < len(data) {
			c.readBuffer = append(c.readBuffer, data[n:]...)
		}
		return n, nil

	case C.NATIVE_NET_ERROR_EOF:
		return 0, io.EOF

	case C.NATIVE_NET_ERROR_TIMEOUT:
		return 0, ErrNativeNetworkTimeout

	case C.NATIVE_NET_ERROR_CLOSED:
		atomic.StoreInt32(&c.closed, 1)
		return 0, ErrNativeConnectionClosed

	default:
		return 0, fmt.Errorf("native read error: code %d", result.error_code)
	}
}

// Write implements net.Conn.Write
func (c *DelegatedConn) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, ErrNativeConnectionClosed
	}

	// Handle zero-length buffer per io.Writer semantics
	if len(b) == 0 {
		return 0, nil
	}

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// Call native write callback
	result := C.call_native_write(c.handle, (*C.uchar)(unsafe.Pointer(&b[0])), C.int(len(b)))

	if result < 0 {
		switch result {
		case C.NATIVE_NET_ERROR_CLOSED:
			atomic.StoreInt32(&c.closed, 1)
			return 0, ErrNativeConnectionClosed
		case C.NATIVE_NET_ERROR_TIMEOUT:
			return 0, ErrNativeNetworkTimeout
		default:
			return 0, fmt.Errorf("native write error: code %d", result)
		}
	}

	return int(result), nil
}

// Close implements net.Conn.Close
func (c *DelegatedConn) Close() error {
	// Use atomic compare-and-swap for idempotent close
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil // Already closed
	}

	C.call_native_close(c.handle)
	return nil
}

// LocalAddr implements net.Conn.LocalAddr
func (c *DelegatedConn) LocalAddr() net.Addr {
	return &nativeAddr{network: "native", address: c.localAddr}
}

// RemoteAddr implements net.Conn.RemoteAddr
func (c *DelegatedConn) RemoteAddr() net.Addr {
	return &nativeAddr{network: "native", address: c.remoteAddr}
}

// SetDeadline implements net.Conn.SetDeadline
func (c *DelegatedConn) SetDeadline(t time.Time) error {
	// Deadlines are handled per-operation via timeouts in native callbacks
	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline
func (c *DelegatedConn) SetReadDeadline(t time.Time) error {
	// Deadlines are handled per-operation via timeouts in native callbacks
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline
func (c *DelegatedConn) SetWriteDeadline(t time.Time) error {
	// Deadlines are handled per-operation via timeouts in native callbacks
	return nil
}

// nativeAddr implements net.Addr for native connections
type nativeAddr struct {
	network string
	address string
}

func (a *nativeAddr) Network() string { return a.network }
func (a *nativeAddr) String() string  { return a.address }

// EnableNativeNetworking registers native network callbacks
//
//export enable_native_networking
func enable_native_networking(
	connectCb C.native_connect_cb_t,
	readCb C.native_read_cb_t,
	writeCb C.native_write_cb_t,
	closeCb C.native_close_cb_t,
) C.int {
	nativeNetworkMutex.Lock()
	defer nativeNetworkMutex.Unlock()

	if connectCb == nil || readCb == nil || writeCb == nil || closeCb == nil {
		if logger != nil {
			logger.Warn("enable_native_networking called with nil callback(s)")
		}
		return 0
	}

	C.store_native_connect_cb(connectCb)
	C.store_native_read_cb(readCb)
	C.store_native_write_cb(writeCb)
	C.store_native_close_cb(closeCb)
	nativeNetworkEnabled = true

	if logger != nil {
		logger.Info("Native networking enabled for VPN compatibility")
	}

	return 1
}

// DisableNativeNetworking unregisters native network callbacks
//
//export disable_native_networking
func disable_native_networking() {
	nativeNetworkMutex.Lock()
	defer nativeNetworkMutex.Unlock()

	C.store_native_connect_cb(nil)
	C.store_native_read_cb(nil)
	C.store_native_write_cb(nil)
	C.store_native_close_cb(nil)
	nativeNetworkEnabled = false

	if logger != nil {
		logger.Info("Native networking disabled")
	}
}

// IsNativeNetworkingAvailable checks if native networking is enabled
func IsNativeNetworkingAvailable() bool {
	nativeNetworkMutex.RLock()
	defer nativeNetworkMutex.RUnlock()
	return nativeNetworkEnabled
}

// NativeDialWebSocket creates a WebSocket connection via native networking
func NativeDialWebSocket(url string, timeoutMs int) (net.Conn, error) {
	nativeNetworkMutex.RLock()
	enabled := nativeNetworkEnabled
	nativeNetworkMutex.RUnlock()

	if !enabled {
		return nil, ErrNativeNetworkNotEnabled
	}

	cURL := C.CString(url)
	defer C.free(unsafe.Pointer(cURL))

	result := C.call_native_connect(C.CONN_TYPE_WEBSOCKET, cURL, C.int(timeoutMs))

	if result.error_code != C.NATIVE_NET_SUCCESS {
		errMsg := "connection failed"
		if result.error_message != nil {
			errMsg = C.GoString(result.error_message)
		}
		return nil, fmt.Errorf("%w: %s (code: %d)", ErrNativeConnectFailed, errMsg, result.error_code)
	}

	if result.handle == nil {
		return nil, fmt.Errorf("%w: nil handle returned", ErrNativeConnectFailed)
	}

	return newDelegatedConn(result.handle, C.CONN_TYPE_WEBSOCKET, url), nil
}

// NativeDialTCP creates a TCP connection via native networking
func NativeDialTCP(address string, timeoutMs int) (net.Conn, error) {
	nativeNetworkMutex.RLock()
	enabled := nativeNetworkEnabled
	nativeNetworkMutex.RUnlock()

	if !enabled {
		return nil, ErrNativeNetworkNotEnabled
	}

	cAddr := C.CString(address)
	defer C.free(unsafe.Pointer(cAddr))

	result := C.call_native_connect(C.CONN_TYPE_TCP, cAddr, C.int(timeoutMs))

	if result.error_code != C.NATIVE_NET_SUCCESS {
		errMsg := "connection failed"
		if result.error_message != nil {
			errMsg = C.GoString(result.error_message)
		}
		return nil, fmt.Errorf("%w: %s (code: %d)", ErrNativeConnectFailed, errMsg, result.error_code)
	}

	if result.handle == nil {
		return nil, fmt.Errorf("%w: nil handle returned", ErrNativeConnectFailed)
	}

	return newDelegatedConn(result.handle, C.CONN_TYPE_TCP, address), nil
}

// registerNativeNetworkBridge registers the native network functions with the client package
func registerNativeNetworkBridge() {
	client.SetNativeNetworkFunctions(
		IsNativeNetworkingAvailable,
		NativeDialWebSocket,
		NativeDialTCP,
	)
	if logger != nil {
		logger.Info("Native network bridge registered with client package",
			zap.String("source", "TEE-LIBRECLAIM"))
	}
}
