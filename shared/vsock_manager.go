package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdlayher/vsock"
)

// VSockConnectionManager manages VSock connections with circuit breaker and metrics
type VSockConnectionManager struct {
	parentCID      uint32
	kmsPort        uint32
	internetPort   uint32
	pool           *VSockPool
	circuitBreaker *CircuitBreaker
	metrics        *ConnectionMetrics
}

// CircuitBreaker provides circuit breaker functionality for VSock connections
type CircuitBreaker struct {
	state       int32
	failures    int32
	lastFailure time.Time
	mu          sync.RWMutex
}

// ConnectionMetrics tracks connection statistics
type ConnectionMetrics struct {
	totalRequests   int64
	successfulReqs  int64
	failedReqs      int64
	avgResponseTime int64
	mu              sync.RWMutex
}

// VSockPool manages a pool of VSock connections
type VSockPool struct {
	mu          sync.RWMutex
	connections chan net.Conn
	factory     func() (net.Conn, error)
	maxIdle     int
	maxActive   int
	idleTimeout time.Duration
	stopCh      chan struct{}
}

const (
	CircuitClosed = iota
	CircuitOpen
	CircuitHalfOpen

	circuitBreakerThreshold = 5
	circuitBreakerTimeout   = 60 * time.Second
)

// isCacheMiss checks if an error is a cache miss and should not count as circuit breaker failure
func isCacheMiss(errorMsg string) bool {
	cacheMissErrors := []string{
		"encrypted item not found",
		"item not found",
		"cache miss",
		"not found",
	}

	for _, missError := range cacheMissErrors {
		if strings.Contains(strings.ToLower(errorMsg), missError) {
			return true
		}
	}
	return false
}

// NewVSockConnectionManager creates a new VSock connection manager
func NewVSockConnectionManager(parentCID, kmsPort, internetPort uint32) *VSockConnectionManager {
	return &VSockConnectionManager{
		parentCID:    parentCID,
		kmsPort:      kmsPort,
		internetPort: internetPort,
		pool:         NewVSockPool(10, 50),
		circuitBreaker: &CircuitBreaker{
			state: CircuitClosed,
		},
		metrics: &ConnectionMetrics{},
	}
}

// NewVSockPool creates a new VSock connection pool
func NewVSockPool(maxIdle, maxActive int) *VSockPool {
	return &VSockPool{
		connections: make(chan net.Conn, maxIdle),
		maxIdle:     maxIdle,
		maxActive:   maxActive,
		idleTimeout: 30 * time.Second,
		stopCh:      make(chan struct{}),
	}
}

// SendKMSRequest sends a KMS request via VSock
func (v *VSockConnectionManager) SendKMSRequest(ctx context.Context, operation string, input interface{}) ([]byte, error) {
	if !v.circuitBreaker.CanExecute() {
		return nil, fmt.Errorf("circuit breaker is open")
	}

	start := time.Now()
	defer func() {
		v.metrics.recordRequest(time.Since(start))
	}()

	// Connect to KMS proxy
	conn, err := vsock.Dial(v.parentCID, v.kmsPort, nil)
	if err != nil {
		v.circuitBreaker.OnFailure()
		v.metrics.recordFailure()
		return nil, fmt.Errorf("failed to connect to KMS proxy: %v", err)
	}
	defer conn.Close()

	// Prepare request
	request := struct {
		Operation string      `json:"operation"`
		Input     interface{} `json:"input"`
	}{
		Operation: operation,
		Input:     input,
	}

	// Send request
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		v.circuitBreaker.OnFailure()
		v.metrics.recordFailure()
		return nil, fmt.Errorf("failed to send KMS request: %v", err)
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var response struct {
		Output json.RawMessage `json:"output,omitempty"`
		Error  string          `json:"error,omitempty"`
	}

	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		v.circuitBreaker.OnFailure()
		v.metrics.recordFailure()
		return nil, fmt.Errorf("failed to read KMS response: %v", err)
	}

	if response.Error != "" {
		// Don't count cache misses as circuit breaker failures
		if !isCacheMiss(response.Error) {
			v.circuitBreaker.OnFailure()
			v.metrics.recordFailure()
		}
		return nil, fmt.Errorf("KMS operation failed: %s", response.Error)
	}

	v.circuitBreaker.OnSuccess()
	v.metrics.recordSuccess()
	return []byte(response.Output), nil
}

// GetMetrics returns connection metrics
func (v *VSockConnectionManager) GetMetrics() map[string]interface{} {
	v.metrics.mu.RLock()
	defer v.metrics.mu.RUnlock()

	return map[string]interface{}{
		"total_requests":        atomic.LoadInt64(&v.metrics.totalRequests),
		"successful_requests":   atomic.LoadInt64(&v.metrics.successfulReqs),
		"failed_requests":       atomic.LoadInt64(&v.metrics.failedReqs),
		"circuit_breaker_state": atomic.LoadInt32(&v.circuitBreaker.state),
	}
}

// Close closes the connection manager
func (v *VSockConnectionManager) Close() {
	if v.pool != nil {
		v.pool.Close()
	}
}

// Circuit breaker methods
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	state := atomic.LoadInt32(&cb.state)
	switch state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailure) >= circuitBreakerTimeout {
			atomic.StoreInt32(&cb.state, CircuitHalfOpen)
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	default:
		return false
	}
}

func (cb *CircuitBreaker) OnSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	atomic.StoreInt32(&cb.failures, 0)
	if atomic.LoadInt32(&cb.state) == CircuitHalfOpen {
		atomic.StoreInt32(&cb.state, CircuitClosed)
	}
}

func (cb *CircuitBreaker) OnFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	failures := atomic.AddInt32(&cb.failures, 1)
	cb.lastFailure = time.Now()

	if failures >= circuitBreakerThreshold {
		atomic.StoreInt32(&cb.state, CircuitOpen)
	}
}

// Connection metrics methods
func (m *ConnectionMetrics) recordRequest(duration time.Duration) {
	atomic.AddInt64(&m.totalRequests, 1)
	atomic.StoreInt64(&m.avgResponseTime, duration.Nanoseconds())
}

func (m *ConnectionMetrics) recordSuccess() {
	atomic.AddInt64(&m.successfulReqs, 1)
}

func (m *ConnectionMetrics) recordFailure() {
	atomic.AddInt64(&m.failedReqs, 1)
}

// VSockPool methods
func (p *VSockPool) Get(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-p.connections:
		return conn, nil
	default:
		if p.factory != nil {
			return p.factory()
		}
		return nil, fmt.Errorf("no connection factory available")
	}
}

func (p *VSockPool) Put(conn net.Conn) {
	select {
	case p.connections <- conn:
		// Connection added to pool
	default:
		// Pool is full, close connection
		conn.Close()
	}
}

func (p *VSockPool) Close() {
	close(p.stopCh)

	// Close all connections in pool
	for {
		select {
		case conn := <-p.connections:
			conn.Close()
		default:
			return
		}
	}
}
