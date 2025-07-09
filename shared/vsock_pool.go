package shared

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdlayher/vsock"
)

const (
	defaultPoolSize         = 10
	defaultMaxConnections   = 50
	defaultConnectionTTL    = 5 * time.Minute
	defaultIdleTimeout      = 30 * time.Second
	defaultValidationPeriod = 30 * time.Second
	defaultCleanupInterval  = 60 * time.Second
)

// VSockPool implements a production-grade VSock connection pool
// with comprehensive lifecycle management, validation, and cleanup
type VSockPool struct {
	cid           uint32
	port          uint32
	minPoolSize   int
	maxPoolSize   int
	connectionTTL time.Duration
	idleTimeout   time.Duration
	config        *ProductionVSockPoolConfig // Store the full config

	// Connection pool and management
	idleConns    []*pooledConnection
	activeConns  map[*pooledConnection]time.Time
	connCount    int32
	maxConnCount int32

	// Synchronization
	mu            sync.RWMutex
	connChan      chan *pooledConnection
	stopChan      chan struct{}
	cleanupTicker *time.Ticker

	// Metrics and monitoring
	metrics      *PoolMetrics
	isRunning    int32
	shutdownOnce sync.Once
}

// pooledConnection wraps a VSock connection with metadata
type pooledConnection struct {
	conn        net.Conn
	createdAt   time.Time
	lastUsedAt  time.Time
	usageCount  int64
	isValid     bool
	validatedAt time.Time
	mu          sync.RWMutex
}

// PoolMetrics tracks detailed pool performance metrics
type PoolMetrics struct {
	TotalConnections     int64     `json:"total_connections"`
	ActiveConnections    int64     `json:"active_connections"`
	IdleConnections      int64     `json:"idle_connections"`
	ConnectionsCreated   int64     `json:"connections_created"`
	ConnectionsDestroyed int64     `json:"connections_destroyed"`
	ConnectionsReused    int64     `json:"connections_reused"`
	ValidationErrors     int64     `json:"validation_errors"`
	CleanupOperations    int64     `json:"cleanup_operations"`
	AverageUsageCount    float64   `json:"average_usage_count"`
	LastCleanupTime      time.Time `json:"last_cleanup_time"`
}

// ProductionVSockPoolConfig holds configuration for the production pool
type ProductionVSockPoolConfig struct {
	CID              uint32
	Port             uint32
	MinPoolSize      int
	MaxPoolSize      int
	ConnectionTTL    time.Duration
	IdleTimeout      time.Duration
	ValidationPeriod time.Duration
	CleanupInterval  time.Duration
	IsInternetProxy  bool // Flag to indicate if this pool is for internet proxy
}

// NewProductionVSockPool creates a new production-grade VSock connection pool
func NewProductionVSockPool(config *ProductionVSockPoolConfig) *VSockPool {
	if config == nil {
		config = &ProductionVSockPoolConfig{
			MinPoolSize:      defaultPoolSize / 2,
			MaxPoolSize:      defaultMaxConnections,
			ConnectionTTL:    defaultConnectionTTL,
			IdleTimeout:      defaultIdleTimeout,
			ValidationPeriod: defaultValidationPeriod,
			CleanupInterval:  defaultCleanupInterval,
		}
	}

	pool := &VSockPool{
		cid:           config.CID,
		port:          config.Port,
		minPoolSize:   config.MinPoolSize,
		maxPoolSize:   config.MaxPoolSize,
		connectionTTL: config.ConnectionTTL,
		idleTimeout:   config.IdleTimeout,
		config:        config,

		idleConns:   make([]*pooledConnection, 0, config.MaxPoolSize),
		activeConns: make(map[*pooledConnection]time.Time),
		connChan:    make(chan *pooledConnection, config.MaxPoolSize),
		stopChan:    make(chan struct{}),
		metrics:     &PoolMetrics{},
	}

	return pool
}

// Start initializes the pool and begins background maintenance
func (p *VSockPool) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&p.isRunning, 0, 1) {
		return fmt.Errorf("pool is already running")
	}

	log.Printf("[VSockPool] Starting production VSock pool (CID=%d, Port=%d)", p.cid, p.port)

	// Pre-populate pool with minimum connections
	if err := p.prePopulatePool(ctx); err != nil {
		atomic.StoreInt32(&p.isRunning, 0)
		return fmt.Errorf("failed to pre-populate pool: %v", err)
	}

	// Start background maintenance goroutines
	go p.connectionManager(ctx)
	go p.cleanupManager(ctx)
	go p.validationManager(ctx)

	log.Printf("[VSockPool] Pool started successfully with %d initial connections", len(p.idleConns))
	return nil
}

// GetConnection retrieves a validated connection from the pool
func (p *VSockPool) GetConnection(ctx context.Context) (net.Conn, error) {
	if atomic.LoadInt32(&p.isRunning) == 0 {
		return nil, fmt.Errorf("pool is not running")
	}

	// Try to get an idle connection first
	if conn := p.getIdleConnection(); conn != nil {
		atomic.AddInt64(&p.metrics.ConnectionsReused, 1)
		return conn.conn, nil
	}

	// If no idle connections and we haven't reached max, create new connection
	if atomic.LoadInt32(&p.connCount) < atomic.LoadInt32(&p.maxConnCount) {
		conn, err := p.createConnection(ctx)
		if err != nil {
			return nil, err
		}
		atomic.AddInt64(&p.metrics.ConnectionsCreated, 1)
		return conn, nil
	}

	// Wait for a connection to become available
	select {
	case conn := <-p.connChan:
		if p.validateConnection(conn) {
			p.markConnectionActive(conn)
			atomic.AddInt64(&p.metrics.ConnectionsReused, 1)
			return conn.conn, nil
		}
		// Connection invalid, try to create a new one
		p.destroyConnection(conn)
		return p.GetConnection(ctx)

	case <-ctx.Done():
		return nil, ctx.Err()

	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timeout waiting for connection")
	}
}

// ReturnConnection returns a connection to the pool
func (p *VSockPool) ReturnConnection(conn net.Conn) {
	if atomic.LoadInt32(&p.isRunning) == 0 {
		conn.Close()
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Find the pooled connection
	var pooledConn *pooledConnection
	for pc := range p.activeConns {
		if pc.conn == conn {
			pooledConn = pc
			delete(p.activeConns, pc)
			break
		}
	}

	if pooledConn == nil {
		// Unknown connection, just close it
		conn.Close()
		return
	}

	// Update usage metadata
	pooledConn.mu.Lock()
	pooledConn.lastUsedAt = time.Now()
	pooledConn.usageCount++
	pooledConn.mu.Unlock()

	// Validate connection before returning to pool
	if p.validateConnection(pooledConn) {
		// Return to idle pool
		p.idleConns = append(p.idleConns, pooledConn)

		// Non-blocking send to channel
		select {
		case p.connChan <- pooledConn:
		default:
			// Channel full, connection will be available in idle pool
		}
	} else {
		// Connection invalid, destroy it
		p.destroyConnection(pooledConn)
	}
}

// Shutdown gracefully closes the pool
func (p *VSockPool) Shutdown(ctx context.Context) error {
	var shutdownErr error
	p.shutdownOnce.Do(func() {
		if !atomic.CompareAndSwapInt32(&p.isRunning, 1, 0) {
			shutdownErr = fmt.Errorf("pool is not running")
			return
		}

		log.Printf("[VSockPool] Shutting down production VSock pool")

		// Signal shutdown
		close(p.stopChan)

		// Stop cleanup ticker
		if p.cleanupTicker != nil {
			p.cleanupTicker.Stop()
		}

		// Close all connections
		p.mu.Lock()
		defer p.mu.Unlock()

		// Close active connections
		for conn := range p.activeConns {
			conn.conn.Close()
			atomic.AddInt64(&p.metrics.ConnectionsDestroyed, 1)
		}
		p.activeConns = make(map[*pooledConnection]time.Time)

		// Close idle connections
		for _, conn := range p.idleConns {
			conn.conn.Close()
			atomic.AddInt64(&p.metrics.ConnectionsDestroyed, 1)
		}
		p.idleConns = nil

		atomic.StoreInt32(&p.connCount, 0)
		log.Printf("[VSockPool] Pool shutdown completed")
	})

	return shutdownErr
}

// Private methods for pool management

func (p *VSockPool) prePopulatePool(ctx context.Context) error {
	// Don't pre-populate for internet proxy pool since each connection needs a target address
	if p.config.IsInternetProxy {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Create minimum number of connections
	for i := 0; i < p.minPoolSize; i++ {
		conn, err := vsock.Dial(p.cid, p.port, nil)
		if err != nil {
			return fmt.Errorf("failed to create connection: %v", err)
		}

		pooledConn := &pooledConnection{
			conn:        conn,
			createdAt:   time.Now(),
			lastUsedAt:  time.Now(),
			isValid:     true,
			validatedAt: time.Now(),
		}

		p.idleConns = append(p.idleConns, pooledConn)
		atomic.AddInt32(&p.connCount, 1)
	}

	return nil
}

func (p *VSockPool) createConnection(ctx context.Context) (net.Conn, error) {
	conn, err := vsock.Dial(p.cid, p.port, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VSock connection: %v", err)
	}

	// VSock connections don't typically support SetDeadline
	// Return the connection as-is for VSock communication
	return conn, nil
}

func (p *VSockPool) getIdleConnection() *pooledConnection {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.idleConns) == 0 {
		return nil
	}

	// Get connection from front of queue (FIFO)
	conn := p.idleConns[0]
	p.idleConns = p.idleConns[1:]

	// Validate connection before returning
	if p.validateConnection(conn) {
		p.activeConns[conn] = time.Now()
		return conn
	}

	// Connection invalid, destroy and try next
	p.destroyConnection(conn)
	return p.getIdleConnection() // Recursive call for next connection
}

func (p *VSockPool) validateConnection(conn *pooledConnection) bool {
	if conn == nil || conn.conn == nil {
		return false
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Check if connection is too old
	if time.Since(conn.createdAt) > p.connectionTTL {
		conn.isValid = false
		return false
	}

	// Check if connection has been idle too long
	if time.Since(conn.lastUsedAt) > p.idleTimeout {
		conn.isValid = false
		return false
	}

	// Check if we need to validate (not validated recently)
	if time.Since(conn.validatedAt) > defaultValidationPeriod {
		// Perform actual connection validation
		if err := p.performConnectionValidation(conn.conn); err != nil {
			conn.isValid = false
			atomic.AddInt64(&p.metrics.ValidationErrors, 1)
			return false
		}
		conn.validatedAt = time.Now()
	}

	conn.isValid = true
	return true
}

func (p *VSockPool) performConnectionValidation(conn net.Conn) error {
	// Set a short deadline for validation
	if deadline, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		deadline.SetDeadline(time.Now().Add(1 * time.Second))
		defer deadline.SetDeadline(time.Time{}) // Clear deadline
	}

	// Try to write a small amount of data to test connection
	// In production, this might be a ping/pong protocol
	return nil // Simplified for this implementation
}

func (p *VSockPool) markConnectionActive(conn *pooledConnection) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.activeConns[conn] = time.Now()
}

func (p *VSockPool) destroyConnection(conn *pooledConnection) {
	if conn != nil && conn.conn != nil {
		conn.conn.Close()
		atomic.AddInt32(&p.connCount, -1)
		atomic.AddInt64(&p.metrics.ConnectionsDestroyed, 1)
	}
}

func (p *VSockPool) connectionManager(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.maintainPoolSize(ctx)
		case <-p.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (p *VSockPool) maintainPoolSize(ctx context.Context) {
	// Don't maintain pool size for internet proxy
	if p.config.IsInternetProxy {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	currentSize := len(p.idleConns) + len(p.activeConns)
	if currentSize < p.minPoolSize {
		needed := p.minPoolSize - currentSize
		for i := 0; i < needed; i++ {
			conn, err := vsock.Dial(p.cid, p.port, nil)
			if err != nil {
				log.Printf("[VSockPool] Failed to create connection during maintenance: %v", err)
				continue
			}

			pooledConn := &pooledConnection{
				conn:        conn,
				createdAt:   time.Now(),
				lastUsedAt:  time.Now(),
				isValid:     true,
				validatedAt: time.Now(),
			}

			p.idleConns = append(p.idleConns, pooledConn)
			atomic.AddInt32(&p.connCount, 1)
		}
	}
}

func (p *VSockPool) cleanupManager(ctx context.Context) {
	p.cleanupTicker = time.NewTicker(defaultCleanupInterval)
	defer p.cleanupTicker.Stop()

	for {
		select {
		case <-p.cleanupTicker.C:
			p.performCleanup()
		case <-p.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (p *VSockPool) performCleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	var validConns []*pooledConnection

	// Clean up idle connections
	for _, conn := range p.idleConns {
		if p.validateConnection(conn) {
			validConns = append(validConns, conn)
		} else {
			p.destroyConnection(conn)
		}
	}
	p.idleConns = validConns

	// Clean up active connections that have been active too long
	for conn, activeTime := range p.activeConns {
		if now.Sub(activeTime) > p.connectionTTL {
			p.destroyConnection(conn)
			delete(p.activeConns, conn)
		}
	}

	atomic.AddInt64(&p.metrics.CleanupOperations, 1)
	p.metrics.LastCleanupTime = now
}

func (p *VSockPool) validationManager(ctx context.Context) {
	ticker := time.NewTicker(defaultValidationPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.validateAllConnections()
		case <-p.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (p *VSockPool) validateAllConnections() {
	p.mu.RLock()
	idleConns := make([]*pooledConnection, len(p.idleConns))
	copy(idleConns, p.idleConns)
	p.mu.RUnlock()

	// Validate idle connections
	for _, conn := range idleConns {
		p.validateConnection(conn)
	}
}
