package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
)

const (
	// Batching configuration
	MaxBatchSize   = 100             // Maximum logs per batch
	MaxBatchWait   = 1 * time.Second // Maximum time to wait before sending batch
	MaxBufferSize  = 10000           // Maximum logs to buffer (10,000 logs ~10MB)
	ReconnectDelay = 5 * time.Second // Delay between reconnection attempts
	MaxRetries     = 5               // Maximum retries for CloudWatch API calls
	InitialBackoff = 100 * time.Millisecond
	MaxBackoff     = 30 * time.Second
)

// LogEntry represents a structured log entry from TEE_K
type LogEntry struct {
	Timestamp   string                 `json:"timestamp"`
	Level       string                 `json:"level"`
	Message     string                 `json:"message"`
	Service     string                 `json:"service"`
	SessionID   string                 `json:"session_id,omitempty"`
	EnclaveMode bool                   `json:"enclave_mode"`
	Fields      map[string]interface{} `json:"fields,omitempty"`
}

// CloudWatchProxy manages log forwarding from TEE_K to AWS CloudWatch Logs
type CloudWatchProxy struct {
	config    *ProxyConfig
	logger    *zap.Logger
	cwClient  *cloudwatchlogs.Client
	logGroup  string
	logStream string

	// Batching
	logBuffer     []LogEntry
	bufferMutex   sync.Mutex
	batchTimer    *time.Timer
	sequenceToken *string

	// State
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewCloudWatchProxy creates a new CloudWatch proxy instance
func NewCloudWatchProxy(proxyConfig *ProxyConfig, logger *zap.Logger) (*CloudWatchProxy, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize AWS CloudWatch client
	awsConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(proxyConfig.AWS.Region),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	cwClient := cloudwatchlogs.NewFromConfig(awsConfig)

	// Determine log group and stream names
	logGroup := getEnvOrDefault("CLOUDWATCH_LOG_GROUP", "/aws/nitro-enclaves/tee-k")
	logStream := fmt.Sprintf("%s-%d", time.Now().Format("2006-01-02"), time.Now().Unix())

	proxy := &CloudWatchProxy{
		config:    proxyConfig,
		logger:    logger.With(zap.String("component", "cloudwatch_proxy")),
		cwClient:  cwClient,
		logGroup:  logGroup,
		logStream: logStream,
		logBuffer: make([]LogEntry, 0, MaxBatchSize),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Ensure log stream exists
	if err := proxy.ensureLogStream(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create log stream: %v", err)
	}

	return proxy, nil
}

// Start begins listening for log entries from TEE_K via VSock
func (p *CloudWatchProxy) Start(ctx context.Context, port int) error {
	listener, err := vsock.Listen(uint32(port), nil)
	if err != nil {
		return fmt.Errorf("failed to listen on vsock port %d: %v", port, err)
	}

	p.logger.Info("CloudWatch proxy started", zap.Int("port", port), zap.String("log_group", p.logGroup))

	// Start batch flusher goroutine
	p.wg.Add(1)
	go p.batchFlusher()

	// Accept connections
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer listener.Close()

		for {
			select {
			case <-ctx.Done():
				p.logger.Info("CloudWatch proxy shutting down")
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						p.logger.Error("Accept error", zap.Error(err))
						time.Sleep(100 * time.Millisecond)
						continue
					}
				}
				p.logger.Info("CloudWatch connection established", zap.String("remote", conn.RemoteAddr().String()))
				go p.handleConnection(ctx, conn)
			}
		}
	}()

	return nil
}

// Stop gracefully shuts down the CloudWatch proxy
func (p *CloudWatchProxy) Stop() {
	p.cancel()

	// Flush any remaining logs
	p.flushBatch()

	p.wg.Wait()
	p.logger.Info("CloudWatch proxy stopped")
}

// handleConnection processes log entries from a single VSock connection
func (p *CloudWatchProxy) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	p.logger.Info("Starting to read log entries from connection")

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line size

	lineCount := 0
	for scanner.Scan() {
		lineCount++
		p.logger.Debug("Received log line", zap.Int("line_number", lineCount))
		select {
		case <-ctx.Done():
			return
		default:
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			var logEntry LogEntry
			if err := json.Unmarshal(line, &logEntry); err != nil {
				p.logger.Warn("Invalid log entry format", zap.Error(err), zap.String("data", string(line)))
				continue
			}

			p.addLogToBatch(logEntry)
		}
	}

	if err := scanner.Err(); err != nil {
		p.logger.Error("Scanner error", zap.Error(err))
	}
}

// addLogToBatch adds a log entry to the batch buffer
func (p *CloudWatchProxy) addLogToBatch(entry LogEntry) {
	p.bufferMutex.Lock()
	defer p.bufferMutex.Unlock()

	// Check buffer overflow
	if len(p.logBuffer) >= MaxBufferSize {
		p.logger.Warn("Log buffer full, dropping oldest entry")
		p.logBuffer = p.logBuffer[1:] // Drop oldest
	}

	p.logBuffer = append(p.logBuffer, entry)

	// Trigger immediate flush if batch is full
	if len(p.logBuffer) >= MaxBatchSize {
		go p.flushBatch()
	}
}

// batchFlusher periodically flushes the log batch
func (p *CloudWatchProxy) batchFlusher() {
	defer p.wg.Done()

	ticker := time.NewTicker(MaxBatchWait)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.flushBatch()
		}
	}
}

// flushBatch sends the current batch of logs to CloudWatch
func (p *CloudWatchProxy) flushBatch() {
	p.bufferMutex.Lock()
	if len(p.logBuffer) == 0 {
		p.bufferMutex.Unlock()
		return
	}

	// Take current batch
	batch := make([]LogEntry, len(p.logBuffer))
	copy(batch, p.logBuffer)
	p.logBuffer = p.logBuffer[:0] // Clear buffer
	p.bufferMutex.Unlock()

	p.logger.Debug("Flushing log batch", zap.Int("count", len(batch)))

	if err := p.sendToCloudWatch(batch); err != nil {
		p.logger.Error("Failed to send logs to CloudWatch", zap.Error(err), zap.Int("batch_size", len(batch)))
		// TODO: Implement dead letter queue or persistent retry
	} else {
		p.logger.Debug("Successfully sent logs to CloudWatch", zap.Int("count", len(batch)))
	}
}

// sendToCloudWatch sends a batch of logs to CloudWatch with retry logic
func (p *CloudWatchProxy) sendToCloudWatch(batch []LogEntry) error {
	if len(batch) == 0 {
		return nil
	}

	// Convert log entries to CloudWatch format
	logEvents := make([]types.InputLogEvent, len(batch))
	for i, entry := range batch {
		// Parse timestamp or use current time
		timestamp, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			timestamp = time.Now()
		}

		// Create log message with structured fields
		message := entry.Message
		if len(entry.Fields) > 0 {
			fieldsJSON, _ := json.Marshal(entry.Fields)
			message = fmt.Sprintf("%s | fields=%s", message, string(fieldsJSON))
		}
		if entry.SessionID != "" {
			message = fmt.Sprintf("[session=%s] %s", entry.SessionID, message)
		}

		logEvents[i] = types.InputLogEvent{
			Message:   aws.String(message),
			Timestamp: aws.Int64(timestamp.UnixMilli()),
		}
	}

	// Sort log events by timestamp (CloudWatch requirement)
	sort.Slice(logEvents, func(i, j int) bool {
		return *logEvents[i].Timestamp < *logEvents[j].Timestamp
	})

	// Retry with exponential backoff
	var lastErr error
	backoff := InitialBackoff

	for attempt := 0; attempt < MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff = time.Duration(math.Min(float64(backoff*2), float64(MaxBackoff)))
		}

		input := &cloudwatchlogs.PutLogEventsInput{
			LogGroupName:  aws.String(p.logGroup),
			LogStreamName: aws.String(p.logStream),
			LogEvents:     logEvents,
			SequenceToken: p.sequenceToken,
		}

		output, err := p.cwClient.PutLogEvents(p.ctx, input)
		if err != nil {
			lastErr = err
			p.logger.Warn("CloudWatch API error, retrying",
				zap.Error(err),
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff))
			continue
		}

		// Update sequence token for next request
		p.sequenceToken = output.NextSequenceToken
		return nil
	}

	return fmt.Errorf("failed after %d attempts: %v", MaxRetries, lastErr)
}

// ensureLogStream creates the log stream if it doesn't exist
func (p *CloudWatchProxy) ensureLogStream() error {
	// Try to create the log stream (idempotent if exists)
	_, err := p.cwClient.CreateLogStream(p.ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(p.logGroup),
		LogStreamName: aws.String(p.logStream),
	})

	if err != nil {
		// Check if stream already exists
		var resourceAlreadyExists *types.ResourceAlreadyExistsException
		if _, ok := err.(*types.ResourceAlreadyExistsException); ok || errors.As(err, &resourceAlreadyExists) {
			p.logger.Info("Log stream already exists", zap.String("stream", p.logStream))
			return nil
		}
		return fmt.Errorf("failed to create log stream: %v", err)
	}

	p.logger.Info("Created log stream", zap.String("stream", p.logStream))
	return nil
}
