package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"go.uber.org/zap"
)

// S3CacheData stores certificate data in S3 with local memory cache
type S3CacheData struct {
	bucket      string
	s3Client    *s3.Client
	logger      *zap.Logger
	memoryCache map[string]*CacheItem // Local cache for performance
	mutex       sync.RWMutex
}

// NewS3CacheData creates a new S3-backed cache
// bucket: S3 bucket name for certificate storage
// awsConfig: AWS configuration (region, credentials via IAM role)
func NewS3CacheData(ctx context.Context, awsConfig aws.Config, bucket string, logger *zap.Logger) (*S3CacheData, error) {
	s3Client := s3.NewFromConfig(awsConfig)

	// Verify bucket exists and is accessible
	_, err := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access S3 bucket %s: %v (ensure bucket exists and IAM role has s3:GetObject, s3:PutObject, s3:DeleteObject permissions)", bucket, err)
	}

	logger.Info("S3 cache initialized",
		zap.String("bucket", bucket))

	return &S3CacheData{
		bucket:      bucket,
		s3Client:    s3Client,
		logger:      logger,
		memoryCache: make(map[string]*CacheItem),
	}, nil
}

// S3 object key format: {service_name}/{filename}
// Example: tee_k/certificate.pem
func (s *S3CacheData) buildS3Key(serviceName, filename string) string {
	return fmt.Sprintf("%s/%s", serviceName, filename)
}

// StoreItem stores a cache item in S3 with SSE-KMS encryption
func (s *S3CacheData) StoreItem(serviceName, filename string, data, key []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Create CacheItem structure
	item := &CacheItem{
		Data: data,
		Key:  key,
	}

	// Marshal to JSON for storage
	itemJSON, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("failed to marshal cache item: %v", err)
	}

	s3Key := s.buildS3Key(serviceName, filename)

	// Upload to S3 with server-side encryption using KMS
	// SSE-KMS automatically encrypts at rest using the default KMS key
	ctx := context.Background()
	_, err = s.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(s.bucket),
		Key:                  aws.String(s3Key),
		Body:                 bytes.NewReader(itemJSON),
		ServerSideEncryption: "aws:kms",
		// Optional: Specify KMS key ID if not using default
		// SSEKMSKeyId:          aws.String("arn:aws:kms:..."),
	})
	if err != nil {
		return fmt.Errorf("failed to upload to S3: %v", err)
	}

	// Update memory cache
	cacheKey := s.buildS3Key(serviceName, filename)
	s.memoryCache[cacheKey] = item

	s.logger.Info("Stored item in S3",
		zap.String("service", serviceName),
		zap.String("filename", filename),
		zap.String("s3_key", s3Key),
		zap.Int("data_size", len(data)),
		zap.Int("key_size", len(key)))

	return nil
}

// GetItem retrieves a cache item from S3 (with memory cache)
func (s *S3CacheData) GetItem(serviceName, filename string) (*CacheItem, error) {
	cacheKey := s.buildS3Key(serviceName, filename)

	// Check memory cache first
	s.mutex.RLock()
	if item, exists := s.memoryCache[cacheKey]; exists {
		s.mutex.RUnlock()
		s.logger.Debug("Item found in memory cache",
			zap.String("service", serviceName),
			zap.String("filename", filename))
		// Return a copy to avoid race conditions
		return &CacheItem{
			Data: append([]byte(nil), item.Data...),
			Key:  append([]byte(nil), item.Key...),
		}, nil
	}
	s.mutex.RUnlock()

	// Not in memory cache, fetch from S3
	s3Key := s.buildS3Key(serviceName, filename)
	ctx := context.Background()

	result, err := s.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		return nil, fmt.Errorf("item not found in S3: %s/%s: %v", serviceName, filename, err)
	}
	defer result.Body.Close()

	// Read response body
	itemJSON, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 object: %v", err)
	}

	// Unmarshal CacheItem
	var item CacheItem
	if err := json.Unmarshal(itemJSON, &item); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cache item: %v", err)
	}

	// Update memory cache
	s.mutex.Lock()
	s.memoryCache[cacheKey] = &item
	s.mutex.Unlock()

	s.logger.Info("Retrieved item from S3",
		zap.String("service", serviceName),
		zap.String("filename", filename),
		zap.String("s3_key", s3Key))

	// Return a copy
	return &CacheItem{
		Data: append([]byte(nil), item.Data...),
		Key:  append([]byte(nil), item.Key...),
	}, nil
}

// DeleteItem removes a cache item from S3 and memory cache
func (s *S3CacheData) DeleteItem(serviceName, filename string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s3Key := s.buildS3Key(serviceName, filename)
	ctx := context.Background()

	// Delete from S3
	_, err := s.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		return fmt.Errorf("failed to delete from S3: %v", err)
	}

	// Remove from memory cache
	cacheKey := s.buildS3Key(serviceName, filename)
	delete(s.memoryCache, cacheKey)

	s.logger.Info("Deleted item from S3",
		zap.String("service", serviceName),
		zap.String("filename", filename),
		zap.String("s3_key", s3Key))

	return nil
}
