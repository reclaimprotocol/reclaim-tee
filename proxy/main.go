package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type EnclaveRuntimeConfig struct {
	TEEKDomain string `json:"tee_k_domain"`
	TEETDomain string `json:"tee_t_domain"`
}

type ProxyConfig struct {
	Domains       map[string]EnclaveTarget `json:"domains"`
	AWS           AWSConfig                `json:"aws"`
	Ports         PortConfig               `json:"ports"`
	EnclaveConfig EnclaveRuntimeConfig     `json:"enclave_config"`
}

type EnclaveTarget struct {
	CID uint32 `json:"cid"` // 16 for TEE_K, 17 for TEE_T
}

type AWSConfig struct {
	Region        string `json:"region"`
	S3CacheBucket string `json:"s3_cache_bucket"`
}

type PortConfig struct {
	HTTP       int `json:"http"`       // 80
	HTTPS      int `json:"https"`      // 443
	KMS        int `json:"kms"`        // 5000
	Internet   int `json:"internet"`   // 8444
	CloudWatch int `json:"cloudwatch"` // 5001
}

type Proxy struct {
	config          *ProxyConfig
	logger          *zap.Logger
	httpRouter      *HTTPRouter
	httpsRouter     *HTTPSRouter
	kmsProxy        *KMSProxy
	internetProxy   *InternetProxy
	cloudwatchProxy *CloudWatchProxy
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	config, err := loadConfig()
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	proxy, err := NewProxy(config, logger)
	if err != nil {
		logger.Fatal("Failed to create proxy", zap.Error(err))
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start proxy services
	if err := proxy.Start(); err != nil {
		logger.Fatal("Failed to start proxy", zap.Error(err))
	}

	logger.Info("Proxy started successfully",
		zap.Int("http_port", config.Ports.HTTP),
		zap.Int("https_port", config.Ports.HTTPS),
		zap.Int("kms_port", config.Ports.KMS),
		zap.Int("internet_port", config.Ports.Internet),
		zap.Int("cloudwatch_port", config.Ports.CloudWatch))

	if config.EnclaveConfig.TEETDomain != "" {
		go func() {
			if err := ServeEnclaveConfig(proxy.ctx, &config.EnclaveConfig, logger); err != nil {
				logger.Error("Config server failed", zap.Error(err))
			}
		}()
	}

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutting down proxy...")

	// Graceful shutdown
	proxy.Stop()
	logger.Info("Proxy shutdown complete")
}

func NewProxy(config *ProxyConfig, logger *zap.Logger) (*Proxy, error) {
	ctx, cancel := context.WithCancel(context.Background())

	proxy := &Proxy{
		config: config,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize routing components
	var err error
	proxy.httpRouter, err = NewHTTPRouter(config, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create HTTP router: %v", err)
	}

	proxy.httpsRouter, err = NewHTTPSRouter(config, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create HTTPS router: %v", err)
	}

	proxy.kmsProxy, err = NewKMSProxy(config, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create KMS proxy: %v", err)
	}

	proxy.internetProxy, err = NewInternetProxy(config, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create Internet proxy: %v", err)
	}

	proxy.cloudwatchProxy, err = NewCloudWatchProxy(config, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create CloudWatch proxy: %v", err)
	}

	return proxy, nil
}

func (p *Proxy) Start() error {
	// Start HTTP router (port 80)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.httpRouter.Start(p.ctx, p.config.Ports.HTTP); err != nil {
			p.logger.Error("HTTP router failed", zap.Error(err))
		}
	}()

	// Start HTTPS router (port 443)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.httpsRouter.Start(p.ctx, p.config.Ports.HTTPS); err != nil {
			p.logger.Error("HTTPS router failed", zap.Error(err))
		}
	}()

	// Start KMS proxy (port 5000)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.kmsProxy.Start(p.ctx, p.config.Ports.KMS); err != nil {
			p.logger.Error("KMS proxy failed", zap.Error(err))
		}
	}()

	// Start Internet proxy (port 8444)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.internetProxy.Start(p.ctx, p.config.Ports.Internet); err != nil {
			p.logger.Error("Internet proxy failed", zap.Error(err))
		}
	}()

	// Start CloudWatch proxy (port 5001)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.cloudwatchProxy.Start(p.ctx, p.config.Ports.CloudWatch); err != nil {
			p.logger.Error("CloudWatch proxy failed", zap.Error(err))
		}
	}()

	// Wait a moment for services to start
	time.Sleep(100 * time.Millisecond)
	return nil
}

func (p *Proxy) Stop() {
	p.cancel()
	p.wg.Wait()
}

func loadConfig() (*ProxyConfig, error) {
	configFile := os.Getenv("PROXY_CONFIG")
	if configFile == "" {
		configFile = "proxy-config.json"
	}

	// Try to load from file first
	if data, err := os.ReadFile(configFile); err == nil {
		var config ProxyConfig
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %v", err)
		}
		return &config, nil
	}

	// Fallback to default configuration
	return &ProxyConfig{
		Domains: map[string]EnclaveTarget{
			"tee-k.reclaimprotocol.org": {CID: 16},
			"tee-t.reclaimprotocol.org": {CID: 17},
		},
		AWS: AWSConfig{
			Region: getEnvOrDefault("AWS_REGION", "ap-south-1"),
		},
		Ports: PortConfig{
			HTTP:       80,
			HTTPS:      443,
			KMS:        5000,
			Internet:   8444,
			CloudWatch: 5001,
		},
		EnclaveConfig: EnclaveRuntimeConfig{
			TEEKDomain: "tee-k.reclaimprotocol.org",
			TEETDomain: getEnvOrDefault("TEET_DOMAIN", "tee-t-gcp.reclaimprotocol.org:443"),
		},
	}, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
