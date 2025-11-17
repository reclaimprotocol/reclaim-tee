package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/mdlayher/vsock"
)

const (
	proxyCID   = 3
	configPort = 5555
)

type RuntimeConfig struct {
	TEEKDomain string `json:"tee_k_domain"`
	TEETDomain string `json:"tee_t_domain"`
}

func ReceiveRuntimeConfig() (*RuntimeConfig, error) {
	conn, err := vsock.Dial(proxyCID, configPort, nil)
	if err != nil {
		return nil, fmt.Errorf("vsock dial failed: %w", err)
	}
	defer conn.Close()

	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config RuntimeConfig
	if err := json.Unmarshal(buf, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if config.TEEKDomain == "" || config.TEETDomain == "" {
		return nil, fmt.Errorf("invalid config: missing domains")
	}

	return &config, nil
}
