package main

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/mdlayher/vsock"
)

const (
	proxyCID   = 3
	configPort = 5555
)

func ReceiveRuntimeConfig() (string, error) {
	conn, err := vsock.Dial(proxyCID, configPort, nil)
	if err != nil {
		return "", fmt.Errorf("vsock dial failed: %w", err)
	}
	defer conn.Close()

	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return "", fmt.Errorf("failed to read length: %w", err)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("failed to read domain: %w", err)
	}

	domain := string(buf)
	if domain == "" {
		return "", fmt.Errorf("empty domain received")
	}

	return domain, nil
}
