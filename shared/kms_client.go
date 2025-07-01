package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/mdlayher/vsock"
)

type KMSClient struct {
	parentCID uint32
	keyID     string
}

func NewKMSClient(parentCID uint32, keyID string) *KMSClient {
	return &KMSClient{
		parentCID: parentCID,
		keyID:     keyID,
	}
}

func (k *KMSClient) GenerateDataKey(ctx context.Context, input *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
	// Set the KMS key if not provided
	if input.KeyId == nil && k.keyID != "" {
		input.KeyId = &k.keyID
	}

	return k.sendKMSRequest(ctx, "GenerateDataKey", input)
}

func (k *KMSClient) Decrypt(ctx context.Context, input *kms.DecryptInput) (*kms.DecryptOutput, error) {
	var response struct {
		Output *kms.DecryptOutput `json:"output"`
		Error  string             `json:"error"`
	}

	if err := k.sendKMSRequestGeneric(ctx, "Decrypt", input, &response); err != nil {
		return nil, err
	}

	if response.Error != "" {
		return nil, fmt.Errorf("KMS error: %s", response.Error)
	}

	return response.Output, nil
}

func (k *KMSClient) sendKMSRequest(ctx context.Context, operation string, input interface{}) (*kms.GenerateDataKeyOutput, error) {
	var response struct {
		Output *kms.GenerateDataKeyOutput `json:"output"`
		Error  string                     `json:"error"`
	}

	if err := k.sendKMSRequestGeneric(ctx, operation, input, &response); err != nil {
		return nil, err
	}

	if response.Error != "" {
		return nil, fmt.Errorf("KMS error: %s", response.Error)
	}

	return response.Output, nil
}

func (k *KMSClient) sendKMSRequestGeneric(ctx context.Context, operation string, input interface{}, response interface{}) error {
	conn, err := vsock.Dial(k.parentCID, 5000, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to KMS proxy: %v", err)
	}
	defer conn.Close()

	// Set deadline for the connection
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(30 * time.Second))
	}

	request := map[string]interface{}{
		"operation": operation,
		"input":     input,
	}

	// Send request
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return fmt.Errorf("failed to send KMS request: %v", err)
	}

	// Read response
	if err := json.NewDecoder(conn).Decode(response); err != nil {
		return fmt.Errorf("failed to read KMS response: %v", err)
	}

	return nil
}
