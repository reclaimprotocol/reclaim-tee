package providers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/xeipuuv/gojsonschema"
)

// Cache of compiled schemas per provider name
var providerValidatorMap = make(map[string]*gojsonschema.Schema)
var validatorMutex sync.RWMutex

// Register AJV-like custom formats on init
func init() {
	// url: require scheme+host; allow template placeholders {{param}}
	gojsonschema.FormatCheckers.Add("url", urlFormatChecker{})
	// binary: only true for []byte (mirrors AJV Uint8Array/Buffer); strings return false
	gojsonschema.FormatCheckers.Add("binary", binaryFormatChecker{})
}

type urlFormatChecker struct{}

func (urlFormatChecker) IsFormat(input interface{}) bool {
	str, ok := input.(string)
	if !ok {
		return false
	}
	if strings.Contains(str, "{{") && strings.Contains(str, "}}") {
		return true
	}
	u, err := url.Parse(str)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

type binaryFormatChecker struct{}

func (binaryFormatChecker) IsFormat(input interface{}) bool {
	_, ok := input.([]byte)
	return ok
}

// ValidateProviderParams mirrors TS assertValidateProviderParams
func ValidateProviderParams(providerName string, params interface{}) error {
	validatorMutex.RLock()
	compiled, exists := providerValidatorMap[providerName]
	validatorMutex.RUnlock()

	if !exists {
		sch, ok := PROVIDER_SCHEMAS[providerName]
		if !ok {
			return fmt.Errorf("invalid provider name \"%s\"", providerName)
		}

		schemaLoader := gojsonschema.NewGoLoader(sch.Parameters)
		schema, err := gojsonschema.NewSchema(schemaLoader)
		if err != nil {
			return fmt.Errorf("failed to compile schema for %s: %w", providerName, err)
		}

		validatorMutex.Lock()
		providerValidatorMap[providerName] = schema
		validatorMutex.Unlock()
		compiled = schema
	}

	docLoader := gojsonschema.NewGoLoader(params)
	result, err := compiled.Validate(docLoader)
	if err != nil {
		return fmt.Errorf("params validation failed: %w", err)
	}
	if !result.Valid() {
		// Aggregate errors similarly to TS message payload
		var b strings.Builder
		for _, e := range result.Errors() {
			if b.Len() > 0 {
				b.WriteString("; ")
			}
			b.WriteString(e.String())
		}
		return fmt.Errorf("params validation failed: %s", b.String())
	}
	return nil
}

// ValidateProviderSecretParams mirrors TS secret params validation
func ValidateProviderSecretParams(providerName string, secretParams interface{}) error {
	sch, ok := PROVIDER_SCHEMAS[providerName]
	if !ok {
		return fmt.Errorf("invalid provider name \"%s\"", providerName)
	}

	schemaLoader := gojsonschema.NewGoLoader(sch.SecretParameters)
	schema, err := gojsonschema.NewSchema(schemaLoader)
	if err != nil {
		return fmt.Errorf("failed to compile secret schema for %s: %w", providerName, err)
	}

	docLoader := gojsonschema.NewGoLoader(secretParams)
	result, err := schema.Validate(docLoader)
	if err != nil {
		return fmt.Errorf("secret params validation failed: %w", err)
	}
	if !result.Valid() {
		var b strings.Builder
		for _, e := range result.Errors() {
			if b.Len() > 0 {
				b.WriteString("; ")
			}
			b.WriteString(e.String())
		}
		return fmt.Errorf("secret params validation failed: %s", b.String())
	}
	return nil
}

// Helper function to validate and unmarshal JSON params in one step
func ValidateAndUnmarshalParams(providerName string, jsonData []byte, target interface{}) error {
	var params interface{}
	if err := json.Unmarshal(jsonData, &params); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := ValidateProviderParams(providerName, params); err != nil {
		return err
	}
	if err := json.Unmarshal(jsonData, target); err != nil {
		return fmt.Errorf("failed to unmarshal to target type: %w", err)
	}
	return nil
}

// Helper function for secret params
func ValidateAndUnmarshalSecretParams(providerName string, jsonData []byte, target interface{}) error {
	var params interface{}
	if err := json.Unmarshal(jsonData, &params); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := ValidateProviderSecretParams(providerName, params); err != nil {
		return err
	}
	if err := json.Unmarshal(jsonData, target); err != nil {
		return fmt.Errorf("failed to unmarshal to target type: %w", err)
	}
	return nil
}
