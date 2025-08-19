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
	TraceStart("Validation", "ValidateProviderParams", "Provider", providerName)
	
	validatorMutex.RLock()
	compiled, exists := providerValidatorMap[providerName]
	validatorMutex.RUnlock()
	
	TraceDebug("Validation", "ValidateProviderParams", "Schema cached: %t", exists)

	if !exists {
		TraceStep("Validation", "ValidateProviderParams", 1, 2, "Compiling schema for provider")
		sch, ok := PROVIDER_SCHEMAS[providerName]
		if !ok {
			TraceError("Validation", "ValidateProviderParams", "Unknown provider: %s", providerName)
			return fmt.Errorf("invalid provider name \"%s\"", providerName)
		}

		schemaLoader := gojsonschema.NewGoLoader(sch.Parameters)
		schema, err := gojsonschema.NewSchema(schemaLoader)
		if err != nil {
			TraceError("Validation", "ValidateProviderParams", "Schema compilation failed: %v", err)
			return fmt.Errorf("failed to compile schema for %s: %w", providerName, err)
		}

		validatorMutex.Lock()
		providerValidatorMap[providerName] = schema
		validatorMutex.Unlock()
		compiled = schema
		TraceDebug("Validation", "ValidateProviderParams", "Schema compiled and cached")
	}

	TraceStep("Validation", "ValidateProviderParams", 2, 2, "Validating parameters against schema")
	docLoader := gojsonschema.NewGoLoader(params)
	result, err := compiled.Validate(docLoader)
	if err != nil {
		TraceError("Validation", "ValidateProviderParams", "Validation execution failed: %v", err)
		return fmt.Errorf("params validation failed: %w", err)
	}
	
	if !result.Valid() {
		TraceError("Validation", "ValidateProviderParams", "Validation failed with %d errors", len(result.Errors()))
		// Aggregate errors similarly to TS message payload
		var b strings.Builder
		for i, e := range result.Errors() {
			if b.Len() > 0 {
				b.WriteString("; ")
			}
			b.WriteString(e.String())
			TraceVerbose("Validation", "ValidateProviderParams", "Error %d: %s", i+1, e.String())
		}
		return fmt.Errorf("params validation failed: %s", b.String())
	}
	
	TraceInfo("Validation", "ValidateProviderParams", "Parameters validated successfully")
	return nil
}

// ValidateProviderSecretParams mirrors TS secret params validation
func ValidateProviderSecretParams(providerName string, secretParams interface{}) error {
	TraceStart("Validation", "ValidateProviderSecretParams", "Provider", providerName)
	
	sch, ok := PROVIDER_SCHEMAS[providerName]
	if !ok {
		TraceError("Validation", "ValidateProviderSecretParams", "Unknown provider: %s", providerName)
		return fmt.Errorf("invalid provider name \"%s\"", providerName)
	}

	TraceDebug("Validation", "ValidateProviderSecretParams", "Compiling secret parameters schema")
	schemaLoader := gojsonschema.NewGoLoader(sch.SecretParameters)
	schema, err := gojsonschema.NewSchema(schemaLoader)
	if err != nil {
		TraceError("Validation", "ValidateProviderSecretParams", "Secret schema compilation failed: %v", err)
		return fmt.Errorf("failed to compile secret schema for %s: %w", providerName, err)
	}

	TraceDebug("Validation", "ValidateProviderSecretParams", "Validating secret parameters against schema")
	docLoader := gojsonschema.NewGoLoader(secretParams)
	result, err := schema.Validate(docLoader)
	if err != nil {
		TraceError("Validation", "ValidateProviderSecretParams", "Secret validation execution failed: %v", err)
		return fmt.Errorf("secret params validation failed: %w", err)
	}
	if !result.Valid() {
		TraceError("Validation", "ValidateProviderSecretParams", "Secret validation failed with %d errors", len(result.Errors()))
		var b strings.Builder
		for i, e := range result.Errors() {
			if b.Len() > 0 {
				b.WriteString("; ")
			}
			b.WriteString(e.String())
			TraceVerbose("Validation", "ValidateProviderSecretParams", "Error %d: %s", i+1, e.String())
		}
		return fmt.Errorf("secret params validation failed: %s", b.String())
	}
	TraceInfo("Validation", "ValidateProviderSecretParams", "Secret parameters validated successfully")
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
