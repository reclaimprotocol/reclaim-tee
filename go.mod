module tee-mpc

go 1.24.2

require (
	github.com/austinast/nitro-enclaves-sdk-go v0.0.2
	github.com/aws/aws-sdk-go-v2 v1.22.0
	github.com/aws/aws-sdk-go-v2/config v1.20.0
	github.com/aws/aws-sdk-go-v2/service/kms v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/hf/nsm v0.0.0-20220930140112-cd181bd646b9
	github.com/mdlayher/vsock v1.2.1
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.39.0
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.14.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.14.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.5.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.10.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.16.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.18.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.24.0 // indirect
	github.com/aws/smithy-go v1.22.4 // indirect
	github.com/fxamacker/cbor/v2 v2.8.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
)

replace github.com/aws/aws-sdk-go-v2/service/kms => github.com/edgebitio/nitro-enclaves-sdk-go/kms v0.0.0-20221110205443-8a5476ff3cc2
