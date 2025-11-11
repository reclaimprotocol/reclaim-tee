module proxy

go 1.24.2

require (
	github.com/aws/aws-sdk-go-v2 v1.22.0
	github.com/aws/aws-sdk-go-v2/config v1.20.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.25.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.41.2
	github.com/mdlayher/vsock v1.2.1
	go.uber.org/zap v1.27.0
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
	github.com/aws/smithy-go v1.23.1 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
)

replace github.com/aws/aws-sdk-go-v2/service/kms => github.com/edgebitio/nitro-enclaves-sdk-go/kms v0.0.0-20221110205443-8a5476ff3cc2
