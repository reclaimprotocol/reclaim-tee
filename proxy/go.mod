module proxy

go 1.24

require (
	github.com/aws/aws-sdk-go-v2 v1.22.0
	github.com/aws/aws-sdk-go-v2/config v1.20.0
	github.com/aws/aws-sdk-go-v2/service/kms v0.0.0-00010101000000-000000000000
	github.com/mdlayher/vsock v1.2.1
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
	github.com/aws/smithy-go v1.22.3 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace github.com/aws/aws-sdk-go-v2/service/kms => github.com/edgebitio/nitro-enclaves-sdk-go/kms v0.0.0-20221110205443-8a5476ff3cc2
