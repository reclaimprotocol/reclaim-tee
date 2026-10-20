module github.com/reclaimprotocol/reclaim-tee

go 1.27.3

require (
	cloud.google.com/go/firestore v1.27.0
	cloud.google.com/go/kms v1.35.0
	cloud.google.com/go/logging v1.20.0
	cloud.google.com/go/secretmanager v1.22.0
	filippo.io/nistec v0.0.4
	github.com/aws/aws-sdk-go-v2 v1.47.3
	github.com/aws/aws-sdk-go-v2/config v1.33.9
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.90.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.50.5
	github.com/consensys/gnark v0.16.4
	github.com/consensys/gnark-crypto v0.22.0
	github.com/coreos/go-json v0.0.0-20231102161613-e49c8866685a
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/fxamacker/cbor/v2 v2.9.6
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/go-eventlog v0.0.3-0.20261001001437-1991f15bc4b0
	github.com/google/go-sev-guest v0.15.0
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm-tools v0.4.11
	github.com/gorilla/websocket v1.5.3
	github.com/joho/godotenv v1.5.1
	github.com/markkurossi/mpc v0.0.0-20260616034910-9c484ce016a7
	github.com/mr-tron/base58 v1.3.0
	github.com/reclaimprotocol/jsonpathplus-go/v2 v2.0.1
	github.com/reclaimprotocol/xpath-go v1.8.0
	github.com/reclaimprotocol/zk-symmetric-crypto/gnark v0.0.0-20261012143415-e29524042722
	github.com/xeipuuv/gojsonschema v1.2.0
	go.mozilla.org/pkcs7 v0.10.0
	go.uber.org/zap v1.28.0
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
	golang.org/x/sync v0.24.0
	golang.org/x/sys v0.49.0
	golang.org/x/text v0.43.0
	golang.org/x/time v0.16.0
	google.golang.org/api v0.306.0
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.24.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.3.0 // indirect
	cloud.google.com/go/compute/metadata v0.10.0 // indirect
	cloud.google.com/go/iam v1.14.0 // indirect
	cloud.google.com/go/longrunning v1.3.0 // indirect
	github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20261015094924-dba3d44e282b // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.22 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.4 // indirect
	github.com/aws/smithy-go v1.28.5 // indirect
	github.com/bits-and-blooms/bitset v1.26.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/go-configfs-tsm v0.3.3 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d // indirect
	github.com/google/logger v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20261016150608-1facf8f91b50 // indirect
	github.com/google/s2a-go v0.1.11 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.23 // indirect
	github.com/googleapis/gax-go/v2 v2.26.2 // indirect
	github.com/markkurossi/crypto v0.0.0-20240520115340-daed3f9a1082 // indirect
	github.com/markkurossi/tabulate v0.0.0-20251126123558-a08056f6160f // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.72.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.72.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	google.golang.org/genproto v0.0.0-20261019180522-ce908d29299b // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261019180522-ce908d29299b // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261019180522-ce908d29299b // indirect
)
