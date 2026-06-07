package config

import (
	"cmp"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config is the env-driven router configuration, resolved once at startup.
//
// Required env: APPROVED_IMAGE_DIGESTS, SA_TOKEN_AUDIENCE.
// Everything else has a sensible default.
type Config struct {
	Port              string
	JWTIssuer         string         // router's own outgoing JWT issuer claim
	JWTExpiry         time.Duration  // router's own outgoing JWT lifetime
	SATokenAudience   string         // expected aud in incoming GCP SA identity tokens
	ApprovedDigests   []string       // image digests TEEs may attest to
	ApprovedSAPattern *regexp.Regexp // GCP service account email pattern

	// Thresholds used by Pair.EffectiveStatus.
	HeartbeatStaleness time.Duration // missed-heartbeat threshold before "dead"
	ControlUnhealthy   time.Duration // control_healthy=false sustained → "degraded"
	OTNotReady         time.Duration // ot_ready=false sustained → "degraded"

	// AdminToken gates /pairs, /pairs/{id}/drain, and /pairs/{id}/dead.
	// Empty disables admin endpoints entirely (503). In production deployment
	// behind Cloud Run + IAP, this can stay empty since IAP enforces auth at
	// the network edge; for non-IAP deployments or local ops, set ADMIN_TOKEN.
	AdminToken string

	// FirestoreProjectID, when set, selects the Firestore-backed Store
	// instead of the in-memory one. Required for multi-replica deployments.
	FirestoreProjectID string

	// KMSKeyName, when set, selects the KMS-backed Signer instead of the
	// in-process LocalSigner. Format:
	//
	//	projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<n>
	//
	// Key must be EC_SIGN_P256_SHA256.
	KMSKeyName string
}

// Load reads configuration from environment variables. Returns an error if
// any required value is missing or any value is malformed.
func Load() (*Config, error) {
	digestsRaw := os.Getenv("APPROVED_IMAGE_DIGESTS")
	if digestsRaw == "" {
		return nil, fmt.Errorf("APPROVED_IMAGE_DIGESTS is required")
	}
	digests := strings.Split(digestsRaw, ",")
	for i, d := range digests {
		digests[i] = strings.TrimSpace(d)
	}

	saPatternRaw := cmp.Or(
		os.Getenv("APPROVED_SA_PATTERN"),
		`^tee-vm-[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$`,
	)
	saPattern, err := regexp.Compile(saPatternRaw)
	if err != nil {
		return nil, fmt.Errorf("compile APPROVED_SA_PATTERN: %w", err)
	}

	saAudience := os.Getenv("SA_TOKEN_AUDIENCE")
	if saAudience == "" {
		return nil, fmt.Errorf("SA_TOKEN_AUDIENCE is required (audience TEEs must mint identity tokens with)")
	}

	jwtExpiry, err := parseDurationSeconds("JWT_EXPIRY_SECONDS", 60)
	if err != nil {
		return nil, err
	}
	heartbeatStaleness, err := parseDurationSeconds("HEARTBEAT_STALENESS_SECONDS", 15)
	if err != nil {
		return nil, err
	}
	controlUnhealthy, err := parseDurationSeconds("CONTROL_UNHEALTHY_SECONDS", 30)
	if err != nil {
		return nil, err
	}
	otNotReady, err := parseDurationSeconds("OT_NOT_READY_SECONDS", 60)
	if err != nil {
		return nil, err
	}

	return &Config{
		Port:               cmp.Or(os.Getenv("PORT"), "8080"),
		JWTIssuer:          cmp.Or(os.Getenv("JWT_ISSUER"), "router.reclaimprotocol.org"),
		JWTExpiry:          jwtExpiry,
		SATokenAudience:    saAudience,
		ApprovedDigests:    digests,
		ApprovedSAPattern:  saPattern,
		HeartbeatStaleness: heartbeatStaleness,
		ControlUnhealthy:   controlUnhealthy,
		OTNotReady:         otNotReady,
		AdminToken:         os.Getenv("ADMIN_TOKEN"),
		FirestoreProjectID: os.Getenv("FIRESTORE_PROJECT_ID"),
		KMSKeyName:         os.Getenv("KMS_KEY_NAME"),
	}, nil
}

func parseDurationSeconds(envVar string, defaultSec int) (time.Duration, error) {
	raw := os.Getenv(envVar)
	if raw == "" {
		return time.Duration(defaultSec) * time.Second, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", envVar, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s must be > 0, got %d", envVar, n)
	}
	return time.Duration(n) * time.Second, nil
}
