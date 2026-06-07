package auth

import "slices"

// Allowlist is the set of approved TEE image digests. Loaded from
// APPROVED_IMAGE_DIGESTS at startup; updated per release.
type Allowlist struct {
	digests []string
}

func NewAllowlist(approved []string) *Allowlist {
	return &Allowlist{digests: slices.Clone(approved)}
}

func (a *Allowlist) Contains(digest string) bool {
	return slices.Contains(a.digests, digest)
}
