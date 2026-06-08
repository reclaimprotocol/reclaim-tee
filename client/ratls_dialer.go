package client

import (
	"crypto/tls"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

// newRATLSWebSocketDialer builds a WebSocket dialer wired for RA-TLS.
// The TEE's self-signed cert can't be verified through the usual CA
// chain (InsecureSkipVerify), so VerifyPeerCertificate runs the
// attestation check instead: confirms the GCP attestation JWT is signed
// by Google, the SPKI nonce inside the JWT binds to the cert's actual
// public key, and (importantly) does NOT pin image_digest. Whatever
// digest the TEE attests to is delivered via onAttested so the client
// can stash it for the verification bundle the attestor signs later.
//
// peerRole is "tee_k" or "tee_t" — picks the right SPKI nonce prefix
// for the binding check.
func newRATLSWebSocketDialer(peerRole string, logger *shared.Logger, onAttested func(imageDigest string)) *websocket.Dialer {
	return &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			// RA-TLS certs are self-signed; the attestation extension is
			// the proof, not a CA-issued cert.
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: shared.VerifyRATLSAttestation(peerRole, logger, onAttested),
			MinVersion:            tls.VersionTLS12,
		},
	}
}
