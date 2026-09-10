# Draft: incremental response verification and HTTP completion

Status: protocol/security review proposal; no runtime behavior change.
This is separate from PR #29's bounded EOF fix.

## Objective and terminology

Allow an honest client to finish a complete keep-alive HTTP response promptly,
without treating idle encrypted TLS records as HTTP completion. Preserve the
current confidentiality boundaries, authentication checks, and immutable final
transcript. Do not claim this draft is an implemented or audited secure protocol.

Two guarantees must remain distinct:

1. **Locally observed completion:** the client parses plaintext released after
   record authentication and recognizes a complete HTTP message.
2. **Attested completeness:** the verifier can independently establish that the
   committed transcript contains a complete response, despite a malicious client.

The first can guide an honest client's transport behavior. It cannot alone
establish the second. An authenticated plaintext prefix may still be incomplete.

## Current constraints confirmed in code

- `client/tcp.go` captures opaque records and submits one terminal response batch.
- `tee_t/session_handlers.go:handleBatchedEncryptedResponses` rejects a second
  batch using `ResponseBatchReceived`. This prevents transcript replacement or
  extension after response processing begins.
- `tee_k/response_handlers.go:handleBatchedResponseLengths` produces tag secrets;
  TLS 1.3 sequence/nonce progression is controlled by TEE_K.
- After successful tag verification, TEE_K sends decryption streams to the client
  in `handleBatchedTagVerifications`.
- In split-AEAD mode, TEE_T receives ciphertext and authentication material;
  TEE_K receives record metadata and owns decryption material. Neither currently
  receives the entire response plaintext for an HTTP parser. Sending ciphertext
  to TEE_K or full streams to TEE_T changes the privacy/disclosure model.
- TLS 1.2 CBC uses a different trusted-TEE path: TEE_T already authenticates and
  decrypts response plaintext. Its design must be reviewed separately.
- Provider requests require `Connection: close`. PR #29 uses real EOF and the
  existing overall protocol deadline; this remains the fallback.

## Proposed split-AEAD direction

Negotiate a new versioned response mode explicitly. Existing clients/TEEs keep
one-batch semantics; unknown or unsupported modes must reject or use EOF mode
before any response transcript is started. Never silently downgrade mid-session.

### 1. Append-only authenticated prefixes

Introduce bounded record batches with session/generation binding, monotonically
increasing batch IDs, exact starting sequence, and exact record count. Enclaves
must reject gaps, duplicates, reordering, count mismatches and excessive aggregate
sizes. A transport retry must not consume another nonce or overwrite an accepted
record; define exact retry semantics before implementation.

Commit each record's full header, ciphertext, tag, IV and position before releasing
its authentication/decryption material. TEE_K and TEE_T must agree on the committed
prefix. Bind acknowledgements to a domain-separated prefix commitment and record
count. TEE_K must retain exclusive nonce-sequence authority. Keep key/stream
release restrictions at least as strong as the current protocol.

Appending must not reuse or reset response maps. No response signatures, redaction
finalization, OPRF processing, or terminal proof publication may occur while the
transcript remains appendable. Handle cancellation, stale handlers, reconnection,
partial acknowledgement and concurrent finalize/append explicitly.

### 2. Client-local HTTP framing

Only after record authentication, reconstruct plaintext in the client and parse
HTTP incrementally. Ignore authenticated TLS post-handshake messages for HTTP
framing while retaining their transcript positions. A size/count heuristic over
encrypted records is never a framing signal.

The parser must be bounded and incremental, and must handle:

- Interim 1xx responses before the final response; 101/upgrades require an
  explicit unsupported-mode outcome, not completion as an ordinary response.
- Request-method/status-specific no-body semantics.
- A validated Content-Length and exactly that number of body octets.
- Chunk sizes, data delimiters, terminating chunk and complete trailer section.
- Close-delimited bodies, which continue to require stream closure.
- Duplicate/conflicting Content-Length, Transfer-Encoding ambiguity, overflow,
  malformed syntax, oversized headers/trailers, and unsupported transfer codings.
- Segmentation at every byte boundary and TLS 1.3 padding/control records.

Framing applies to wire-body octets before content decompression. Do not use the
Portal browser's response length, decoded DOM, or a prior request's headers.
Reject ambiguity instead of allowing parser discrepancies across client/attestor.

### 3. Freeze before redaction/signing

After local completion, an untrusted client may request finalization of an exact
committed prefix. Both enclaves must irreversibly freeze the same prefix before
any final redaction/signature flow. Reject append-after-finalize, competing final
prefixes, stale-generation requests and signatures over different prefix lengths.

A client finalize request is a transport decision, not trusted evidence of HTTP
completeness. Existing provider proof checks must not be weakened. Do not add an
"authenticated response complete" assertion based solely on that request.

### 4. Attested completeness remains a design gate

If the product requires completeness against malicious clients, specify how the
verifier authenticates HTTP framing while retaining private header/body data.
Potential directions include selective authenticated framing disclosure with
explicit privacy review, or a framing predicate proven through an appropriate
secure-computation/proof mechanism. Neither is designed or approved here.

Do not silently reveal Set-Cookie, private response headers, arbitrary body bytes,
or full plaintext to an enclave to simplify parsing. Authenticated TLS closure
alone also needs HTTP framing/truncation checks; it is not a universal substitute.

The security review must determine whether a client-local completion optimization
preserves the existing proof semantics, and whether attested completeness is an
additional product requirement. This gate precedes production implementation.

## Required regression and adversarial tests

- Two authenticated post-handshake messages, then HTTP delayed beyond five seconds.
- Complete Content-Length and chunked responses on a socket that stays open.
- Pauses between records, partial TLS/header/chunk/trailer boundaries, and real EOF.
- A truncated authenticated HTTP prefix must never earn a completeness assertion.
- Duplicate/skipped/reordered records, altered ciphertext/tag/header/IV, and invalid
  sequence/nonce progression fail without any successful proof publication.
- Repeated batch IDs with identical and different content; no duplicate key release.
- Finalize racing append/cancel/disconnect, wrong prefix commitments, session swaps,
  stale handlers and reconnections; exactly one immutable final transcript.
- Redaction and OPRF before/after freeze, ensuring no extension after key release
  or signatures invalidates the current soundness assumptions.
- Old/new client and enclave version combinations; no silent downgrade.
- Aggregate resource limits and the overall deadline remain enforced.
- Privacy tests verify that plaintext/secret logs and enclave disclosures do not
  expand merely to support framing.
- Cross-language parser differential tests and live delayed/keep-alive test servers
  with actual cryptographic proof verification, separately for TLS 1.3, TLS 1.2
  AEAD, and the trusted-TEE CBC path.

## Rollout and decision

Keep PR #29 independent. Before enabling the new mode, approve the confidentiality
and proof-semantics decisions, review the protocol state machine, implement the
adversarial tests, and verify old/new interoperability. Then canary explicit opt-in
sessions with counters for authenticated records, first HTTP-byte latency, framing
mode, final prefix length and terminal reason. Never log raw secret values.

This draft intentionally does not remove the one-batch guard or activate a parser.
A prose design and passing transport tests are not evidence of cryptographic
soundness for a new incremental protocol.
