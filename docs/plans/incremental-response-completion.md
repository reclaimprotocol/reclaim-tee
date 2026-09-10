# Negotiated incremental response completion

Status: implementation and fresh source audits are complete.
The full build and local race suites pass. Signed-claim verification of the latest audit fixes remains pending.
The baseline includes the EOF fix from PR #29.

## Objective

New clients can finish an authenticated HTTP response before TCP EOF.
Old clients and peers retain the single-batch EOF protocol.
Both TEEs freeze the same response prefix before redaction, OPRF, or signatures.
The existing signed proof format and confidentiality boundaries remain unchanged.
Local HTTP completion does not add an attested completeness claim.

## Phase 0: Discovery

Sources and existing patterns:

- `proto/transport.proto`: connection capability fields and existing response batch envelopes.
- `client/tls.go`: publish response state before the atomic handshake flag.
- `tee_k/cbc_handlers.go`: wait for a peer acknowledgment before handshake completion.
- `tee_k/connection_manager.go`: retain capabilities on the exact peer connection.
- `tee_t/session_handlers.go`: commit ciphertext before the request for tag secrets.
- `tee_k/response_handlers.go`: release decryption streams after successful tag verification.
- `tee_k/session_manager.go`: preserve `NextResponseTagSeq` as the TLS 1.3 nonce authority.
- `client/verification.go`: decrypt under response-map ownership, then reconstruct and redact.
- `providers/http_parser.go`: reuse the strict streaming parser for HTTP framing.
- `demo.sh`: build the router, both TEEs, and the client against the existing local attestor.

The TCP reader owns record assembly, sequence numbers, and pending batches.
The WebSocket reader accepts authenticated streams and publishes batch results.
Current decryption code trims ciphertext entries, so repeated streams must fail before mutation.
Current redaction code requires stable response maps.
CBC uses a separate trusted-TEE protocol and remains in EOF mode.

## Phase 1: Add the negotiated protocol

1. Add a response-mode enum with legacy EOF as zero and incremental v1 as one.
2. Add the requested mode to `RequestConnection` and the selected mode to `HandshakeComplete`.
3. Advertise peer support through the existing `SessionConnectionAck`.
4. Store that capability on the exact peer connection.
5. If the client and peer support v1, negotiate after cipher selection through a dedicated request and acknowledgment.
6. Bind negotiation to the session, a fresh 32-byte binding, and the trusted cipher suite.
7. If the cipher uses CBC or the peer lacks support, select legacy without new peer messages.

Use the CBC acknowledgment pattern and exact-session routing APIs.
Install the acknowledgment waiter before the send.
Keep cancellation and timeout paths bounded.

Verification:

- Old connection messages select legacy mode.
- New clients with either old peer select legacy mode.
- Unknown modes, duplicate acknowledgments, and wrong bindings fail.
- CBC retains its current messages and proof path.
- Regenerate protobuf code through the repository build procedure.

Guards: preserve field numbers, legacy defaults, and existing test hooks.

## Phase 2: Authenticate immutable batches and freeze the response

1. Add metadata to the existing encrypted, length, tag-secret, verification, and decryption batches.
2. Bind each batch to the session binding, batch ID, record position, count, and cumulative commitment.
3. Use one canonical commitment helper for the client and TEE_T.
4. Accept only one outstanding batch and contiguous record sequences.
5. Reject retries, duplicates, gaps, reordered records, invalid shapes, and excessive aggregate sizes.
6. Before requesting tag secrets, copy the complete records and compute their commitment.
7. Release streams only for the current authenticated batch.
8. Preserve cumulative records, nonces, and streams for the existing final proof flow.
9. Add a client-to-TEE_K freeze request for an exact authenticated prefix.
10. Require TEE_T to freeze that prefix before TEE_K acknowledges completion to the client.
11. Gate redaction, OPRF, and final signatures on the frozen state.

Before the first batch, the TCP reader sends `ResponseCaptureReady` to TEE_K after all earlier `TCPData` messages.
TEE_K processes this marker on the same WebSocket reader as those messages.
It initializes the TLS 1.3 nonce offset without consuming a nonce, then acknowledges the marker.
The TCP reader waits for that acknowledgment before it sends ciphertext to TEE_T.
TEE_K rejects incremental lengths before the marker and rejects `TCPData` after it.
This barrier preserves order across the two client sockets and the client reader goroutines.

Use `NextResponseTagSeq`, current batch codecs, and exact-session identities.
Keep full ciphertext out of TEE_K and full decryption streams out of TEE_T.
No handler holds a state mutex across network writes.
An ambiguous send fails the session without replay or rollback.

Verification:

- Reject altered metadata, duplicate sequences, unexpected streams, and append after freeze.
- Reject competing prefixes and stale session identities.
- Fail authentication before any successful final proof publication.
- Verify both freeze ordering and cancellation races.
- Preserve the legacy one-batch guard.

## Phase 3: Add client framing and finalization

1. Publish negotiated state before `handshakeComplete` becomes true.
2. Keep batch submission and finalization under TCP-reader ownership.
3. Accept each metadata-bound stream once before any ciphertext mutation.
4. Authenticate bounded batches after each TCP read or 64 records, then apply HTTP framing.
5. Reuse strict parser behavior for Content-Length, chunk terminators, trailers, and EOF bodies.
6. Handle request-method and status-specific body rules explicitly.
7. Reject unsupported upgrades and framing ambiguity.
8. Preserve existing behavior for response forms that the final proof path cannot process.
9. After local completion, stop capture and request the exact-prefix freeze.
10. After the freeze acknowledgment, reconstruct and redact once against stable response data.
11. Preserve the total response record count across all batches.
12. Add a client configuration and demo CLI override for legacy and incremental modes.

Interim-response support requires consistent final-response selection and redaction offsets throughout the proof path.
The implementation must either supply that consistency or return an explicit unsupported response error.

Verification:

- Authenticate handshake-only records before HTTP delayed beyond five seconds.
- Complete Content-Length and chunked responses before server EOF.
- Preserve pauses within HTTP and TLS records.
- Reject truncated bodies and trailers at EOF.
- Require TCP EOF or authenticated TLS `close_notify` for close-delimited bodies.
- Verify no redaction or OPRF starts before the peer freeze acknowledgment.
- Run the race detector over response collection, stream handling, and shutdown.

## Phase 4: Local proof verification

1. Verify the existing attestor endpoint without restarting that process.
2. Use `./demo.sh` as the service and client test base.
3. Run a legacy-mode proof and an incremental-mode proof.
4. Run supported TLS 1.3 and TLS 1.2 AEAD proof cases.
5. Run a CBC fallback case through the existing trusted-TEE path.
6. Add delayed and persistent-connection fixtures without a production trust bypass.
7. Distinguish transport fixtures from proof cases that reach the attestor.

Verification records must identify the commands, selected modes, attestor results, and any environment limits.
Keep the local attestor and user incident logs intact.

## Phase 5: Audit, fix, audit

1. Run an independent protocol and security audit after implementation.
2. Run an independent client, compatibility, and test-coverage audit.
3. Correct every actionable finding within this feature.
4. Repeat affected unit, race, and local proof cases after each correction.
5. Run another independent audit of the corrected implementation.
6. Stop after the audits find no unresolved blocking defects and required checks pass.

The audit covers compatibility, nonce authority, immutable commitments, confidentiality, freeze races, parser boundaries, and proof equivalence.
The final report must separate local proof evidence from properties that the implementation does not claim.

## Rollout and rollback

Deploy TEEs that support both modes first.
Then release clients that request incremental v1 and require explicit acceptance.
Clients can request legacy mode to restore EOF behavior.
Retain legacy support throughout this change.
Do not merge, deploy, or alter the attestor as part of local implementation verification.

## Local verification commands

The existing attestor must be available at `ws://localhost:8001/ws`.
Each normal demo builds and starts its own router and TEEs.
The unchanged demo script stops those services after the client finishes.

```bash
./demo.sh --response-mode=legacy 1.3
./demo.sh --response-mode=incremental 1.3
./demo.sh --response-mode=incremental 1.2 0xc02f
./demo.sh --response-mode=incremental 1.2 0xc013
```

The last case requires origin support for CBC and must select legacy mode.
The normal demo also exercises MPC OPRF redaction.

The opt-in integration fixture requires an already running local router and TEE pair.
It uses real TLS records and normal certificate verification for `example.com`.
It delays response delivery by six seconds and withholds TCP EOF.
It must produce a signed claim with both TEE signatures valid.
It uses a public response match without OPRF redaction.

```bash
DEMO_INCREMENTAL_TEST=1 DEMO_ROUTER_URL=http://localhost:9090 \
  go test ./client -run '^TestIncrementalDemoIntegration$' -count=1 -v -timeout=120s
```

`DEMO_RESPONSE_CASE` also accepts `incremental-normal`, `legacy-normal`, and `legacy-no-eof`.
The `legacy-no-eof` case must reach its 12-second core timeout.
`DEMO_TLS_VERSION=1.2 DEMO_CIPHER_SUITE=0xc02f` selects the TLS 1.2 GCM fixture.
The fixture rejects nonlocal router and attestor endpoints.
Ordinary test runs skip this fixture. Deterministic transport and authentication regressions run without external services.

```bash
go test -race ./client ./providers ./shared ./tee_k ./tee_t -count=1 -timeout=180s
```

## Scope and limitations

Incremental v1 authenticates up to 64 records per batch and submits remaining records after each TCP read.
Each submitted batch must authenticate in full before the client receives decryption streams.
Any invalid tag in that batch remains fatal, including a record after HTTP completion.
The client cannot select an earlier boundary within a failed batch.
The protocol does not attest that the origin sent no later records.
Legacy mode retains its existing EOF batch behavior.
The strict HTTP proof parser does not support interim responses or protocol upgrades.
