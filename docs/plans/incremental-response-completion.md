# Negotiated incremental response completion

Status: implementation, independent re-audit, and final incremental verification are complete.
The baseline includes the EOF fix from PR #29.
The record-by-record completion correction passed the final race suites and four live demo cases.
Three direct probes and a legacy TLS 1.3 demo also passed after the user disabled the TUN proxy.
Legacy TLS 1.3 still fails if an EOF batch includes an invalid record after closure.

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
4. Authenticate and frame each complete TLS record before capturing the next record in incremental v1.
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

## Earlier local verification: September 10, 2026, run started at 06:08 UTC

All seven demo commands passed after the capture barrier and cleanup-race corrections.
These historical results precede the later incident and completion correction described below.
The external attestor remained at `ws://localhost:8001/ws` throughout the matrix.
Each demo started and stopped its own router and TEEs.

The commands ran in this order:

```bash
./demo.sh --response-mode=legacy 1.3
./demo.sh --response-mode=incremental 1.3
DEMO_INCREMENTAL_TEST=1 DEMO_RESPONSE_CASE=incremental-delayed-no-eof ./demo.sh
DEMO_INCREMENTAL_TEST=1 DEMO_RESPONSE_CASE=legacy-no-eof ./demo.sh
DEMO_INCREMENTAL_TEST=1 DEMO_RESPONSE_CASE=incremental-delayed-no-eof DEMO_TLS_VERSION=1.2 DEMO_CIPHER_SUITE=0xc02f ./demo.sh
./demo.sh --response-mode=incremental 1.2 0xc02f
DEMO_INCREMENTAL_TEST=1 DEMO_RESPONSE_CASE=incremental-normal DEMO_TLS_VERSION=1.2 DEMO_CIPHER_SUITE=0xc013 ./demo.sh
```

| Case | Selected mode | Cipher | Protocol or fixture elapsed | Result |
| --- | --- | --- | --- | --- |
| Legacy, normal TLS 1.3 | Legacy EOF | `0x1303` | 692.281792 ms | Signed attestor claim, one matching MPC OPRF output |
| Incremental, normal TLS 1.3 | Incremental v1 | `0x1303` | 229.946232 ms | Signed attestor claim, one matching MPC OPRF output |
| Delayed response without EOF, TLS 1.3 | Incremental v1 | `0x1303` | 6.229991506 s | Both TEE signatures valid, signed attestor claim |
| Legacy without EOF | Legacy EOF | `0x1303` | 12.003269980 s | Expected core timeout, no successful claim |
| Delayed response without EOF, TLS 1.2 | Incremental v1 | `0xc02f` | 6.294461560 s | Both TEE signatures valid, signed attestor claim |
| Incremental, normal TLS 1.2 | Incremental v1 | `0xc02f` | 302.913439 ms | Signed attestor claim, one matching MPC OPRF output |
| Incremental request with CBC | Legacy EOF | `0xc013` | 290.352951 ms | Both TEE signatures valid, signed attestor claim |

The TLS 1.3 fixture delayed delivery for 6.001032652 seconds.
The TLS 1.2 fixture delayed delivery for 6.000538053 seconds.
Both fixtures returned 865 decrypted HTTP bytes and reported `returned_eof=false`.
The CBC fixture reported `returned_eof=true`.
These durations describe individual local runs.

The delayed TLS 1.3 claim identifier was `0xb1644231ca3c0b944bbd47c331c3f5e2f4bdff9d74351904bb31d719ac460592`.
The delayed TLS 1.2 claim identifier was `0x9a05e137643d6bfc15eb2996a9224472ddcc2415828ab97b1ed6aed899237ecb`.
The CBC claim identifier was `0xef5e1c123cee2cb7c2ae8fb16b8266fbaf0cc9aaad22b06ad2a661df03628727`.

The logs for this earlier matrix are in `/tmp/reclaim-tee-incremental-final-20260910T060815Z`.
Each numbered case directory contains `demo.log` and copies of available service logs.
The root directory contains `status.json` with exact commands, environment variables, process results, and selected evidence.
The standalone logs contain complete claim identifiers and matching MPC OPRF output counts.

An earlier attempt stopped when DNS lookup for `example.com` timed out before TLS negotiation.
Its failure logs remain in `/tmp/reclaim-tee-incremental-final-20260910T060555Z/02-incremental-tls13`.
The seven-case run before the cleanup correction remains in `/tmp/reclaim-tee-incremental-final-20260910T053712Z`.

The full shared and enclave suites passed:

```bash
go test ./shared ./tee_k ./tee_t
go test -race ./tee_t
```

The corresponding artifacts are `/tmp/incremental-cleanup-backend-full.json` and `/tmp/incremental-cleanup-teet-race.json`.
Each artifact has an adjacent `.log` file with test output.
The earlier shared and enclave race gate remains in `/tmp/incremental-backend-race-final.json`.

The protocol audit reproduced a race between response authentication and TEE_T cleanup.
The consolidated buffer also contains plaintext for CBC sessions.
A dedicated mutex now protects append, CBC publication, signing snapshots, and cleanup.
Cleanup clears the buffer and rejects later writes before it waits for CBC or OPRF locks.
OPRF processing copies only its requested AEAD range, at most 64 bytes, under this mutex.
CBC plaintext buffers retain their cleanup zeroing.

Permanent regressions cover concurrent authentication and cleanup, owned snapshots, zeroed backing buffers, and response-lock deadlock prevention.
The original audit reproducer and the new regressions passed independent race testing after the correction.
The independent re-audit found no remaining blocking defect in the correction.

## Later TLS record incident: September 10, 2026

Later TLS 1.3 ChaCha20-Poly1305 demos received four response records together.
The first three tags passed, but the fourth failed.
This occurred in both incremental and legacy TLS 1.3 mode.
The pre-PR baseline `d6b124fb6fa6530df78fa58bc18cdba0617d0458` reproduced the same fourth-tag failure.
Its source tree matches the main-branch merge commit `8087982`.
The URL-port correction did not change the default port used by these demos.

A direct `net.Conn` probe reproduced the record sequence without the split client or either TEE.
It used `minitls.NewClientWithConfig`, the demo HTTP request, and normal certificate verification for `example.com:443`.

| Sequence | Wire bytes | Authentication | Authenticated content |
| --- | --- | --- | --- |
| 0 | 885 | Passed | Application data, 863 bytes |
| 1 | 27 | Passed | Application data, 5 bytes |
| 2 | 24 | Passed | Alert: `close_notify`, level 1, code 0 |
| 3 | 24 | Failed | Unknown |

The fourth record also failed with the original application key at sequence numbers 0 through 15.
Its hash differed from the preceding alert record.
The probe logged hashes, lengths, sequence numbers, content types, and alert codes.
It did not log keys, tag secrets, HTTP plaintext, or HTTP headers.
A separate comparison passed 56 ChaCha20-Poly1305 cases against `golang.org/x/crypto/chacha20poly1305`, including the observed lengths and block boundaries.

The confirmed failure mechanism is batch authentication before local completion detection.
The client previously submitted all complete records from one TCP read before it could inspect any authenticated plaintext.
An invalid later record therefore prevented it from recognizing the earlier completed HTTP response or authenticated closure.
The direct probe excludes client buffer reuse and TEE nonce selection as necessary causes of this observed failure.

At this stage, the source of the extra record and the reason it was sent remained unverified.
The user identified a TUN proxy as a possible source.
The later TUN-disabled results below record the observed change after that network configuration change.
No KeyUpdate appeared in the authenticated records.
These results do not establish the cause of every historical tag failure.

The probe, output, and detailed findings are in `/tmp/reclaim-tag-code-audit`.
The earlier failing demos are `/tmp/reclaim-tee-pr31-codeql-demo.log` and `/tmp/reclaim-tee-pr31-codeql-demo-repeat.log`.
The legacy diagnostic is `/tmp/reclaim-tee-tag-sequence-legacy-20260910T071722Z/legacy-tls13-sequence-diagnostic/demo.log`.
The baseline reproduction is in `/tmp/reclaim-tee-tag-sequence-baseline-20260910T072108Z`.
Its `status.json` records `./demo.sh 1.3`, the diagnostic overlay, and the failed process result.

### Incremental completion correction

The v1 client authenticates and frames each complete TLS record before it captures the next record.
A framed HTTP response can therefore finish before later TLS records enter the committed prefix.
A close-delimited response still requires TCP EOF or an authenticated `close_notify`.
Authentication failure within the selected prefix remains fatal.
The client does not infer record content from its length or accept a failed tag.

Each client batch contains one record; the existing peer metadata and freeze protocol remain unchanged.
The exact authenticated prefix must freeze in both TEEs before redaction, OPRF, or signing.
Extra application bytes within the TLS record that completes HTTP still fail strict framing.
Bytes from a later record can remain unread or unprocessed after completion.
This behavior selects a record-boundary prefix and does not attest that the server sent nothing later.

The client now waits for one authentication exchange per record.
Responses with many small records can therefore take longer than responses authenticated in larger batches.

### Legacy limitation

Old peers and explicit legacy mode retain the EOF batch protocol.
The legacy TLS 1.3 split-AEAD client cannot inspect an encrypted `close_notify` until the entire batch passes authentication.
If an EOF batch includes an invalid record after closure, the legacy TLS 1.3 session still fails authentication.
TLS 1.2 CBC also continues to select legacy mode, but uses its separate trusted-TEE authentication path.
This incident did not establish the same failure for CBC.
A successful legacy demo does not remove this conditional limitation.
Clients and both TEEs must support and select incremental v1 to use the completion correction.

### Completion regression verification

`TestIncrementalTCPStopsAtAuthenticatedRecordBoundary` uses real ChaCha20-Poly1305 and AES-GCM authentication with simulated peer replies.
It supplies complete encrypted records together in one TCP read.
The simulated peer releases streams only after every record in the submitted batch passes authentication.

Before the correction, all six valid-response cases failed before freeze because the batch included the invalid trailing record.
The failure output is `/tmp/reclaim-tee-tag-boundary-before.log`.
The initial race rerun passed after the correction; its output is `/tmp/reclaim-tee-tag-boundary-after.log`.
These commands produced those results, respectively:

```bash
go test ./client -run '^TestIncrementalTCPStopsAtAuthenticatedRecordBoundary$' -count=1 -timeout=60s
go test -race ./client -run 'TestIncrementalTCPStopsAtAuthenticatedRecordBoundary|TestIncrementalTCPHandshakeOnlyThenDelayedHTTP' -count=1 -timeout=90s
```

The final regression also covers a partial next TLS header after complete HTTP.
It verifies exact captured, submitted, and frozen record counts.
It requires the correct error for a bad tag before completion, closure before Content-Length completion, and extra HTTP bytes within one record.
Reconstruction must wait for the matching freeze acknowledgment.

The independent audit found no remaining blocking issue in the correction.
The following final race gate passed for the client in 1.654 seconds and the providers in 1.085 seconds:

```bash
go test -race ./client ./providers -run 'TestIncremental|TestTCPResponse|TestTCPReadPreservesDataWithTerminalError|TestHTTPResponseFramer|TestDemoResponseConn' -count=1 -timeout=120s
```

Its output is `/tmp/reclaim-tag-code-audit/final-focused-race.log`.
This gate includes the record boundary, capture barrier, delayed handshake, watchdog, EOF, byte-plus-error, framing, and transport fixture tests.
The full race suite passed for the client in 3.573 seconds and the providers in 1.186 seconds:

```bash
go test -race ./client ./providers -count=1 -timeout=180s
```

Its output is `/tmp/reclaim-tee-tag-boundary-full-race.log`.

### Final live verification: September 10, 2026, run started at 07:28 UTC

All four incremental cases passed after the record-boundary correction and final test refinements.
The commands ran in this order against the existing local attestor:

```bash
./demo.sh --response-mode=incremental 1.3
./demo.sh --response-mode=incremental 1.2 0xc02f
DEMO_INCREMENTAL_TEST=1 DEMO_RESPONSE_CASE=incremental-delayed-no-eof ./demo.sh
DEMO_INCREMENTAL_TEST=1 DEMO_RESPONSE_CASE=incremental-delayed-no-eof DEMO_TLS_VERSION=1.2 DEMO_CIPHER_SUITE=0xc02f ./demo.sh
```

| Case | Cipher | Protocol or fixture elapsed | Result |
| --- | --- | --- | --- |
| Normal TLS 1.3 | `0x1303` | 536.201628 ms | Signed attestor claim, one matching MPC OPRF output |
| Normal TLS 1.2 | `0xc02f` | 481.371725 ms | Signed attestor claim, one matching MPC OPRF output |
| Delayed TLS 1.3 without EOF | `0x1303` | 6.434227391 s | Both TEE signatures valid, signed attestor claim |
| Delayed TLS 1.2 without EOF | `0xc02f` | 6.500389926 s | Both TEE signatures valid, signed attestor claim |

Each case selected incremental v1 and froze exactly two response records.
The delayed TLS 1.3 fixture measured a 6.000453688-second delay; the TLS 1.2 fixture measured 6.001106734 seconds.
Both returned 868 decrypted HTTP bytes and reported `returned_eof=false`.
These measurements describe individual runs, not a latency benchmark.

The normal TLS 1.3 claim identifier was `0x5dd5ef2741c6ec4d708fc0434fca887c29e0b740d5c4c35d9302335e33252b8d`.
The normal TLS 1.2 claim identifier was `0x8922d1436b98f06a0e93d03e8551248077cd07aa6d016f4ba19dfe9bf4a35794`.
The delayed TLS 1.3 claim identifier was `0x5ca45c7e9094b283d681ea093d5894f07a7acdbf4f1b94ffb9a2a1bbdfd4a8d8`.
The delayed TLS 1.2 claim identifier was `0xd207a29094a699150f966dc3ef23aebe2ba5a07793fb7e87829394e8c547fdaf`.

The logs are in `/tmp/reclaim-tee-tag-boundary-final-20260910T072846Z`.
Its `status.json` records all four commands, environments, zero exit codes, and successful completion.
Each case directory contains `demo.log` and available service logs.
These incremental results do not remove the conditional legacy TLS 1.3 limitation described above.

### Verification after the TUN was disabled: September 10, 2026

The user disabled the TUN proxy after the preceding diagnosis and incremental demo runs.
Three direct probes then used the unchanged `/tmp/reclaim-tag-code-audit/main.go` program with normal certificate verification.
Each command ran separately:

```bash
go run /tmp/reclaim-tag-code-audit/main.go probe
go run /tmp/reclaim-tag-code-audit/main.go probe
go run /tmp/reclaim-tag-code-audit/main.go probe
```

All three connections negotiated TLS 1.3 ChaCha20-Poly1305 and reached TCP EOF.
Every run produced this record sequence:

| Sequence | Wire bytes | Authenticated content |
| --- | --- | --- |
| 0 | 882 | Application data, 860 bytes |
| 1 | 27 | Application data, 5 bytes |
| 2 | 24 | `close_notify`, level 1, code 0 |

All nine record tags passed.
There was no fourth record, partial trailing header, or partial trailing payload in these runs.
The separate outputs are `/tmp/reclaim-tag-code-audit/tun-disabled/probe-1.log`, `probe-2.log`, and `probe-3.log`.
The same directory contains `results.json` with all three zero exit codes.
The logs retain record hashes, lengths, sequences, and authenticated types without keys or HTTP plaintext.

The legacy TLS 1.3 demo also passed with the TUN disabled:

```bash
./demo.sh --response-mode=legacy 1.3
```

It captured three response records of 882, 27, and 24 wire bytes and submitted one EOF batch.
It produced one matching MPC OPRF output and a signed attestor claim in 535.953849 milliseconds.
The claim identifier was `0xc7ed9c943ceefac514a0d24f9be23c04bd9827b9f35f75adae0a2669ea2966ba`.
The complete output is `/tmp/reclaim-tee-tun-disabled-legacy-tls13.log`.

The invalid fourth record disappeared in these samples after the TUN was disabled.
This before-and-after result supports an association with the TUN configuration.
It does not identify the component that produced the record or establish the cause of every historical tag failure.
Legacy mode succeeded in the tested TUN-disabled environment.
Its authentication limitation applies if invalid bytes after closure return in a later EOF batch.
No source code, probe code, or network settings changed during these verification commands.

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
