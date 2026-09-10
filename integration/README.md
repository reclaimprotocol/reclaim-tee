# Incremental response demo

These tests use `./demo.sh`, local TEEs, and an existing local attestor.
The demo starts its own router and TEEs. It stops these services after each run.
It does not start or stop the attestor.

The target is `https://example.com/`. The test uses real TLS records and normal certificate verification.
A test connection delays response delivery after the HTTP request. It can also withhold TCP EOF until the client closes the connection.
The fixture changes transport timing only. It does not change TLS data or install a certificate authority.

Start the attestor at `ws://localhost:8001/ws` before these commands.
Run each command from the repository root. Run the commands in sequence because the demo uses fixed ports.

```bash
./demo.sh --response-mode=legacy 1.3
./demo.sh --response-mode=incremental 1.3

DEMO_INCREMENTAL_TEST=1 DEMO_RESPONSE_CASE=incremental-delayed-no-eof ./demo.sh
DEMO_INCREMENTAL_TEST=1 DEMO_RESPONSE_CASE=legacy-no-eof ./demo.sh

DEMO_INCREMENTAL_TEST=1 DEMO_TLS_VERSION=1.2 DEMO_CIPHER_SUITE=0xc02f ./demo.sh
```

The default integration case delays delivery for six seconds and never returns TCP EOF.
Incremental mode must produce an attestor claim with both TEE signatures valid.
The legacy case must reach the core timeout after 12 seconds. An unexpected successful claim fails that test.

`DEMO_RESPONSE_CASE` accepts these values:

| Value | Requested mode | Transport behavior | Expected result |
| --- | --- | --- | --- |
| `incremental-normal` | Incremental | Normal reads and EOF | Attestor claim |
| `legacy-normal` | Legacy | Normal reads and EOF | Attestor claim |
| `incremental-delayed-no-eof` | Incremental | Six-second delay, no EOF | Attestor claim |
| `legacy-no-eof` | Legacy | No EOF | Core timeout |

`DEMO_TLS_VERSION` accepts `1.2` or `1.3`. Its default is `1.3`.
`DEMO_CIPHER_SUITE` uses the same cipher names or hex identifiers as the standalone client.
`DEMO_ATTESTOR_URL` selects another local WebSocket endpoint. Its default is `ws://localhost:8001/ws`.
The integration test rejects nonlocal router and attestor endpoints.

For a CBC fallback test, use a supported CBC cipher with either normal case.
The selected response mode must be legacy for CBC. The target must support the requested cipher.

Each successful integration case logs the claim identifier, selected mode, cipher, elapsed time, response size, and measured delay.
The delayed case proves completion without TCP EOF. It does not identify the subtype of encrypted handshake records.
The normal standalone demo also exercises MPC OPRF redaction. The integration fixture uses a public response match without redaction.

The integration test skips during ordinary `go test` runs.
Transport fixture tests run without the attestor or external network.

## Capture barrier and earlier evidence

The TCP reader completes a `ResponseCaptureReady` exchange before its first incremental batch.
TEE_K accounts for earlier forwarded TLS records before it acknowledges that marker.
This barrier prevents the two client sockets from changing the first response nonce.

The seven-case matrix started at 06:08 UTC on September 10, 2026, and passed after the barrier and cleanup-race corrections.
This matrix precedes the later TLS record incident described below.
Both delayed cases produced signed attestor claims after six seconds without TCP EOF.
The legacy case reached its expected 12-second timeout.
The CBC case selected legacy mode and produced a signed attestor claim.
The normal standalone cases also produced one matching MPC OPRF output from both TEEs.

The [implementation plan](../docs/plans/incremental-response-completion.md) contains exact commands, durations, claim identifiers, and log locations.
The cleanup correction passed independent re-audit and the full TEE_T race suite.

## Later TLS record incident and completion boundary

Later TLS 1.3 runs failed on a fourth record after three successful tag checks.
A direct TLS probe reproduced this sequence with normal certificate verification:
authenticated application data, authenticated application data, authenticated `close_notify`, then a record that failed authentication.
The probe bypassed the split client and both TEEs.
The pre-PR baseline reproduced the same fourth-tag failure; its artifacts are in `/tmp/reclaim-tee-tag-sequence-baseline-20260910T072108Z`.

The user identified a TUN proxy as a possible source.
Later verification after the user disabled it is recorded below.
The evidence does not identify the component that produced the record or the cause of every historical tag failure.
The probe findings and output are in `/tmp/reclaim-tag-code-audit`.

Incremental v1 authenticates and frames each complete TLS record before capturing the next record.
It can freeze the completed HTTP prefix before a later record enters the transcript.
Close-delimited responses still require TCP EOF or an authenticated `close_notify`.
A failed tag within the required response prefix remains fatal.
Extra application bytes inside the TLS record that completes HTTP remain a framing error.

Each client batch contains one record, using the existing peer metadata and freeze exchange.
This requires an authentication exchange per record and can increase latency for responses with many small records.

Old peers and explicit legacy mode retain the EOF batch protocol.
The legacy TLS 1.3 split-AEAD client cannot classify an encrypted `close_notify` before the entire batch passes authentication.
If an EOF batch contains an invalid record after closure, a legacy TLS 1.3 session still fails authentication.
TLS 1.2 CBC continues to select legacy mode through its separate trusted-TEE path.
This incident did not establish the same failure for CBC.
Clients and both TEEs must support and select incremental v1 to use the completion correction.
Legacy mode passed again after the TUN was disabled, as described below.

The deterministic record-boundary regression uses real ChaCha20-Poly1305 and AES-GCM authentication with simulated peer replies.
Its six valid-response cases failed before the correction and passed afterward.
The final tests also cover partial trailing headers, required-record authentication failures, truncated HTTP, and extra bytes within one record.
The independent focused race gate and full client/provider race suite passed.
The implementation plan records their exact scope and output paths.

## Final incremental demo results

The final run started at 07:28 UTC on September 10, 2026, after the record-boundary correction and final test refinements.
All four commands passed:

```bash
./demo.sh --response-mode=incremental 1.3
./demo.sh --response-mode=incremental 1.2 0xc02f
DEMO_INCREMENTAL_TEST=1 DEMO_RESPONSE_CASE=incremental-delayed-no-eof ./demo.sh
DEMO_INCREMENTAL_TEST=1 DEMO_RESPONSE_CASE=incremental-delayed-no-eof DEMO_TLS_VERSION=1.2 DEMO_CIPHER_SUITE=0xc02f ./demo.sh
```

Each case selected incremental v1, froze two response records, and produced a signed attestor claim.
The normal cases each produced one matching MPC OPRF output from both TEEs.
The delayed cases completed in 6.434227391 seconds for TLS 1.3 and 6.500389926 seconds for TLS 1.2 AES-GCM.
Both returned 868 HTTP bytes, validated both TEE signatures, and reported `returned_eof=false`.

The logs and completed `status.json` are in `/tmp/reclaim-tee-tag-boundary-final-20260910T072846Z`.
The implementation plan contains measured delays, claim identifiers, test commands, and the conditional legacy limitation.

## Verification with the TUN disabled

The user disabled the TUN proxy on September 10, 2026, after the preceding runs.
Three unchanged direct TLS 1.3 ChaCha20-Poly1305 probes then authenticated every record through TCP EOF with normal certificate verification.
Each received two application records and an authenticated `close_notify`, at sequences 0, 1, and 2.
All nine tags passed; no fourth record or partial trailing bytes appeared.
The separate logs and exit results are in `/tmp/reclaim-tag-code-audit/tun-disabled`.

`./demo.sh --response-mode=legacy 1.3` also passed with the TUN disabled.
It captured three response records, produced one matching MPC OPRF output, and received a signed claim in 535.953849 milliseconds.
Its output is `/tmp/reclaim-tee-tun-disabled-legacy-tls13.log`.

These samples associate the extra record with the TUN configuration change.
They do not identify its exact source or prove that every historical tag failure has the same cause.
The legacy limitation applies when invalid records after closure enter an EOF batch; legacy passed in this tested environment.
