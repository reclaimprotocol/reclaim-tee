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

## Capture barrier and final evidence

The TCP reader completes a `ResponseCaptureReady` exchange before its first incremental batch.
TEE_K accounts for earlier forwarded TLS records before it acknowledges that marker.
This barrier prevents the two client sockets from changing the first response nonce.

The seven-case matrix passed on September 10, 2026, after the barrier and cleanup-race corrections.
Both delayed cases produced signed attestor claims after six seconds without TCP EOF.
The legacy case reached its expected 12-second timeout.
The CBC case selected legacy mode and produced a signed attestor claim.
The normal standalone cases also produced one matching MPC OPRF output from both TEEs.

The [implementation plan](../docs/plans/incremental-response-completion.md) contains exact commands, durations, claim identifiers, and log locations.
The cleanup correction passed independent re-audit and the full TEE_T race suite.
