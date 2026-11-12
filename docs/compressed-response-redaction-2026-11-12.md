# TEE redaction on a compressed response body — investigation, 2026-11-12

Read-only investigation, then a proposed fix on local branches (nothing pushed or deployed).
Code: `reclaim-tee` `origin/main` @ `e313ebf` (Popcorn `reclaim-api` pins `cf66aa97505e`,
2 commits behind with no change to `providers/` or `client/`), `reclaim-portal` `origin/main` @ `08b1b121`.
No production data was queried. No student data, cookies or tokens are recorded here.

## TL;DR

- The TEE **does not decode any Content-Encoding**. It always sends `Accept-Encoding: identity`
  (`providers/http.go`, `CreateRequest`) and forbids providers and the portal from overriding it.
  It assumes the origin obeys. Nothing in `providers/` or `client/` reads `Content-Encoding`.
- Sharda University Agra (`9c4d159b`): the origin sometimes returns **gzip anyway**. The TEE runs
  the regex on the gzip bytes and fails. The quoted "found element"
  `H++/vQgAAAAAAAQA77+9…` decodes to `1f EF BF BD 08 00 00 00 00 00 04 00 …`. This is a gzip member
  header (`1f 8b 08`, mtime 0, XFL 4, OS 0) whose `0x8b` became U+FFFD in the UTF‑8 decode.
  `XFL=4, OS=0` with a zero mtime matches the header that .NET `GZipStream` writes. That is consistent
  with ASP.NET application-level compression (for example `Response.Filter = new GZipStream(...)`),
  which ignores `Accept-Encoding`. The intermittent rate suggests one backend in a farm does this.
  This is a hypothesis and is not verified.
- **Decoding before redaction is not a sound fix.** Reveals are byte ranges of the TLS plaintext. A
  field inside a DEFLATE/Brotli stream has no byte-aligned position, so it cannot be revealed alone.
  If you match on decoded text, the reveal would cover bytes that the verifier sees as compressed
  garbage. The proof would not verify, or it would reveal the whole body.
- **JSPM (`91c905b7`) is a different failure class.** On gzip bytes, `jsonpathplus-go.Query` fails
  in `ParseOrderedJSON` and returns `JSONPath query failed: …`. It does not return `jsonPath not found`.
  `jsonPath not found` means the TEE got **valid JSON without the path**, which is a different
  (probably error or empty) response to the second fetch. The cause is not determined. See §4.
- Secondary bug: the portal classifier labels this error `provider`. So a **correct** Sharda config
  is sent to AI repair, which risks a bad repair.

## 1. Code path

| Step | Location | Behaviour |
|---|---|---|
| Portal header build | `reclaim-portal` `packages/browser-events/src/utils/claim-generation/claim-builder.ts:288-291` | Removes `accept-encoding` from public and secret claim headers ("The attestor manages response compression itself"). |
| Portal prove call | `claim-generator.ts:2629-2700` | `POST {tee}/reclaim/prove`, one attempt. Non-2xx → `PROOF_GENERATION_FAILED`, `recordSessionFailure(httpStatus 500, errorExcerpt)`. No retry. |
| TEE request | `reclaim-tee` `providers/http.go` `CreateRequest` (~L176-186) | Fixed header block `Host`, `Connection: close`, `Content-Length`, **`Accept-Encoding: identity`**. `clientReservedHeaders` (L22) rejects any config `Accept-Encoding`. The request has been like this since the initial commit. |
| Response analysis | `client/redaction.go` `analyzeResponseRedaction` → `analyzeHTTPContent` → `getAutomaticHTTPRedactions` → `client/client.go:670` `providers.GetResponseRedactions` | Error-wrapping chain matches the production message exactly. |
| Parse | `providers/http_parser.go` `finishHeaders` (L298+) | Handles `chunked` / `Content-Length` / EOF framing only. `res.Body` is de-chunked but **never decompressed**. In strict (TLS1.2 CBC) mode `Transfer-Encoding: gzip, chunked` is accepted (chunked last) and gzip is ignored too. |
| Charset | `providers/http.go` `GetResponseRedactions` → `decodeResponseBody` (`response_charset.go`) | Decodes bytes as the declared charset. Invalid UTF-8 → U+FFFD, mapped back to raw offsets. |
| Match | `providers/response.go` `processRedactionRequest` / `applyRegexWindow` (L219-285) | Regex over the decoded text. On a miss: `regexp %s does not match found element '<base64 of segment>'`, which is the error seen. |
| Portal classification | `packages/shared/src/failure-classifier.ts:140-160` | `failed to analyze response redaction` + `does not match found element` → **`provider`**, checked before the HTTP 500 → `infra` rule. |

The portal's own browser-side extraction succeeds because Chrome decodes gzip before the CDP capture.
The TEE refetches the live URL itself (see sibling note `response-body-cap-investigation-2026-11-12.md`).

## 2. Encoding cases (current behaviour)

| Server response | TEE today |
|---|---|
| Identity (obeys `identity`) | Works. |
| `Content-Encoding: gzip` / `deflate` / `br` / `zstd`, with Content-Length or chunked | Regex/XPath/JSONPath run on compressed bytes. Fails with a confusing selector error. |
| gzip body with **no** Content-Encoding header | Same. |
| Double-encoded (`gzip, gzip`) | Same. |
| `Transfer-Encoding: gzip, chunked` | Dechunked, still gzip. Same. |

## 3. Proposed fix (branches, not pushed)

### 3a. reclaim-tee: fail fast with a typed error — branch `fix/reject-content-encoded-response`

- `providers/content_coding.go`: `ErrResponseContentEncoded` and `checkResponseNotContentEncoded`.
  It rejects any `Content-Encoding` other than identity, any `Transfer-Encoding` other than
  `chunked`/identity, and any body that starts with gzip magic `1f 8b 08` (catches a missing
  header; text/HTML/JSON never starts with `0x1f`). No zlib/brotli sniffing: their magic bytes are
  not reliable.
- `providers/http.go` `GetResponseRedactions`: calls the check after the 2xx check and only when
  redaction rules exist.
- `providers/content_coding_test.go`: gzip with Content-Length, gzip + chunked, gzip without header
  (plain and chunked), `br`, `deflate`, `gzip, gzip`, `Transfer-Encoding: gzip, chunked` (strict
  CBC and normal), identity / explicit identity / chunked identity still reveal the value, and no
  rules → no inspection.

**Attestation impact: none.** The transcript, request bytes and reveal ranges for identity
responses do not change. For compressed responses the TEE now returns a clear error instead of a
selector error. No proof that verifies today is lost, because these never produced a proof.

### 3b. reclaim-portal: stop sending correct providers to repair — worktree `../reclaim-portal-tee-encoding`, branch `fix/classify-compressed-tee-body`

- `failure-classifier.ts`: a regex mismatch whose found element starts with base64 `H4sI` (raw gzip)
  or `H++/vQg` (gzip after UTF‑8 replacement) is no longer `provider`. It falls through to
  HTTP 500 → `infra`. The new TEE error is `infra` by the same rule. This works before and after the
  TEE deploy.
- Test added. `vitest run test/failure-classifier.test.ts`: 18/18 pass.

### 3c. Optional follow-up (not implemented): one prove retry on `content-encoded`

If the farm-node hypothesis holds, one retry of `/reclaim/prove` with a new proxy session may reach
a well-behaved backend. Measure the share of Sharda TEE attempts that hit this before you build it.

### Rejected alternatives

- **Decode then redact**: unsound, as described in the TL;DR. Reveal offsets cannot be mapped into
  a compressed stream.
- **Reveal the whole compressed body and decompress in the verifier**: this needs an attestor and
  verifier protocol change, and it discloses the whole page (other PII). Do not use it for identity pages.
- **Send `Accept-Encoding: identity`**: this is already sent. The origin ignores it.
- **Omit Accept-Encoding**: the RFC 9110 default then allows any coding. That is worse.

## 4. JSPM `91c905b7` — `jsonPath not found` (about 1 in 50)

The error text rules out gzip (see TL;DR). The TEE got parseable JSON without the configured
path. Likely causes are a second-request response that differs from the browser's (expired or
single-use token in `getHeaderDetails`, rate limiting, `{"status":false,...}`, or a different
body because of header/cookie differences). The TEE error does not include the body, so this
can't be confirmed from logs. Next steps (need production access):

1. In ClickHouse `otel.otel_logs` (`portal-browserevents`), compare `[TEE] Prove 1 providerParams`
   for failing and successful sessions (header set, proxy vendor, time between capture and prove).
2. Check whether failures cluster on proxy vendor (`grass` vs `brightdata`) or on a long
   capture→prove delay.
3. Consider adding a hashed/size-only body fingerprint (no content) to the TEE `jsonPath not found`
   error to tell "empty/error JSON" apart from "schema drift".

## 5. Not verified

- No production query was run. The failure rate for Sharda among all TEE attempts and the
  farm-node hypothesis are unmeasured.
- Tests were run locally with Go 1.27.3. `go test ./providers/ ./client/ ./shared/` passes. `go vet` and `gofmt` are clean.
  No end-to-end TEE run against a real gzip-ignoring origin was done.
