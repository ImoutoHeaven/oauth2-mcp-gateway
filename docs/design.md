# oauth2-mcp-gateway design

## 1. Sidecar boundary and scope

`oauth2-mcp-gateway` is a single-upstream OAuth 2.1 authentication sidecar for Model Context Protocol (MCP) servers. One gateway process binds a local socket behind an edge reverse proxy or tunnel (such as Nginx, Traefik, Caddy, Cloudflare Tunnel, or Tailscale Funnel) and fronts one MCP service.

In scope:

1. Serve OAuth 2.1 discovery metadata (RFC 9728 and RFC 8414), Dynamic Client Registration (RFC 7591), PKCE `S256` authorization code grants, single-tip generation-tracked refresh token rotation, and authenticated token revocation (RFC 7009).
2. Validate `Host` and normalized `Origin` headers, expose unauthenticated `GET` and `HEAD /healthz` probes (`200 OK`, `{"ok":true}` on `GET`), and verify opaque Bearer access tokens on `<resource_path>` (default `/mcp`) bound to `<public_url><resource_path>`.
3. Bridge authorized MCP traffic to an upstream Streamable HTTP MCP endpoint or to isolated per-session `stdio` child processes.
4. Stream configured unauthenticated capability URL prefixes (such as `/t/`) directly to an HTTP upstream origin without buffering bodies in memory.

Outside scope:

- TLS termination, ACME certificate management, HTTP/2 or HTTP/3 edge listeners, and multi-service virtual-host routing stay at the reverse proxy or tunnel.
- Persistent state lives in one local JSON file without external OIDC identity providers, SQL databases, or web administration UIs.
- MCP tool definitions, arguments, and results pass through without filtering or schema edits.

## 2. Configuration validation and state persistence

The gateway loads one JSON configuration file (capped at `1 MiB`) from `--config <path>` or `OAUTH2_MCP_GATEWAY_CONFIG` (default `gateway.json`). Startup rejects unknown fields (`deny_unknown_fields`). Any string field equal to `"${VAR}"` expands from the process environment at startup, except entries in `upstream.args`, which pass verbatim as child command arguments. Partial interpolation (such as `"prefix-${VAR}"`) and unset or empty referenced variables fail startup.

Top-level fields:

- `listen`: local `IP:PORT` socket address to bind, such as `"127.0.0.1:8080"`.
- `public_url`: canonical external origin without path, query, fragment, or userinfo, such as `"https://mcp.example.com"`. Plain `http://` is permitted only when the host is `localhost`, `127.0.0.1`, or `[::1]`.
- `resource_path`: public MCP route served directly by the gateway, default `"/mcp"`. Segments must be non-empty ASCII letters, digits, or `-._~` without `.` or `..`, and cannot overlap `/oauth/`, `/.well-known/`, `/healthz/`, or any `passthrough_prefixes`. Changing `public_url` or `resource_path` invalidates existing resource-bound grants and requires clients to re-authorize.
- `state_path`: regular file path for persisted OAuth clients and hashed token grants (`state.json`), resolved relative to the config file directory when relative. On Unix, startup creates missing parent directories with mode `0700` and writes `state.json` with mode `0600` via a sibling temporary file, `fsync`, and atomic `rename`.
- `oauth`: owner credential and token lifetime configuration.
- `upstream`: tagged union (`"transport": "http"` or `"transport": "stdio"`).

`oauth` fields:

- `owner_password_hash` (`pbkdf2-sha256$<iterations>$<salt_b64>$<hash_b64>`, `600000` default iterations from `hash-password`, `10000..=5000000` accepted; `hash-password` reads one UTF-8 line up to `4096` bytes from `stdin`) or `owner_password` (non-empty plaintext secret hashed in memory at startup with `PBKDF2-HMAC-SHA256` at `600000` iterations). Providing both or neither fails startup.
- `scopes`: non-empty list of whitespace-free RFC 6749 scope tokens, default `["mcp"]`.
- `allowed_redirect_hosts`: optional hostname allowlist for DCR `redirect_uris`, default `[]`. Loopback `http://` callbacks remain allowed; when non-empty, `https://` callbacks must match an IDNA-normalized entry in `allowed_redirect_hosts`. Wildcards and reserved OAuth response query parameters are rejected.
- `access_token_ttl_secs`: `60..=86400`, default `3600`.
- `refresh_token_ttl_secs`: `300..=7776000`, default `2592000` (30 days), at least `access_token_ttl_secs`.
- `max_grant_lifetime_secs`: cumulative sliding refresh ceiling per grant measured from initial authorization, default `3 * refresh_token_ttl_secs`, capped at `31536000` (365 days) and at least `refresh_token_ttl_secs`.
- `refresh_grace_secs`: `0..=86400` and `<= refresh_token_ttl_secs`, default `min(access_token_ttl_secs, refresh_token_ttl_secs)` (`3600` seconds by default).
- `refresh_reuse_policy`: `"converge"` (default) or `"revoke"`.
- `max_registered_clients`: `16..=4096`, default `512`.

`upstream` fields:

- `"transport": "http"`:
  - `url`: upstream MCP endpoint URL (`http://` or `https://`, without userinfo, query, or fragment).
  - `bearer_tokens`: optional pool of non-empty ASCII Bearer tokens, default `[]`. When non-empty, each OAuth grant pins the least-loaded slot at authorization time and sends `Authorization: Bearer <token>` upstream. When empty, client OAuth `Authorization` is stripped and no upstream `Authorization` header is sent.
  - `passthrough_prefixes`: optional path prefixes starting and ending with `/` (such as `["/t/"]`), default `[]`. Prefixes cannot overlap `<resource_path>`, `/oauth/`, `/.well-known/`, `/healthz/`, or the path of `upstream.url` (matched case-insensitively).
  - `request_timeout_secs`: `5..=3600`, default `300`.
- `"transport": "stdio"`:
  - `command`: executable path or name.
  - `args`: argument list passed verbatim, default `[]`.
  - `env`: explicit child environment variables, default `{}`.
  - `cwd`: optional child working directory.
  - `max_sessions`: `1..=256`, default `32`.
  - `session_idle_secs`: `30..=86400`, default `1800`.

## 3. Request guards, OAuth 2.1 endpoints, and refresh rotation

### 3.1 Host, Origin, and CORS discovery guards

- `Host` validation checks incoming `Host` authorities and blocks DNS rebinding requests against loopback `http://` listeners.
- `Origin` validation compares normalized browser `Origin` headers against `public_url` across `<resource_path>`, `/oauth/*`, and `passthrough_prefixes`, returning `403 Forbidden` on mismatches while allowing non-browser clients that omit `Origin`.
- `/.well-known/*` routes answer `GET` and `OPTIONS` with read-only CORS headers so browser-based MCP clients can read discovery metadata prior to login.

### 3.2 OAuth 2.1 endpoints (`src/oauth.rs`)

1. `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource<resource_path>` (RFC 9728):
   - Both routes publish `resource: "<public_url><resource_path>"` and `authorization_servers: ["<public_url>"]` so clients probing root or path-scoped discovery resolve the same resource URI.
2. `GET /.well-known/oauth-authorization-server` and `GET /.well-known/oauth-authorization-server<resource_path>` (RFC 8414):
   - Publish `issuer: "<public_url>"`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `response_types_supported: ["code"]`, `response_modes_supported: ["query"]`, `grant_types_supported: ["authorization_code", "refresh_token"]`, `token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"]`, `code_challenge_methods_supported: ["S256"]`, and `authorization_response_iss_parameter_supported: true`. Other subpaths return `404`.
3. `POST /oauth/register` (RFC 7591):
   - Rejects `redirect_uri` entries that are relative, contain fragments or userinfo, carry reserved OAuth response query keys, use non-loopback `http://`, or fall outside `allowed_redirect_hosts`.
   - Applies RFC 7591 defaults (`grant_types: ["authorization_code", "refresh_token"]`, `response_types: ["code"]`, `token_endpoint_auth_method: "none"`), mints secrets for confidential clients (persisting only SHA-256 digests), and at `max_registered_clients` evicts only the oldest client with no active grants, pending logins, or authorization codes.
4. `GET /oauth/authorize` and `POST /oauth/authorize`:
   - Require `response_type=code`, a registered `client_id`, an exact registered `redirect_uri`, and PKCE `S256` (`code_challenge` of 43 base64url characters decoding to 32 bytes) for public and confidential clients alike.
   - Normalize optional RFC 8707 `resource` values (`<public_url>`, `<public_url>/`, or `<public_url><resource_path>`) to `<public_url><resource_path>`, rejecting other targets with `invalid_target`.
   - Bind each pending login form (`5` minute TTL, up to `512` pending forms total and `32` per client IP) to the browser via an `HttpOnly; SameSite=Lax` CSRF cookie: `__Host-mcp_ar_<id>` (`Secure; Path=/`) on `https://`, or `mcp_ar_<id>` (`Path=/oauth/authorize`) on loopback `http://`.
   - Serve a self-contained HTML login form with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'` and `X-Frame-Options: DENY`, showing client identity, callback URI, and requested scopes with `Authorize` and `Cancel`/`Deny` (`error=access_denied`) actions. Password verification runs constant-time PBKDF2, caps retries at 3 per form session, and rate-limits failures per client IP.
   - Issue a single-use authorization code (`5` minute TTL) and redirect with `code`, `iss=<public_url>` (RFC 9207), and optional `state`.
5. `POST /oauth/token`:
   - `authorization_code`: consumes the single-use code (replaying a consumed code revokes the issued grant), authenticates confidential clients, verifies `redirect_uri`, `resource`, and `BASE64URL_NOPAD(SHA256(code_verifier)) == code_challenge`, pins the least-loaded `pool_slot`, records initial authorization time for `max_grant_lifetime_secs`, persists SHA-256 digests of the access token and generation-0 refresh token, and sets `Cache-Control: no-store`.
   - `refresh_token`: rotates structured single-tip tokens (`rt1.<grant_id>.<gen>.<nonce>.<tag>`):
     - Rotating active generation `G` advances the tip to `G + 1`, clamps token lifetime by `refresh_token_ttl_secs` and the grant's `max_grant_lifetime_secs` deadline, persists SHA-256 digests of active `G + 1` and grace `G` in `state.json`, and caches the current tip response in memory until `grace_until`.
     - Parallel subagents presenting the grace token within `refresh_grace_secs` verify client credentials, resource, and scope, then receive the cached tip response so concurrent refreshes across multiple hops converge on one active tip.
     - Presenting an older family token after `refresh_grace_secs` follows `refresh_reuse_policy`: `"converge"` (default) verifies client credentials, resource, HMAC family lineage tag, and remaining grant lifetime, then returns the live tip response (rotating if the memory cache expired) so resumed parent or child agents keep sibling sessions alive; `"revoke"` enforces RFC 9700 reuse detection, revokes the grant, and terminates all bound HTTP and `stdio` sessions.
6. `POST /oauth/revoke` (RFC 7009):
   - Authenticates the caller (`client_id` matching the grant for public clients, or `client_secret_basic` / `client_secret_post` for confidential clients), revokes any matching grant, terminates bound HTTP and `stdio` sessions, and returns `200 OK`.

OAuth `POST` endpoints cap request bodies at `64 KiB` with a `10` second read timeout.

## 4. Active byte budget and upstream transport semantics

### 4.1 Process active byte budget (`src/types.rs`)

- One process-wide `ByteBudget` (default `1 GiB`, configurable in tests) accounts for owned MCP request buffers, decoded request text and keys, retained request identifiers, encoded stdin lines, notification encodings, HTTP SSE priming buffers, and all buffered `stdio` response lines. These leases measure payload allocation capacity, not allocator overhead, `Value` container metadata, or total process RSS.
- Passing a buffer from the `stdio` line reader into downstream HTTP streaming transfers its `ByteLease` in place so one buffer is charged once, while independent concurrent buffers sum against the shared budget.
- Every initial reservation and buffer growth uses non-blocking `try_acquire` / `try_reserve` and charges allocated buffer capacity. When doubling capacity would exceed the available budget, growth reserves only the required capacity. A rejected growth frees its buffer before releasing the old lease and fails immediately, without waiting while holding memory.
- Both MCP ingress paths accumulate request frames in a capacity-leased `Vec` instead of collecting chunks and merging them. HTTP forwarding transfers that allocation into a `Bytes` owner; cloning or slicing it retains the lease until the final user releases it. The existing `16 MiB` limit and `30` second body-read deadline remain; budget rejection returns `503` with `Connection: close`. Empty GET/DELETE bodies need no positive reservation.
- Stdio parsing reserves an additional `3R` bytes for a body of length `R`: decoded text fits in `R`, and the JSON parser's escaped-string scratch has a `2R` growth allowance. The raw body has its own lease and is freed after parsing. The parsed value then retains only its measured string/key capacities. Rewritten values and retained ID/progress-token copies are admitted before cloning; encoding counts the exact JSON length before allocating, including the stdin newline. The stdin queue and writer own the resulting leased `Bytes`, independently of the caller's lifetime.
- Each waiter preallocates a correlated error buffer sized by its encoded client ID plus `256` bytes for the fixed error fields and messages. This buffer also supplies the temporary ID encoding during large-response rewriting. Budget failure can therefore still deliver the original ID without allocating an uncharged replacement. Normal completion or cancellation frees the unused buffer; an error transfers its lease into the downstream frame. Locally generated disconnect/timeout cancellation keeps its existing bounded stdin control path.
- `LeasedFrameCursor` and the HTTP SSE priming filter transfer their buffers and leases into `Bytes` ownership. Output frames share that allocation in slices of at most `64 KiB`; the lease remains charged until the cursor and every returned frame release it. Static SSE prefixes and suffixes use separate frames. A reply is wrapped in this body owner before awaiting child cleanup, so cancellation drops the payload before its lease, including when the cleanup future has not been polled.

Budget tests check the response rewrite with exactly `40,000` bytes available and reject a `40,001`-byte result while retaining the original ID. A separate normal forwarding test includes the concurrent request, retained identifiers, and error workspace in the process pool, checks ID and explicit-null preservation, and requires the final active charge to return to zero.

### 4.2 HTTP upstream (`src/upstream_http.rs`)

- Unauthenticated calls on `<resource_path>` return `401 Unauthorized` with `WWW-Authenticate: Bearer resource_metadata="<public_url>/.well-known/oauth-protected-resource<resource_path>"` and `Connection: close` before reading the body.
- Authorized `<resource_path>` calls read JSON-RPC request bodies up to `16 MiB` (`30` second read timeout) before forwarding, and stream upstream JSON and SSE response bodies without a response size limit. `https://` upstreams enforce `.https_only()` with OS native TLS root certificates.
- Forwarded calls strip hop-by-hop headers, client OAuth `Authorization`, `Origin`, `Cookie`, `Set-Cookie`, upstream `WWW-Authenticate`, and spoofed `X-User-*` headers, inject `Authorization: Bearer <bearer_tokens[grant.pool_slot]>` when pooled tokens are configured, set `X-Forwarded-Proto` from `public_url`, and add `X-Accel-Buffering: no`.
- Session bindings cap at `32` `Mcp-Session-Id` entries per `grant_id` and `4096` across the process. Each `SessionBinding` carries a monotonic `binding_id`, `last_used_seq`, `active_post_streams`, and a per-session `CancellationToken`:
  - Request lookup records `req_binding_id` under the state lock, and response handling checks `binding_id == req_binding_id` so late `404`, `200`, or `DELETE` responses from an evicted or deleted generation never remove, cancel, or stream onto a newly rebound session sharing the same `Mcp-Session-Id`. When request and response headers carry the same session ID, session metadata updates in place without re-running new-session binding.
  - `POST` calls increment `active_post_streams` from pre-flight lookup (or new-session response bind) until `GrantBoundBody` finishes streaming the response, refreshing `last_used_seq` when a `POST` stream completes. Background `GET` SSE listener streams leave `active_post_streams` and `last_used_seq` untouched and select on the per-session `CancellationToken`, closing as soon as the session is evicted, deleted, or revoked.
  - Capacity eviction chooses only among `active_post_streams == 0` bindings with the lowest `last_used_seq`, cancels the victim's session token, and sends an upstream `DELETE`. When every slot at the per-grant or global limit has `active_post_streams > 0`, the gateway preserves running calls, dispatches an upstream `DELETE` to clean up the newly minted `Mcp-Session-Id`, and returns `503 Service Unavailable`.
- On `Content-Type: text/event-stream` responses, `SsePrimingFilterBody` drops leading SSE blocks that contain no `data:` line (such as bare `retry:` directives or comment keepalives), enforcing the `1 MiB` per-stream priming cap and acquiring `ByteBudget` capacity before appending bytes to the priming buffer.
- Grant revocation (`POST /oauth/revoke` or post-grace replay under `"revoke"`) bumps the grant epoch, cancels active response streams for that grant, and sends upstream `DELETE` requests for its bound sessions.
- `passthrough_prefixes` routes reject path traversal (`..`, `\`, NUL bytes, control bytes, and multi-round percent-encoded dot segments), validate `Origin` when present, strip sensitive headers, and stream `GET`, `HEAD`, and `PUT` bodies directly without buffering in memory.

### 4.3 Stdio upstream (`src/upstream_stdio.rs`)

- Spawned children start with `env_clear()`, receiving a minimal OS runtime variable allowlist plus `upstream.env`. On Unix, each child enters a dedicated `setsid` process group; during termination the gateway closes `stdin`, keeps the group leader unreaped via `waitid(..., WNOWAIT)` across `200 ms` grace wait, sends `SIGTERM` (`2 s` wait) and `SIGKILL` to `-pid`, and reaps the leader last so the kernel cannot recycle the PGID mid-signal. On Windows, each child starts with `CREATE_SUSPENDED`, attaches to a Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and only then resumes (compatible with nested jobs without `CREATE_BREAKAWAY_FROM_JOB`). Assignment or resume failures transfer the job, child, and slot into the tracked reaper before awaiting cleanup. Caller cancellation cannot release that slot early, and shutdown waits for pending spawn reservations and reapers.
- In-session `POST <resource_path>` lookup validates `grant_id` and child liveness, updates `(last_client_active_ms, last_client_seq)`, and increments `active_requests` (`ActiveRequestClaim`) atomically under one session table lock, handing that count directly to notification write or `RequestGuard` so concurrent GC never sees `active_requests == 0` mid-dispatch.
- Wire framing rewrites JSON-RPC `id`, cancellation `requestId`, `_meta.relatedRequestId`, and `_meta.progressToken` per call and restores the caller's identifiers on matching notifications and responses. The stdout reader replies to child `ping` requests and returns method-not-found errors for unsupported server-to-client requests so children do not block; client disconnects write `notifications/cancelled` with the mapped wire `requestId` to child `stdin`. A cancellation whose client ID no longer matches an active request is accepted without forwarding, so a late cancellation cannot stop another wire request.
- Sessionless calls carrying `MCP-Protocol-Version: 2026-07-28` or `_meta["io.modelcontextprotocol/protocolVersion"] = "2026-07-28"` without `Mcp-Session-Id` run on an ephemeral initialized child managed by `EphemeralGuard` and reap the child as soon as the response finishes or the caller disconnects. A sessionless notification waits up to `30 s` for its FIFO stdin line to complete `write_all` and `flush`, then reaps the child before returning `202`. This receipt also covers the preceding `notifications/initialized` line; it confirms pipe delivery, not application processing. A failed write or closed receipt returns `502`, and a write timeout returns `504`, after the same tracked cleanup. Queue or byte-budget rejection keeps the existing `503` response. The queued or writing line retains its leased bytes until completion or cancellation.
- Slot accounting maintains `sessions.len() + reserved_slots + terminating_slots <= max_sessions` at all times:
  - `EphemeralGuard` owns the `SlotReservation` from child spawn until table commit; on early exit, SSE stream completion, or caller TCP disconnect, `SlotReservation::into_terminating` atomically shifts the slot from `reserved_slots` to `terminating_slots` and runs process-group termination inside a tracked background task before releasing the slot and waking `slot_notify` waiters.
  - Client idle tracking updates `(last_client_active_ms, last_client_seq)` only on `initialize` table commit, valid in-session requests or notifications, normal request completion, and downstream SSE frame consumption. Unsolicited child `stdout` output and disconnect cancellations do not refresh client activity.
  - `acquire_slot` runs three steps under the session table lock: (1) reserve immediately when `used_slots() < max_sessions`; (2) reap all dead (`!alive`) or `session_idle_secs`-expired idle sessions across all grants, transferring one freed slot directly to the caller and placing any remaining victims in `terminating_slots`; (3) if still full, evict the single session matching the caller's `grant_id` with `alive == true`, `active_requests == 0`, client idle duration `>= pressure_idle` (default `600` seconds, capped by `session_idle_secs`), and minimal `(last_client_active_ms, last_client_seq)`, transferring its slot before reaping outside the lock. If no victim qualifies while `terminating_slots > 0`, the caller waits (up to `INIT_TIMEOUT`) for reaping to free a slot; otherwise admission returns `503 "session limit reached"`.
- Inbound JSON-RPC bodies cap at `16 MiB`. Child `stdout` framing separates control messages from tool responses:
  - Every stdout line reserves capacity before its first append, with the raw buffer and lease in one owner through partial reads, cancellation, parsing, and dispatch. Completed small lines reserve the same `3R` parsing workspace as ingress requests, then retain measured text/key capacity. Child `ping` and method-not-found replies borrow the child ID and count their encoding before allocating; queued lines and pending sends own the resulting leased bytes. Budget rejection uses the existing explicit waiter error and child cleanup path.
  - Lines within `1 MiB` parse normally; per-session queued SSE notification copies share a `4 MiB` budget charged by each copy's allocated string capacity and drop excess notifications when full. Each encoding also owns a process-budget lease. Dequeue adds the SSE prefix and suffix in the same allocation after any required non-blocking growth; its process lease follows the returned frame. Dropping the queue entry releases the separate session-queue charge, so that `4 MiB` queue budget does not cover frames already handed downstream.
  - Lines exceeding `1 MiB` continue buffering up to `512 MiB` only when at least one call is in flight and `ByteBudget` grants a non-blocking lease. A streaming top-level JSON scanner (tracking string escapes and brace depth `1`) locates `"method"` and the exact byte span of top-level `"id"`; completed large responses validate strict JSON syntax via zero-AST `serde::de::IgnoredAny` and splice the client `id` directly into the leased `Vec<u8>`.
  - Any rejection before consuming the line's trailing `\n` (exceeding `512 MiB`, scanning top-level `"method"` past `1 MiB`, output past `1 MiB` with no active request, or exhausting `ByteBudget`) terminates the session and delivers the explicit error status and reason to all waiting JSON and SSE callers. Complete oversized `"method"` lines or unmatched response IDs are discarded in place while keeping the session open.
