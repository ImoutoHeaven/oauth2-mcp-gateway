# oauth2-mcp-gateway 0.1.0 design

## 1. Sidecar boundary and scope

`oauth2-mcp-gateway` is a single-upstream OAuth 2.1 authentication sidecar for Model Context Protocol (MCP) servers. One gateway process binds a local socket behind a reverse proxy (such as Nginx, Traefik, Caddy, Cloudflare Tunnel, or Tailscale Funnel) and stands directly in front of one MCP service.

Responsibilities inside scope:

1. Serve OAuth 2.1 metadata, Dynamic Client Registration (RFC 7591), PKCE S256 authorization code grants, refresh token rotation with a bounded concurrency grace window, and token revocation (RFC 7009).
2. Authenticate inbound `/mcp` requests using opaque Bearer access tokens bound to the configured public resource URL.
3. Forward authenticated MCP traffic to either:
   - an upstream Streamable HTTP MCP server using a credential selected from a configured upstream Bearer token pool, or
   - a per-session isolated `stdio` MCP child process managed by the gateway.
4. Forward configured unauthenticated capability URL prefixes (for example `/t/`) directly to an HTTP upstream as byte streams without buffering bodies in memory.

Responsibilities outside scope:

- TLS termination, ACME certificates, HTTP/2 or HTTP/3 termination, and virtual-host or multi-service path routing. An edge reverse proxy handles these.
- External OIDC federation (Google, GitHub, Okta), multi-user RBAC databases, SQL ORMs, and web activity dashboards.
- MCP tool aggregation, tool name rewriting, or JSON Schema transformation. Upstream JSON-RPC payloads pass through unchanged.

## 2. Configuration contract

The gateway reads one JSON configuration file selected via `--config <path>` (default `gateway.json`). Unknown fields are rejected (`deny_unknown_fields`). String fields equal to `"${VAR}"` expand from the process environment at startup (except `upstream.args`, whose items pass verbatim as command arguments); missing or empty referenced variables fail startup.

Required top-level fields:

- `listen`: local socket address to bind, such as `"127.0.0.1:8080"`.
- `public_url`: canonical external origin without path, query, fragment, or userinfo, such as `"https://mcp.example.com"`. Plain `http://` is accepted only when the host is `localhost`, `127.0.0.1`, or `[::1]`.
- `state_path`: regular file path for persisted OAuth clients and hashed token grants (created with mode `0600`, updated via sibling temporary file `fsync` and atomic `rename`).
- `oauth`: owner credential and token lifetimes.
- `upstream`: tagged union (`"transport": "http"` or `"transport": "stdio"`).

Key `oauth` settings and defaults:

- `owner_password_hash` (PBKDF2-HMAC-SHA256 formatted `pbkdf2-sha256$210000$<salt_b64>$<hash_b64>`) or `owner_password` (plain secret expanded from `"${VAR}"` and hashed into PBKDF2-HMAC-SHA256 in memory at startup; specifying both or an empty secret fails startup).
- `scopes`: supported scope strings, default `["mcp"]`.
- `allowed_redirect_hosts`: optional hostname allowlist for DCR `redirect_uris`. When empty, any `https://` host (without fragment or userinfo) and loopback `http://` hosts are permitted. When non-empty, non-loopback `https://` hosts must match an entry in `allowed_redirect_hosts`.
- `access_token_ttl_secs`: `60..=86400`, default `3600`.
- `refresh_token_ttl_secs`: `300..=7776000`, default `2592000` (30 days).
- `refresh_grace_secs`: `0..=600`, default `120`.
- `max_registered_clients`: `16..=4096`, default `512`.

Key `upstream` settings:

- `http`:
  - `url`: upstream MCP endpoint URL (for example `"http://127.0.0.1:9000/mcp"`).
  - `bearer_tokens`: optional non-empty strings. When non-empty, each OAuth grant pins one slot chosen by least-active-grant count at authorization time, and proxied `/mcp` requests carry `Authorization: Bearer <token>`. When empty, the inbound OAuth `Authorization` header is stripped and no upstream `Authorization` header is sent.
  - `passthrough_prefixes`: optional path prefixes starting and ending with `/` (such as `["/t/"]`, never overlapping `/mcp/`, `/oauth/`, `/.well-known/`, `/healthz/`, or the path of `upstream.url`, matched case-insensitively). Matching paths with no `..`, backslash, NUL, or percent-encoded dot segments stream `GET`, `HEAD`, and `PUT` directly to the upstream origin without OAuth verification.
- `stdio`:
  - `command`: executable path or name.
  - `args`: argument array, default `[]`.
  - `env`: explicit environment overrides, default `{}`.
  - `cwd`: optional working directory.
  - `max_sessions`: `1..=256`, default `32`.
  - `session_idle_secs`: `30..=86400`, default `1800`.

## 3. OAuth 2.1 and client compatibility

The gateway exposes six OAuth routes:

1. `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource/{*path}` (RFC 9728):
   - Root metadata reports `resource: "<public_url>/mcp"` and `authorization_servers: ["<public_url>"]`.
   - Path-scoped metadata `/.well-known/oauth-protected-resource/mcp` reports `resource: "<public_url>/mcp"` so clients that resolve path-relative metadata (including Claude.ai Web) match exact resource identifiers.
2. `GET /.well-known/oauth-authorization-server` and `GET /.well-known/oauth-authorization-server/{*path}` (RFC 8414):
   - Publishes `issuer: "<public_url>"`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `response_types_supported: ["code"]`, `grant_types_supported: ["authorization_code", "refresh_token"]`, `token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"]`, `code_challenge_methods_supported: ["S256"]`, and `authorization_response_iss_parameter_supported: true`.
3. `POST /oauth/register` (RFC 7591):
   - Validates every `redirect_uri`. Rejects relative URLs, fragments, userinfo, non-loopback `http://`, and hosts outside `allowed_redirect_hosts` when configured.
   - Applies RFC 7591 defaults when omitted (`grant_types: ["authorization_code", "refresh_token"]`, `response_types: ["code"]`, `token_endpoint_auth_method: "none"`). Issues a random `client_secret` (storing only its SHA-256 hash) when `token_endpoint_auth_method` is `client_secret_post` or `client_secret_basic`.
   - Evicts the oldest ungranted dynamically registered client when `max_registered_clients` is reached, so unauthenticated registration floods cannot exhaust storage or evict active grants.
4. `GET /oauth/authorize` and `POST /oauth/authorize`:
   - Requires `response_type=code`, registered `client_id`, exact registered `redirect_uri`, `code_challenge_method=S256`, and valid base64url `code_challenge` (43 to 128 ASCII characters) for every client, both public and confidential.
   - Validates optional RFC 8707 `resource`: accepts `<public_url>`, `<public_url>/`, or `<public_url>/mcp`, normalizing to `<public_url>/mcp`; rejects any other target with `invalid_target`.
   - Binds the pending authorization request (`ar_id`, 5 minute TTL, max 256 pending entries) to the browser via an `HttpOnly; SameSite=Lax; Path=/oauth/authorize` CSRF cookie (`Secure` when `public_url` uses `https`) paired with a hidden form field.
   - Rate-limits failed password submissions (max 10 failures per 15 minutes) and verifies the owner password with constant-time comparison.
   - Renders a minimal HTML form with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'` and `X-Frame-Options: DENY`, showing only the client identifier, redirect URI, scopes, password input, and `Authorize` submit action.
   - Redirects `303 See Other` to `redirect_uri` with `code`, `iss=<public_url>` (RFC 9207, checked by ChatGPT and OAuth 2.1 clients), and `state` when supplied.
5. `POST /oauth/token`:
   - `authorization_code`: consumes the single-use code (5 minute TTL), verifies client secret if confidential, verifies exact `redirect_uri` and `resource`, verifies `BASE64URL_NOPAD(SHA256(code_verifier)) == code_challenge`, selects the least-loaded `pool_slot`, persists SHA-256 digests of the new 256-bit `access_token` and `refresh_token`, and returns `Cache-Control: no-store`.
   - `refresh_token`: supports concurrent multi-agent refresh bursts without weakening theft detection:
     - First exchange of refresh token `R0` at time `t0` atomically marks `R0` rotated with `grace_until = min(R0.expires_at, t0 + refresh_grace_secs)`, mints `(A1, R1)` under the same `grant_id` and `pool_slot`, and caches the serialized token response in memory keyed by `hash(R0)` until `grace_until`.
     - Concurrent retries of `R0` before `grace_until` validate client and scope/resource rules and return the cached `(A1, R1)` (or mint a sibling access token within the same grant if the gateway restarted mid-grace, without extending `R0`'s `grace_until` or the grant's refresh ceiling). All concurrent subagents converge on `R1`.
     - Any presentation of `R0` after `grace_until` triggers RFC 9700 reuse detection and revokes the entire `grant_id` (invalidating `A1`, `R1`, and all tokens in that grant).
6. `POST /oauth/revoke` (RFC 7009):
   - Authenticates confidential clients and revokes the matching grant if found, returning `200 OK`.

## 4. Upstream transport semantics

### 4.1 HTTP upstream (`src/upstream_http.rs`)

- Unauthenticated `/mcp` requests receive `401 Unauthorized` with `WWW-Authenticate: Bearer resource_metadata="<public_url>/.well-known/oauth-protected-resource/mcp"` and `Connection: close` before reading the request body.
- Authenticated `/mcp` requests enforce a `16 MiB` JSON-RPC request body limit, remove hop-by-hop headers and incoming `Authorization`, inject `Authorization: Bearer <bearer_tokens[grant.pool_slot]>` (when `bearer_tokens` is non-empty), set `X-Forwarded-Proto` from `public_url`, and stream the upstream response with `X-Accel-Buffering: no`.
- When upstream responds with `Content-Type: text/event-stream`, the stream filter drops leading SSE blocks that contain no `data:` field (such as bare `retry:` or priming comment blocks) before the first JSON-RPC event, preventing Gemini Web connectors from failing on empty initial SSE events. All subsequent frames stream through unchanged.
- Requests matching `passthrough_prefixes` verify path safety (rejecting `..`, `\`, NUL, and percent-encoded dot segments regardless of case), strip any incoming `Authorization`, and stream `GET`, `HEAD`, and `PUT` bodies directly in both directions with no body size cap and no memory buffering.

### 4.2 Stdio upstream (`src/upstream_stdio.rs`)

- Each `initialize` request without `Mcp-Session-Id` spawns an isolated child process in its own Unix process group (`setsid`), forwards `initialize`, returns the upstream response verbatim with a newly generated `Mcp-Session-Id` header, and retains the live child under that session ID.
- Subsequent `POST /mcp` requests carrying `Mcp-Session-Id` route JSON-RPC requests and notifications to that session's child stdin as single-line JSON. While a request is in flight, server-initiated notifications targeting that request (such as `notifications/progress`) and matching JSON-RPC responses stream out as `text/event-stream` `data: <json>\n\n` events (with no empty priming frame). If the HTTP client disconnects before the response arrives, the gateway writes `notifications/cancelled` for that request ID to the child.
- Inline sessionless requests carrying `_meta["io.modelcontextprotocol/protocolVersion"]` (MCP `2026-07-28`) without `Mcp-Session-Id` run against an ephemeral initialized child process and close it after the response completes.
- `DELETE /mcp` with `Mcp-Session-Id`, idle session expiry (`session_idle_secs`), or gateway shutdown closes child stdin, sends `SIGTERM` to the child's process group after `200 ms`, escalates to `SIGKILL` after `2 s`, and reaps the child.
