# oauth2-mcp-gateway 0.1.0 design

## 1. Sidecar boundary and scope

`oauth2-mcp-gateway` is a single-upstream OAuth 2.1 authentication sidecar for Model Context Protocol (MCP) servers. One gateway process binds a local socket behind an edge reverse proxy or tunnel (Nginx, Traefik, Caddy, Cloudflare Tunnel, or Tailscale Funnel) and fronts one MCP service.

In scope:

1. Serve OAuth 2.1 discovery metadata, Dynamic Client Registration (RFC 7591), PKCE `S256` authorization code grants, single-tip generation-tracked refresh token rotation, and authenticated token revocation (RFC 7009).
2. Validate `Host` and normalized `Origin` headers, and authenticate inbound requests on `<resource_path>` (default `/mcp`) using opaque Bearer access tokens bound to `<public_url><resource_path>`.
3. Bridge authenticated MCP traffic to an upstream Streamable HTTP MCP endpoint (with optional static Bearer token pooling and per-grant session binding) or to isolated per-session `stdio` child processes.
4. Stream configured unauthenticated capability URL prefixes (such as `/t/`) directly to an HTTP upstream origin without buffering bodies in memory.

Outside scope:

- TLS termination, ACME certificate management, HTTP/2 or HTTP/3 edge listeners, and multi-service virtual-host routing. An edge reverse proxy or tunnel handles these layers.
- External OIDC federation, multi-user RBAC databases, SQL storage engines, and web administration consoles.
- MCP tool filtering, tool name rewriting, or JSON Schema modification. Tool schemas and tool arguments pass through unchanged.

## 2. Configuration and state persistence

The gateway loads one JSON configuration file (maximum 1 MiB) from `--config <path>` or `OAUTH2_MCP_GATEWAY_CONFIG` (default `gateway.json`). Startup rejects unknown fields (`deny_unknown_fields`). String fields equal to `"${VAR}"` expand from the process environment at startup, except entries in `upstream.args`, which pass verbatim as child command arguments. Partial interpolation such as `"prefix-${VAR}"` and missing or empty referenced variables fail startup.

Top-level fields:

- `listen`: local socket address to bind, such as `"127.0.0.1:8080"`.
- `public_url`: canonical external origin without path, query, fragment, or userinfo, such as `"https://mcp.example.com"`. Plain `http://` is permitted only when the host is `localhost`, `127.0.0.1`, or `[::1]`.
- `resource_path`: optional public MCP path, default `"/mcp"`. The gateway serves `<resource_path>` directly, so a reverse proxy using `location / { proxy_pass http://127.0.0.1:8080; }` forwards `<resource_path>`, `/.well-known/*`, `/oauth/*`, and `passthrough_prefixes` without URL rewriting.
- `state_path`: regular file path for persisted OAuth clients and hashed token grants (`state.json`). Relative paths resolve against the configuration file directory. On Unix, the gateway creates missing parent directories with mode `0700` and enforces mode `0600` on `state.json` using a sibling temporary file, `fsync`, and atomic `rename`.
- `oauth`: owner credential and token lifetime configuration.
- `upstream`: tagged union (`"transport": "http"` or `"transport": "stdio"`).

`oauth` settings and defaults:

- `owner_password_hash` (`pbkdf2-sha256$<iterations>$<salt_b64>$<hash_b64>`, `600000` default iterations from `hash-password`, `10000..=5000000` accepted) or `owner_password` (plaintext secret expanded from `"${VAR}"` and hashed in memory at startup with `PBKDF2-HMAC-SHA256` at `600000` iterations). Specifying both, neither, or an empty secret fails startup.
- `scopes`: allowed RFC 6749 scope tokens, default `["mcp"]`.
- `allowed_redirect_hosts`: optional hostname allowlist for DCR `redirect_uris`. Loopback `http://` hosts remain permitted; when non-empty, `https://` hosts must match an IDNA-normalized entry in `allowed_redirect_hosts`. Wildcards are rejected.
- `access_token_ttl_secs`: `60..=86400`, default `3600`.
- `refresh_token_ttl_secs`: `300..=7776000`, default `2592000` (30 days), at least `access_token_ttl_secs`.
- `max_grant_lifetime_secs`: total sliding refresh lifetime ceiling per grant measured from initial authorization, default `3 * refresh_token_ttl_secs`, capped at `31536000` (365 days) and at least `refresh_token_ttl_secs`.
- `refresh_grace_secs`: `0..=86400` and `<= refresh_token_ttl_secs`, default `min(access_token_ttl_secs, refresh_token_ttl_secs)` (`3600` seconds by default, synced with `access_token_ttl_secs`).
- `refresh_reuse_policy`: `"converge"` (default) or `"revoke"`.
- `max_registered_clients`: `16..=4096`, default `512`.

`upstream` settings:

- `http`:
  - `url`: upstream MCP endpoint URL (`http://` or `https://`, without userinfo, query, or fragment).
  - `bearer_tokens`: optional pool of non-empty ASCII Bearer tokens. When non-empty, each OAuth grant pins the least-loaded slot at authorization time and sends `Authorization: Bearer <token>` on proxied MCP calls. When empty, the inbound OAuth `Authorization` header is stripped and no upstream `Authorization` header is sent.
  - `passthrough_prefixes`: optional path prefixes starting and ending with `/` (such as `["/t/"]`). Prefixes cannot overlap `<resource_path>`, `/oauth/`, `/.well-known/`, `/healthz/`, or the path of `upstream.url` (matched case-insensitively).
  - `request_timeout_secs`: `5..=3600`, default `300`.
- `stdio`:
  - `command`: executable path or name.
  - `args`: argument list passed verbatim, default `[]`.
  - `env`: explicit child environment variables, default `{}`.
  - `cwd`: optional child working directory.
  - `max_sessions`: `1..=256`, default `32`.
  - `session_idle_secs`: `30..=86400`, default `1800`.

## 3. Request guards, OAuth 2.1, and single-tip refresh rotation

### 3.1 Host, Origin, and CORS discovery guards

- `Host` header validation verifies incoming `Host` authorities and blocks DNS rebinding requests targeting loopback `http://` deployments.
- `Origin` validation compares normalized `Origin` headers against `public_url` across `<resource_path>`, `/oauth/*`, and `passthrough_prefixes`, returning `403 Forbidden` on mismatches while permitting non-browser clients that omit `Origin`.
- `/.well-known/*` routes answer `GET` and `OPTIONS` with read-only CORS headers so browser-based MCP clients can discover OAuth metadata before authorization.

### 3.2 OAuth 2.1 endpoints (`src/oauth.rs`)

1. `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource<resource_path>` (RFC 9728):
   - Both routes advertise `resource: "<public_url><resource_path>"` and `authorization_servers: ["<public_url>"]` so clients resolving either root or path-scoped metadata match exact resource URIs.
2. `GET /.well-known/oauth-authorization-server` and `GET /.well-known/oauth-authorization-server<resource_path>` (RFC 8414):
   - Publish `issuer: "<public_url>"`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `response_types_supported: ["code"]`, `response_modes_supported: ["query"]`, `grant_types_supported: ["authorization_code", "refresh_token"]`, `token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"]`, `code_challenge_methods_supported: ["S256"]`, and `authorization_response_iss_parameter_supported: true`. Unconfigured subpaths return `404`.
3. `POST /oauth/register` (RFC 7591):
   - Validates each `redirect_uri` (rejecting relative URLs, fragments, userinfo, reserved OAuth response query parameters, non-loopback `http://`, and hosts outside `allowed_redirect_hosts`).
   - Applies RFC 7591 defaults (`grant_types: ["authorization_code", "refresh_token"]`, `response_types: ["code"]`, `token_endpoint_auth_method: "none"`), mints a secret for confidential clients (persisting only its SHA-256 digest), and evicts only the oldest client with no active grants, pending logins, or authorization codes when `max_registered_clients` is full.
4. `GET /oauth/authorize` and `POST /oauth/authorize`:
   - Require `response_type=code`, a registered `client_id`, an exact registered `redirect_uri`, and PKCE `S256` (`code_challenge` of 43 base64url characters, decoding to a 32-byte SHA-256 digest) for every client.
   - Normalize optional RFC 8707 `resource` values (`<public_url>`, `<public_url>/`, or `<public_url><resource_path>`) to `<public_url><resource_path>`, rejecting any other target with `invalid_target`.
   - Bind each pending login form (`5` minute TTL, up to `512` pending sessions total and `32` per client IP) to the browser using an `HttpOnly; SameSite=Lax` CSRF cookie: `__Host-mcp_ar_<id>` (`Secure; Path=/`) when `public_url` uses `https://`, or `mcp_ar_<id>` (`Path=/oauth/authorize`) on loopback `http://`.
   - Render a self-contained login form with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'` and `X-Frame-Options: DENY`. The form displays client identity, callback URI, and requested scopes, provides both `Authorize` and `Cancel`/`Deny` (`error=access_denied`), caps password retries at 3 per form session, and rate-limits password failures per client IP using constant-time PBKDF2 verification.
   - Issue a single-use authorization code (`5` minute TTL) and return `code`, `iss=<public_url>` (RFC 9207), and optional `state` to the callback.
5. `POST /oauth/token`:
   - `authorization_code`: consumes the single-use code, authenticates confidential clients, checks `redirect_uri`, `resource`, and `BASE64URL_NOPAD(SHA256(code_verifier)) == code_challenge`, assigns the least-loaded `pool_slot`, records the grant creation timestamp for `max_grant_lifetime_secs`, persists SHA-256 digests of the initial access token and generation-0 refresh token, and responds with `Cache-Control: no-store`.
   - `refresh_token`: implements single-tip generation-tracked rotation using structured tokens (`rt1.<grant_id>.<gen>.<nonce>.<tag>`):
     - Rotating the active tip generation `G` advances the grant to `G + 1`, bounds expiry by both `refresh_token_ttl_secs` and the grant's `max_grant_lifetime_secs` deadline, persists SHA-256 digests of the active `G + 1` token and (during `refresh_grace_secs`) the grace `G` token in `state.json`, and caches the current tip token response in process memory until `grace_until`.
     - Concurrent subagents presenting the grace token within `refresh_grace_secs` validate client credentials, resource, and scope, then receive the current tip response from memory so parallel callers converge on the latest tip even across multi-hop refreshes.
     - Presenting a valid family refresh token from an older generation after `refresh_grace_secs` expires follows `refresh_reuse_policy`: `"converge"` (default) verifies client credentials, resource, HMAC family tag, and active grant lifetime, then returns the live tip response (or rotates the tip if memory cache is absent or expired) so paused parent or child MCP agents resume without tearing down sibling sessions; `"revoke"` triggers strict RFC 9700 reuse detection, revokes the entire `grant_id`, and terminates all bound HTTP and `stdio` sessions.
6. `POST /oauth/revoke` (RFC 7009):
   - Requires client authentication (`client_id` matching the grant for public clients, or `client_secret_basic` / `client_secret_post` for confidential clients), revokes the owning grant when present, terminates all bound HTTP and `stdio` sessions, and returns `200 OK`.

OAuth `POST` endpoints enforce a `64 KiB` body limit and a `10` second read deadline. Changing `public_url` or `resource_path` invalidates existing resource-bound grants and requires re-authorization.

## 4. Upstream transport semantics

### 4.1 HTTP upstream (`src/upstream_http.rs`)

- Unauthenticated requests on `<resource_path>` receive `401 Unauthorized` with `WWW-Authenticate: Bearer resource_metadata="<public_url>/.well-known/oauth-protected-resource<resource_path>"` and `Connection: close` before reading the request body.
- Authenticated `<resource_path>` requests buffer JSON-RPC bodies up to `16 MiB` in full before forwarding upstream. When `upstream.url` uses `https://`, the connector enforces `.https_only()` verified against OS native TLS root certificates.
- The bridge binds upstream `Mcp-Session-Id` values to the caller's OAuth `grant_id` and rejects cross-grant session access. Forwarded requests and responses strip hop-by-hop headers, client OAuth `Authorization`, `Origin`, `Cookie`, `Set-Cookie`, upstream `WWW-Authenticate`, and spoofed `X-User-*` headers, inject `Authorization: Bearer <bearer_tokens[grant.pool_slot]>` when `bearer_tokens` is non-empty, set `X-Forwarded-Proto` from `public_url`, and add `X-Accel-Buffering: no`.
- On `Content-Type: text/event-stream` responses, the stream filter drops leading SSE blocks that carry no `data:` field (such as bare `retry:` lines or comment keepalives) before forwarding the event stream.
- When a grant is revoked (by `POST /oauth/revoke` or refresh reuse detection), `HttpUpstream` cancels active response streams for that grant and dispatches upstream `DELETE` requests for its bound `Mcp-Session-Id` sessions.
- Requests matching `passthrough_prefixes` reject path traversal (`..`, `\`, NUL bytes, and percent-encoded dot segments), enforce normalized `Origin` validation when `Origin` is present, strip `Authorization`, `Origin`, `Cookie`, `Set-Cookie`, and `X-User-*` headers, and stream `GET`, `HEAD`, and `PUT` bodies directly in both directions without buffering in memory.

### 4.2 Stdio upstream (`src/upstream_stdio.rs`)

- Every spawned child starts with `env_clear()`, receiving only minimal OS runtime variables alongside explicit `upstream.env` entries.
- On `initialize` without `Mcp-Session-Id`, the gateway spawns a dedicated child process, assigns it to a fresh `setsid` process group on Unix or a mandatory Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` on Windows (working as a nested Job Object without `CREATE_BREAKAWAY_FROM_JOB`), forwards `initialize`, and binds the returned `Mcp-Session-Id` to the caller's `grant_id`.
- Subsequent `POST <resource_path>` calls rewrite JSON-RPC `id`, cancellation `requestId`, `_meta.relatedRequestId`, and `_meta.progressToken` per wire request so concurrent calls on one session cannot collide, then restore the caller's identifiers on matching `text/event-stream` notifications and responses while leaving tool schemas and payloads untouched.
- The stdout reader answers child-initiated `ping` requests directly and returns JSON-RPC method-not-found errors for unsupported server-to-client requests so children never block waiting for a client reply. If an HTTP caller disconnects before its response arrives, the gateway writes `notifications/cancelled` with the mapped wire `requestId` to child stdin.
- Sessionless requests carrying `MCP-Protocol-Version: 2026-07-28` or `_meta["io.modelcontextprotocol/protocolVersion"] = "2026-07-28"` without `Mcp-Session-Id` run on an ephemeral initialized child process, stream SSE events as they arrive, and terminate the child when the response finishes.
- `DELETE <resource_path>`, grant revocation, idle expiry (`session_idle_secs`), or gateway shutdown immediately terminates bound stateful, initializing, and sessionless children. On Unix, the gateway keeps child group leaders unreaped via `waitid(..., WNOWAIT)` while signaling the process group (`SIGTERM` after stdin close, escalating to `SIGKILL`) and reaps the leader only after group termination completes; on Windows, closing the Job Object terminates the entire child process tree.
