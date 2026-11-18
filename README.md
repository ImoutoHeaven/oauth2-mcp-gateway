# oauth2-mcp-gateway

`oauth2-mcp-gateway` is a single-binary OAuth 2.1 sidecar for one Model Context Protocol (MCP) server. It runs on a local socket behind your reverse proxy (Nginx, Traefik, Caddy, or Cloudflare Tunnel), authenticates remote MCP clients with self-hosted OAuth 2.1, and bridges authorized `/mcp` requests to either an upstream Streamable HTTP MCP endpoint or isolated `stdio` child processes.

## Scope and boundaries

One gateway process sits in front of one upstream MCP service:

- Handles OAuth 2.1 discovery metadata, Dynamic Client Registration (RFC 7591), PKCE `S256` authorization code grants, refresh token rotation, and token revocation (RFC 7009).
- Verifies Bearer access tokens on `/mcp` and binds each grant to the configured public resource URL (`<public_url>/mcp`).
- Bridges `/mcp` traffic to an upstream HTTP MCP server (with optional static Bearer token pooling and unauthenticated byte-stream passthrough prefixes such as `/t/`) or to per-session `stdio` MCP subprocesses.

Out of scope by design:

- No TLS or ACME certificate termination. Terminate HTTPS at your reverse proxy or tunnel.
- No multi-domain or multi-path routing across multiple MCP backends. Run one sidecar per upstream MCP service.
- No web dashboard, external OIDC login provider, or SQL database. State lives in one `0600` JSON file updated via `fsync` and atomic rename.
- No MCP tool filtering, tool renaming, or JSON Schema rewriting. JSON-RPC payloads pass through untouched.

## Quick start

### 1. Build the binary and hash an owner password

Requires Rust 1.92 or newer:

```bash
cargo build --release
printf '%s\n' 'replace-with-a-long-owner-password' \
  | ./target/release/oauth2-mcp-gateway hash-password
```

`hash-password` reads one password from `stdin` and prints a `pbkdf2-sha256$210000$<salt>$<digest>` verifier string.

### 2. Write and validate the configuration

Copy [`examples/gateway-http.json`](examples/gateway-http.json) or [`examples/gateway-stdio.json`](examples/gateway-stdio.json) to `gateway.json`, export the referenced secrets, and run `check`:

```bash
export OWNER_PASSWORD_HASH='pbkdf2-sha256$210000$...'
export UPSTREAM_BEARER_TOKEN_1='upstream-token-a'
export UPSTREAM_BEARER_TOKEN_2='upstream-token-b'

./target/release/oauth2-mcp-gateway check --config gateway.json
```

### 3. Start the sidecar

```bash
./target/release/oauth2-mcp-gateway serve --config gateway.json
```

`OAUTH2_MCP_GATEWAY_CONFIG` sets the default `--config` path when the flag is omitted. `SIGINT` and `SIGTERM` drain active HTTP connections and terminate managed `stdio` process groups before exit.

## Configuration

Unknown JSON fields fail startup. Any string field set to `"${VAR}"` (except entries in `upstream.args`, which pass verbatim to the child command) expands from the process environment at startup. Partial string interpolation such as `"prefix-${VAR}"` is rejected, and missing or empty referenced variables fail startup.

### Top-level fields

| Field | Required | Description |
| :--- | :--- | :--- |
| `listen` | yes | Local `IP:PORT` socket address to bind, such as `"127.0.0.1:8080"`. |
| `public_url` | yes | External origin without path, query, fragment, or userinfo, such as `"https://mcp.example.com"`. Plain `http://` is allowed only on `localhost`, `127.0.0.1`, and `[::1]`. |
| `state_path` | yes | File path for persisted OAuth clients and hashed token grants. Created with mode `0600`. |
| `oauth` | yes | OAuth 2.1 owner credential and token lifetime settings. |
| `upstream` | yes | Upstream MCP bridge configuration (`"transport": "http"` or `"transport": "stdio"`). |

### `oauth` fields

Provide either `owner_password_hash` or `owner_password`. Setting both fails startup.

| Field | Default | Description |
| :--- | :--- | :--- |
| `owner_password_hash` | none | Output of `hash-password` (`pbkdf2-sha256$<iter>$<salt>$<hash>`). |
| `owner_password` | none | Plaintext secret (typically `"${OWNER_PASSWORD}"`), hashed with PBKDF2-HMAC-SHA256 in memory at startup. |
| `scopes` | `["mcp"]` | Non-empty list of whitespace-free OAuth scope tokens. |
| `allowed_redirect_hosts` | `[]` | Optional hostname allowlist for Dynamic Client Registration `redirect_uris`. Loopback `http://` callbacks remain allowed; when non-empty, `https://` callbacks must match a listed host. Wildcards are rejected. |
| `access_token_ttl_secs` | `3600` | Access token lifetime in seconds (`60..=86400`). |
| `refresh_token_ttl_secs` | `2592000` | Refresh token lifetime in seconds (`300..=7776000`, at least `access_token_ttl_secs`). |
| `refresh_grace_secs` | `120` | Concurrency grace window in seconds (`0..=600`) for parallel refresh requests using a rotated refresh token. |
| `max_registered_clients` | `512` | Maximum stored DCR clients (`16..=4096`). Unauthenticated registrations at capacity evict only the oldest client that has no active grants. |

### `upstream` fields (`"transport": "http"`)

| Field | Default | Description |
| :--- | :--- | :--- |
| `url` | required | Upstream Streamable HTTP MCP endpoint URL, such as `"http://127.0.0.1:9000/mcp"`. |
| `bearer_tokens` | `[]` | Static upstream Bearer token pool. When non-empty, each OAuth grant pins the least-loaded slot at authorization time and sends `Authorization: Bearer <token>` upstream. When empty, the client OAuth `Authorization` header is stripped and no upstream `Authorization` header is added. |
| `passthrough_prefixes` | `[]` | Unauthenticated capability prefixes starting and ending with `/`, such as `["/t/"]`. Must not overlap `/mcp/`, `/oauth/`, `/.well-known/`, `/healthz/`, or the path of `upstream.url`. Streams `GET`, `HEAD`, and `PUT` bodies directly to the upstream origin without buffering in memory. |
| `request_timeout_secs` | `300` | Upstream response header timeout in seconds (`5..=3600`). |

### `upstream` fields (`"transport": "stdio"`)

| Field | Default | Description |
| :--- | :--- | :--- |
| `command` | required | Executable name or path for the `stdio` MCP server. |
| `args` | `[]` | Command arguments passed verbatim without environment expansion. |
| `env` | `{}` | Environment overrides passed to the child process (values support `"${VAR}"`). |
| `cwd` | none | Optional working directory for the child process. |
| `max_sessions` | `32` | Maximum concurrent `stdio` sessions (`1..=256`). Returns `503` when full. |
| `session_idle_secs` | `1800` | Idle timeout in seconds (`30..=86400`) before an inactive session process group is terminated. |

## Nginx reverse proxy example

Disable proxy response buffering so Server-Sent Events (`text/event-stream`) and passthrough transfers stream immediately, and forward the external scheme in `X-Forwarded-Proto`:

```nginx
server {
    listen 443 ssl http2;
    server_name mcp.example.com;

    ssl_certificate     /etc/letsencrypt/live/mcp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp.example.com/privkey.pem;

    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

## Protocol behavior

### OAuth 2.1 endpoints

- `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource/mcp` (RFC 9728): advertise `resource: "<public_url>/mcp"` and `authorization_servers: ["<public_url>"]`. Unauthenticated `/mcp` requests return `401` with `WWW-Authenticate: Bearer resource_metadata="<public_url>/.well-known/oauth-protected-resource/mcp"`.
- `GET /.well-known/oauth-authorization-server` (RFC 8414): advertises endpoints, `code_challenge_methods_supported: ["S256"]`, and `authorization_response_iss_parameter_supported: true`.
- `POST /oauth/register` (RFC 7591): registers public (`none`) or confidential (`client_secret_post`, `client_secret_basic`) clients. Client secrets and issued tokens are stored only as SHA-256 digests.
- `GET /oauth/authorize` and `POST /oauth/authorize`: enforces PKCE `S256` for all clients, binds the login form with an `HttpOnly; SameSite=Lax` `mcp_ar_<id>` CSRF cookie and strict `Content-Security-Policy`, throttles failed password attempts (10 failures per 15 minutes), and redirects `303 See Other` with `code`, `iss` (RFC 9207), and `state`.
- `POST /oauth/token`: exchanges single-use authorization codes and rotates refresh tokens. During `refresh_grace_secs` after a refresh token `R0` rotates to `(A1, R1)`, concurrent refresh requests presenting `R0` receive the same `(A1, R1)` response so parallel subagents converge on `R1`. Presenting `R0` after `refresh_grace_secs` expires triggers RFC 9700 reuse detection and revokes the entire grant.
- `POST /oauth/revoke` (RFC 7009): revokes the grant owning the submitted access or refresh token.
- `GET /healthz`: unauthenticated liveness check returning `{"ok":true}`.

### MCP Streamable HTTP bridging

- HTTP upstream mode enforces a `16 MiB` limit on `/mcp` JSON-RPC request bodies, strips hop-by-hop headers and client OAuth tokens, sets `X-Accel-Buffering: no`, and strips leading `text/event-stream` blocks that carry no `data:` line (such as bare `retry:` or comment keepalives) before forwarding the event stream. Requests matching `passthrough_prefixes` reject path traversal (`..`, backslashes, NUL bytes, and percent-encoded dot segments) and stream `GET`, `HEAD`, and `PUT` without body size limits.
- Stdio upstream mode spawns a dedicated child process in its own Unix process group (`setsid`) on `initialize`, returns a `Mcp-Session-Id` bound to the caller's OAuth `grant_id`, and rejects cross-grant `POST` or `DELETE` attempts on that session ID with `404`. In-flight `POST /mcp` calls stream matching `notifications/progress` events and the final JSON-RPC response as `text/event-stream` without empty priming frames, and send `notifications/cancelled` to the child if the HTTP client disconnects early. Inline sessionless requests carrying `MCP-Protocol-Version: 2026-07-28` or `_meta["io.modelcontextprotocol/protocolVersion"] = "2026-07-28"` run on an ephemeral initialized subprocess that is reaped immediately after the response completes.

## License

Apache-2.0. See [LICENSE](LICENSE).
