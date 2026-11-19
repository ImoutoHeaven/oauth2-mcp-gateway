# oauth2-mcp-gateway

`oauth2-mcp-gateway` is a single-binary OAuth 2.1 authentication sidecar for one Model Context Protocol (MCP) server. It binds a local socket behind a reverse proxy or tunnel (Nginx, Traefik, Caddy, Cloudflare Tunnel, or Tailscale Funnel), authenticates remote MCP clients with self-hosted OAuth 2.1, and bridges authorized requests on `<resource_path>` (default `/mcp`) to an upstream Streamable HTTP MCP endpoint or isolated `stdio` child processes.

## Scope and boundaries

One gateway process sits in front of one upstream MCP service:

- Serves OAuth 2.1 discovery metadata, Dynamic Client Registration (RFC 7591), PKCE `S256` authorization code grants, single-tip generation-tracked refresh token rotation, and authenticated token revocation (RFC 7009).
- Verifies Bearer access tokens on `<resource_path>`, validates `Host` and normalized `Origin` headers, and binds every grant to `<public_url><resource_path>`.
- Bridges `<resource_path>` traffic to an upstream HTTP MCP server (with optional static Bearer token pooling, per-grant session binding, and unauthenticated byte-stream passthrough prefixes such as `/t/`) or to isolated per-session `stdio` MCP subprocesses.

Outside scope:

- TLS or ACME certificate termination. Terminate HTTPS at your reverse proxy or tunnel.
- Multi-domain or multi-backend routing across separate MCP services. Run one sidecar per upstream MCP service.
- Web dashboards, external OIDC identity providers, or SQL databases. Persisted state lives in one JSON file (`0600` in a `0700` directory on Unix) written via `fsync` and atomic rename.
- MCP tool filtering, tool renaming, or JSON Schema transformation. Tool schemas and arguments pass through unchanged.

## Quick start

### 1. Build the binary and hash an owner password

Requires Rust 1.92 or newer. Windows MSVC builds link the C runtime statically (`+crt-static`), so `oauth2-mcp-gateway.exe` runs without installing the Visual C++ Redistributable.

```bash
cargo build --release
printf '%s\n' 'replace-with-a-long-owner-password' \
  | ./target/release/oauth2-mcp-gateway hash-password
```

`hash-password` reads one UTF-8 password (up to 4096 bytes) from `stdin` and prints a `pbkdf2-sha256$600000$<salt>$<digest>` verifier string.

### 2. Write and validate the configuration

Copy [`examples/gateway-http.json`](examples/gateway-http.json) or [`examples/gateway-stdio.json`](examples/gateway-stdio.json) to `gateway.json`, export the referenced secrets, and run `check`:

```bash
export OWNER_PASSWORD_HASH='pbkdf2-sha256$600000$...'
export UPSTREAM_BEARER_TOKEN_1='upstream-token-a'
export UPSTREAM_BEARER_TOKEN_2='upstream-token-b'

./target/release/oauth2-mcp-gateway check --config gateway.json
```

### 3. Start the sidecar

```bash
./target/release/oauth2-mcp-gateway serve --config gateway.json
```

`OAUTH2_MCP_GATEWAY_CONFIG` sets the default `--config` path when the flag is omitted. `SIGINT` (and `SIGTERM` on Unix) drains active HTTP connections and terminates managed `stdio` child process trees before exit.

## Configuration

Startup rejects unknown JSON fields and configuration files larger than 1 MiB. Any string field equal to `"${VAR}"` expands from the process environment at startup, except entries in `upstream.args`, which pass verbatim to the child command. Partial string interpolation such as `"prefix-${VAR}"` is rejected, and unset or empty referenced variables fail startup.

### Top-level fields

| Field | Required | Description |
| :--- | :--- | :--- |
| `listen` | yes | Local `IP:PORT` socket address to bind, such as `"127.0.0.1:8080"`. |
| `public_url` | yes | External origin without path, query, fragment, or userinfo, such as `"https://mcp.example.com"`. Plain `http://` is permitted only on `localhost`, `127.0.0.1`, and `[::1]`. |
| `resource_path` | no | Public MCP route served directly by the gateway. Defaults to `"/mcp"`. Must start with `/` and use nonempty segments of ASCII letters, digits, or `-._~` without `.` or `..` segments, and cannot overlap `/oauth/`, `/.well-known/`, `/healthz/`, or any `passthrough_prefixes`. |
| `state_path` | yes | File path for persisted OAuth clients and hashed token grants. On Unix, the gateway creates missing parent directories with mode `0700` and enforces mode `0600` on `state.json`. |
| `oauth` | yes | OAuth 2.1 owner credential and token lifetime settings. |
| `upstream` | yes | Upstream MCP bridge configuration (`"transport": "http"` or `"transport": "stdio"`). |

### `oauth` fields

Set either `owner_password_hash` or `owner_password`. Providing both or neither fails startup.

| Field | Default | Description |
| :--- | :--- | :--- |
| `owner_password_hash` | none | Output of `hash-password` (`pbkdf2-sha256$<iter>$<salt>$<digest>`, `600000` iterations by default, `10000..=5000000` accepted). |
| `owner_password` | none | Plaintext secret (typically `"${OWNER_PASSWORD}"`), hashed with `PBKDF2-HMAC-SHA256` (`600000` iterations) in memory at startup. |
| `scopes` | `["mcp"]` | Non-empty list of whitespace-free RFC 6749 scope tokens. |
| `allowed_redirect_hosts` | `[]` | Optional hostname allowlist for Dynamic Client Registration `redirect_uris`. Loopback `http://` callbacks remain allowed; when non-empty, `https://` callbacks must match a listed host. Wildcards and callback query keys reserved by OAuth responses are rejected. |
| `access_token_ttl_secs` | `3600` | Access token lifetime in seconds (`60..=86400`). |
| `refresh_token_ttl_secs` | `2592000` | Single refresh token lifetime in seconds (`300..=7776000`, at least `access_token_ttl_secs`). |
| `max_grant_lifetime_secs` | `3x refresh_token_ttl_secs` | Maximum cumulative sliding refresh lifetime for a grant from initial authorization, capped at 365 days (`31536000` seconds, at least `refresh_token_ttl_secs`). |
| `refresh_grace_secs` | `access_token_ttl_secs` (`3600`) | Concurrency grace window in seconds (`0..=86400`, `<= refresh_token_ttl_secs`) synced by default with `access_token_ttl_secs` so parallel or resumed subagents presenting a rotated token converge on the current tip. |
| `refresh_reuse_policy` | `"converge"` | Controls stale same-client refresh tokens presented after `refresh_grace_secs`: `"converge"` (default) converges any authenticated family token to the active tip until explicit revocation or `max_grant_lifetime_secs`; `"revoke"` enforces strict RFC 9700 grant revocation on post-grace replay. |
| `max_registered_clients` | `512` | Maximum stored DCR clients (`16..=4096`). Unauthenticated registrations at capacity evict only the oldest client with no active grants, pending logins, or authorization codes. |

### `upstream` fields (`"transport": "http"`)

| Field | Default | Description |
| :--- | :--- | :--- |
| `url` | required | Upstream Streamable HTTP MCP endpoint URL (`http://` or `https://`), such as `"http://127.0.0.1:9000/mcp"`. `https://` upstreams enforce TLS with OS native root certificates. |
| `bearer_tokens` | `[]` | Static upstream Bearer token pool. When non-empty, each OAuth grant pins the least-loaded slot at authorization time and sends `Authorization: Bearer <token>` upstream. When empty, the inbound OAuth `Authorization` header is stripped and no upstream `Authorization` header is added. |
| `passthrough_prefixes` | `[]` | Unauthenticated capability prefixes starting and ending with `/`, such as `["/t/"]`. Cannot overlap `<resource_path>`, `/oauth/`, `/.well-known/`, `/healthz/`, or the path of `upstream.url`. Streams `GET`, `HEAD`, and `PUT` bodies directly to the upstream origin without buffering in memory. |
| `request_timeout_secs` | `300` | Upstream response header timeout in seconds (`5..=3600`). |

### `upstream` fields (`"transport": "stdio"`)

| Field | Default | Description |
| :--- | :--- | :--- |
| `command` | required | Executable name or path for the `stdio` MCP server. |
| `args` | `[]` | Command arguments passed verbatim without environment expansion. |
| `env` | `{}` | Explicit environment variables passed to the child process (values support `"${VAR}"`). Host environment variables are cleared (`env_clear()`), forwarding only minimal OS runtime variables plus `upstream.env`. |
| `cwd` | none | Optional working directory for the child process. |
| `max_sessions` | `32` | Maximum concurrent `stdio` sessions (`1..=256`). Returns `503` when full. |
| `session_idle_secs` | `1800` | Idle timeout in seconds (`30..=86400`) before an inactive session process tree is terminated. |

## Nginx reverse proxy

Disable proxy response buffering so Server-Sent Events (`text/event-stream`) and passthrough transfers stream without edge delay:

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

The gateway serves custom `resource_path` values directly on `<resource_path>`, so the same `location / { proxy_pass http://127.0.0.1:8080; }` block forwards `<resource_path>`, `/.well-known/*`, `/oauth/*`, and any `passthrough_prefixes` without path rewrites. Changing `public_url` or `resource_path` invalidates existing resource-bound grants and requires clients to authorize again.

## Protocol behavior

### Request guards and CORS discovery

- `Host` validation checks incoming `Host` headers and blocks DNS rebinding attempts against loopback `http://` listeners.
- `Origin` validation checks normalized browser `Origin` headers against `public_url` across `<resource_path>`, `/oauth/*`, and `passthrough_prefixes`, rejecting mismatched origins with `403 Forbidden`. Non-browser clients that omit `Origin` are permitted.
- `/.well-known/*` endpoints support read-only CORS discovery (`GET` and `OPTIONS`) for browser-based MCP clients.

### OAuth 2.1 endpoints

- `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource<resource_path>` (RFC 9728) publish `resource: "<public_url><resource_path>"` and `authorization_servers: ["<public_url>"]`. Unauthenticated requests on `<resource_path>` return `401` with `WWW-Authenticate: Bearer resource_metadata="<public_url>/.well-known/oauth-protected-resource<resource_path>"`.
- `GET /.well-known/oauth-authorization-server` and `GET /.well-known/oauth-authorization-server<resource_path>` (RFC 8414) publish endpoint URLs, `code_challenge_methods_supported: ["S256"]`, and `authorization_response_iss_parameter_supported: true`.
- `POST /oauth/register` (RFC 7591) registers public (`none`) and confidential (`client_secret_post`, `client_secret_basic`) clients, storing confidential secrets only as SHA-256 digests.
- `GET /oauth/authorize` and `POST /oauth/authorize` require PKCE `S256` for all clients, bind the login form with an `HttpOnly; SameSite=Lax` CSRF cookie (`__Host-mcp_ar_<id>` on `https://`, `mcp_ar_<id>` on loopback `http://`) and strict `Content-Security-Policy`, expose a `Cancel`/`Deny` action (`error=access_denied`), cap retries at 3 per form session, and rate-limit password failures per client IP. Approved logins return `code`, `iss` (RFC 9207), and optional `state` to the registered callback.
- `POST /oauth/token` exchanges single-use authorization codes and rotates generation-tracked refresh tokens (`rt1.<grant_id>.<gen>.<nonce>.<tag>`) within `oauth.max_grant_lifetime_secs`. Active and grace refresh tokens are verified by SHA-256 digest in `state.json`, while process memory caches the current tip response during `refresh_grace_secs` (default `3600` seconds, synced with `access_token_ttl_secs`) so concurrent subagents converge on the latest tip across multi-hop refreshes. Under the default `refresh_reuse_policy: "converge"`, authenticated same-client requests presenting an older family generation past the grace window still converge on the active tip until explicit `/oauth/revoke` or `max_grant_lifetime_secs`; setting `"revoke"` enables strict RFC 9700 grant revocation on post-grace replay.
- `POST /oauth/revoke` (RFC 7009) requires client authentication (`client_id` for public clients, `client_secret_basic` or `client_secret_post` for confidential clients), revokes the matching grant, and terminates bound HTTP and `stdio` sessions.
- `GET /healthz` and `HEAD /healthz` return `200 OK` (`{"ok":true}` on `GET`) without authentication.

### MCP Streamable HTTP bridging

- `HttpUpstream` buffers `<resource_path>` JSON-RPC request bodies up to `16 MiB` before forwarding, enforces `.https_only()` with OS native TLS roots on `https://` upstreams, and binds upstream `Mcp-Session-Id` identifiers to each OAuth `grant_id`. It strips hop-by-hop headers, client OAuth credentials, `Origin`, `Cookie`, `Set-Cookie`, upstream `WWW-Authenticate`, and spoofed `X-User-*` headers, sets `X-Accel-Buffering: no`, drops leading `text/event-stream` blocks that lack a `data:` line, and cancels active response streams while sending upstream `DELETE` when a grant is revoked. Requests under `passthrough_prefixes` reject path traversal (`..`, backslashes, NUL bytes, and percent-encoded dot segments), strip sensitive headers, and stream `GET`, `HEAD`, and `PUT` without buffering bodies in memory.
- `StdioUpstream` spawns child processes with `env_clear()` (passing only minimal OS runtime variables plus `upstream.env`), rewrites JSON-RPC `id`, `requestId`, `relatedRequestId`, and `progressToken` per wire call while keeping tool schemas and payloads intact, and answers child `ping` or unsupported server requests so child processes do not deadlock. On Unix, each child runs in its own `setsid` process group and stays unreaped via `WNOWAIT` until process-group termination finishes; on Windows, each child requires a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Sessionless calls carrying `MCP-Protocol-Version: 2026-07-28` or `_meta["io.modelcontextprotocol/protocolVersion"] = "2026-07-28"` execute on ephemeral initialized children, and grant revocation or shutdown terminates all bound stateful, initializing, and sessionless children.

## License

Apache-2.0. See [LICENSE](LICENSE).
