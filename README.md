# oauth2-mcp-gateway

`oauth2-mcp-gateway` is a single-binary OAuth 2.1 authentication sidecar for one Model Context Protocol (MCP) server. It binds a local socket behind a reverse proxy or tunnel, authenticates remote MCP clients, and bridges authorized requests on `<resource_path>` (default `/mcp`) to an upstream Streamable HTTP MCP endpoint or isolated `stdio` child processes.

TLS termination and multi-domain virtual hosting stay at your reverse proxy or tunnel. Each gateway process fronts one MCP upstream, stores OAuth registrations and hashed token grants in a single local `state.json` file, and forwards MCP tool schemas and arguments unchanged.

## Quick start

Requires Rust 1.92 or newer. Windows MSVC builds link the C runtime statically (`+crt-static`).

```bash
cargo build --release --locked

printf '%s\n' 'replace-with-a-long-owner-password' \
  | ./target/release/oauth2-mcp-gateway hash-password
```

Copy [`examples/gateway-http.json`](examples/gateway-http.json) or [`examples/gateway-stdio.json`](examples/gateway-stdio.json) to `gateway.json`, export any `"${VAR}"` secrets referenced by the file, validate, and start the server:

```bash
export OWNER_PASSWORD_HASH='pbkdf2-sha256$600000$...'
export UPSTREAM_BEARER_TOKEN_1='upstream-token-a'
export UPSTREAM_BEARER_TOKEN_2='upstream-token-b'

./target/release/oauth2-mcp-gateway check --config gateway.json
./target/release/oauth2-mcp-gateway serve --config gateway.json
```

`OAUTH2_MCP_GATEWAY_CONFIG` sets the default config path when `--config` is omitted. `SIGINT` (and `SIGTERM` on Unix) drains active HTTP connections and terminates managed `stdio` child process trees before exit.

## Configuration

String fields equal to `"${VAR}"` expand from the environment at startup, except `upstream.args` entries, which pass verbatim.

### Top-level fields

| Field | Type | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `listen` | string | required | Local `IP:PORT` socket address to bind, such as `"127.0.0.1:8080"`. |
| `public_url` | string | required | External origin URL (`https://`, or loopback `http://`), such as `"https://mcp.example.com"`. |
| `resource_path` | string | `"/mcp"` | Public MCP endpoint path served by the gateway. |
| `state_path` | string | required | Path to the persisted OAuth client and grant state file (`state.json`). |
| `oauth` | object | required | Owner credential and OAuth 2.1 token lifetime settings. |
| `upstream` | object | required | Upstream MCP transport configuration (`"transport": "http"` or `"stdio"`). |

### `oauth` fields

Set either `owner_password_hash` or `owner_password`.

| Field | Type | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `owner_password_hash` | string | none | PBKDF2-HMAC-SHA256 verifier string produced by `hash-password`. |
| `owner_password` | string | none | Plaintext owner password hashed in memory at startup. |
| `scopes` | `string[]` | `["mcp"]` | Allowed OAuth 2.1 scope tokens. |
| `allowed_redirect_hosts` | `string[]` | `[]` | Optional hostname allowlist for `https://` client callback URIs. |
| `access_token_ttl_secs` | integer | `3600` | Access token lifetime in seconds. |
| `refresh_token_ttl_secs` | integer | `2592000` | Single refresh token lifetime in seconds. |
| `max_grant_lifetime_secs` | integer | `3x refresh_token_ttl_secs` | Cumulative sliding refresh ceiling per grant in seconds (up to 365 days). |
| `refresh_grace_secs` | integer | `access_token_ttl_secs` | Grace window in seconds for concurrent subagents refreshing a rotated token. |
| `refresh_reuse_policy` | string | `"converge"` | Post-grace handling for older family tokens (`"converge"` or `"revoke"`). |
| `max_registered_clients` | integer | `512` | Maximum stored Dynamic Client Registration entries. |

### `upstream` fields (`"transport": "http"`)

| Field | Type | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `url` | string | required | Upstream Streamable HTTP MCP endpoint URL (`http://` or `https://`). |
| `bearer_tokens` | `string[]` | `[]` | Optional upstream Bearer token pool pinned per OAuth grant. |
| `passthrough_prefixes` | `string[]` | `[]` | Unauthenticated URL prefixes (such as `["/t/"]`) streamed directly to the upstream origin. |
| `request_timeout_secs` | integer | `300` | Upstream response and stream frame timeout in seconds. |

### `upstream` fields (`"transport": "stdio"`)

| Field | Type | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `command` | string | required | Executable path or name for the `stdio` MCP server. |
| `args` | `string[]` | `[]` | Command arguments passed verbatim to the child process. |
| `env` | `object` | `{}` | Explicit environment variables passed to the cleared child environment. |
| `cwd` | string | none | Optional working directory for the child process. |
| `max_sessions` | integer | `32` | Maximum concurrent `stdio` child processes across active, handshaking, and reaping slots. |
| `session_idle_secs` | integer | `1800` | Client inactivity timeout in seconds before an idle session is terminated. |

## Nginx reverse proxy

Disable proxy buffering so `text/event-stream` responses and passthrough transfers stream immediately:

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

One `location /` block forwards `<resource_path>`, `/.well-known/*`, `/oauth/*`, `/healthz`, and `passthrough_prefixes` without URL rewrites.

## Development and design

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
python3 scripts/ci/run-tests.py
```

See [`docs/design.md`](docs/design.md) for request guards, OAuth 2.1 endpoint rules, single-tip refresh rotation, upstream session eviction, active byte budgets, and child process-group reaping.

## License

Apache-2.0. See [LICENSE](LICENSE).
