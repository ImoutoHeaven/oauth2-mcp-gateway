use crate::crypto::PasswordVerifier;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use url::{Host, Url};

#[derive(Clone, Debug)]
pub struct GatewayConfig {
    pub listen: SocketAddr,
    pub public_url: String,
    pub resource_path: String,
    pub public_is_https: bool,
    pub state_path: PathBuf,
    pub oauth: OAuthSettings,
    pub upstream: UpstreamSettings,
}

#[derive(Clone, Debug)]
pub struct OAuthSettings {
    pub verifier: PasswordVerifier,
    pub scopes: Vec<String>,
    pub allowed_redirect_hosts: Vec<String>,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub refresh_grace_secs: u64,
    pub max_registered_clients: usize,
}

#[derive(Clone, Debug)]
pub enum UpstreamSettings {
    Http(HttpUpstreamSettings),
    Stdio(StdioUpstreamSettings),
}

impl UpstreamSettings {
    pub fn pool_size(&self) -> usize {
        match self {
            Self::Http(h) if !h.bearer_tokens.is_empty() => h.bearer_tokens.len(),
            _ => 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpUpstreamSettings {
    pub url: Url,
    pub origin_base: Url,
    pub public_is_https: bool,
    pub bearer_tokens: Vec<String>,
    pub passthrough_prefixes: Vec<String>,
    pub request_timeout_secs: u64,
}

#[derive(Clone, Debug)]
pub struct StdioUpstreamSettings {
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub max_sessions: usize,
    pub session_idle_secs: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: String,
    public_url: String,
    resource_path: Option<String>,
    state_path: String,
    oauth: RawOAuth,
    upstream: RawUpstream,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOAuth {
    owner_password: Option<String>,
    owner_password_hash: Option<String>,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    #[serde(default)]
    allowed_redirect_hosts: Vec<String>,
    #[serde(default = "default_access_ttl")]
    access_token_ttl_secs: u64,
    #[serde(default = "default_refresh_ttl")]
    refresh_token_ttl_secs: u64,
    #[serde(default = "default_refresh_grace")]
    refresh_grace_secs: u64,
    #[serde(default = "default_max_clients")]
    max_registered_clients: usize,
}

#[derive(Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase", deny_unknown_fields)]
enum RawUpstream {
    Http {
        url: String,
        #[serde(default)]
        bearer_tokens: Vec<String>,
        #[serde(default)]
        passthrough_prefixes: Vec<String>,
        #[serde(default = "default_http_timeout")]
        request_timeout_secs: u64,
    },
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        cwd: Option<String>,
        #[serde(default = "default_max_sessions")]
        max_sessions: usize,
        #[serde(default = "default_session_idle")]
        session_idle_secs: u64,
    },
}

fn default_scopes() -> Vec<String> {
    vec!["mcp".to_owned()]
}
fn default_access_ttl() -> u64 {
    3600
}
fn default_refresh_ttl() -> u64 {
    30 * 24 * 3600
}
fn default_refresh_grace() -> u64 {
    120
}
fn default_max_clients() -> usize {
    512
}
fn default_http_timeout() -> u64 {
    300
}
fn default_max_sessions() -> usize {
    32
}
fn default_session_idle() -> u64 {
    1800
}

pub fn expand_env_reference(raw: &str, field: &str) -> Result<String, String> {
    if let Some(inner) = raw.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(format!("invalid environment reference in {field}"));
        }
        let val = std::env::var(inner).map_err(|_| {
            format!("environment variable {inner} referenced by {field} is not set")
        })?;
        if val.is_empty() {
            return Err(format!(
                "environment variable {inner} referenced by {field} must not be empty"
            ));
        }
        return Ok(val);
    }
    if raw.contains("${") {
        return Err(format!(
            "partial environment interpolation is not supported in {field}; use full \"${{VAR}}\""
        ));
    }
    Ok(raw.to_owned())
}

pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let trimmed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    trimmed.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

pub fn normalize_allowed_host(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('*')
        || trimmed.ends_with('.')
        || trimmed.contains('/')
        || trimmed.contains('@')
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!(
            "invalid hostname in allowed_redirect_hosts: {raw:?}"
        ));
    }
    let host = Host::parse(trimmed)
        .map_err(|_| format!("invalid hostname in allowed_redirect_hosts: {raw:?}"))?;
    let serialized = host.to_string().to_ascii_lowercase();
    if matches!(host, Host::Domain(_)) && serialized.contains(':') {
        return Err(format!(
            "invalid hostname in allowed_redirect_hosts: {raw:?}"
        ));
    }
    Ok(serialized)
}

pub fn validate_public_url(raw: &str) -> Result<(String, bool), String> {
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("public_url must not contain whitespace or control characters".to_owned());
    }
    let parsed = Url::parse(raw).map_err(|e| format!("invalid public_url: {e}"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("public_url must not contain userinfo".to_owned());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("public_url must not contain a query or fragment".to_owned());
    }
    if parsed.path() != "/" {
        return Err(format!(
            "public_url must be an origin without a path, got path {:?}",
            parsed.path()
        ));
    }
    let Some(host) = parsed.host_str() else {
        return Err("public_url must specify a host".to_owned());
    };
    let is_https = match parsed.scheme() {
        "https" => true,
        "http" if is_loopback_host(host) => false,
        "http" => {
            return Err("public_url may use http:// only for loopback hosts".to_owned());
        }
        other => return Err(format!("unsupported public_url scheme {other:?}")),
    };
    let origin = parsed.origin().ascii_serialization();
    Ok((origin, is_https))
}

impl GatewayConfig {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("cannot access config {}: {e}", path.display()))?;
        if meta.len() > 1024 * 1024 {
            return Err("config file exceeds 1 MiB limit".to_owned());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
        let base_dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        Self::from_json_str(&text, base_dir)
    }

    pub fn from_json_str(json_text: &str, base_dir: &Path) -> Result<Self, String> {
        let base_dir = if base_dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            base_dir
        };
        let raw: RawConfig =
            serde_json::from_str(json_text).map_err(|e| format!("invalid config JSON: {e}"))?;
        let listen_str = expand_env_reference(&raw.listen, "listen")?;
        let listen: SocketAddr = listen_str
            .parse()
            .map_err(|e| format!("invalid listen socket address: {e}"))?;

        let pub_str = expand_env_reference(&raw.public_url, "public_url")?;
        let (public_url, public_is_https) = validate_public_url(&pub_str)?;

        let resource_path = expand_env_reference(
            raw.resource_path.as_deref().unwrap_or("/mcp"),
            "resource_path",
        )?;
        let valid_segment = |segment: &str| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
        };
        if !resource_path
            .strip_prefix('/')
            .is_some_and(|path| path.split('/').all(valid_segment))
        {
            return Err("resource_path must be an absolute path with nonempty segments".to_owned());
        }

        let resource_dir = format!("{}/", resource_path.to_ascii_lowercase());
        if ["/oauth/", "/.well-known/", "/healthz/"]
            .iter()
            .any(|reserved| resource_dir.starts_with(reserved))
        {
            return Err("resource_path overlaps a reserved gateway route".to_owned());
        }

        let state_str = expand_env_reference(&raw.state_path, "state_path")?;
        if state_str.trim().is_empty()
            || state_str.contains('\0')
            || state_str.ends_with('/')
            || state_str.ends_with('\\')
        {
            return Err("state_path must name a regular file, not a directory".to_owned());
        }
        let state_raw = PathBuf::from(&state_str);
        let state_path = if state_raw.is_absolute() {
            state_raw
        } else {
            base_dir.join(state_raw)
        };

        let verifier = match (&raw.oauth.owner_password, &raw.oauth.owner_password_hash) {
            (Some(_), Some(_)) => {
                return Err(
                    "specify either oauth.owner_password or oauth.owner_password_hash, not both"
                        .to_owned(),
                );
            }
            (None, None) => {
                return Err(
                    "either oauth.owner_password or oauth.owner_password_hash is required"
                        .to_owned(),
                );
            }
            (Some(pw), None) => {
                let expanded = expand_env_reference(pw, "oauth.owner_password")?;
                PasswordVerifier::from_plaintext(&expanded)?
            }
            (None, Some(hash)) => {
                let expanded = expand_env_reference(hash, "oauth.owner_password_hash")?;
                PasswordVerifier::parse_encoded(&expanded)?
            }
        };

        if raw.oauth.scopes.is_empty() {
            return Err("oauth.scopes must contain at least one scope token".to_owned());
        }
        let mut scopes = Vec::with_capacity(raw.oauth.scopes.len());
        for (idx, scope) in raw.oauth.scopes.iter().enumerate() {
            let expanded = expand_env_reference(scope, &format!("oauth.scopes[{idx}]"))?;
            if expanded.trim().is_empty()
                || expanded
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(
                    "oauth.scopes must contain non-empty whitespace-free scope tokens".to_owned(),
                );
            }
            scopes.push(expanded);
        }

        if !(60..=86_400).contains(&raw.oauth.access_token_ttl_secs) {
            return Err("oauth.access_token_ttl_secs must be in 60..=86400".to_owned());
        }
        if !(300..=7_776_000).contains(&raw.oauth.refresh_token_ttl_secs) {
            return Err("oauth.refresh_token_ttl_secs must be in 300..=7776000".to_owned());
        }
        if raw.oauth.refresh_token_ttl_secs < raw.oauth.access_token_ttl_secs {
            return Err(
                "oauth.refresh_token_ttl_secs must be >= oauth.access_token_ttl_secs".to_owned(),
            );
        }
        if raw.oauth.refresh_grace_secs > 600 {
            return Err("oauth.refresh_grace_secs must be in 0..=600".to_owned());
        }
        if !(16..=4096).contains(&raw.oauth.max_registered_clients) {
            return Err("oauth.max_registered_clients must be in 16..=4096".to_owned());
        }

        let mut allowed_redirect_hosts = Vec::with_capacity(raw.oauth.allowed_redirect_hosts.len());
        for (idx, host) in raw.oauth.allowed_redirect_hosts.iter().enumerate() {
            let expanded =
                expand_env_reference(host, &format!("oauth.allowed_redirect_hosts[{idx}]"))?;
            allowed_redirect_hosts.push(normalize_allowed_host(&expanded)?);
        }

        let oauth = OAuthSettings {
            verifier,
            scopes,
            allowed_redirect_hosts,
            access_token_ttl_secs: raw.oauth.access_token_ttl_secs,
            refresh_token_ttl_secs: raw.oauth.refresh_token_ttl_secs,
            refresh_grace_secs: raw.oauth.refresh_grace_secs,
            max_registered_clients: raw.oauth.max_registered_clients,
        };

        let upstream = match raw.upstream {
            RawUpstream::Http {
                url,
                bearer_tokens,
                passthrough_prefixes,
                request_timeout_secs,
            } => {
                let expanded_url = expand_env_reference(&url, "upstream.url")?;
                let parsed =
                    Url::parse(&expanded_url).map_err(|e| format!("invalid upstream.url: {e}"))?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err("upstream.url must use http:// or https://".to_owned());
                }
                if !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                {
                    return Err(
                        "upstream.url must not contain userinfo, query, or fragment".to_owned()
                    );
                }
                if parsed.host_str().is_none() {
                    return Err("upstream.url must specify a host".to_owned());
                }
                let origin_base = Url::parse(&parsed.origin().ascii_serialization())
                    .map_err(|e| format!("invalid upstream origin: {e}"))?;

                let mut tokens = Vec::with_capacity(bearer_tokens.len());
                for (idx, tok) in bearer_tokens.iter().enumerate() {
                    let expanded =
                        expand_env_reference(tok, &format!("upstream.bearer_tokens[{idx}]"))?;
                    if expanded.trim().is_empty() || expanded.chars().any(char::is_control) {
                        return Err(format!(
                            "upstream.bearer_tokens[{idx}] must be non-empty and free of control characters"
                        ));
                    }
                    tokens.push(expanded);
                }

                let mut prefixes = Vec::with_capacity(passthrough_prefixes.len());
                for (idx, prefix) in passthrough_prefixes.iter().enumerate() {
                    let expanded = expand_env_reference(
                        prefix,
                        &format!("upstream.passthrough_prefixes[{idx}]"),
                    )?;
                    validate_passthrough_prefix(&expanded, parsed.path())?;
                    if resource_dir.starts_with(&expanded.to_ascii_lowercase()) {
                        return Err(format!(
                            "resource_path overlaps passthrough prefix {expanded:?}"
                        ));
                    }
                    prefixes.push(expanded);
                }
                if !(5..=3600).contains(&request_timeout_secs) {
                    return Err("upstream.request_timeout_secs must be in 5..=3600".to_owned());
                }
                UpstreamSettings::Http(HttpUpstreamSettings {
                    url: parsed,
                    origin_base,
                    public_is_https,
                    bearer_tokens: tokens,
                    passthrough_prefixes: prefixes,
                    request_timeout_secs,
                })
            }
            RawUpstream::Stdio {
                command,
                args,
                env,
                cwd,
                max_sessions,
                session_idle_secs,
            } => {
                let command = expand_env_reference(&command, "upstream.command")?;
                if command.trim().is_empty() || command.contains('\0') {
                    return Err(
                        "upstream.command must be a non-empty string without NUL".to_owned()
                    );
                }
                if args.iter().any(|a| a.contains('\0')) {
                    return Err("upstream.args must not contain NUL bytes".to_owned());
                }
                let mut expanded_env = BTreeMap::new();
                for (k, v) in env {
                    if k.is_empty() || k.contains('=') || k.contains('\0') {
                        return Err(format!("invalid environment variable name {k:?}"));
                    }
                    let val = expand_env_reference(&v, &format!("upstream.env.{k}"))?;
                    if val.contains('\0') {
                        return Err(format!("upstream.env.{k} must not contain NUL bytes"));
                    }
                    expanded_env.insert(k, val);
                }
                let resolved_cwd = match cwd {
                    None => None,
                    Some(dir) => {
                        let expanded = expand_env_reference(&dir, "upstream.cwd")?;
                        if expanded.trim().is_empty() || expanded.contains('\0') {
                            return Err("upstream.cwd must not be empty or contain NUL".to_owned());
                        }
                        let p = PathBuf::from(expanded);
                        Some(if p.is_absolute() { p } else { base_dir.join(p) })
                    }
                };
                if !(1..=256).contains(&max_sessions) {
                    return Err("upstream.max_sessions must be in 1..=256".to_owned());
                }
                if !(30..=86_400).contains(&session_idle_secs) {
                    return Err("upstream.session_idle_secs must be in 30..=86400".to_owned());
                }
                UpstreamSettings::Stdio(StdioUpstreamSettings {
                    command,
                    args,
                    env: expanded_env,
                    cwd: resolved_cwd,
                    max_sessions,
                    session_idle_secs,
                })
            }
        };

        Ok(Self {
            listen,
            public_url,
            resource_path,
            public_is_https,
            state_path,
            oauth,
            upstream,
        })
    }

    pub fn mcp_resource_url(&self) -> String {
        format!("{}{}", self.public_url, self.resource_path)
    }
}

fn validate_passthrough_prefix(prefix: &str, upstream_path: &str) -> Result<(), String> {
    if prefix.len() < 3 || !prefix.starts_with('/') || !prefix.ends_with('/') {
        return Err(format!(
            "passthrough prefix {prefix:?} must start and end with '/' and name a subpath (such as \"/t/\")"
        ));
    }
    if prefix.contains("..")
        || prefix.contains('\\')
        || prefix.contains('?')
        || prefix.contains('#')
        || prefix.contains('%')
        || prefix.contains("//")
        || prefix.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!(
            "passthrough prefix {prefix:?} contains forbidden characters"
        ));
    }
    let lower = prefix.to_ascii_lowercase();
    for reserved in ["/mcp/", "/oauth/", "/.well-known/", "/healthz/"] {
        if lower.starts_with(reserved) || reserved.starts_with(&lower) {
            return Err(format!(
                "passthrough prefix {prefix:?} overlaps reserved gateway route {reserved:?}"
            ));
        }
    }
    let trimmed_up = upstream_path.trim_end_matches('/');
    if !trimmed_up.is_empty() {
        let up_dir = format!("{}/", trimmed_up.to_ascii_lowercase());
        if lower.starts_with(&up_dir) || up_dir.starts_with(&lower) {
            return Err(format!(
                "passthrough prefix {prefix:?} overlaps upstream MCP path {upstream_path:?}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash() -> String {
        PasswordVerifier::from_plaintext_with_iterations("secret123", 10_000)
            .unwrap()
            .encode()
    }

    #[test]
    fn parses_http_upstream_and_rejects_bad_passthrough_or_non_https_public_url() {
        let hash = test_hash();
        let ok_json = format!(
            r#"{{
              "listen": "127.0.0.1:8080",
              "public_url": "https://mcp.example.com/",
              "state_path": "state.json",
              "oauth": {{
                "owner_password_hash": "{hash}",
                "allowed_redirect_hosts": ["Claude.AI", "münchen.example.com", "[::1]"]
              }},
              "upstream": {{
                "transport": "http",
                "url": "http://127.0.0.1:9000/api/mcp",
                "bearer_tokens": ["tok-a", "tok-b"],
                "passthrough_prefixes": ["/t/"]
              }}
            }}"#
        );
        let cfg = GatewayConfig::from_json_str(&ok_json, Path::new("")).unwrap();
        assert_eq!(cfg.public_url, "https://mcp.example.com");
        assert!(cfg.public_is_https);
        assert_eq!(cfg.state_path, Path::new("./state.json"));
        assert_eq!(
            cfg.state_path.parent(),
            Some(Path::new(".")),
            "empty base_dir must normalize so state_path.parent() is never empty"
        );
        assert_eq!(
            cfg.oauth.allowed_redirect_hosts,
            vec!["claude.ai", "xn--mnchen-3ya.example.com", "[::1]"]
        );
        let UpstreamSettings::Http(http_up) = &cfg.upstream else {
            panic!("expected http upstream");
        };
        assert!(http_up.public_is_https);
        assert_eq!(cfg.upstream.pool_size(), 2);

        let bad_http = ok_json.replace("https://mcp.example.com/", "http://mcp.example.com/");
        assert!(GatewayConfig::from_json_str(&bad_http, Path::new("/tmp")).is_err());

        let case_reserved = ok_json.replace("\"/t/\"", "\"/MCP/\"");
        assert!(GatewayConfig::from_json_str(&case_reserved, Path::new("/tmp")).is_err());

        let upstream_overlap = ok_json.replace("\"/t/\"", "\"/api/\"");
        assert!(GatewayConfig::from_json_str(&upstream_overlap, Path::new("/tmp")).is_err());

        for invalid_resource_path in [
            "/oauth",
            "/oauth/token",
            "/.well-known/oauth-protected-resource",
            "/healthz",
            "/t",
            "/t/download",
            "/api/../mcp",
        ] {
            let json = ok_json.replace(
                "\"state_path\":",
                &format!("\"resource_path\": {invalid_resource_path:?}, \"state_path\":"),
            );
            let error = GatewayConfig::from_json_str(&json, Path::new("/tmp")).unwrap_err();
            assert!(error.starts_with("resource_path"), "{error}");
        }

        let wildcard_host = ok_json.replace("\"Claude.AI\"", "\"*.claude.ai\"");
        assert!(GatewayConfig::from_json_str(&wildcard_host, Path::new("/tmp")).is_err());
    }

    #[test]
    fn validates_loopback_http_and_env_expansion_boundaries() {
        let hash = test_hash();
        let loopback_json = format!(
            r#"{{
              "listen": "127.0.0.1:8080",
              "public_url": "http://[::1]:8080",
              "state_path": "state.json",
              "oauth": {{ "owner_password_hash": "{hash}" }},
              "upstream": {{
                "transport": "stdio",
                "command": "echo",
                "args": ["${{LITERAL_ARG_KEPT}}"]
              }}
            }}"#
        );
        let cfg = GatewayConfig::from_json_str(&loopback_json, Path::new(".")).unwrap();
        assert_eq!(cfg.public_url, "http://[::1]:8080");
        assert!(!cfg.public_is_https);
        let UpstreamSettings::Stdio(stdio) = &cfg.upstream else {
            panic!("expected stdio upstream");
        };
        assert_eq!(stdio.args, vec!["${LITERAL_ARG_KEPT}"]);

        assert!(expand_env_reference("${DEFINITELY_UNSET_GW_TEST_VAR}", "field").is_err());
        assert!(expand_env_reference("prefix-${VAR}", "field").is_err());
        assert!(expand_env_reference("${BAD-NAME}", "field").is_err());
    }
}
