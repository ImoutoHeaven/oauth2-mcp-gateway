use crate::crypto::{PasswordVerifier, zeroize_string};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use url::{Host, Url};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpNet {
    V4 { addr: u32, mask: u32, prefix: u8 },
    V6 { addr: u128, mask: u128, prefix: u8 },
}

impl IpNet {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("empty IP or CIDR".to_owned());
        }
        let Some((ip_part, prefix_part)) = trimmed.split_once('/') else {
            let ip = trimmed
                .parse::<IpAddr>()
                .map_err(|e| format!("{e}"))?
                .to_canonical();
            return Ok(match ip {
                IpAddr::V4(v4) => Self::V4 {
                    addr: u32::from(v4),
                    mask: u32::MAX,
                    prefix: 32,
                },
                IpAddr::V6(v6) => Self::V6 {
                    addr: u128::from(v6),
                    mask: u128::MAX,
                    prefix: 128,
                },
            });
        };

        if ip_part.is_empty()
            || prefix_part.is_empty()
            || prefix_part.contains('/')
            || !prefix_part.bytes().all(|b| b.is_ascii_digit())
            || (prefix_part.len() > 1 && prefix_part.starts_with('0'))
        {
            return Err(format!("invalid CIDR notation {trimmed:?}"));
        }
        let prefix = prefix_part
            .parse::<u8>()
            .map_err(|_| format!("invalid CIDR prefix length in {trimmed:?}"))?;
        let raw_ip = ip_part
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid IP address in {trimmed:?}: {e}"))?;

        match raw_ip {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return Err(format!("IPv4 CIDR prefix length {prefix} exceeds 32"));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Ok(Self::V4 {
                    addr: u32::from(v4) & mask,
                    mask,
                    prefix,
                })
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return Err(format!("IPv6 CIDR prefix length {prefix} exceeds 128"));
                }
                if let Some(v4) = v6.to_ipv4_mapped()
                    && prefix >= 96
                {
                    let v4_prefix = prefix - 96;
                    let mask = if v4_prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - v4_prefix)
                    };
                    return Ok(Self::V4 {
                        addr: u32::from(v4) & mask,
                        mask,
                        prefix: v4_prefix,
                    });
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Ok(Self::V6 {
                    addr: u128::from(v6) & mask,
                    mask,
                    prefix,
                })
            }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip.to_canonical()) {
            (Self::V4 { addr, mask, .. }, IpAddr::V4(v4)) => (u32::from(v4) & mask) == addr,
            (Self::V6 { addr, mask, .. }, IpAddr::V6(v6)) => (u128::from(v6) & mask) == addr,
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GatewayConfig {
    pub listen: SocketAddr,
    pub public_url: String,
    pub resource_path: String,
    pub public_is_https: bool,
    pub state_path: PathBuf,
    pub trusted_proxies: Vec<IpNet>,
    pub oauth: OAuthSettings,
    pub upstream: UpstreamSettings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefreshReusePolicy {
    #[default]
    Converge,
    Revoke,
}

#[derive(Clone)]
pub struct OAuthSettings {
    pub verifier: PasswordVerifier,
    pub scopes: Vec<String>,
    pub allowed_redirect_hosts: Vec<String>,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub max_grant_lifetime_secs: u64,
    pub refresh_grace_secs: u64,
    pub refresh_reuse_policy: RefreshReusePolicy,
    pub max_registered_clients: usize,
}

impl std::fmt::Debug for OAuthSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthSettings")
            .field("verifier", &"<redacted>")
            .field("scopes", &self.scopes)
            .field("allowed_redirect_hosts", &self.allowed_redirect_hosts)
            .field("access_token_ttl_secs", &self.access_token_ttl_secs)
            .field("refresh_token_ttl_secs", &self.refresh_token_ttl_secs)
            .field("max_grant_lifetime_secs", &self.max_grant_lifetime_secs)
            .field("refresh_grace_secs", &self.refresh_grace_secs)
            .field("refresh_reuse_policy", &self.refresh_reuse_policy)
            .field("max_registered_clients", &self.max_registered_clients)
            .finish()
    }
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

#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamAuthContextConfig {
    pub check_listen: SocketAddr,
    pub check_token: String,
}

impl Drop for UpstreamAuthContextConfig {
    fn drop(&mut self) {
        zeroize_string(&mut self.check_token);
    }
}

impl std::fmt::Debug for UpstreamAuthContextConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamAuthContextConfig")
            .field("check_listen", &self.check_listen)
            .field("check_token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct HttpUpstreamSettings {
    pub url: Url,
    pub origin_base: Url,
    pub public_is_https: bool,
    pub bearer_tokens: Vec<String>,
    pub passthrough_prefixes: Vec<String>,
    pub request_timeout_secs: u64,
    pub auth_context: Option<UpstreamAuthContextConfig>,
}

impl std::fmt::Debug for HttpUpstreamSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpUpstreamSettings")
            .field("url", &self.url)
            .field("origin_base", &self.origin_base)
            .field("public_is_https", &self.public_is_https)
            .field(
                "bearer_tokens",
                &format_args!("<{} redacted>", self.bearer_tokens.len()),
            )
            .field("passthrough_prefixes", &self.passthrough_prefixes)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .field("auth_context", &self.auth_context)
            .finish()
    }
}

#[derive(Clone)]
pub struct StdioUpstreamSettings {
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub max_sessions: usize,
    pub session_idle_secs: u64,
}

impl std::fmt::Debug for StdioUpstreamSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_env: BTreeMap<&str, &str> = self
            .env
            .keys()
            .map(|k| (k.as_str(), "<redacted>"))
            .collect();
        f.debug_struct("StdioUpstreamSettings")
            .field("command", &self.command)
            .field("args", &self.args)
            .field("env", &redacted_env)
            .field("cwd", &self.cwd)
            .field("max_sessions", &self.max_sessions)
            .field("session_idle_secs", &self.session_idle_secs)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: String,
    public_url: String,
    resource_path: Option<String>,
    state_path: String,
    #[serde(default)]
    trusted_proxies: Vec<String>,
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
    max_grant_lifetime_secs: Option<u64>,
    #[serde(default)]
    refresh_grace_secs: Option<u64>,
    #[serde(default)]
    refresh_reuse_policy: RefreshReusePolicy,
    #[serde(default = "default_max_clients")]
    max_registered_clients: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthContext {
    check_listen: String,
    check_token: String,
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
        #[serde(default)]
        auth_context: Option<RawAuthContext>,
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

        let mut trusted_proxies = Vec::with_capacity(raw.trusted_proxies.len());
        for (idx, raw_entry) in raw.trusted_proxies.iter().enumerate() {
            let expanded = expand_env_reference(raw_entry, &format!("trusted_proxies[{idx}]"))?;
            let parsed_net = IpNet::parse(&expanded)
                .map_err(|e| format!("invalid IP or CIDR in trusted_proxies[{idx}]: {e}"))?;
            if !trusted_proxies.contains(&parsed_net) {
                trusted_proxies.push(parsed_net);
            }
        }

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
                let mut expanded = expand_env_reference(pw, "oauth.owner_password")?;
                let res = PasswordVerifier::from_plaintext(&expanded);
                zeroize_string(&mut expanded);
                res?
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
            if !is_valid_scope_token(&expanded) {
                return Err(format!(
                    "oauth.scopes[{idx}] must be a valid RFC 6749 scope token"
                ));
            }
            if !scopes.contains(&expanded) {
                scopes.push(expanded);
            }
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
        let max_grant_lifetime_secs = raw.oauth.max_grant_lifetime_secs.unwrap_or_else(|| {
            raw.oauth
                .refresh_token_ttl_secs
                .saturating_mul(3)
                .clamp(raw.oauth.refresh_token_ttl_secs, 31_536_000)
        });
        if !(raw.oauth.refresh_token_ttl_secs..=31_536_000).contains(&max_grant_lifetime_secs) {
            return Err(
                "oauth.max_grant_lifetime_secs must be in oauth.refresh_token_ttl_secs..=31536000"
                    .to_owned(),
            );
        }
        let refresh_grace_secs = raw.oauth.refresh_grace_secs.unwrap_or_else(|| {
            raw.oauth
                .access_token_ttl_secs
                .min(raw.oauth.refresh_token_ttl_secs)
        });
        if refresh_grace_secs > 86_400 || refresh_grace_secs > raw.oauth.refresh_token_ttl_secs {
            return Err(
                "oauth.refresh_grace_secs must be in 0..=86400 and <= oauth.refresh_token_ttl_secs"
                    .to_owned(),
            );
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
            max_grant_lifetime_secs,
            refresh_grace_secs,
            refresh_reuse_policy: raw.oauth.refresh_reuse_policy,
            max_registered_clients: raw.oauth.max_registered_clients,
        };

        let upstream = match raw.upstream {
            RawUpstream::Http {
                url,
                bearer_tokens,
                passthrough_prefixes,
                request_timeout_secs,
                auth_context,
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
                    if expanded.is_empty()
                        || !expanded.is_ascii()
                        || expanded
                            .bytes()
                            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                        || http::HeaderValue::from_str(&format!("Bearer {expanded}")).is_err()
                    {
                        return Err(format!(
                            "upstream.bearer_tokens[{idx}] must be a valid ASCII Bearer token without whitespace or control characters"
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
                    let lower = expanded.to_ascii_lowercase();
                    if resource_dir.starts_with(&lower) || lower.starts_with(&resource_dir) {
                        return Err(format!(
                            "resource_path overlaps passthrough prefix {expanded:?}"
                        ));
                    }
                    prefixes.push(expanded);
                }
                if !(5..=3600).contains(&request_timeout_secs) {
                    return Err("upstream.request_timeout_secs must be in 5..=3600".to_owned());
                }
                let auth_context = match auth_context {
                    None => None,
                    Some(raw_ac) => {
                        if tokens.is_empty() {
                            return Err(
                                "upstream.bearer_tokens must not be empty when upstream.auth_context is configured"
                                    .to_owned(),
                            );
                        }
                        let check_listen_str = expand_env_reference(
                            &raw_ac.check_listen,
                            "upstream.auth_context.check_listen",
                        )?;
                        let check_listen: SocketAddr = check_listen_str.parse().map_err(|e| {
                            format!(
                                "invalid upstream.auth_context.check_listen socket address: {e}"
                            )
                        })?;
                        if !check_listen.ip().is_loopback() {
                            return Err(
                                "upstream.auth_context.check_listen must use a loopback IP address"
                                    .to_owned(),
                            );
                        }
                        if listen.port() != 0 && check_listen == listen {
                            return Err("upstream.auth_context.check_listen must not equal listen"
                                .to_owned());
                        }
                        let mut check_token = expand_env_reference(
                            &raw_ac.check_token,
                            "upstream.auth_context.check_token",
                        )?;
                        if check_token.len() < 16
                            || !check_token.bytes().all(|b| (0x21..=0x7E).contains(&b))
                        {
                            zeroize_string(&mut check_token);
                            return Err(
                                "upstream.auth_context.check_token must contain at least 16 visible ASCII characters"
                                    .to_owned(),
                            );
                        }
                        Some(UpstreamAuthContextConfig {
                            check_listen,
                            check_token,
                        })
                    }
                };
                UpstreamSettings::Http(HttpUpstreamSettings {
                    url: parsed,
                    origin_base,
                    public_is_https,
                    bearer_tokens: tokens,
                    passthrough_prefixes: prefixes,
                    request_timeout_secs,
                    auth_context,
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
            trusted_proxies,
            oauth,
            upstream,
        })
    }

    pub fn mcp_resource_url(&self) -> String {
        format!("{}{}", self.public_url, self.resource_path)
    }
}

pub(crate) fn is_valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
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
    for reserved in ["/oauth/", "/.well-known/", "/healthz/"] {
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
        assert_eq!(cfg.oauth.refresh_token_ttl_secs, 2_592_000);
        assert_eq!(cfg.oauth.max_grant_lifetime_secs, 7_776_000);
        let UpstreamSettings::Stdio(stdio) = &cfg.upstream else {
            panic!("expected stdio upstream");
        };
        assert_eq!(stdio.args, vec!["${LITERAL_ARG_KEPT}"]);

        let custom_rt = loopback_json.replace(
            "\"owner_password_hash\":",
            "\"refresh_token_ttl_secs\": 7776000, \"owner_password_hash\":",
        );
        let custom_cfg = GatewayConfig::from_json_str(&custom_rt, Path::new(".")).unwrap();
        assert_eq!(custom_cfg.oauth.max_grant_lifetime_secs, 23_328_000);

        let too_short_grant = loopback_json.replace(
            "\"owner_password_hash\":",
            "\"refresh_token_ttl_secs\": 3600, \"max_grant_lifetime_secs\": 1800, \"owner_password_hash\":",
        );
        assert!(GatewayConfig::from_json_str(&too_short_grant, Path::new(".")).is_err());

        let too_long_grant = loopback_json.replace(
            "\"owner_password_hash\":",
            "\"max_grant_lifetime_secs\": 31536001, \"owner_password_hash\":",
        );
        assert!(GatewayConfig::from_json_str(&too_long_grant, Path::new(".")).is_err());

        assert!(expand_env_reference("${DEFINITELY_UNSET_GW_TEST_VAR}", "field").is_err());
        assert!(expand_env_reference("prefix-${VAR}", "field").is_err());
        assert!(expand_env_reference("${BAD-NAME}", "field").is_err());
    }

    #[test]
    fn validates_auth_context_and_trusted_proxies() {
        let hash = test_hash();
        let valid_json = serde_json::json!({
            "listen": "127.0.0.1:8080",
            "public_url": "https://mcp.example.com",
            "state_path": "state.json",
            "trusted_proxies": [
                "127.0.0.1",
                "::ffff:127.0.0.1",
                "127.0.0.1/32",
                "10.0.0.0/8",
                "fd00::/8",
                "::1/128"
            ],
            "oauth": { "owner_password_hash": hash },
            "upstream": {
                "transport": "http",
                "url": "http://127.0.0.1:9000/mcp",
                "bearer_tokens": ["hop-secret-token"],
                "auth_context": {
                    "check_listen": "127.0.0.1:8083",
                    "check_token": "0123456789abcdef_check"
                }
            }
        });
        let cfg = GatewayConfig::from_json_str(&valid_json.to_string(), Path::new("/tmp")).unwrap();
        assert_eq!(cfg.trusted_proxies.len(), 4);
        assert!(
            cfg.trusted_proxies
                .iter()
                .any(|n| n.contains("10.254.12.9".parse().unwrap()))
        );
        assert!(
            !cfg.trusted_proxies
                .iter()
                .any(|n| n.contains("11.0.0.1".parse().unwrap()))
        );
        assert!(
            cfg.trusted_proxies
                .iter()
                .any(|n| n.contains("fd12:3456::1".parse().unwrap()))
        );
        assert!(
            !cfg.trusted_proxies
                .iter()
                .any(|n| n.contains("fe80::1".parse().unwrap()))
        );
        assert!(
            IpNet::parse("0.0.0.0/0")
                .unwrap()
                .contains("203.0.113.1".parse().unwrap())
        );
        assert!(
            IpNet::parse("::/0")
                .unwrap()
                .contains("2001:db8::1".parse().unwrap())
        );

        for bad_proxy in [
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/8/16",
            "10.0.0.0/",
            "/8",
            "10.0.0.0/08",
            "10.0.0.0/+8",
            "not-an-ip/24",
        ] {
            let mut j = valid_json.clone();
            j["trusted_proxies"] = serde_json::json!([bad_proxy]);
            assert!(
                GatewayConfig::from_json_str(&j.to_string(), Path::new("/tmp")).is_err(),
                "expected trusted_proxies entry {bad_proxy:?} to fail"
            );
        }
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("0123456789abcdef_check"));
        let UpstreamSettings::Http(ref http_up) = cfg.upstream else {
            panic!("expected http upstream");
        };
        let ac = http_up.auth_context.as_ref().unwrap();
        assert_eq!(ac.check_listen, "127.0.0.1:8083".parse().unwrap());

        for bad_listen in [
            "0.0.0.0:8083",
            "[::]:8083",
            "192.168.1.10:8083",
            "127.0.0.1:8080",
        ] {
            let mut j = valid_json.clone();
            j["upstream"]["auth_context"]["check_listen"] = serde_json::json!(bad_listen);
            assert!(
                GatewayConfig::from_json_str(&j.to_string(), Path::new("/tmp")).is_err(),
                "expected check_listen {bad_listen} to fail"
            );
        }

        for bad_token in [
            "short-15-chars!",
            "has space in token!!",
            "non-ascii-token-é!",
        ] {
            let mut j = valid_json.clone();
            j["upstream"]["auth_context"]["check_token"] = serde_json::json!(bad_token);
            assert!(
                GatewayConfig::from_json_str(&j.to_string(), Path::new("/tmp")).is_err(),
                "expected check_token {bad_token:?} to fail"
            );
        }

        let mut no_bearers = valid_json.clone();
        no_bearers["upstream"]["bearer_tokens"] = serde_json::json!([]);
        assert!(GatewayConfig::from_json_str(&no_bearers.to_string(), Path::new("/tmp")).is_err());

        let mut unknown_field = valid_json.clone();
        unknown_field["upstream"]["auth_context"]["extra"] = serde_json::json!(true);
        assert!(
            GatewayConfig::from_json_str(&unknown_field.to_string(), Path::new("/tmp")).is_err()
        );

        let stdio_with_ac = serde_json::json!({
            "listen": "127.0.0.1:8080",
            "public_url": "https://mcp.example.com",
            "state_path": "state.json",
            "oauth": { "owner_password_hash": hash },
            "upstream": {
                "transport": "stdio",
                "command": "echo",
                "auth_context": {
                    "check_listen": "127.0.0.1:8083",
                    "check_token": "0123456789abcdef_check"
                }
            }
        });
        assert!(
            GatewayConfig::from_json_str(&stdio_with_ac.to_string(), Path::new("/tmp")).is_err()
        );
    }
}
