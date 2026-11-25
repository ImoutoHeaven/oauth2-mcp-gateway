use crate::config::{GatewayConfig, IpNet, RefreshReusePolicy, is_loopback_host};
use crate::crypto::{
    Crypto, compute_auth_ref, constant_time_eq_str, constant_time_sha256_eq, hmac_sha256,
    is_valid_s256_challenge, random_token_b64, sha256_b64, verify_pkce_s256, zeroize_bytes,
    zeroize_string,
};
use crate::store::{
    AccessTokenRecord, GraceRefreshRecord, GrantRecord, MAX_GRACE_REFRESHES, PersistedState,
    RefreshTokenRecord, RegisteredClient, StateStore, unix_now,
};
use crate::types::{
    AuthChallenge, HttpReply, VerifiedToken, bytes_body, empty_body, hex_nibble, json_reply,
    method_not_allowed, text_reply,
};
use crate::upstream_http::{ContentLengthCheck, check_content_length_limit, close_empty_reply};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body::Body;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use url::Url;

const MAX_POST_BODY_BYTES: usize = 64 * 1024;
const MAX_CHECK_BODY_BYTES: usize = 4 * 1024;
const OAUTH_BODY_TIMEOUT: Duration = Duration::from_secs(10);
const CHECK_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REDIRECT_URIS: usize = 16;
const MAX_CLIENT_NAME_CHARS: usize = 256;
const MAX_STATE_BYTES: usize = 1024;
const PENDING_AUTH_TTL_SECS: u64 = 300;
const MAX_CONSUMED_AUTH_NONCES: usize = 4096;
const AUTH_CODE_TTL_SECS: u64 = 300;
const MAX_AUTH_CODES: usize = 256;
const CONSUMED_CODE_TTL_SECS: u64 = 300;
const MAX_CONSUMED_CODES: usize = 1024;
const PW_FAIL_WINDOW: Duration = Duration::from_secs(15 * 60);
const PW_MAX_FAILURES: usize = 10;
const PW_VERIFY_CONCURRENCY: usize = 4;
const MAX_PW_FAILURE_IPS: usize = 4096;
const LOOPBACK_PW_BUCKET_CAPACITY: f64 = 10.0;
const LOOPBACK_PW_BUCKET_REFILL_PER_SEC: f64 = 0.5;
const MAX_ACCESS_TOKENS_PER_GRANT: usize = 64;
const MAX_GRACE_CACHE: usize = 1024;
const MAX_ACTIVE_GRANTS: usize = 4096;

const AUTH_PAGE_CSP: &str =
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'";

type EarlyReply = Box<HttpReply>;
type RevokeHook = Arc<dyn Fn(&str) + Send + Sync>;

pub struct OAuthEngine {
    core: Arc<EngineCore>,
}

struct EngineCore {
    config: Arc<GatewayConfig>,
    store: StateStore,
    crypto: Crypto,
    inner: Mutex<EngineState>,
    persist_lock: Arc<tokio::sync::Mutex<()>>,
    pw_verify_sem: Arc<Semaphore>,
    on_revoke: Option<RevokeHook>,
    #[cfg(test)]
    register_persist_barrier: Mutex<Option<tests::RegisterPersistBarrier>>,
}

struct LoopbackTokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl LoopbackTokenBucket {
    fn new() -> Self {
        Self {
            tokens: LOOPBACK_PW_BUCKET_CAPACITY,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * LOOPBACK_PW_BUCKET_REFILL_PER_SEC)
                .min(LOOPBACK_PW_BUCKET_CAPACITY);
            self.last_refill = now;
        }
    }

    fn has_budget(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= 1.0
    }

    fn record_failure(&mut self, now: Instant) {
        self.refill(now);
        self.tokens = (self.tokens - 1.0).max(0.0);
    }
}

struct EngineState {
    persisted: PersistedState,
    access_index: HashMap<String, String>,
    grant_index: HashMap<String, usize>,
    aref_index: HashMap<String, usize>,
    consumed_auth_nonces: VecDeque<(String, u64)>,
    auth_codes: VecDeque<AuthCodeEntry>,
    consumed_codes: VecDeque<ConsumedCodeEntry>,
    grace_cache: HashMap<String, GraceCacheEntry>,
    pw_failures: HashMap<IpAddr, VecDeque<Instant>>,
    loopback_pw_bucket: LoopbackTokenBucket,
    rr_cursor: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct SealedAuthForm {
    nonce_id: String,
    cookie_csrf: String,
    client_id: String,
    client_name: Option<String>,
    redirect_uri: String,
    scopes: Vec<String>,
    resource: String,
    state: Option<String>,
    code_challenge: String,
    expires_at: u64,
}

struct AuthorizeFormView<'a> {
    ar_id: &'a str,
    csrf_token: &'a str,
    client_id: &'a str,
    client_name: Option<&'a str>,
    redirect_uri: &'a str,
    scopes: &'a [String],
    resource: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckRequest {
    #[serde(rename = "ref")]
    auth_ref: String,
}

struct AuthCodeEntry {
    code_sha256: String,
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    resource: String,
    code_challenge: String,
    expires_at: u64,
}

struct ConsumedCodeEntry {
    code_sha256: String,
    grant_id: String,
    expires_at: u64,
}

#[derive(Clone)]
struct GraceCacheEntry {
    tip_gen: u64,
    access_token: String,
    refresh_token: String,
    a_expires_at: u64,
    scopes: Vec<String>,
    grace_until: u64,
}

impl Drop for GraceCacheEntry {
    fn drop(&mut self) {
        zeroize_string(&mut self.access_token);
        zeroize_string(&mut self.refresh_token);
    }
}

#[derive(Deserialize)]
struct DcrRequest {
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    token_endpoint_auth_method: Option<String>,
    scope: Option<String>,
}

struct RotatedTip {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    scopes: Vec<String>,
    cache_entry: Option<GraceCacheEntry>,
}

struct ParsedRefreshToken<'a> {
    grant_id: &'a str,
    r#gen: u64,
    nonce: &'a str,
    tag: &'a str,
}

impl EngineCore {
    fn notify_revoke(&self, grant_id: &str) {
        if let Some(hook) = &self.on_revoke {
            hook(grant_id);
        }
    }
}

impl EngineState {
    fn sync_indexes(&mut self) {
        self.access_index.clear();
        self.grant_index.clear();
        self.aref_index.clear();
        for (idx, grant) in self.persisted.grants.iter().enumerate() {
            self.grant_index.insert(grant.grant_id.clone(), idx);
            self.aref_index
                .insert(compute_auth_ref(&grant.resource, &grant.grant_id), idx);
            for at in &grant.access_tokens {
                self.access_index
                    .insert(at.token_sha256.clone(), grant.grant_id.clone());
            }
        }
    }

    fn prune_persisted(&mut self, now: u64) {
        if self.persisted.prune_expired(now) {
            self.sync_indexes();
        }
    }

    fn prune_ephemeral(&mut self, now: u64) {
        self.consumed_auth_nonces
            .retain(|(_, expires_at)| *expires_at > now);
        self.auth_codes.retain(|entry| entry.expires_at > now);
        self.consumed_codes.retain(|entry| entry.expires_at > now);
        self.grace_cache
            .retain(|_, entry| entry.grace_until >= now && entry.a_expires_at > now);
        let mono_now = Instant::now();
        self.pw_failures.retain(|_, deque| {
            while let Some(&ts) = deque.front() {
                if mono_now.saturating_duration_since(ts) >= PW_FAIL_WINDOW {
                    deque.pop_front();
                } else {
                    break;
                }
            }
            !deque.is_empty()
        });
    }

    fn is_auth_nonce_consumed(&self, nonce_id: &str) -> bool {
        self.consumed_auth_nonces
            .iter()
            .any(|(id, _)| constant_time_eq_str(id, nonce_id))
    }

    fn record_consumed_auth_nonce(&mut self, nonce_id: String, expires_at: u64) {
        if self.is_auth_nonce_consumed(&nonce_id) {
            return;
        }
        while self.consumed_auth_nonces.len() >= MAX_CONSUMED_AUTH_NONCES {
            self.consumed_auth_nonces.pop_front();
        }
        self.consumed_auth_nonces.push_back((nonce_id, expires_at));
    }

    fn has_pw_budget(&mut self, ip: IpAddr, use_loopback_bucket: bool) -> bool {
        if use_loopback_bucket {
            self.loopback_pw_bucket.has_budget(Instant::now())
        } else {
            self.pw_failures.get(&ip).map_or(0, VecDeque::len) < PW_MAX_FAILURES
        }
    }

    fn record_pw_failure(&mut self, ip: IpAddr, use_loopback_bucket: bool) {
        let now = Instant::now();
        if use_loopback_bucket {
            self.loopback_pw_bucket.record_failure(now);
            return;
        }
        if self.pw_failures.len() >= MAX_PW_FAILURE_IPS
            && !self.pw_failures.contains_key(&ip)
            && let Some(oldest_ip) = self
                .pw_failures
                .iter()
                .min_by_key(|(_, dq)| dq.back().copied())
                .map(|(k, _)| *k)
        {
            self.pw_failures.remove(&oldest_ip);
        }
        self.pw_failures.entry(ip).or_default().push_back(now);
    }

    fn insert_grace_cache(&mut self, grant_id: String, entry: GraceCacheEntry) {
        if self.grace_cache.len() >= MAX_GRACE_CACHE
            && !self.grace_cache.contains_key(&grant_id)
            && let Some(evict_key) = self
                .grace_cache
                .iter()
                .min_by_key(|(_, e)| e.grace_until)
                .map(|(k, _)| k.clone())
        {
            self.grace_cache.remove(&evict_key);
        }
        self.grace_cache.insert(grant_id, entry);
    }

    fn record_consumed_code(&mut self, code_sha256: String, grant_id: String, expires_at: u64) {
        if self
            .consumed_codes
            .iter()
            .any(|c| constant_time_eq_str(&c.code_sha256, &code_sha256))
        {
            return;
        }
        while self.consumed_codes.len() >= MAX_CONSUMED_CODES {
            self.consumed_codes.pop_front();
        }
        self.consumed_codes.push_back(ConsumedCodeEntry {
            code_sha256,
            grant_id,
            expires_at,
        });
    }

    fn remove_grant_immediate(&mut self, grant_id: &str) -> Option<PersistedState> {
        let before = self.persisted.grants.len();
        self.persisted.grants.retain(|g| g.grant_id != grant_id);
        self.grace_cache.remove(grant_id);
        if self.persisted.grants.len() == before {
            return None;
        }
        self.sync_indexes();
        Some(self.persisted.clone())
    }

    fn select_pool_slot(&mut self, pool_size: usize) -> usize {
        let size = pool_size.max(1);
        let mut counts = vec![0usize; size];
        for grant in &self.persisted.grants {
            if grant.pool_slot < size {
                counts[grant.pool_slot] += 1;
            }
        }
        let min_load = counts.iter().copied().min().unwrap_or(0);
        let start = self.rr_cursor % size;
        let mut chosen = start;
        for offset in 0..size {
            let idx = (start + offset) % size;
            if counts[idx] == min_load {
                chosen = idx;
                break;
            }
        }
        self.rr_cursor = (chosen + 1) % size;
        chosen
    }
}

impl OAuthEngine {
    pub fn open(config: Arc<GatewayConfig>) -> Result<Arc<Self>, String> {
        Self::open_internal(config, None)
    }

    pub fn open_with_revoke_hook(
        config: Arc<GatewayConfig>,
        on_revoke: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Arc<Self>, String> {
        Self::open_internal(config, Some(on_revoke))
    }

    fn open_internal(
        config: Arc<GatewayConfig>,
        on_revoke: Option<RevokeHook>,
    ) -> Result<Arc<Self>, String> {
        let now = unix_now();
        let crypto = Crypto::new_random()?;
        let (store, persisted) = StateStore::open(config.state_path.clone(), now)?;
        let mut state = EngineState {
            persisted,
            access_index: HashMap::new(),
            grant_index: HashMap::new(),
            aref_index: HashMap::new(),
            consumed_auth_nonces: VecDeque::new(),
            auth_codes: VecDeque::new(),
            consumed_codes: VecDeque::new(),
            grace_cache: HashMap::new(),
            pw_failures: HashMap::new(),
            loopback_pw_bucket: LoopbackTokenBucket::new(),
            rr_cursor: 0,
        };
        state.sync_indexes();
        let initial_consumed: Vec<(String, String, u64)> = state
            .persisted
            .grants
            .iter()
            .filter_map(|grant| {
                let (h, exp) = grant.consumed_code_sha256.as_ref()?;
                (*exp > now).then(|| (h.clone(), grant.grant_id.clone(), *exp))
            })
            .collect();
        for (h, gid, exp) in initial_consumed {
            state.record_consumed_code(h, gid, exp);
        }
        Ok(Arc::new(Self {
            core: Arc::new(EngineCore {
                config,
                store,
                crypto,
                inner: Mutex::new(state),
                persist_lock: Arc::new(tokio::sync::Mutex::new(())),
                pw_verify_sem: Arc::new(Semaphore::new(PW_VERIFY_CONCURRENCY)),
                on_revoke,
                #[cfg(test)]
                register_persist_barrier: Mutex::new(None),
            }),
        }))
    }

    pub fn resource_path(&self) -> &str {
        &self.core.config.resource_path
    }

    pub fn is_grant_active(&self, grant_id: &str) -> bool {
        let now = unix_now();
        let expected_resource = self.core.config.mcp_resource_url();
        let guard = self
            .core
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(&idx) = guard.grant_index.get(grant_id) else {
            return false;
        };
        let Some(grant) = guard.persisted.grants.get(idx) else {
            return false;
        };
        now < grant.max_expires_at
            && grant.resource == expected_resource
            && (grant.access_tokens.iter().any(|at| at.expires_at > now)
                || grant
                    .current_refresh
                    .as_ref()
                    .is_some_and(|rt| rt.expires_at > now))
    }

    async fn run_uncancellable<F, Fut>(&self, f: F) -> HttpReply
    where
        F: FnOnce(Arc<EngineCore>) -> Fut + Send + 'static,
        Fut: Future<Output = HttpReply> + Send + 'static,
    {
        let core = Arc::clone(&self.core);
        // Detached task finishes state commit and fsync even if client drops TCP mid-request.
        let handle = tokio::spawn(async move {
            let _persist_guard = Arc::clone(&core.persist_lock).lock_owned().await;
            let reply = f(core).await;
            drop(_persist_guard);
            reply
        });
        match handle.await {
            Ok(reply) => reply,
            Err(_) => oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "persistence task panicked",
            ),
        }
    }

    pub fn handles_path(path: &str) -> bool {
        path == "/.well-known/oauth-protected-resource"
            || path.starts_with("/.well-known/oauth-protected-resource/")
            || path == "/.well-known/oauth-authorization-server"
            || path.starts_with("/.well-known/oauth-authorization-server/")
            || path.starts_with("/oauth/")
    }

    pub async fn handle(&self, req: Request<Incoming>) -> HttpReply {
        let peer_ip = req.extensions().get::<IpAddr>().copied();
        let path = req.uri().path().to_owned();
        match path.as_str() {
            p if p == "/.well-known/oauth-protected-resource"
                || p.strip_prefix("/.well-known/oauth-protected-resource")
                    == Some(self.core.config.resource_path.as_str()) =>
            {
                if req.method() != Method::GET {
                    return method_not_allowed("GET");
                }
                self.handle_prm()
            }
            p if p.starts_with("/.well-known/oauth-protected-resource/") => not_found_reply(),
            p if p == "/.well-known/oauth-authorization-server"
                || p.strip_prefix("/.well-known/oauth-authorization-server")
                    == Some(self.core.config.resource_path.as_str()) =>
            {
                if req.method() != Method::GET {
                    return method_not_allowed("GET");
                }
                self.handle_as_metadata()
            }
            p if p.starts_with("/.well-known/oauth-authorization-server/") => not_found_reply(),
            "/oauth/register" => {
                if req.method() != Method::POST {
                    return method_not_allowed("POST");
                }
                self.handle_register(req).await
            }
            "/oauth/authorize" => match *req.method() {
                Method::GET => self.handle_authorize_get(&req),
                Method::POST => self.handle_authorize_post(req, peer_ip).await,
                _ => method_not_allowed("GET, POST"),
            },
            "/oauth/token" => {
                if req.method() != Method::POST {
                    return method_not_allowed("POST");
                }
                self.handle_token(req).await
            }
            "/oauth/revoke" => {
                if req.method() != Method::POST {
                    return method_not_allowed("POST");
                }
                self.handle_revoke(req).await
            }
            _ => not_found_reply(),
        }
    }

    pub fn verify_bearer(&self, headers: &HeaderMap) -> Result<VerifiedToken, AuthChallenge> {
        let mut auth_iter = headers.get_all(header::AUTHORIZATION).iter();
        let Some(raw_header) = auth_iter.next() else {
            return Err(AuthChallenge::MissingToken);
        };
        if auth_iter.next().is_some() {
            return Err(AuthChallenge::InvalidToken);
        }
        let Ok(header_str) = raw_header.to_str() else {
            return Err(AuthChallenge::InvalidToken);
        };
        let trimmed = header_str.trim_ascii();
        if trimmed.eq_ignore_ascii_case("bearer") {
            return Err(AuthChallenge::InvalidToken);
        }
        let Some(rest) = strip_bearer_prefix(trimmed) else {
            return Err(AuthChallenge::MissingToken);
        };
        let token = rest.trim_ascii();
        if token.is_empty()
            || token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(AuthChallenge::InvalidToken);
        }

        let token_hash = sha256_b64(token);
        let now = unix_now();
        let expected_resource = self.core.config.mcp_resource_url();

        let guard = self
            .core
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(grant_id) = guard.access_index.get(&token_hash) else {
            return Err(AuthChallenge::InvalidToken);
        };
        let Some(&grant_idx) = guard.grant_index.get(grant_id) else {
            return Err(AuthChallenge::InvalidToken);
        };
        let Some(grant) = guard.persisted.grants.get(grant_idx) else {
            return Err(AuthChallenge::InvalidToken);
        };
        if now >= grant.max_expires_at || grant.resource != expected_resource {
            return Err(AuthChallenge::InvalidToken);
        }
        let Some(at) = grant
            .access_tokens
            .iter()
            .find(|at| at.expires_at > now && constant_time_eq_str(&at.token_sha256, &token_hash))
        else {
            return Err(AuthChallenge::InvalidToken);
        };
        if !at
            .scopes
            .iter()
            .any(|s| self.core.config.oauth.scopes.contains(s))
        {
            return Err(AuthChallenge::InsufficientScope);
        }
        Ok(VerifiedToken {
            grant_id: grant.grant_id.clone(),
            client_id: grant.client_id.clone(),
            pool_slot: grant.pool_slot,
            scopes: at.scopes.clone(),
            resource: grant.resource.clone(),
        })
    }

    pub fn www_authenticate_value(&self, challenge: AuthChallenge) -> String {
        let meta_url = format!(
            "{}/.well-known/oauth-protected-resource{}",
            self.core.config.public_url, self.core.config.resource_path
        );
        match challenge {
            AuthChallenge::MissingToken => format!("Bearer resource_metadata=\"{meta_url}\""),
            AuthChallenge::InvalidToken => {
                format!("Bearer resource_metadata=\"{meta_url}\", error=\"invalid_token\"")
            }
            AuthChallenge::InsufficientScope => {
                let scope = self.core.config.oauth.scopes.join(" ");
                format!(
                    "Bearer resource_metadata=\"{meta_url}\", error=\"insufficient_scope\", scope=\"{scope}\""
                )
            }
        }
    }

    pub fn unauthorized_reply(&self, challenge: AuthChallenge) -> HttpReply {
        let status = match challenge {
            AuthChallenge::InsufficientScope => StatusCode::FORBIDDEN,
            AuthChallenge::MissingToken | AuthChallenge::InvalidToken => StatusCode::UNAUTHORIZED,
        };
        Response::builder()
            .status(status)
            .header(
                header::WWW_AUTHENTICATE,
                self.www_authenticate_value(challenge),
            )
            .header(header::CONNECTION, "close")
            .header(header::CACHE_CONTROL, "no-store")
            .body(empty_body())
            .expect("valid auth challenge reply")
    }

    pub async fn handle_auth_check(
        &self,
        req: Request<Incoming>,
        peer_ip: IpAddr,
        expected_token_sha256: &[u8; 32],
    ) -> HttpReply {
        if !peer_ip.to_canonical().is_loopback() {
            return close_empty_reply(StatusCode::FORBIDDEN);
        }
        if req.headers().contains_key(header::ORIGIN) {
            return close_empty_reply(StatusCode::FORBIDDEN);
        }
        if req.uri().path() != "/authorization/check" || req.uri().query().is_some() {
            return not_found_reply();
        }
        if req.method() != Method::POST {
            return method_not_allowed("POST");
        }
        if !verify_check_bearer(req.headers(), expected_token_sha256) {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::WWW_AUTHENTICATE, "Bearer")
                .header(header::CONNECTION, "close")
                .header(header::CACHE_CONTROL, "no-store")
                .body(empty_body())
                .expect("valid 401 check reply");
        }
        if !has_media_type(req.headers(), "application/json") {
            return json_reply(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &json!({ "error": "Content-Type must be application/json" }),
            );
        }
        let body = match read_limited_body_with(req, MAX_CHECK_BODY_BYTES, CHECK_BODY_TIMEOUT).await
        {
            Ok(bytes) => bytes,
            Err(BodyReadError::TooLarge) => {
                return with_connection_close(json_reply(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &json!({ "error": "request body exceeds 4 KiB limit" }),
                ));
            }
            Err(BodyReadError::Timeout) => {
                return with_connection_close(json_reply(
                    StatusCode::REQUEST_TIMEOUT,
                    &json!({ "error": "request body read timed out" }),
                ));
            }
            Err(BodyReadError::InvalidContentLength | BodyReadError::ReadFailed) => {
                return with_connection_close(json_reply(
                    StatusCode::BAD_REQUEST,
                    &json!({ "error": "invalid request body" }),
                ));
            }
        };
        let parsed: CheckRequest = match serde_json::from_slice(&body) {
            Ok(req_obj) => req_obj,
            Err(_) => {
                return json_reply(
                    StatusCode::BAD_REQUEST,
                    &json!({ "error": "invalid check payload" }),
                );
            }
        };
        json_reply(StatusCode::OK, &self.check_authorization(&parsed.auth_ref))
    }

    pub fn check_authorization(&self, auth_ref: &str) -> serde_json::Value {
        if !auth_ref.starts_with("aref_") || auth_ref.len() > 128 {
            return json!({ "active": false });
        }
        let now = unix_now();
        let expected_resource = self.core.config.mcp_resource_url();
        let configured_scopes = &self.core.config.oauth.scopes;

        let guard = self
            .core
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(&idx) = guard.aref_index.get(auth_ref) else {
            return json!({ "active": false });
        };
        let Some(grant) = guard.persisted.grants.get(idx) else {
            return json!({ "active": false });
        };
        if now >= grant.max_expires_at || grant.resource != expected_resource {
            return json!({ "active": false });
        }
        let expected_aref = compute_auth_ref(&grant.resource, &grant.grant_id);
        if !constant_time_eq_str(&expected_aref, auth_ref) {
            return json!({ "active": false });
        }

        let live_refresh_exp = grant
            .current_refresh
            .as_ref()
            .filter(|rt| rt.expires_at > now)
            .map(|rt| rt.expires_at);
        let max_access_exp = grant
            .access_tokens
            .iter()
            .filter(|at| at.expires_at > now)
            .map(|at| at.expires_at)
            .max();
        let max_token_exp = match (live_refresh_exp, max_access_exp) {
            (Some(r), Some(a)) => r.max(a),
            (Some(r), None) => r,
            (None, Some(a)) => a,
            (None, None) => return json!({ "active": false }),
        };
        let live_expires_at = max_token_exp.min(grant.max_expires_at);
        if live_expires_at <= now {
            return json!({ "active": false });
        }

        let mut effective_scopes = Vec::new();
        if live_refresh_exp.is_some() {
            for s in &grant.scopes {
                if configured_scopes.contains(s) && !effective_scopes.contains(s) {
                    effective_scopes.push(s.clone());
                }
            }
        } else {
            for at in grant.access_tokens.iter().filter(|at| at.expires_at > now) {
                for s in &at.scopes {
                    if configured_scopes.contains(s) && !effective_scopes.contains(s) {
                        effective_scopes.push(s.clone());
                    }
                }
            }
        }

        if effective_scopes.is_empty() {
            return json!({ "active": false });
        }

        json!({
            "active": true,
            "principal": auth_ref,
            "resource": grant.resource,
            "scopes": effective_scopes,
            "expiresAt": live_expires_at,
        })
    }

    fn handle_prm(&self) -> HttpReply {
        let pub_url = &self.core.config.public_url;
        json_reply(
            StatusCode::OK,
            &json!({
                "resource": self.core.config.mcp_resource_url(),
                "authorization_servers": [pub_url],
                "bearer_methods_supported": ["header"],
                "scopes_supported": self.core.config.oauth.scopes,
            }),
        )
    }

    fn handle_as_metadata(&self) -> HttpReply {
        let pub_url = &self.core.config.public_url;
        json_reply(
            StatusCode::OK,
            &json!({
                "issuer": pub_url,
                "authorization_endpoint": format!("{pub_url}/oauth/authorize"),
                "token_endpoint": format!("{pub_url}/oauth/token"),
                "registration_endpoint": format!("{pub_url}/oauth/register"),
                "revocation_endpoint": format!("{pub_url}/oauth/revoke"),
                "scopes_supported": self.core.config.oauth.scopes,
                "response_types_supported": ["code"],
                "response_modes_supported": ["query"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": [
                    "none",
                    "client_secret_post",
                    "client_secret_basic"
                ],
                "revocation_endpoint_auth_methods_supported": [
                    "none",
                    "client_secret_post",
                    "client_secret_basic"
                ],
                "code_challenge_methods_supported": ["S256"],
                "authorization_response_iss_parameter_supported": true,
            }),
        )
    }

    async fn handle_register(&self, req: Request<Incoming>) -> HttpReply {
        if !has_media_type(req.headers(), "application/json") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "Content-Type must be application/json",
            );
        }
        let body = match read_limited_body(req).await {
            Ok(bytes) => bytes,
            Err(err) => return body_error_json(err),
        };
        let raw_req: DcrRequest = match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(_) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_client_metadata",
                    "malformed JSON registration payload",
                );
            }
        };

        let Some(raw_uris) = raw_req.redirect_uris else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "redirect_uris is required",
            );
        };
        if raw_uris.is_empty() || raw_uris.len() > MAX_REDIRECT_URIS {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                "redirect_uris must contain 1 to 16 entries",
            );
        }
        let mut redirect_uris = Vec::with_capacity(raw_uris.len());
        for uri in raw_uris {
            if !is_allowed_redirect_uri(&self.core.config, &uri) {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_redirect_uri",
                    "redirect_uri violates scheme, syntax, or host policy",
                );
            }
            if !redirect_uris.contains(&uri) {
                redirect_uris.push(uri);
            }
        }

        let client_name = match raw_req.client_name {
            None => None,
            Some(name) => {
                if name.chars().any(is_forbidden_display_char) {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        "invalid client_name",
                    );
                }
                let trimmed = name.trim();
                if trimmed.chars().count() > MAX_CLIENT_NAME_CHARS {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        "invalid client_name",
                    );
                }
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_owned())
                }
            }
        };

        let allowed_scopes = match raw_req.scope {
            None => None,
            Some(raw_scope) => {
                let Some(parsed) = parse_scope_list(&raw_scope, &self.core.config.oauth.scopes)
                else {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        "invalid or unsupported scope",
                    );
                };
                Some(parsed)
            }
        };

        let grant_types = match raw_req.grant_types {
            None => vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
            Some(list) => {
                if list.is_empty() {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        "grant_types must not be empty",
                    );
                }
                let mut dedup = Vec::with_capacity(list.len());
                for gt in list {
                    if gt != "authorization_code" && gt != "refresh_token" {
                        return oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_client_metadata",
                            "unsupported grant_type",
                        );
                    }
                    if !dedup.contains(&gt) {
                        dedup.push(gt);
                    }
                }
                if !dedup.iter().any(|g| g == "authorization_code") {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        "authorization_code grant_type is required",
                    );
                }
                dedup
            }
        };

        let response_types = match raw_req.response_types {
            None => vec!["code".to_owned()],
            Some(list) => {
                if list.is_empty() || list.iter().any(|rt| rt != "code") {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        "only response_type code is supported",
                    );
                }
                vec!["code".to_owned()]
            }
        };

        let auth_method = raw_req
            .token_endpoint_auth_method
            .unwrap_or_else(|| "none".to_owned());
        if !matches!(
            auth_method.as_str(),
            "none" | "client_secret_post" | "client_secret_basic"
        ) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "unsupported token_endpoint_auth_method",
            );
        }

        let Ok(client_suffix) = random_token_b64(18) else {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "random generation failed",
            );
        };
        let client_id = format!("cli_{client_suffix}");

        let (plain_secret, secret_sha256) = if auth_method == "none" {
            (None, None)
        } else {
            let Ok(sec) = random_token_b64(32) else {
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "random generation failed",
                );
            };
            let digest = sha256_b64(&sec);
            (Some(sec), Some(digest))
        };

        self.run_uncancellable(move |core| async move {
            let now = unix_now();
            let record = RegisteredClient {
                client_id: client_id.clone(),
                client_name: client_name.clone(),
                redirect_uris: redirect_uris.clone(),
                grant_types: grant_types.clone(),
                response_types: response_types.clone(),
                token_endpoint_auth_method: auth_method.clone(),
                client_secret_sha256: secret_sha256,
                allowed_scopes: allowed_scopes.clone(),
                issued_at: now,
            };

            let snapshot = {
                let mut guard = core
                    .inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.prune_persisted(now);
                guard.prune_ephemeral(now);

                let max_clients = core.config.oauth.max_registered_clients;
                let mut candidate_clients = guard.persisted.clients.clone();
                while candidate_clients.len() >= max_clients {
                    let oldest_idle_idx = candidate_clients
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| {
                            !guard
                                .persisted
                                .grants
                                .iter()
                                .any(|g| g.client_id == c.client_id)
                                && !guard.auth_codes.iter().any(|a| a.client_id == c.client_id)
                        })
                        .min_by_key(|(idx, c)| (c.issued_at, *idx))
                        .map(|(idx, _)| idx);

                    let Some(evict_idx) = oldest_idle_idx else {
                        return oauth_error(
                            StatusCode::TOO_MANY_REQUESTS,
                            "temporarily_unavailable",
                            "maximum active registered clients reached",
                        );
                    };
                    candidate_clients.remove(evict_idx);
                }

                candidate_clients.push(record);
                let mut snap = guard.persisted.clone();
                snap.clients = candidate_clients;
                snap
            };

            #[cfg(test)]
            tests::pause_register_persist(&core).await;

            let Ok(persisted) = persist_snapshot(&core.store, snapshot).await else {
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "failed to persist registered client",
                );
            };

            {
                let mut guard = core
                    .inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.persisted = persisted;
                guard.sync_indexes();
            }

            let mut resp_obj = serde_json::Map::new();
            resp_obj.insert("client_id".to_owned(), json!(client_id));
            resp_obj.insert("client_id_issued_at".to_owned(), json!(now));
            if let Some(mut secret) = plain_secret {
                resp_obj.insert("client_secret".to_owned(), json!(&secret));
                resp_obj.insert("client_secret_expires_at".to_owned(), json!(0));
                zeroize_string(&mut secret);
            }
            if let Some(name) = client_name {
                resp_obj.insert("client_name".to_owned(), json!(name));
            }
            if let Some(scopes) = allowed_scopes {
                resp_obj.insert("scope".to_owned(), json!(scopes.join(" ")));
            }
            resp_obj.insert("redirect_uris".to_owned(), json!(redirect_uris));
            resp_obj.insert("grant_types".to_owned(), json!(grant_types));
            resp_obj.insert("response_types".to_owned(), json!(response_types));
            resp_obj.insert("token_endpoint_auth_method".to_owned(), json!(auth_method));

            json_reply(StatusCode::CREATED, &serde_json::Value::Object(resp_obj))
        })
        .await
    }

    fn handle_authorize_get(&self, req: &Request<Incoming>) -> HttpReply {
        let query = req.uri().query().unwrap_or("");
        let Ok(params) = parse_unique_form(query.as_bytes()) else {
            return html_status_reply(
                StatusCode::BAD_REQUEST,
                "Duplicate or malformed query parameter",
            );
        };

        let Some(client_id) = params.get("client_id").filter(|v| !v.is_empty()) else {
            return html_status_reply(StatusCode::BAD_REQUEST, "Missing client_id");
        };
        let Some(redirect_uri) = params.get("redirect_uri").filter(|v| !v.is_empty()) else {
            return html_status_reply(StatusCode::BAD_REQUEST, "Missing redirect_uri");
        };

        let now = unix_now();
        let client_meta = {
            let guard = self
                .core
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard
                .persisted
                .clients
                .iter()
                .find(|c| c.client_id == *client_id)
                .cloned()
        };

        let Some(client) = client_meta else {
            return html_status_reply(StatusCode::BAD_REQUEST, "Unknown client_id");
        };
        if !matches_registered_redirect_uri(&client.redirect_uris, redirect_uri)
            || !is_allowed_redirect_uri(&self.core.config, redirect_uri)
        {
            return html_status_reply(StatusCode::BAD_REQUEST, "Unregistered redirect_uri");
        }

        let state_param = params.get("state").cloned();
        if state_param
            .as_deref()
            .is_some_and(|s| s.len() > MAX_STATE_BYTES || s.chars().any(char::is_control))
        {
            return html_status_reply(StatusCode::BAD_REQUEST, "Invalid state parameter");
        }

        match params.get("response_type").map(String::as_str) {
            Some("code") => {}
            Some(_) => {
                return authorize_error_redirect(
                    &self.core.config,
                    redirect_uri,
                    "unsupported_response_type",
                    state_param.as_deref(),
                );
            }
            None => {
                return authorize_error_redirect(
                    &self.core.config,
                    redirect_uri,
                    "invalid_request",
                    state_param.as_deref(),
                );
            }
        }

        if !client.grant_types.iter().any(|g| g == "authorization_code")
            || !client.response_types.iter().any(|r| r == "code")
        {
            return authorize_error_redirect(
                &self.core.config,
                redirect_uri,
                "unauthorized_client",
                state_param.as_deref(),
            );
        }

        let challenge_method_ok = params
            .get("code_challenge_method")
            .is_some_and(|m| m == "S256");
        let Some(code_challenge) = params
            .get("code_challenge")
            .filter(|c| challenge_method_ok && is_valid_s256_challenge(c))
            .cloned()
        else {
            return authorize_error_redirect(
                &self.core.config,
                redirect_uri,
                "invalid_request",
                state_param.as_deref(),
            );
        };

        let effective_allowed_scopes: Vec<String> = match &client.allowed_scopes {
            None => self.core.config.oauth.scopes.clone(),
            Some(client_scopes) => client_scopes
                .iter()
                .filter(|s| self.core.config.oauth.scopes.contains(s))
                .cloned()
                .collect(),
        };
        if effective_allowed_scopes.is_empty() {
            return authorize_error_redirect(
                &self.core.config,
                redirect_uri,
                "invalid_scope",
                state_param.as_deref(),
            );
        }

        let scopes = match params.get("scope") {
            None => effective_allowed_scopes,
            Some(raw_scope) => {
                let Some(parsed_scopes) = parse_scope_list(raw_scope, &effective_allowed_scopes)
                else {
                    return authorize_error_redirect(
                        &self.core.config,
                        redirect_uri,
                        "invalid_scope",
                        state_param.as_deref(),
                    );
                };
                parsed_scopes
            }
        };

        let Ok(resource) = normalize_resource(
            &self.core.config,
            params.get("resource").map(String::as_str),
        ) else {
            return authorize_error_redirect(
                &self.core.config,
                redirect_uri,
                "invalid_target",
                state_param.as_deref(),
            );
        };

        let (Ok(nonce_id), Ok(cookie_csrf)) = (random_token_b64(18), random_token_b64(24)) else {
            return html_status_reply(StatusCode::INTERNAL_SERVER_ERROR, "Random source error");
        };

        let sealed_payload = SealedAuthForm {
            nonce_id: nonce_id.clone(),
            cookie_csrf: cookie_csrf.clone(),
            client_id: client.client_id,
            client_name: client.client_name,
            redirect_uri: redirect_uri.clone(),
            scopes,
            resource,
            state: state_param,
            code_challenge,
            expires_at: now.saturating_add(PENDING_AUTH_TTL_SECS),
        };
        let Ok(plaintext) = serde_json::to_vec(&sealed_payload) else {
            return html_status_reply(StatusCode::INTERNAL_SERVER_ERROR, "Encoding error");
        };
        let aad = auth_form_aad(&self.core.config.public_url, &nonce_id);
        let Ok(sealed_token) = self.core.crypto.seal(&aad, &plaintext) else {
            return html_status_reply(StatusCode::INTERNAL_SERVER_ERROR, "Random source error");
        };

        let cookie = build_ar_cookie(
            self.core.config.public_is_https,
            &nonce_id,
            &cookie_csrf,
            PENDING_AUTH_TTL_SECS,
        );
        let view = AuthorizeFormView {
            ar_id: &sealed_payload.nonce_id,
            csrf_token: &sealed_token,
            client_id: &sealed_payload.client_id,
            client_name: sealed_payload.client_name.as_deref(),
            redirect_uri: &sealed_payload.redirect_uri,
            scopes: &sealed_payload.scopes,
            resource: &sealed_payload.resource,
        };
        authorize_form_reply(StatusCode::OK, &view, None, Some(&cookie))
    }

    async fn handle_authorize_post(
        &self,
        req: Request<Incoming>,
        peer_ip: Option<IpAddr>,
    ) -> HttpReply {
        if !has_media_type(req.headers(), "application/x-www-form-urlencoded") {
            return html_status_reply(
                StatusCode::BAD_REQUEST,
                "Content-Type must be application/x-www-form-urlencoded",
            );
        }
        let req_headers = req.headers().clone();
        let body = match read_limited_body(req).await {
            Ok(bytes) => bytes,
            Err(err) => return body_error_html(err),
        };
        let Ok(mut form) = parse_unique_form(&body) else {
            return html_status_reply(StatusCode::BAD_REQUEST, "Invalid form submission");
        };

        let Some(ar_id) = form.get("ar_id").filter(|v| !v.is_empty()).cloned() else {
            return html_status_reply(StatusCode::BAD_REQUEST, "Missing authorization session");
        };
        let Some(form_csrf) = form.get("csrf_token").filter(|v| !v.is_empty()).cloned() else {
            return html_status_reply(StatusCode::FORBIDDEN, "Missing CSRF token");
        };
        let is_deny = match form.get("decision").map(String::as_str) {
            None | Some("approve") => false,
            Some("deny") => true,
            Some(_) => return html_status_reply(StatusCode::BAD_REQUEST, "Invalid decision"),
        };

        let (ip_key, use_loopback_bucket) =
            resolve_rate_limit_ip(&req_headers, peer_ip, &self.core.config.trusted_proxies);
        let now = unix_now();

        {
            let mut guard = self
                .core
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.prune_ephemeral(now);
            if !is_deny && !guard.has_pw_budget(ip_key, use_loopback_bucket) {
                return html_status_reply(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many failed attempts",
                );
            }
            if guard.is_auth_nonce_consumed(&ar_id) {
                return html_status_reply(
                    StatusCode::BAD_REQUEST,
                    "Authorization request already consumed",
                );
            }
        }

        let aad = auth_form_aad(&self.core.config.public_url, &ar_id);
        let Some(mut plaintext) = self.core.crypto.open(&aad, &form_csrf) else {
            return html_status_reply(StatusCode::FORBIDDEN, "CSRF validation failed");
        };
        let parsed_res = serde_json::from_slice::<SealedAuthForm>(&plaintext);
        zeroize_bytes(&mut plaintext);
        let Ok(mut pending) = parsed_res else {
            return html_status_reply(StatusCode::FORBIDDEN, "CSRF validation failed");
        };
        if !constant_time_eq_str(&pending.nonce_id, &ar_id) {
            zeroize_string(&mut pending.cookie_csrf);
            return html_status_reply(StatusCode::FORBIDDEN, "CSRF validation failed");
        }
        if pending.expires_at <= now {
            zeroize_string(&mut pending.cookie_csrf);
            return html_status_reply(
                StatusCode::BAD_REQUEST,
                "Authorization request expired or unknown",
            );
        }

        let cookie_name = ar_cookie_name(self.core.config.public_is_https, &pending.nonce_id);
        if !has_valid_csrf_cookie(&req_headers, &cookie_name, &pending.cookie_csrf) {
            zeroize_string(&mut pending.cookie_csrf);
            return html_status_reply(StatusCode::FORBIDDEN, "CSRF validation failed");
        }
        zeroize_string(&mut pending.cookie_csrf);

        if is_deny {
            let clear_cookie =
                build_ar_cookie(self.core.config.public_is_https, &pending.nonce_id, "", 0);
            let Ok(mut location) = Url::parse(&pending.redirect_uri) else {
                return html_status_reply(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid redirect target",
                );
            };
            {
                let mut pairs = location.query_pairs_mut();
                pairs.append_pair("error", "access_denied");
                pairs.append_pair("iss", &self.core.config.public_url);
                if let Some(st) = &pending.state {
                    pairs.append_pair("state", st);
                }
            }
            return finish_authorize_redirect(&req_headers, &clear_cookie, &location);
        }

        let mut password = form.remove("password").unwrap_or_default();
        let Ok(verify_permit) = Arc::clone(&self.core.pw_verify_sem).acquire_owned().await else {
            zeroize_string(&mut password);
            return html_status_reply(StatusCode::SERVICE_UNAVAILABLE, "Server shutting down");
        };
        {
            let mut guard = self
                .core
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let check_now = unix_now();
            guard.prune_ephemeral(check_now);
            if !guard.has_pw_budget(ip_key, use_loopback_bucket) {
                zeroize_string(&mut password);
                return html_status_reply(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many failed attempts",
                );
            }
            if guard.is_auth_nonce_consumed(&pending.nonce_id) {
                zeroize_string(&mut password);
                return html_status_reply(
                    StatusCode::BAD_REQUEST,
                    "Authorization request already consumed",
                );
            }
        }

        let verifier = self.core.config.oauth.verifier.clone();
        let pw_valid = tokio::task::spawn_blocking(move || {
            let _permit = verify_permit;
            let valid = verifier.verify(&password);
            zeroize_string(&mut password);
            valid
        })
        .await
        .unwrap_or(false);

        let finish_now = unix_now();
        if !pw_valid {
            {
                let mut guard = self
                    .core
                    .inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.prune_ephemeral(finish_now);
                guard.record_pw_failure(ip_key, use_loopback_bucket);
            }
            let view = AuthorizeFormView {
                ar_id: &pending.nonce_id,
                csrf_token: &form_csrf,
                client_id: &pending.client_id,
                client_name: pending.client_name.as_deref(),
                redirect_uri: &pending.redirect_uri,
                scopes: &pending.scopes,
                resource: &pending.resource,
            };
            return authorize_form_reply(
                StatusCode::UNAUTHORIZED,
                &view,
                Some("Incorrect password"),
                None,
            );
        }

        if pending.expires_at <= finish_now {
            return html_status_reply(
                StatusCode::BAD_REQUEST,
                "Authorization request expired or unknown",
            );
        }

        let Ok(raw_code) = random_token_b64(32) else {
            return html_status_reply(StatusCode::INTERNAL_SERVER_ERROR, "Random source error");
        };
        let code_hash = sha256_b64(&raw_code);

        {
            let mut guard = self
                .core
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.prune_ephemeral(finish_now);
            if guard.is_auth_nonce_consumed(&pending.nonce_id) {
                return html_status_reply(
                    StatusCode::BAD_REQUEST,
                    "Authorization request already consumed",
                );
            }
            let client_still_registered = guard.persisted.clients.iter().any(|c| {
                c.client_id == pending.client_id
                    && matches_registered_redirect_uri(&c.redirect_uris, &pending.redirect_uri)
            });
            if !client_still_registered {
                return html_status_reply(
                    StatusCode::BAD_REQUEST,
                    "Client is no longer registered",
                );
            }

            guard.record_consumed_auth_nonce(pending.nonce_id.clone(), pending.expires_at);
            while guard.auth_codes.len() >= MAX_AUTH_CODES {
                guard.auth_codes.pop_front();
            }
            guard.auth_codes.push_back(AuthCodeEntry {
                code_sha256: code_hash,
                client_id: pending.client_id.clone(),
                redirect_uri: pending.redirect_uri.clone(),
                scopes: pending.scopes.clone(),
                resource: pending.resource.clone(),
                code_challenge: pending.code_challenge.clone(),
                expires_at: finish_now.saturating_add(AUTH_CODE_TTL_SECS),
            });
        }

        let clear_cookie =
            build_ar_cookie(self.core.config.public_is_https, &pending.nonce_id, "", 0);
        let Ok(mut location) = Url::parse(&pending.redirect_uri) else {
            return html_status_reply(StatusCode::INTERNAL_SERVER_ERROR, "Invalid redirect target");
        };
        {
            let mut pairs = location.query_pairs_mut();
            pairs.append_pair("code", &raw_code);
            pairs.append_pair("iss", &self.core.config.public_url);
            if let Some(st) = &pending.state {
                pairs.append_pair("state", st);
            }
        }

        finish_authorize_redirect(&req_headers, &clear_cookie, &location)
    }

    async fn handle_token(&self, req: Request<Incoming>) -> HttpReply {
        if !has_media_type(req.headers(), "application/x-www-form-urlencoded") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Content-Type must be application/x-www-form-urlencoded",
            );
        }
        let req_headers = req.headers().clone();
        let body = match read_limited_body(req).await {
            Ok(bytes) => bytes,
            Err(err) => return body_error_json(err),
        };
        let Ok(form) = parse_unique_form(&body) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "duplicate or malformed form parameter",
            );
        };

        let client = match self.authenticate_token_client(&req_headers, &form) {
            Ok(c) => c,
            Err(reply) => return *reply,
        };

        match form.get("grant_type").map(String::as_str) {
            Some("authorization_code") => self.handle_token_auth_code(client, form).await,
            Some("refresh_token") => self.handle_token_refresh(client, form).await,
            Some(_) => oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "grant_type is not supported",
            ),
            None => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "grant_type is required",
            ),
        }
    }

    async fn handle_token_auth_code(
        &self,
        client: RegisteredClient,
        form: BTreeMap<String, String>,
    ) -> HttpReply {
        if !client.grant_types.iter().any(|g| g == "authorization_code") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                "client is not authorized for authorization_code",
            );
        }
        let Some(raw_code) = form.get("code").filter(|c| !c.is_empty()).cloned() else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code is required",
            );
        };

        let code_hash = sha256_b64(&raw_code);

        self.run_uncancellable(move |core| async move {
            let now = unix_now();

            enum AuthCodePlan {
                Replay {
                    grant_id: String,
                    snapshot: Option<PersistedState>,
                },
                Issue {
                    snapshot: PersistedState,
                    grant_id: String,
                    access_token: String,
                    refresh_token: Option<String>,
                    expires_in: u64,
                    scopes: Vec<String>,
                },
                Reply(EarlyReply),
            }

            let plan = {
                let mut guard = core
                    .inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.prune_persisted(now);
                guard.prune_ephemeral(now);

                let replayed = guard
                    .consumed_codes
                    .iter()
                    .find(|c| constant_time_eq_str(&c.code_sha256, &code_hash))
                    .map(|c| c.grant_id.clone())
                    .or_else(|| {
                        guard.persisted.grants.iter().find_map(|g| {
                            let (h, exp) = g.consumed_code_sha256.as_ref()?;
                            (*exp > now && constant_time_eq_str(h, &code_hash))
                                .then(|| g.grant_id.clone())
                        })
                    });

                if let Some(replayed_grant_id) = replayed {
                    guard.record_consumed_code(
                        code_hash.clone(),
                        replayed_grant_id.clone(),
                        now.saturating_add(CONSUMED_CODE_TTL_SECS),
                    );
                    let snapshot = guard.remove_grant_immediate(&replayed_grant_id);
                    AuthCodePlan::Replay {
                        grant_id: replayed_grant_id,
                        snapshot,
                    }
                } else {
                    let mut make_plan = || -> AuthCodePlan {
                        let Some(code_verifier) =
                            form.get("code_verifier").filter(|v| !v.is_empty())
                        else {
                            return AuthCodePlan::Reply(Box::new(oauth_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_request",
                                "code_verifier is required",
                            )));
                        };

                        let requested_resource = match form.get("resource") {
                            None => None,
                            Some(raw_res) => {
                                match normalize_resource(&core.config, Some(raw_res)) {
                                    Ok(norm) => Some(norm),
                                    Err(()) => {
                                        return AuthCodePlan::Reply(Box::new(oauth_error(
                                            StatusCode::BAD_REQUEST,
                                            "invalid_target",
                                            "invalid resource target",
                                        )));
                                    }
                                }
                            }
                        };

                        let Some(code_pos) = guard
                            .auth_codes
                            .iter()
                            .position(|entry| constant_time_eq_str(&entry.code_sha256, &code_hash))
                        else {
                            return AuthCodePlan::Reply(Box::new(oauth_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_grant",
                                "unknown or expired authorization code",
                            )));
                        };

                        let (
                            code_client_id,
                            code_redirect_uri,
                            code_resource,
                            code_challenge,
                            code_scopes,
                        ) = {
                            let entry = &guard.auth_codes[code_pos];
                            (
                                entry.client_id.clone(),
                                entry.redirect_uri.clone(),
                                entry.resource.clone(),
                                entry.code_challenge.clone(),
                                entry.scopes.clone(),
                            )
                        };

                        if code_client_id != client.client_id {
                            guard.auth_codes.remove(code_pos);
                            return AuthCodePlan::Reply(Box::new(oauth_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_grant",
                                "authorization code was not issued to this client",
                            )));
                        }
                        if form.get("redirect_uri").map(String::as_str)
                            != Some(code_redirect_uri.as_str())
                        {
                            guard.auth_codes.remove(code_pos);
                            return AuthCodePlan::Reply(Box::new(oauth_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_grant",
                                "redirect_uri mismatch",
                            )));
                        }
                        if let Some(res) = requested_resource
                            && res != code_resource
                        {
                            guard.auth_codes.remove(code_pos);
                            return AuthCodePlan::Reply(Box::new(oauth_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_target",
                                "resource mismatch",
                            )));
                        }
                        if !verify_pkce_s256(code_verifier, &code_challenge) {
                            guard.auth_codes.remove(code_pos);
                            return AuthCodePlan::Reply(Box::new(oauth_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_grant",
                                "PKCE verification failed",
                            )));
                        }
                        if guard.persisted.grants.len() >= MAX_ACTIVE_GRANTS {
                            return AuthCodePlan::Reply(Box::new(oauth_error(
                                StatusCode::TOO_MANY_REQUESTS,
                                "temporarily_unavailable",
                                "maximum active grants reached",
                            )));
                        }

                        let (Ok(grant_suffix), Ok(access_token), Ok(family_key_b64)) = (
                            random_token_b64(18),
                            random_token_b64(32),
                            random_token_b64(32),
                        ) else {
                            return AuthCodePlan::Reply(Box::new(oauth_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "server_error",
                                "random generation failed",
                            )));
                        };

                        let grant_id = format!("grt_{grant_suffix}");
                        let max_expires_at =
                            now.saturating_add(core.config.oauth.max_grant_lifetime_secs);
                        let access_ttl = core.config.oauth.access_token_ttl_secs;
                        let refresh_ttl = core.config.oauth.refresh_token_ttl_secs;
                        let a0_expires_at = now.saturating_add(access_ttl).min(max_expires_at);
                        let issue_refresh = client.grant_types.iter().any(|g| g == "refresh_token");

                        let (refresh_token, current_refresh) = if issue_refresh {
                            let Ok(rt0) = mint_refresh_token(&grant_id, 0, &family_key_b64) else {
                                return AuthCodePlan::Reply(Box::new(oauth_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "server_error",
                                    "random generation failed",
                                )));
                            };
                            let r0_expires_at = now.saturating_add(refresh_ttl).min(max_expires_at);
                            let rec = RefreshTokenRecord {
                                r#gen: 0,
                                token_sha256: sha256_b64(&rt0),
                                expires_at: r0_expires_at,
                            };
                            (Some(rt0), Some(rec))
                        } else {
                            (None, None)
                        };

                        let pool_slot = guard.select_pool_slot(core.config.upstream.pool_size());
                        let grant = GrantRecord {
                            grant_id: grant_id.clone(),
                            client_id: client.client_id.clone(),
                            pool_slot,
                            scopes: code_scopes.clone(),
                            resource: code_resource,
                            issued_at: now,
                            max_expires_at,
                            family_key_b64,
                            current_gen: 0,
                            current_refresh,
                            grace_refreshes: Vec::new(),
                            access_tokens: vec![AccessTokenRecord {
                                token_sha256: sha256_b64(&access_token),
                                expires_at: a0_expires_at,
                                scopes: code_scopes.clone(),
                            }],
                            consumed_code_sha256: Some((
                                code_hash.clone(),
                                now.saturating_add(CONSUMED_CODE_TTL_SECS),
                            )),
                        };

                        let mut snapshot = guard.persisted.clone();
                        snapshot.grants.push(grant);
                        AuthCodePlan::Issue {
                            snapshot,
                            grant_id,
                            access_token,
                            refresh_token,
                            expires_in: a0_expires_at.saturating_sub(now).max(1),
                            scopes: code_scopes,
                        }
                    };
                    make_plan()
                }
            };

            match plan {
                AuthCodePlan::Reply(reply) => *reply,
                AuthCodePlan::Replay { grant_id, snapshot } => {
                    if let Some(snap) = snapshot {
                        core.notify_revoke(&grant_id);
                        if persist_snapshot(&core.store, snap).await.is_err() {
                            return oauth_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "server_error",
                                "failed to persist grant revocation",
                            );
                        }
                    }
                    oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "authorization code has already been used",
                    )
                }
                AuthCodePlan::Issue {
                    snapshot,
                    grant_id,
                    access_token,
                    refresh_token,
                    expires_in,
                    scopes,
                } => {
                    let Ok(persisted) = persist_snapshot(&core.store, snapshot).await else {
                        return oauth_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "server_error",
                            "failed to persist token grant",
                        );
                    };
                    {
                        let mut guard = core
                            .inner
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        guard.persisted = persisted;
                        guard.sync_indexes();
                        if let Some(pos) = guard
                            .auth_codes
                            .iter()
                            .position(|entry| constant_time_eq_str(&entry.code_sha256, &code_hash))
                        {
                            guard.auth_codes.remove(pos);
                        }
                        guard.record_consumed_code(
                            code_hash,
                            grant_id,
                            now.saturating_add(CONSUMED_CODE_TTL_SECS),
                        );
                    }
                    token_success_reply(
                        &access_token,
                        expires_in,
                        refresh_token.as_deref(),
                        &scopes,
                    )
                }
            }
        })
        .await
    }

    async fn handle_token_refresh(
        &self,
        client: RegisteredClient,
        form: BTreeMap<String, String>,
    ) -> HttpReply {
        if !client.grant_types.iter().any(|g| g == "refresh_token") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                "client is not authorized for refresh_token",
            );
        }
        let Some(raw_rt) = form.get("refresh_token").filter(|t| !t.is_empty()).cloned() else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "refresh_token is required",
            );
        };

        self.run_uncancellable(move |core| async move {
            let Some(parsed) = parse_refresh_token(&raw_rt) else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "unknown or expired refresh token",
                );
            };
            let rt_hash = sha256_b64(&raw_rt);
            let now = unix_now();

            enum RefreshPlan {
                Reply(EarlyReply),
                RevokeReplay {
                    grant_id: String,
                    snapshot: PersistedState,
                },
                PersistTip {
                    snapshot: PersistedState,
                    grant_id: String,
                    tip: RotatedTip,
                },
            }

            let plan = {
                let mut guard = core
                    .inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.prune_persisted(now);
                guard.prune_ephemeral(now);

                let mut make_plan = || -> RefreshPlan {
                    let Some(&grant_idx) = guard.grant_index.get(parsed.grant_id) else {
                        return RefreshPlan::Reply(Box::new(oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "unknown or expired refresh token",
                        )));
                    };
                    let grant = &guard.persisted.grants[grant_idx];
                    if !verify_refresh_family_tag(&parsed, &grant.family_key_b64) {
                        return RefreshPlan::Reply(Box::new(oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "unknown or expired refresh token",
                        )));
                    }
                    if grant.client_id != client.client_id {
                        return RefreshPlan::Reply(Box::new(oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "refresh token was not issued to this client",
                        )));
                    }
                    if grant.resource != core.config.mcp_resource_url() {
                        return RefreshPlan::Reply(Box::new(oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "refresh token targets a previous resource URL",
                        )));
                    }
                    if now >= grant.max_expires_at {
                        return RefreshPlan::Reply(Box::new(oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "grant has reached maximum lifetime",
                        )));
                    }

                    let grant_id = grant.grant_id.clone();
                    let grace_secs = core.config.oauth.refresh_grace_secs;

                    if parsed.r#gen > grant.current_gen {
                        return RefreshPlan::Reply(Box::new(oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "unknown or expired refresh token",
                        )));
                    }

                    if parsed.r#gen < grant.current_gen {
                        let within_grace = grace_secs > 0
                            && grant.grace_refreshes.iter().any(|gr| {
                                gr.r#gen == parsed.r#gen
                                    && now <= gr.grace_until
                                    && constant_time_eq_str(&gr.token_sha256, &rt_hash)
                            });
                        if !within_grace
                            && core.config.oauth.refresh_reuse_policy == RefreshReusePolicy::Revoke
                        {
                            let snap = guard
                                .remove_grant_immediate(&grant_id)
                                .expect("grant_idx matched");
                            return RefreshPlan::RevokeReplay {
                                grant_id,
                                snapshot: snap,
                            };
                        }

                        // Ensure the active tip has not expired before converging an older generation.
                        let tip_live = grant.current_refresh.as_ref().is_some_and(|cur| {
                            cur.r#gen == grant.current_gen && cur.expires_at > now
                        });
                        if !tip_live {
                            return RefreshPlan::Reply(Box::new(oauth_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_grant",
                                "unknown or expired refresh token",
                            )));
                        }

                        let effective_scopes =
                            match validate_refresh_scope_and_resource(&core.config, grant, &form) {
                                Ok(scopes) => scopes,
                                Err(reply) => return RefreshPlan::Reply(reply),
                            };
                        if within_grace && effective_scopes.len() != grant.scopes.len() {
                            return RefreshPlan::Reply(Box::new(oauth_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_scope",
                                "refresh retry cannot narrow the current scope",
                            )));
                        }

                        if let Some(cached) = guard.grace_cache.get(&grant_id).cloned()
                            && cached.tip_gen == grant.current_gen
                            && cached.a_expires_at > now
                            && cached.scopes.len() == effective_scopes.len()
                            && cached.scopes.iter().all(|s| effective_scopes.contains(s))
                        {
                            let rem_ttl = cached.a_expires_at.saturating_sub(now).max(1);
                            return RefreshPlan::Reply(Box::new(token_success_reply(
                                &cached.access_token,
                                rem_ttl,
                                Some(&cached.refresh_token),
                                &cached.scopes,
                            )));
                        }

                        let mut snapshot = guard.persisted.clone();
                        let target_grant = &mut snapshot.grants[grant_idx];
                        let Ok(tip) = rotate_grant_tip(
                            target_grant,
                            effective_scopes,
                            now,
                            core.config.oauth.access_token_ttl_secs,
                            core.config.oauth.refresh_token_ttl_secs,
                            grace_secs,
                            core.config.oauth.refresh_reuse_policy,
                        ) else {
                            return RefreshPlan::Reply(Box::new(oauth_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "server_error",
                                "random generation failed",
                            )));
                        };

                        return RefreshPlan::PersistTip {
                            snapshot,
                            grant_id,
                            tip,
                        };
                    }

                    // Active tip: parsed.gen == grant.current_gen.
                    let Some(cur_rt) = &grant.current_refresh else {
                        return RefreshPlan::Reply(Box::new(oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "unknown or expired refresh token",
                        )));
                    };
                    if cur_rt.r#gen != grant.current_gen
                        || cur_rt.expires_at <= now
                        || !constant_time_eq_str(&cur_rt.token_sha256, &rt_hash)
                    {
                        return RefreshPlan::Reply(Box::new(oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "unknown or expired refresh token",
                        )));
                    }

                    let effective_scopes =
                        match validate_refresh_scope_and_resource(&core.config, grant, &form) {
                            Ok(s) => s,
                            Err(reply) => return RefreshPlan::Reply(reply),
                        };

                    let mut snapshot = guard.persisted.clone();
                    let target_grant = &mut snapshot.grants[grant_idx];
                    let Ok(tip) = rotate_grant_tip(
                        target_grant,
                        effective_scopes,
                        now,
                        core.config.oauth.access_token_ttl_secs,
                        core.config.oauth.refresh_token_ttl_secs,
                        grace_secs,
                        core.config.oauth.refresh_reuse_policy,
                    ) else {
                        return RefreshPlan::Reply(Box::new(oauth_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "server_error",
                            "random generation failed",
                        )));
                    };

                    RefreshPlan::PersistTip {
                        snapshot,
                        grant_id,
                        tip,
                    }
                };
                make_plan()
            };

            match plan {
                RefreshPlan::Reply(reply) => *reply,
                RefreshPlan::RevokeReplay { grant_id, snapshot } => {
                    core.notify_revoke(&grant_id);
                    if persist_snapshot(&core.store, snapshot).await.is_err() {
                        return oauth_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "server_error",
                            "failed to persist grant revocation",
                        );
                    }
                    oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "refresh token reuse detected",
                    )
                }
                RefreshPlan::PersistTip {
                    snapshot,
                    grant_id,
                    tip,
                } => {
                    let Ok(persisted) = persist_snapshot(&core.store, snapshot).await else {
                        return oauth_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "server_error",
                            "failed to persist rotated token",
                        );
                    };
                    {
                        let mut guard = core
                            .inner
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        guard.persisted = persisted;
                        guard.sync_indexes();
                        if let Some(entry) = tip.cache_entry {
                            guard.insert_grace_cache(grant_id, entry);
                        }
                    }
                    token_success_reply(
                        &tip.access_token,
                        tip.expires_in,
                        Some(&tip.refresh_token),
                        &tip.scopes,
                    )
                }
            }
        })
        .await
    }

    async fn handle_revoke(&self, req: Request<Incoming>) -> HttpReply {
        if !has_media_type(req.headers(), "application/x-www-form-urlencoded") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Content-Type must be application/x-www-form-urlencoded",
            );
        }
        let req_headers = req.headers().clone();
        let body = match read_limited_body(req).await {
            Ok(bytes) => bytes,
            Err(err) => return body_error_json(err),
        };
        let Ok(form) = parse_unique_form(&body) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "duplicate or malformed form parameter",
            );
        };

        let authed_client = match self.authenticate_token_client(&req_headers, &form) {
            Ok(c) => c,
            Err(reply) => return *reply,
        };

        let Some(raw_token) = form.get("token").cloned() else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token parameter is required",
            );
        };
        if raw_token.is_empty() {
            return empty_ok_reply();
        }

        self.run_uncancellable(move |core| async move {
            let token_hash = sha256_b64(&raw_token);
            let now = unix_now();

            let revoked_plan = {
                let mut guard = core
                    .inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.prune_persisted(now);
                guard.prune_ephemeral(now);

                let matched_grant_id = guard.access_index.get(&token_hash).cloned().or_else(|| {
                    let parsed = parse_refresh_token(&raw_token)?;
                    let &idx = guard.grant_index.get(parsed.grant_id)?;
                    let grant = &guard.persisted.grants[idx];
                    if parsed.r#gen == grant.current_gen {
                        let cur = grant.current_refresh.as_ref()?;
                        (cur.r#gen == grant.current_gen
                            && constant_time_eq_str(&cur.token_sha256, &token_hash)
                            && verify_refresh_family_tag(&parsed, &grant.family_key_b64))
                        .then(|| grant.grant_id.clone())
                    } else if parsed.r#gen < grant.current_gen {
                        verify_refresh_family_tag(&parsed, &grant.family_key_b64)
                            .then(|| grant.grant_id.clone())
                    } else {
                        None
                    }
                });

                let Some(grant_id) = matched_grant_id else {
                    return empty_ok_reply();
                };
                let Some(&idx) = guard.grant_index.get(&grant_id) else {
                    return empty_ok_reply();
                };
                if guard.persisted.grants[idx].client_id != authed_client.client_id {
                    return empty_ok_reply();
                }

                let snapshot = guard
                    .remove_grant_immediate(&grant_id)
                    .expect("grant_id matched");
                (grant_id, snapshot)
            };

            let (grant_id, snapshot) = revoked_plan;
            core.notify_revoke(&grant_id);
            if persist_snapshot(&core.store, snapshot).await.is_err() {
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "failed to persist grant revocation",
                );
            }
            empty_ok_reply()
        })
        .await
    }

    fn authenticate_token_client(
        &self,
        headers: &HeaderMap,
        form: &BTreeMap<String, String>,
    ) -> Result<RegisteredClient, EarlyReply> {
        let basic_creds = parse_basic_auth(headers)?;
        let form_client_id = form.get("client_id").map(String::as_str);
        let form_secret = form.get("client_secret").map(String::as_str);

        if basic_creds.is_some() && form_secret.is_some() {
            return Err(Box::new(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "multiple client authentication methods provided",
            )));
        }

        let client_id = match (&basic_creds, form_client_id) {
            (Some((b_id, _)), Some(f_id)) => {
                if b_id != f_id {
                    return Err(Box::new(oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "mismatched client_id between header and body",
                    )));
                }
                b_id.as_str()
            }
            (Some((b_id, _)), None) => b_id.as_str(),
            (None, Some(f_id)) if !f_id.is_empty() => f_id,
            _ => {
                return Err(Box::new(invalid_client_reply(false, "missing client_id")));
            }
        };

        let used_basic = basic_creds.is_some();
        let client_opt = {
            let guard = self
                .core
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard
                .persisted
                .clients
                .iter()
                .find(|c| c.client_id == client_id)
                .cloned()
        };

        let Some(client) = client_opt else {
            return Err(Box::new(invalid_client_reply(used_basic, "unknown client")));
        };

        match client.token_endpoint_auth_method.as_str() {
            "client_secret_basic" => {
                let Some((_, secret)) = &basic_creds else {
                    return Err(Box::new(invalid_client_reply(
                        true,
                        "Basic authentication required",
                    )));
                };
                let Some(expected_hash) = &client.client_secret_sha256 else {
                    return Err(Box::new(invalid_client_reply(
                        true,
                        "client secret missing",
                    )));
                };
                let candidate_hash = sha256_b64(secret);
                if secret.is_empty() || !constant_time_eq_str(&candidate_hash, expected_hash) {
                    return Err(Box::new(invalid_client_reply(
                        true,
                        "invalid client credentials",
                    )));
                }
            }
            "client_secret_post" => {
                if used_basic {
                    return Err(Box::new(invalid_client_reply(
                        true,
                        "client requires client_secret_post",
                    )));
                }
                let Some(secret) = form_secret.filter(|s| !s.is_empty()) else {
                    return Err(Box::new(invalid_client_reply(
                        false,
                        "client_secret is required",
                    )));
                };
                let Some(expected_hash) = &client.client_secret_sha256 else {
                    return Err(Box::new(invalid_client_reply(
                        false,
                        "client secret missing",
                    )));
                };
                let candidate_hash = sha256_b64(secret);
                if !constant_time_eq_str(&candidate_hash, expected_hash) {
                    return Err(Box::new(invalid_client_reply(
                        false,
                        "invalid client credentials",
                    )));
                }
            }
            "none" => {
                if let Some((_, secret)) = &basic_creds
                    && !secret.is_empty()
                {
                    return Err(Box::new(invalid_client_reply(
                        true,
                        "public client has no client_secret",
                    )));
                }
                if form_secret.is_some_and(|s| !s.is_empty()) {
                    return Err(Box::new(invalid_client_reply(
                        false,
                        "public client has no client_secret",
                    )));
                }
            }
            _ => {
                return Err(Box::new(invalid_client_reply(
                    used_basic,
                    "unsupported client auth method",
                )));
            }
        }

        Ok(client)
    }
}

async fn persist_snapshot(
    store: &StateStore,
    snapshot: PersistedState,
) -> Result<PersistedState, ()> {
    let store_clone = store.clone();
    let to_save = snapshot.clone();
    match tokio::task::spawn_blocking(move || store_clone.save(&to_save)).await {
        Ok(Ok(())) => Ok(snapshot),
        Ok(Err(err)) => {
            eprintln!("oauth2-mcp-gateway: failed to persist OAuth state: {err}");
            Err(())
        }
        Err(err) => {
            eprintln!("oauth2-mcp-gateway: state persistence task failed: {err}");
            Err(())
        }
    }
}

fn rotate_grant_tip(
    grant: &mut GrantRecord,
    effective_scopes: Vec<String>,
    now: u64,
    access_ttl: u64,
    refresh_ttl: u64,
    grace_secs: u64,
    reuse_policy: RefreshReusePolicy,
) -> Result<RotatedTip, ()> {
    let next_gen = grant.current_gen.checked_add(1).ok_or(())?;
    let a_new = random_token_b64(32).map_err(|_| ())?;
    let r_new = mint_refresh_token(&grant.grant_id, next_gen, &grant.family_key_b64)?;

    if let Some(prev_rt) = grant.current_refresh.take()
        && grace_secs > 0
    {
        let gu = prev_rt.expires_at.min(now.saturating_add(grace_secs));
        if gu >= now {
            grant.grace_refreshes.push(GraceRefreshRecord {
                r#gen: prev_rt.r#gen,
                token_sha256: prev_rt.token_sha256,
                grace_until: gu,
            });
        }
    }
    grant.grace_refreshes.retain(|gr| gr.grace_until >= now);
    if grant.grace_refreshes.len() > MAX_GRACE_REFRESHES {
        let excess = grant.grace_refreshes.len() - MAX_GRACE_REFRESHES;
        grant.grace_refreshes.drain(0..excess);
    }

    let a_expires_at = now.saturating_add(access_ttl).min(grant.max_expires_at);
    let r_expires_at = now.saturating_add(refresh_ttl).min(grant.max_expires_at);

    grant.current_gen = next_gen;
    grant.current_refresh = Some(RefreshTokenRecord {
        r#gen: next_gen,
        token_sha256: sha256_b64(&r_new),
        expires_at: r_expires_at,
    });
    grant.access_tokens.push(AccessTokenRecord {
        token_sha256: sha256_b64(&a_new),
        expires_at: a_expires_at,
        scopes: effective_scopes.clone(),
    });
    if grant.access_tokens.len() > MAX_ACCESS_TOKENS_PER_GRANT {
        let excess = grant.access_tokens.len() - MAX_ACCESS_TOKENS_PER_GRANT;
        grant.access_tokens.drain(0..excess);
    }

    let cache_entry = (grace_secs > 0 || reuse_policy == RefreshReusePolicy::Converge).then(|| {
        let max_gu = grant
            .grace_refreshes
            .iter()
            .map(|gr| gr.grace_until)
            .max()
            .unwrap_or_else(|| r_expires_at.min(now.saturating_add(grace_secs)));
        let cache_until = if reuse_policy == RefreshReusePolicy::Converge {
            max_gu.max(a_expires_at)
        } else {
            max_gu
        };
        GraceCacheEntry {
            tip_gen: next_gen,
            access_token: a_new.clone(),
            refresh_token: r_new.clone(),
            a_expires_at,
            scopes: effective_scopes.clone(),
            grace_until: cache_until,
        }
    });

    let expires_in = a_expires_at.saturating_sub(now).max(1);
    Ok(RotatedTip {
        access_token: a_new,
        refresh_token: r_new,
        expires_in,
        scopes: effective_scopes,
        cache_entry,
    })
}

fn mint_refresh_token(grant_id: &str, generation: u64, family_key_b64: &str) -> Result<String, ()> {
    let mut family_key = URL_SAFE_NO_PAD.decode(family_key_b64).map_err(|_| ())?;
    if family_key.len() != 32 {
        zeroize_bytes(&mut family_key);
        return Err(());
    }
    let nonce = random_token_b64(32).map_err(|_| ())?;
    let signing_input = format!("{grant_id}.{generation}.{nonce}");
    let mut mac = hmac_sha256(&family_key, signing_input.as_bytes());
    zeroize_bytes(&mut family_key);
    let tag = URL_SAFE_NO_PAD.encode(mac);
    zeroize_bytes(&mut mac);
    Ok(format!("rt1.{grant_id}.{generation}.{nonce}.{tag}"))
}

fn parse_refresh_token(raw: &str) -> Option<ParsedRefreshToken<'_>> {
    let mut parts = raw.split('.');
    let prefix = parts.next()?;
    let grant_id = parts.next()?;
    let gen_str = parts.next()?;
    let nonce = parts.next()?;
    let tag = parts.next()?;
    if parts.next().is_some()
        || prefix != "rt1"
        || grant_id.is_empty()
        || gen_str.is_empty()
        || (gen_str.len() > 1 && gen_str.starts_with('0'))
        || nonce.is_empty()
        || tag.is_empty()
    {
        return None;
    }
    let r#gen = gen_str.parse::<u64>().ok()?;
    Some(ParsedRefreshToken {
        grant_id,
        r#gen,
        nonce,
        tag,
    })
}

fn verify_refresh_family_tag(parsed: &ParsedRefreshToken<'_>, family_key_b64: &str) -> bool {
    let Ok(mut family_key) = URL_SAFE_NO_PAD.decode(family_key_b64) else {
        return false;
    };
    if family_key.len() != 32 {
        zeroize_bytes(&mut family_key);
        return false;
    }
    let signing_input = format!("{}.{}.{}", parsed.grant_id, parsed.r#gen, parsed.nonce);
    let mut mac = hmac_sha256(&family_key, signing_input.as_bytes());
    zeroize_bytes(&mut family_key);
    let expected_tag = URL_SAFE_NO_PAD.encode(mac);
    zeroize_bytes(&mut mac);
    constant_time_eq_str(parsed.tag, &expected_tag)
}

fn validate_refresh_scope_and_resource(
    config: &GatewayConfig,
    grant: &GrantRecord,
    form: &BTreeMap<String, String>,
) -> Result<Vec<String>, EarlyReply> {
    if let Some(raw_res) = form.get("resource") {
        let Ok(norm) = normalize_resource(config, Some(raw_res)) else {
            return Err(Box::new(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "invalid resource target",
            )));
        };
        if norm != grant.resource {
            return Err(Box::new(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource does not match grant",
            )));
        }
    }

    match form.get("scope") {
        None => Ok(grant.scopes.clone()),
        Some(raw_scope) => {
            let Some(parsed) = parse_scope_list(raw_scope, &grant.scopes) else {
                return Err(Box::new(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "requested scope exceeds granted scope",
                )));
            };
            Ok(parsed)
        }
    }
}

fn is_forbidden_display_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn extract_raw_host_and_path(raw: &str) -> Option<(&str, &str)> {
    if raw.is_empty()
        || raw.contains('\\')
        || raw.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let (_, after_scheme) = raw.split_once("://")?;
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let raw_host = if authority.starts_with('[') {
        let close = authority.find(']')?;
        let port_part = &authority[close + 1..];
        if let Some(port) = port_part.strip_prefix(':') {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
        } else if !port_part.is_empty() {
            return None;
        }
        &authority[..=close]
    } else if let Some((h, port)) = authority.split_once(':') {
        if h.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        h
    } else {
        authority
    };
    let rest = &after_scheme[authority_end..];
    let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
    Some((raw_host, &rest[..path_end]))
}

fn has_clean_url_path(raw_path: &str) -> bool {
    if raw_path.is_empty() {
        return true;
    }
    for seg in raw_path.split('/') {
        if seg == "." || seg == ".." {
            return false;
        }
        let bytes = seg.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                if i + 2 >= bytes.len() {
                    return false;
                }
                let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
                else {
                    return false;
                };
                let b = (hi << 4) | lo;
                if b == 0 || b == b'/' || b == b'\\' {
                    return false;
                }
                decoded.push(b);
                i += 3;
            } else {
                decoded.push(bytes[i]);
                i += 1;
            }
        }
        if decoded == b"." || decoded == b".." {
            return false;
        }
    }
    true
}

fn is_canonical_host(raw_host: &str, parsed_host: &str) -> bool {
    if raw_host.contains('%') || raw_host.ends_with('.') {
        return false;
    }
    if raw_host.is_ascii() {
        raw_host.eq_ignore_ascii_case(parsed_host)
    } else {
        url::Host::parse(raw_host).is_ok_and(|h| h.to_string().eq_ignore_ascii_case(parsed_host))
    }
}

fn is_allowed_redirect_uri(config: &GatewayConfig, raw: &str) -> bool {
    let Some((raw_host, raw_path)) = extract_raw_host_and_path(raw) else {
        return false;
    };
    if !has_clean_url_path(raw_path) {
        return false;
    }
    let Ok(parsed) = Url::parse(raw) else {
        return false;
    };
    if parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query_pairs().any(|(key, _)| {
            matches!(
                key.as_ref(),
                "code" | "iss" | "state" | "error" | "error_description" | "error_uri"
            )
        })
    {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if !is_canonical_host(raw_host, host) {
        return false;
    }
    if extract_explicit_port(raw).is_some_and(|p| p == 0) {
        return false;
    }
    if is_loopback_host(host) {
        return matches!(parsed.scheme(), "http" | "https");
    }
    if parsed.scheme() != "https" {
        return false;
    }
    if config.oauth.allowed_redirect_hosts.is_empty() {
        return true;
    }
    let lower_host = host.to_ascii_lowercase();
    config
        .oauth
        .allowed_redirect_hosts
        .iter()
        .any(|allowed| allowed == &lower_host)
}

fn extract_explicit_port(raw: &str) -> Option<u16> {
    let (_, after_scheme) = raw.split_once("://")?;
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let port_str = if authority.starts_with('[') {
        let close = authority.find(']')?;
        authority[close + 1..].strip_prefix(':')?
    } else {
        authority.split_once(':')?.1
    };
    port_str.parse::<u16>().ok()
}

fn parse_http_literal_loopback_target(raw: &str) -> Option<(IpAddr, String, Option<String>)> {
    let (raw_host, raw_path) = extract_raw_host_and_path(raw)?;
    if !has_clean_url_path(raw_path) || extract_explicit_port(raw).is_some_and(|p| p == 0) {
        return None;
    }
    let parsed = Url::parse(raw).ok()?;
    if parsed.scheme() != "http"
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    let host_str = parsed.host_str()?;
    if !is_canonical_host(raw_host, host_str) {
        return None;
    }
    let ip = match parsed.host()? {
        url::Host::Ipv4(v4) if v4 == Ipv4Addr::LOCALHOST => IpAddr::V4(v4),
        url::Host::Ipv6(v6) if v6 == Ipv6Addr::LOCALHOST => IpAddr::V6(v6),
        _ => return None,
    };
    let norm_path = if raw_path.is_empty() {
        "/".to_owned()
    } else {
        raw_path.to_owned()
    };
    Some((ip, norm_path, parsed.query().map(str::to_owned)))
}

fn matches_registered_redirect_uri(registered_uris: &[String], candidate: &str) -> bool {
    if registered_uris.iter().any(|u| u == candidate) {
        return true;
    }
    let Some(cand_target) = parse_http_literal_loopback_target(candidate) else {
        return false;
    };
    registered_uris
        .iter()
        .filter_map(|u| parse_http_literal_loopback_target(u))
        .any(|reg_target| reg_target == cand_target)
}

fn normalize_resource(config: &GatewayConfig, raw: Option<&str>) -> Result<String, ()> {
    let mcp_url = config.mcp_resource_url();
    let Some(val) = raw else {
        return Ok(mcp_url);
    };
    let (raw_host, raw_path) = extract_raw_host_and_path(val).ok_or(())?;
    if !has_clean_url_path(raw_path) {
        return Err(());
    }
    let parsed = Url::parse(val).map_err(|_| ())?;
    if parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(());
    }
    let parsed_host = parsed.host_str().ok_or(())?;
    if !is_canonical_host(raw_host, parsed_host) {
        return Err(());
    }
    if !parsed
        .origin()
        .ascii_serialization()
        .eq_ignore_ascii_case(&config.public_url)
    {
        return Err(());
    }
    if parsed.path() == "/" || parsed.path() == config.resource_path {
        Ok(mcp_url)
    } else {
        Err(())
    }
}

fn authorize_error_redirect(
    config: &GatewayConfig,
    redirect_uri: &str,
    error_code: &str,
    state: Option<&str>,
) -> HttpReply {
    let Ok(mut location) = Url::parse(redirect_uri) else {
        return html_status_reply(StatusCode::BAD_REQUEST, "Invalid redirect_uri");
    };
    {
        let mut pairs = location.query_pairs_mut();
        pairs.append_pair("error", error_code);
        pairs.append_pair("iss", &config.public_url);
        if let Some(st) = state {
            pairs.append_pair("state", st);
        }
    }
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location.as_str())
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(empty_body())
        .expect("valid 303 error redirect")
}

fn finish_authorize_redirect(
    req_headers: &HeaderMap,
    clear_cookie: &str,
    location: &Url,
) -> HttpReply {
    if is_navigate_fetch_mode(req_headers) {
        // Chromium applies form-action to POST redirects; meta-refresh navigates cleanly.
        let callback = escape_html(location.as_str());
        let html = format!(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>Continue</title><meta http-equiv=\"refresh\" content=\"0;url={callback}\">\
             </head><body><a href=\"{callback}\">Continue</a></body></html>"
        );
        return html_reply_with_cookie(StatusCode::OK, html, Some(clear_cookie));
    }

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location.as_str())
        .header(header::SET_COOKIE, clear_cookie)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(empty_body())
        .expect("valid 303 response")
}

fn is_navigate_fetch_mode(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-mode")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|mode| mode.trim_ascii().eq_ignore_ascii_case("navigate"))
}

fn ar_cookie_name(public_is_https: bool, ar_id: &str) -> String {
    if public_is_https {
        format!("__Host-mcp_ar_{ar_id}")
    } else {
        format!("mcp_ar_{ar_id}")
    }
}

fn build_ar_cookie(public_is_https: bool, ar_id: &str, csrf_token: &str, max_age: u64) -> String {
    let name = ar_cookie_name(public_is_https, ar_id);
    if public_is_https {
        format!("{name}={csrf_token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax")
    } else {
        format!(
            "{name}={csrf_token}; Path=/oauth/authorize; Max-Age={max_age}; HttpOnly; SameSite=Lax"
        )
    }
}

fn auth_form_aad(public_url: &str, nonce_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(public_url.len() + 1 + nonce_id.len());
    aad.extend_from_slice(public_url.as_bytes());
    aad.push(0);
    aad.extend_from_slice(nonce_id.as_bytes());
    aad
}

fn is_trusted_proxy(trusted_proxies: &[IpNet], ip: IpAddr) -> bool {
    trusted_proxies.iter().any(|net| net.contains(ip))
}

fn extract_single_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let mut iter = headers.get_all("x-real-ip").iter();
    let raw_hdr = iter.next()?;
    if iter.next().is_some() {
        return None;
    }
    let trimmed = raw_hdr.to_str().ok()?.trim_ascii();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

fn resolve_rate_limit_ip(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[IpNet],
) -> (IpAddr, bool) {
    let Some(raw_peer) = peer_ip else {
        return (IpAddr::V4(Ipv4Addr::UNSPECIFIED), false);
    };
    let peer = raw_peer.to_canonical();
    if trusted_proxies.is_empty() {
        return (peer, peer.is_loopback());
    }
    if !is_trusted_proxy(trusted_proxies, peer) {
        return (peer, false);
    }

    let xff_headers: Vec<&http::HeaderValue> = headers.get_all("x-forwarded-for").iter().collect();
    if !xff_headers.is_empty() {
        let mut rightmost_valid: Option<IpAddr> = None;
        let mut malformed = false;
        'outer: for hdr in xff_headers.into_iter().rev() {
            let Ok(raw) = hdr.to_str() else {
                malformed = true;
                break;
            };
            for part in raw.rsplit(',') {
                let trimmed = part.trim_ascii();
                if trimmed.is_empty() {
                    continue;
                }
                let Ok(parsed) = trimmed.parse::<IpAddr>() else {
                    malformed = true;
                    break 'outer;
                };
                let canonical = parsed.to_canonical();
                rightmost_valid = Some(canonical);
                if !is_trusted_proxy(trusted_proxies, canonical) {
                    return (canonical, false);
                }
            }
        }
        if malformed {
            let fallback = rightmost_valid.unwrap_or(peer);
            return (fallback, false);
        }
        if let Some(real_ip) = extract_single_real_ip(headers)
            && !is_trusted_proxy(trusted_proxies, real_ip)
        {
            return (real_ip, false);
        }
        if let Some(valid) = rightmost_valid {
            return (valid, valid.is_loopback());
        }
    }

    if let Some(real_ip) = extract_single_real_ip(headers) {
        if !is_trusted_proxy(trusted_proxies, real_ip) {
            return (real_ip, false);
        }
        return (real_ip, real_ip.is_loopback());
    }

    (peer, peer.is_loopback())
}

fn verify_check_bearer(headers: &HeaderMap, expected_token_sha256: &[u8; 32]) -> bool {
    let mut iter = headers.get_all(header::AUTHORIZATION).iter();
    let Some(raw_hdr) = iter.next() else {
        return false;
    };
    if iter.next().is_some() {
        return false;
    }
    let Ok(hdr_str) = raw_hdr.to_str() else {
        return false;
    };
    let Some(rest) = strip_bearer_prefix(hdr_str.trim_ascii()) else {
        return false;
    };
    let token = rest.trim_ascii();
    if token.is_empty() || !token.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return false;
    }
    constant_time_sha256_eq(token, expected_token_sha256)
}

fn strip_bearer_prefix(header_val: &str) -> Option<&str> {
    if header_val.len() < 7 {
        return None;
    }
    let (scheme, rest) = header_val.split_at(6);
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let first = rest.as_bytes().first().copied()?;
    if !first.is_ascii_whitespace() {
        return None;
    }
    Some(&rest[1..])
}

fn parse_basic_auth(headers: &HeaderMap) -> Result<Option<(String, String)>, EarlyReply> {
    let mut iter = headers.get_all(header::AUTHORIZATION).iter();
    let Some(raw) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(Box::new(invalid_client_reply(
            true,
            "multiple Authorization headers provided",
        )));
    }
    let Ok(val) = raw.to_str() else {
        return Err(Box::new(invalid_client_reply(
            true,
            "malformed Authorization header",
        )));
    };
    let trimmed = val.trim_ascii();
    if trimmed.len() < 6 || !trimmed[..5].eq_ignore_ascii_case("basic") {
        return Err(Box::new(invalid_client_reply(
            true,
            "unsupported Authorization scheme",
        )));
    }
    let rest = &trimmed[5..];
    if !rest.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
        return Err(Box::new(invalid_client_reply(
            true,
            "malformed Basic credentials",
        )));
    }
    let b64 = rest.trim_ascii();
    if b64.is_empty() {
        return Err(Box::new(invalid_client_reply(
            true,
            "empty Basic credentials",
        )));
    }
    let decoded_bytes = STANDARD
        .decode(b64)
        .or_else(|_| STANDARD_NO_PAD.decode(b64))
        .map_err(|_| {
            Box::new(invalid_client_reply(
                true,
                "invalid Base64 in Basic credentials",
            ))
        })?;
    let mut decoded_str = String::from_utf8(decoded_bytes)
        .map_err(|_| Box::new(invalid_client_reply(true, "non-UTF-8 Basic credentials")))?;

    if let Some((raw_id, raw_secret)) = decoded_str.split_once(':') {
        let id_res = form_urldecode_component(raw_id);
        let sec_res = form_urldecode_component(raw_secret);
        zeroize_string(&mut decoded_str);
        let client_id = id_res.map_err(|()| {
            Box::new(invalid_client_reply(
                true,
                "invalid URL encoding in client_id",
            ))
        })?;
        let client_secret = sec_res.map_err(|()| {
            Box::new(invalid_client_reply(
                true,
                "invalid URL encoding in client_secret",
            ))
        })?;
        return Ok(Some((client_id, client_secret)));
    }

    let unescaped_res = form_urldecode_component(&decoded_str);
    zeroize_string(&mut decoded_str);
    let mut unescaped = unescaped_res.map_err(|()| {
        Box::new(invalid_client_reply(
            true,
            "invalid Basic credential encoding",
        ))
    })?;
    let Some((client_id, client_secret)) = unescaped.split_once(':') else {
        zeroize_string(&mut unescaped);
        return Err(Box::new(invalid_client_reply(
            true,
            "Basic credentials missing colon separator",
        )));
    };
    let out = (client_id.to_owned(), client_secret.to_owned());
    zeroize_string(&mut unescaped);
    Ok(Some(out))
}

fn form_urldecode_component(input: &str) -> Result<String, ()> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        match bytes[idx] {
            b'+' => {
                out.push(b' ');
                idx += 1;
            }
            b'%' => {
                if idx + 2 >= bytes.len() {
                    return Err(());
                }
                let hi = hex_nibble(bytes[idx + 1]).ok_or(())?;
                let lo = hex_nibble(bytes[idx + 2]).ok_or(())?;
                out.push((hi << 4) | lo);
                idx += 3;
            }
            b => {
                out.push(b);
                idx += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

enum BodyReadError {
    InvalidContentLength,
    TooLarge,
    ReadFailed,
    Timeout,
}

async fn read_limited_body(req: Request<Incoming>) -> Result<Bytes, BodyReadError> {
    read_limited_body_with(req, MAX_POST_BODY_BYTES, OAUTH_BODY_TIMEOUT).await
}

async fn read_limited_body_with(
    req: Request<Incoming>,
    max_bytes: usize,
    timeout_dur: Duration,
) -> Result<Bytes, BodyReadError> {
    match check_content_length_limit(req.headers(), max_bytes as u64) {
        ContentLengthCheck::Ok => {}
        ContentLengthCheck::Invalid => return Err(BodyReadError::InvalidContentLength),
        ContentLengthCheck::TooLarge => return Err(BodyReadError::TooLarge),
    }
    if req.body().size_hint().lower() > max_bytes as u64 {
        return Err(BodyReadError::TooLarge);
    }

    let limited = Limited::new(req.into_body(), max_bytes);
    match tokio::time::timeout(timeout_dur, limited.collect()).await {
        Ok(Ok(collected)) => Ok(collected.to_bytes()),
        Ok(Err(err)) if err.is::<LengthLimitError>() => Err(BodyReadError::TooLarge),
        Ok(Err(_)) => Err(BodyReadError::ReadFailed),
        Err(_) => Err(BodyReadError::Timeout),
    }
}

fn with_connection_close(mut reply: HttpReply) -> HttpReply {
    reply.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    reply
}

fn body_error_json(err: BodyReadError) -> HttpReply {
    match err {
        BodyReadError::InvalidContentLength => with_connection_close(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid Content-Length header",
        )),
        BodyReadError::TooLarge => with_connection_close(oauth_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "request body exceeds 64 KiB limit",
        )),
        BodyReadError::ReadFailed => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "failed to read request body",
        ),
        BodyReadError::Timeout => with_connection_close(oauth_error(
            StatusCode::REQUEST_TIMEOUT,
            "invalid_request",
            "OAuth request body read timed out",
        )),
    }
}

fn body_error_html(err: BodyReadError) -> HttpReply {
    match err {
        BodyReadError::InvalidContentLength => with_connection_close(html_status_reply(
            StatusCode::BAD_REQUEST,
            "Invalid Content-Length header",
        )),
        BodyReadError::TooLarge => with_connection_close(html_status_reply(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request body exceeds 64 KiB limit",
        )),
        BodyReadError::ReadFailed => {
            html_status_reply(StatusCode::BAD_REQUEST, "Failed to read request body")
        }
        BodyReadError::Timeout => with_connection_close(html_status_reply(
            StatusCode::REQUEST_TIMEOUT,
            "OAuth request body read timed out",
        )),
    }
}

fn has_media_type(headers: &HeaderMap, expected: &str) -> bool {
    let Some(raw) = headers.get(header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(text) = raw.to_str() else {
        return false;
    };
    let media = text.split(';').next().unwrap_or("").trim_ascii();
    media.eq_ignore_ascii_case(expected)
}

fn parse_unique_form(bytes: &[u8]) -> Result<BTreeMap<String, String>, ()> {
    if std::str::from_utf8(bytes).is_err() {
        return Err(());
    }
    let mut map = BTreeMap::new();
    for (k, v) in form_urlencoded::parse(bytes) {
        if map.insert(k.into_owned(), v.into_owned()).is_some() {
            return Err(());
        }
    }
    Ok(map)
}

fn parse_scope_list(raw: &str, allowed: &[String]) -> Option<Vec<String>> {
    if raw.trim().is_empty() || raw.chars().any(char::is_control) {
        return None;
    }
    let mut out = Vec::new();
    for tok in raw.split(' ') {
        if tok.is_empty() {
            continue;
        }
        if !allowed.iter().any(|a| a == tok) {
            return None;
        }
        if !out.iter().any(|existing| existing == tok) {
            out.push(tok.to_owned());
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn has_valid_csrf_cookie(headers: &HeaderMap, target_name: &str, expected_csrf: &str) -> bool {
    let mut matched = false;
    for val in headers.get_all(header::COOKIE) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let Some((name, cookie_val)) = pair.trim_ascii().split_once('=') else {
                continue;
            };
            if name.trim_ascii() == target_name
                && constant_time_eq_str(cookie_val.trim_ascii(), expected_csrf)
            {
                matched = true;
            }
        }
    }
    matched
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn render_authorize_page(pending: &AuthorizeFormView<'_>, error_notice: Option<&str>) -> String {
    let display_raw = pending.client_name.unwrap_or(pending.client_id);
    let display = escape_html(display_raw);
    let client_id = escape_html(pending.client_id);
    let resource = escape_html(pending.resource);
    let redirect_uri = escape_html(pending.redirect_uri);
    let callback_host = Url::parse(pending.redirect_uri)
        .ok()
        .and_then(|u| match (u.host_str(), u.port()) {
            (Some(h), Some(p)) => Some(escape_html(&format!("{h}:{p}"))),
            (Some(h), None) => Some(escape_html(h)),
            _ => None,
        })
        .unwrap_or_default();
    let ar_id = escape_html(pending.ar_id);
    let csrf_token = escape_html(pending.csrf_token);

    let mut scope_chips = String::new();
    for scope in pending.scopes {
        scope_chips.push_str("<span class=\"chip\">");
        scope_chips.push_str(&escape_html(scope));
        scope_chips.push_str("</span>");
    }

    let alert_block = match error_notice {
        Some(msg) => format!("<p class=\"alert\" role=\"alert\">{}</p>", escape_html(msg)),
        None => String::new(),
    };

    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head>\
<meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>Allow {display}</title>\
<style>\
*{{box-sizing:border-box;margin:0;padding:0}}\
body{{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem;background:#f8fafc;color:#0f172a;font-family:system-ui,-apple-system,sans-serif;line-height:1.5}}\
main{{width:100%;max-width:42rem;background:#ffffff;border:1px solid #e2e8f0;border-radius:0.75rem;padding:2.5rem;box-shadow:0 10px 30px rgba(15,23,42,0.06)}}\
h1{{font-size:clamp(1.35rem,2.4vw,1.7rem);font-weight:650;letter-spacing:-0.02em;margin-bottom:1.5rem;word-break:break-word}}\
dl{{display:grid;gap:0.9rem;margin-bottom:1.5rem;padding:1.25rem;background:#f8fafc;border-radius:0.5rem;border:1px solid #e2e8f0}}\
.row{{display:grid;gap:0.2rem}}\
dt{{font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:#475569}}\
dd{{font-size:0.9rem;color:#0f172a;word-break:break-all}}\
.host{{display:block;font-weight:600;margin-bottom:0.15rem}}\
code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:0.85rem;color:#334155}}\
.chips{{display:flex;flex-wrap:wrap;gap:0.45rem}}\
.chip{{display:inline-block;padding:0.18rem 0.55rem;background:#e2e8f0;color:#0f172a;border-radius:0.375rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:0.8rem}}\
.alert{{margin-bottom:1.25rem;padding:0.75rem 1rem;border-radius:0.5rem;background:#fef2f2;border:1px solid #fecaca;color:#991b1b;font-size:0.9rem;font-weight:500}}\
label{{display:block;font-size:0.875rem;font-weight:600;margin-bottom:0.5rem;color:#1e293b}}\
input[type=\"password\"]{{width:100%;padding:0.7rem 0.875rem;font-size:1rem;border:1px solid #cbd5e1;border-radius:0.5rem;background:#ffffff;color:#0f172a;margin-bottom:1.5rem}}\
input[type=\"password\"]:focus{{outline:2px solid #0f172a;outline-offset:1px}}\
.actions{{display:grid;grid-template-columns:1fr auto;gap:0.75rem}}\
button{{padding:0.78rem 1.25rem;font-size:0.95rem;font-weight:600;border-radius:0.5rem;cursor:pointer;transition:background-color 150ms ease}}\
.approve{{color:#ffffff;background:#0f172a;border:1px solid #0f172a}}\
.approve:hover{{background:#1e293b}}\
.deny{{color:#0f172a;background:#ffffff;border:1px solid #cbd5e1}}\
.deny:hover{{background:#f1f5f9}}\
@media (prefers-reduced-motion:reduce){{button{{transition:none}}}}\
</style>\
</head>\
<body>\
<main>\
<h1>Allow {display}</h1>\
<dl>\
<div class=\"row\"><dt>Resource</dt><dd><code>{resource}</code></dd></div>\
<div class=\"row\"><dt>Callback</dt><dd><span class=\"host\">{callback_host}</span><code>{redirect_uri}</code></dd></div>\
<div class=\"row\"><dt>Client ID</dt><dd><code>{client_id}</code></dd></div>\
<div class=\"row\"><dt>Scopes</dt><dd class=\"chips\">{scope_chips}</dd></div>\
</dl>\
{alert_block}\
<form method=\"post\" action=\"/oauth/authorize\">\
<input type=\"hidden\" name=\"ar_id\" value=\"{ar_id}\">\
<input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token}\">\
<label for=\"password\">Password</label>\
<input id=\"password\" name=\"password\" type=\"password\" required autofocus autocomplete=\"current-password\">\
<div class=\"actions\">\
<button type=\"submit\" name=\"decision\" value=\"approve\" class=\"approve\">Allow access</button>\
<button type=\"submit\" name=\"decision\" value=\"deny\" formnovalidate class=\"deny\">Deny</button>\
</div>\
</form>\
</main>\
</body>\
</html>"
    )
}

fn authorize_form_reply(
    status: StatusCode,
    pending: &AuthorizeFormView<'_>,
    error_notice: Option<&str>,
    cookie: Option<&str>,
) -> HttpReply {
    let mut reply =
        html_reply_with_cookie(status, render_authorize_page(pending, error_notice), cookie);
    // Browsers send Origin: null on form POSTs from a no-referrer page.
    reply.headers_mut().insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("strict-origin"),
    );
    reply
}

fn html_reply_with_cookie(status: StatusCode, html: String, cookie: Option<&str>) -> HttpReply {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_SECURITY_POLICY, AUTH_PAGE_CSP)
        .header(header::X_FRAME_OPTIONS, "DENY")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    if let Some(c) = cookie {
        builder = builder.header(header::SET_COOKIE, c);
    }
    builder.body(bytes_body(html)).expect("valid HTML response")
}

fn html_status_reply(status: StatusCode, message: &str) -> HttpReply {
    let escaped = escape_html(message);
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error</title></head><body><main><p>{escaped}</p></main></body></html>"
    );
    html_reply_with_cookie(status, html, None)
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> HttpReply {
    json_reply(
        status,
        &json!({
            "error": error,
            "error_description": description,
        }),
    )
}

fn invalid_client_reply(with_basic_challenge: bool, description: &str) -> HttpReply {
    let payload = serde_json::to_vec(&json!({
        "error": "invalid_client",
        "error_description": description,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());

    let mut builder = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store");
    if with_basic_challenge {
        builder = builder.header(header::WWW_AUTHENTICATE, "Basic");
    }
    builder
        .body(bytes_body(payload))
        .expect("valid 401 client error")
}

fn token_success_reply(
    access_token: &str,
    expires_in: u64,
    refresh_token: Option<&str>,
    scopes: &[String],
) -> HttpReply {
    let mut map = serde_json::Map::new();
    map.insert("access_token".to_owned(), json!(access_token));
    map.insert("token_type".to_owned(), json!("Bearer"));
    map.insert("expires_in".to_owned(), json!(expires_in));
    if let Some(rt) = refresh_token {
        map.insert("refresh_token".to_owned(), json!(rt));
    }
    map.insert("scope".to_owned(), json!(scopes.join(" ")));

    let payload =
        serde_json::to_vec(&serde_json::Value::Object(map)).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .body(bytes_body(payload))
        .expect("valid token response")
}

fn empty_ok_reply() -> HttpReply {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CACHE_CONTROL, "no-store")
        .body(empty_body())
        .expect("valid 200 empty reply")
}

fn not_found_reply() -> HttpReply {
    text_reply(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        "not found",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PasswordVerifier;
    use http_body_util::Full;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::task::Poll;
    use tokio::sync::oneshot;

    pub(super) struct RegisterPersistBarrier {
        planned: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }

    pub(super) async fn pause_register_persist(core: &EngineCore) {
        let barrier = core.register_persist_barrier.lock().unwrap().take();
        if let Some(barrier) = barrier {
            let _ = barrier.planned.send(());
            let _ = barrier.resume.await;
        }
    }

    async fn dispatch(
        engine: Arc<OAuthEngine>,
        req: Request<Full<Bytes>>,
        first_poll: Option<oneshot::Sender<()>>,
    ) -> (StatusCode, Bytes) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let first_poll = Mutex::new(first_poll);
            let service = hyper::service::service_fn(move |req| {
                let engine = Arc::clone(&engine);
                let first_poll = first_poll.lock().unwrap().take();
                async move {
                    let reply = if let Some(first_poll) = first_poll {
                        let mut response = Box::pin(engine.handle(req));
                        let polled =
                            std::future::poll_fn(|cx| Poll::Ready(response.as_mut().poll(cx)))
                                .await;
                        let _ = first_poll.send(());
                        match polled {
                            Poll::Ready(reply) => reply,
                            Poll::Pending => response.await,
                        }
                    } else {
                        engine.handle(req).await
                    };
                    Ok::<_, Infallible>(reply)
                }
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server_io), service)
                .await
                .unwrap();
        });
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
            .await
            .unwrap();
        let client = tokio::spawn(conn);
        let response = sender.send_request(req).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        drop(sender);
        client.await.unwrap().unwrap();
        server.await.unwrap();
        (status, body)
    }

    fn registration_request() -> Request<Full<Bytes>> {
        Request::builder()
            .method(Method::POST)
            .uri("/oauth/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(
                br#"{"redirect_uris":["http://127.0.0.1:43210/callback"]}"#,
            )))
            .unwrap()
    }

    #[tokio::test]
    async fn authorize_get_is_stateless_and_post_rejects_evicted_client() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let tmp = tempfile::TempDir::new().unwrap();
            let owner_hash =
                PasswordVerifier::from_plaintext_with_iterations("owner-test-password", 10_000)
                    .unwrap()
                    .encode();
            let config = GatewayConfig::from_json_str(
                &json!({
                    "listen": "127.0.0.1:0",
                    "public_url": "https://mcp.example.com",
                    "state_path": "state.json",
                    "oauth": {
                        "owner_password_hash": owner_hash,
                        "max_registered_clients": 16
                    },
                    "upstream": {
                        "transport": "http",
                        "url": "http://127.0.0.1:9090/mcp",
                        "bearer_tokens": ["test-upstream-token"]
                    }
                })
                .to_string(),
                tmp.path(),
            )
            .unwrap();
            let engine = OAuthEngine::open(Arc::new(config)).unwrap();
            let mut clients = Vec::new();
            for _ in 0..16 {
                let (status, body) =
                    dispatch(Arc::clone(&engine), registration_request(), None).await;
                assert_eq!(status, StatusCode::CREATED);
                clients.push(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["client_id"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                );
            }

            let (planned_tx, planned_rx) = oneshot::channel();
            let (resume_tx, resume_rx) = oneshot::channel();
            *engine.core.register_persist_barrier.lock().unwrap() = Some(RegisterPersistBarrier {
                planned: planned_tx,
                resume: resume_rx,
            });
            let registration =
                tokio::spawn(dispatch(Arc::clone(&engine), registration_request(), None));
            planned_rx.await.unwrap();

            let challenge = sha256_b64("ordinary-pkce-verifier-0123456789abcdef0123456789");
            let query = form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("response_type", "code"),
                    ("client_id", clients[0].as_str()),
                    ("redirect_uri", "http://127.0.0.1:43210/callback"),
                    ("code_challenge", challenge.as_str()),
                    ("code_challenge_method", "S256"),
                ])
                .finish();

            let req = Request::builder()
                .uri(format!("/oauth/authorize?{query}"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            // Stateless GET completes without waiting on persist_lock.
            let (get_status, get_body) = dispatch(Arc::clone(&engine), req, None).await;
            assert_eq!(get_status, StatusCode::OK);
            assert!(
                engine
                    .core
                    .inner
                    .lock()
                    .unwrap()
                    .consumed_auth_nonces
                    .is_empty()
            );

            let html = std::str::from_utf8(&get_body).unwrap();
            let extract_val = |name: &str| -> String {
                let needle = format!("name=\"{name}\" value=\"");
                let start = html.find(&needle).unwrap() + needle.len();
                let end = html[start..].find('"').unwrap() + start;
                html[start..end].to_owned()
            };
            let ar_id = extract_val("ar_id");
            let csrf_token = extract_val("csrf_token");
            let aad = auth_form_aad("https://mcp.example.com", &ar_id);
            let opened: SealedAuthForm =
                serde_json::from_slice(&engine.core.crypto.open(&aad, &csrf_token).unwrap())
                    .unwrap();
            let cookie = format!("__Host-mcp_ar_{ar_id}={}", opened.cookie_csrf);

            resume_tx.send(()).unwrap();
            assert_eq!(registration.await.unwrap().0, StatusCode::CREATED);

            let post_body = form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("ar_id", ar_id.as_str()),
                    ("csrf_token", csrf_token.as_str()),
                    ("password", "owner-test-password"),
                ])
                .finish();
            let post_req = Request::builder()
                .method(Method::POST)
                .uri("/oauth/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie)
                .body(Full::new(Bytes::from(post_body)))
                .unwrap();
            let (post_status, _) = dispatch(Arc::clone(&engine), post_req, None).await;
            assert_eq!(post_status, StatusCode::BAD_REQUEST);
            assert!(
                engine
                    .core
                    .inner
                    .lock()
                    .unwrap()
                    .consumed_auth_nonces
                    .is_empty()
            );
        })
        .await
        .expect("DCR and authorization requests settle");
    }
}
