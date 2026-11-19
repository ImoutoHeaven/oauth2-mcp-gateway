use crate::config::{GatewayConfig, is_loopback_host};
use crate::crypto::{
    constant_time_eq_str, is_valid_s256_challenge, random_token_b64, sha256_b64, verify_pkce_s256,
};
use crate::store::{
    AccessTokenRecord, GrantRecord, PersistedState, RefreshTokenRecord, RegisteredClient,
    StateStore, unix_now,
};
use crate::types::{
    AuthChallenge, HttpReply, VerifiedToken, bytes_body, empty_body, json_reply, text_reply,
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const MAX_POST_BODY_BYTES: usize = 64 * 1024;
const OAUTH_BODY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECT_URIS: usize = 16;
const MAX_CLIENT_NAME_CHARS: usize = 256;
const PENDING_AUTH_TTL_SECS: u64 = 300;
const MAX_PENDING_AUTHS: usize = 256;
const AUTH_CODE_TTL_SECS: u64 = 300;
const MAX_AUTH_CODES: usize = 256;
const CONSUMED_CODE_TTL_SECS: u64 = 300;
const MAX_CONSUMED_CODES: usize = 1024;
const PW_FAIL_WINDOW_SECS: u64 = 15 * 60;
const PW_MAX_FAILURES: usize = 10;
const MAX_ACCESS_TOKENS_PER_GRANT: usize = 64;
const MAX_ROTATED_REFRESH_PER_GRANT: usize = 256;

const AUTH_PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'";

type EarlyReply = Box<HttpReply>;

pub struct OAuthEngine {
    config: Arc<GatewayConfig>,
    store: StateStore,
    inner: Mutex<EngineState>,
    pw_verify_gate: tokio::sync::Mutex<()>,
}

struct EngineState {
    persisted: PersistedState,
    pending_auths: VecDeque<PendingAuthRequest>,
    auth_codes: VecDeque<AuthCodeEntry>,
    consumed_codes: VecDeque<ConsumedCodeEntry>,
    grace_cache: HashMap<String, GraceCacheEntry>,
    pw_failures: VecDeque<u64>,
    rr_cursor: usize,
}

#[derive(Clone)]
struct PendingAuthRequest {
    ar_id: String,
    csrf_token: String,
    client_id: String,
    client_name: Option<String>,
    redirect_uri: String,
    scopes: Vec<String>,
    resource: String,
    state: Option<String>,
    code_challenge: String,
    expires_at: u64,
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
    grant_id: String,
    access_token: String,
    refresh_token: String,
    a1_expires_at: u64,
    scopes: Vec<String>,
    grace_until: u64,
}

#[derive(Deserialize)]
struct DcrRequest {
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    token_endpoint_auth_method: Option<String>,
}

impl EngineState {
    fn prune_ephemeral(&mut self, now: u64) {
        self.pending_auths.retain(|entry| entry.expires_at > now);
        self.auth_codes.retain(|entry| entry.expires_at > now);
        self.consumed_codes.retain(|entry| entry.expires_at > now);
        self.grace_cache
            .retain(|_, entry| entry.grace_until >= now && entry.a1_expires_at > now);
        while let Some(&ts) = self.pw_failures.front() {
            if ts.saturating_add(PW_FAIL_WINDOW_SECS) <= now {
                self.pw_failures.pop_front();
            } else {
                break;
            }
        }
    }

    fn revoke_grant_in_memory(&mut self, grant_id: &str) -> bool {
        let before = self.persisted.grants.len();
        self.persisted.grants.retain(|g| g.grant_id != grant_id);
        self.grace_cache.retain(|_, e| e.grant_id != grant_id);
        self.persisted.grants.len() != before
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
        let now = unix_now();
        let (store, persisted) = StateStore::open(config.state_path.clone(), now)?;
        let state = EngineState {
            persisted,
            pending_auths: VecDeque::new(),
            auth_codes: VecDeque::new(),
            consumed_codes: VecDeque::new(),
            grace_cache: HashMap::new(),
            pw_failures: VecDeque::new(),
            rr_cursor: 0,
        };
        Ok(Arc::new(Self {
            config,
            store,
            inner: Mutex::new(state),
            pw_verify_gate: tokio::sync::Mutex::new(()),
        }))
    }

    pub fn handles_path(path: &str) -> bool {
        path == "/.well-known/oauth-protected-resource"
            || path.starts_with("/.well-known/oauth-protected-resource/")
            || path == "/.well-known/oauth-authorization-server"
            || path.starts_with("/.well-known/oauth-authorization-server/")
            || path.starts_with("/oauth/")
    }

    pub async fn handle(&self, req: Request<Incoming>) -> HttpReply {
        let path = req.uri().path().to_owned();
        match path.as_str() {
            p if p == "/.well-known/oauth-protected-resource"
                || p.strip_prefix("/.well-known/oauth-protected-resource")
                    == Some(self.config.resource_path.as_str()) =>
            {
                if req.method() != Method::GET {
                    return method_not_allowed("GET");
                }
                self.handle_prm()
            }
            p if p.starts_with("/.well-known/oauth-protected-resource/") => not_found_reply(),
            "/.well-known/oauth-authorization-server"
            | "/.well-known/oauth-authorization-server/mcp" => {
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
                Method::POST => self.handle_authorize_post(req).await,
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
        let expected_resource = self.config.mcp_resource_url();

        let guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for grant in &guard.persisted.grants {
            if grant.resource != expected_resource {
                continue;
            }
            for at in &grant.access_tokens {
                if at.expires_at > now && constant_time_eq_str(&at.token_sha256, &token_hash) {
                    return Ok(VerifiedToken {
                        grant_id: grant.grant_id.clone(),
                        client_id: grant.client_id.clone(),
                        pool_slot: grant.pool_slot,
                        scopes: grant.scopes.clone(),
                        resource: grant.resource.clone(),
                    });
                }
            }
        }
        Err(AuthChallenge::InvalidToken)
    }

    pub fn www_authenticate_value(&self, challenge: AuthChallenge) -> String {
        let meta_url = format!(
            "{}/.well-known/oauth-protected-resource{}",
            self.config.public_url, self.config.resource_path
        );
        match challenge {
            AuthChallenge::MissingToken => format!("Bearer resource_metadata=\"{meta_url}\""),
            AuthChallenge::InvalidToken => {
                format!("Bearer resource_metadata=\"{meta_url}\", error=\"invalid_token\"")
            }
        }
    }

    pub fn unauthorized_reply(&self, challenge: AuthChallenge) -> HttpReply {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                header::WWW_AUTHENTICATE,
                self.www_authenticate_value(challenge),
            )
            .header(header::CONNECTION, "close")
            .header(header::CACHE_CONTROL, "no-store")
            .body(empty_body())
            .expect("valid 401 reply")
    }

    fn handle_prm(&self) -> HttpReply {
        let pub_url = &self.config.public_url;
        json_reply(
            StatusCode::OK,
            &json!({
                "resource": self.config.mcp_resource_url(),
                "authorization_servers": [pub_url],
                "bearer_methods_supported": ["header"],
                "scopes_supported": self.config.oauth.scopes,
            }),
        )
    }

    fn handle_as_metadata(&self) -> HttpReply {
        let pub_url = &self.config.public_url;
        json_reply(
            StatusCode::OK,
            &json!({
                "issuer": pub_url,
                "authorization_endpoint": format!("{pub_url}/oauth/authorize"),
                "token_endpoint": format!("{pub_url}/oauth/token"),
                "registration_endpoint": format!("{pub_url}/oauth/register"),
                "revocation_endpoint": format!("{pub_url}/oauth/revoke"),
                "scopes_supported": self.config.oauth.scopes,
                "response_types_supported": ["code"],
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
            Err(reply) => return reply,
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
                "invalid_redirect_uri",
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
            if !self.is_allowed_redirect_uri(&uri) {
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
                let trimmed = name.trim();
                if trimmed.chars().count() > MAX_CLIENT_NAME_CHARS
                    || trimmed.chars().any(char::is_control)
                {
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

        let now = unix_now();
        let record = RegisteredClient {
            client_id: client_id.clone(),
            client_name: client_name.clone(),
            redirect_uris: redirect_uris.clone(),
            grant_types: grant_types.clone(),
            response_types: response_types.clone(),
            token_endpoint_auth_method: auth_method.clone(),
            client_secret_sha256: secret_sha256,
            issued_at: now,
        };

        {
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.persisted.prune_expired(now);
            guard.prune_ephemeral(now);

            let max_clients = self.config.oauth.max_registered_clients;
            let mut candidate_clients = guard.persisted.clients.clone();
            let mut evicted_ids = Vec::new();
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
                let removed = candidate_clients.remove(evict_idx);
                evicted_ids.push(removed.client_id);
            }

            candidate_clients.push(record);
            let mut snapshot = guard.persisted.clone();
            snapshot.clients = candidate_clients;
            if self.store.save(&snapshot).is_err() {
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "failed to persist registered client",
                );
            }
            guard.persisted = snapshot;
            if !evicted_ids.is_empty() {
                guard
                    .pending_auths
                    .retain(|p| !evicted_ids.contains(&p.client_id));
                guard
                    .auth_codes
                    .retain(|c| !evicted_ids.contains(&c.client_id));
            }
        }

        let mut resp_obj = serde_json::Map::new();
        resp_obj.insert("client_id".to_owned(), json!(client_id));
        resp_obj.insert("client_id_issued_at".to_owned(), json!(now));
        if let Some(secret) = plain_secret {
            resp_obj.insert("client_secret".to_owned(), json!(secret));
            resp_obj.insert("client_secret_expires_at".to_owned(), json!(0));
        }
        if let Some(name) = client_name {
            resp_obj.insert("client_name".to_owned(), json!(name));
        }
        resp_obj.insert("redirect_uris".to_owned(), json!(redirect_uris));
        resp_obj.insert("grant_types".to_owned(), json!(grant_types));
        resp_obj.insert("response_types".to_owned(), json!(response_types));
        resp_obj.insert("token_endpoint_auth_method".to_owned(), json!(auth_method));

        json_reply(StatusCode::CREATED, &serde_json::Value::Object(resp_obj))
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
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.prune_ephemeral(now);
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
        if !client.redirect_uris.iter().any(|u| u == redirect_uri)
            || !self.is_allowed_redirect_uri(redirect_uri)
        {
            return html_status_reply(StatusCode::BAD_REQUEST, "Unregistered redirect_uri");
        }

        let state_param = params.get("state").cloned();
        if state_param
            .as_deref()
            .is_some_and(|s| s.chars().any(char::is_control))
        {
            return html_status_reply(StatusCode::BAD_REQUEST, "Invalid state parameter");
        }

        match params.get("response_type").map(String::as_str) {
            Some("code") => {}
            Some(_) => {
                return self.authorize_error_redirect(
                    redirect_uri,
                    "unsupported_response_type",
                    state_param.as_deref(),
                );
            }
            None => {
                return self.authorize_error_redirect(
                    redirect_uri,
                    "invalid_request",
                    state_param.as_deref(),
                );
            }
        }

        if !client.grant_types.iter().any(|g| g == "authorization_code")
            || !client.response_types.iter().any(|r| r == "code")
        {
            return self.authorize_error_redirect(
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
            return html_status_reply(
                StatusCode::BAD_REQUEST,
                "PKCE S256 code_challenge is required",
            );
        };

        let scopes = match params.get("scope") {
            None => self.config.oauth.scopes.clone(),
            Some(raw_scope) => {
                let Some(parsed_scopes) = parse_scope_list(raw_scope, &self.config.oauth.scopes)
                else {
                    return self.authorize_error_redirect(
                        redirect_uri,
                        "invalid_scope",
                        state_param.as_deref(),
                    );
                };
                parsed_scopes
            }
        };

        let Ok(resource) = self.normalize_resource(params.get("resource").map(String::as_str))
        else {
            return self.authorize_error_redirect(
                redirect_uri,
                "invalid_target",
                state_param.as_deref(),
            );
        };

        let (Ok(ar_id), Ok(csrf_token)) = (random_token_b64(18), random_token_b64(24)) else {
            return html_status_reply(StatusCode::INTERNAL_SERVER_ERROR, "Random source error");
        };

        let pending = PendingAuthRequest {
            ar_id: ar_id.clone(),
            csrf_token: csrf_token.clone(),
            client_id: client.client_id.clone(),
            client_name: client.client_name.clone(),
            redirect_uri: redirect_uri.clone(),
            scopes,
            resource,
            state: state_param,
            code_challenge,
            expires_at: now.saturating_add(PENDING_AUTH_TTL_SECS),
        };

        {
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.prune_ephemeral(now);
            while guard.pending_auths.len() >= MAX_PENDING_AUTHS {
                guard.pending_auths.pop_front();
            }
            guard.pending_auths.push_back(pending.clone());
        }

        let cookie = self.build_ar_cookie(&ar_id, &csrf_token, PENDING_AUTH_TTL_SECS);
        let html = render_authorize_page(&pending, None);
        html_reply_with_cookie(StatusCode::OK, html, Some(&cookie))
    }

    async fn handle_authorize_post(&self, req: Request<Incoming>) -> HttpReply {
        if !has_media_type(req.headers(), "application/x-www-form-urlencoded") {
            return html_status_reply(
                StatusCode::BAD_REQUEST,
                "Content-Type must be application/x-www-form-urlencoded",
            );
        }
        let req_headers = req.headers().clone();
        let body = match read_limited_body(req).await {
            Ok(bytes) => bytes,
            Err(reply) => return reply,
        };
        let Ok(form) = parse_unique_form(&body) else {
            return html_status_reply(StatusCode::BAD_REQUEST, "Invalid form submission");
        };

        let Some(ar_id) = form.get("ar_id").filter(|v| !v.is_empty()) else {
            return html_status_reply(StatusCode::BAD_REQUEST, "Missing authorization session");
        };
        let Some(form_csrf) = form.get("csrf_token").filter(|v| !v.is_empty()) else {
            return html_status_reply(StatusCode::FORBIDDEN, "Missing CSRF token");
        };
        let password = form.get("password").cloned().unwrap_or_default();

        let now = unix_now();
        let pending_snapshot = {
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.prune_ephemeral(now);
            if guard.pw_failures.len() >= PW_MAX_FAILURES {
                return html_status_reply(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many failed attempts",
                );
            }
            guard
                .pending_auths
                .iter()
                .find(|entry| entry.ar_id == *ar_id)
                .cloned()
        };

        let Some(pending) = pending_snapshot else {
            return html_status_reply(
                StatusCode::BAD_REQUEST,
                "Authorization request expired or unknown",
            );
        };

        let cookie_name = format!("mcp_ar_{}", pending.ar_id);
        let Some(cookie_csrf) = extract_cookie(&req_headers, &cookie_name) else {
            return html_status_reply(StatusCode::FORBIDDEN, "Missing session cookie");
        };
        if !constant_time_eq_str(&cookie_csrf, &pending.csrf_token)
            || !constant_time_eq_str(form_csrf, &pending.csrf_token)
        {
            return html_status_reply(StatusCode::FORBIDDEN, "CSRF validation failed");
        }

        let _verify_guard = self.pw_verify_gate.lock().await;
        {
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let check_now = unix_now();
            guard.prune_ephemeral(check_now);
            if guard.pw_failures.len() >= PW_MAX_FAILURES {
                return html_status_reply(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many failed attempts",
                );
            }
        }

        let verifier = self.config.oauth.verifier.clone();
        let pw_valid = tokio::task::spawn_blocking(move || verifier.verify(&password))
            .await
            .unwrap_or(false);

        let finish_now = unix_now();
        if !pw_valid {
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.prune_ephemeral(finish_now);
            guard.pw_failures.push_back(finish_now);
            let html = render_authorize_page(&pending, Some("Incorrect password"));
            return html_reply_with_cookie(StatusCode::UNAUTHORIZED, html, None);
        }

        let Ok(raw_code) = random_token_b64(32) else {
            return html_status_reply(StatusCode::INTERNAL_SERVER_ERROR, "Random source error");
        };
        let code_hash = sha256_b64(&raw_code);

        let consumed = {
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.prune_ephemeral(finish_now);
            let Some(pos) = guard
                .pending_auths
                .iter()
                .position(|entry| entry.ar_id == pending.ar_id)
            else {
                return html_status_reply(
                    StatusCode::BAD_REQUEST,
                    "Authorization request already consumed",
                );
            };
            let entry = guard.pending_auths.remove(pos).expect("position exists");
            let client_still_registered = guard
                .persisted
                .clients
                .iter()
                .any(|c| c.client_id == entry.client_id);
            if !client_still_registered {
                return html_status_reply(
                    StatusCode::BAD_REQUEST,
                    "Client is no longer registered",
                );
            }

            while guard.auth_codes.len() >= MAX_AUTH_CODES {
                guard.auth_codes.pop_front();
            }
            guard.auth_codes.push_back(AuthCodeEntry {
                code_sha256: code_hash,
                client_id: entry.client_id.clone(),
                redirect_uri: entry.redirect_uri.clone(),
                scopes: entry.scopes.clone(),
                resource: entry.resource.clone(),
                code_challenge: entry.code_challenge.clone(),
                expires_at: finish_now.saturating_add(AUTH_CODE_TTL_SECS),
            });
            entry
        };

        let clear_cookie = self.build_ar_cookie(&consumed.ar_id, "", 0);
        let Ok(mut location) = Url::parse(&consumed.redirect_uri) else {
            return html_status_reply(StatusCode::INTERNAL_SERVER_ERROR, "Invalid redirect target");
        };
        {
            let mut pairs = location.query_pairs_mut();
            pairs.append_pair("code", &raw_code);
            pairs.append_pair("iss", &self.config.public_url);
            if let Some(st) = &consumed.state {
                pairs.append_pair("state", st);
            }
        }

        if req_headers
            .get("sec-fetch-mode")
            .is_some_and(|mode| mode == "navigate")
        {
            // Chromium applies form-action to the POST redirect chain. A new document
            // can navigate to the registered callback without sending the form body.
            let callback = escape_html(location.as_str());
            let html = format!(
                "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
                 <title>Return to the app</title><meta http-equiv=\"refresh\" content=\"0;url={callback}\">\
                 </head><body><a href=\"{callback}\">Return to the app</a></body></html>"
            );
            return html_reply_with_cookie(StatusCode::OK, html, Some(&clear_cookie));
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
            Err(reply) => return reply,
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
            Some("authorization_code") => self.handle_token_auth_code(&client, &form),
            Some("refresh_token") => self.handle_token_refresh(&client, &form),
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

    fn handle_token_auth_code(
        &self,
        client: &RegisteredClient,
        form: &BTreeMap<String, String>,
    ) -> HttpReply {
        if !client.grant_types.iter().any(|g| g == "authorization_code") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                "client is not authorized for authorization_code",
            );
        }
        let Some(raw_code) = form.get("code").filter(|c| !c.is_empty()) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code is required",
            );
        };

        let code_hash = sha256_b64(raw_code);
        let now = unix_now();

        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.persisted.prune_expired(now);
        guard.prune_ephemeral(now);

        if let Some(replayed_grant_id) = guard
            .consumed_codes
            .iter()
            .find(|c| constant_time_eq_str(&c.code_sha256, &code_hash))
            .map(|c| c.grant_id.clone())
        {
            let mut snapshot = guard.persisted.clone();
            let before = snapshot.grants.len();
            snapshot.grants.retain(|g| g.grant_id != replayed_grant_id);
            if snapshot.grants.len() != before {
                if self.store.save(&snapshot).is_err() {
                    return oauth_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "failed to persist grant revocation",
                    );
                }
                guard.persisted = snapshot;
            }
            guard
                .grace_cache
                .retain(|_, e| e.grant_id != replayed_grant_id);
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code has already been used",
            );
        }

        let Some(code_verifier) = form.get("code_verifier").filter(|v| !v.is_empty()) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code_verifier is required",
            );
        };

        let requested_resource = match form.get("resource") {
            None => None,
            Some(raw_res) => match self.normalize_resource(Some(raw_res)) {
                Ok(norm) => Some(norm),
                Err(()) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_target",
                        "invalid resource target",
                    );
                }
            },
        };

        let Some(code_pos) = guard
            .auth_codes
            .iter()
            .position(|entry| constant_time_eq_str(&entry.code_sha256, &code_hash))
        else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unknown or expired authorization code",
            );
        };
        let code_entry = guard.auth_codes.remove(code_pos).expect("position exists");

        if code_entry.client_id != client.client_id {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code was not issued to this client",
            );
        }
        if form.get("redirect_uri").map(String::as_str) != Some(code_entry.redirect_uri.as_str()) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "redirect_uri mismatch",
            );
        }
        if let Some(res) = requested_resource
            && res != code_entry.resource
        {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource mismatch",
            );
        }
        if !verify_pkce_s256(code_verifier, &code_entry.code_challenge) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "PKCE verification failed",
            );
        }

        let (Ok(grant_suffix), Ok(access_token), Ok(refresh_token)) = (
            random_token_b64(18),
            random_token_b64(32),
            random_token_b64(32),
        ) else {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "random generation failed",
            );
        };

        let grant_id = format!("grt_{grant_suffix}");
        let pool_slot = guard.select_pool_slot(self.config.upstream.pool_size());
        let access_ttl = self.config.oauth.access_token_ttl_secs;
        let refresh_ttl = self.config.oauth.refresh_token_ttl_secs;
        let issue_refresh = client.grant_types.iter().any(|g| g == "refresh_token");

        let mut refresh_tokens = Vec::new();
        if issue_refresh {
            refresh_tokens.push(RefreshTokenRecord {
                token_sha256: sha256_b64(&refresh_token),
                expires_at: now.saturating_add(refresh_ttl),
                grace_until: None,
            });
        }

        let grant = GrantRecord {
            grant_id: grant_id.clone(),
            client_id: client.client_id.clone(),
            pool_slot,
            scopes: code_entry.scopes.clone(),
            resource: code_entry.resource,
            access_tokens: vec![AccessTokenRecord {
                token_sha256: sha256_b64(&access_token),
                expires_at: now.saturating_add(access_ttl),
            }],
            refresh_tokens,
        };

        let mut snapshot = guard.persisted.clone();
        snapshot.grants.push(grant);
        if self.store.save(&snapshot).is_err() {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to persist token grant",
            );
        }
        guard.persisted = snapshot;

        while guard.consumed_codes.len() >= MAX_CONSUMED_CODES {
            guard.consumed_codes.pop_front();
        }
        guard.consumed_codes.push_back(ConsumedCodeEntry {
            code_sha256: code_hash,
            grant_id,
            expires_at: now.saturating_add(CONSUMED_CODE_TTL_SECS),
        });

        token_success_reply(
            &access_token,
            access_ttl,
            issue_refresh.then_some(refresh_token.as_str()),
            &code_entry.scopes,
        )
    }

    fn handle_token_refresh(
        &self,
        client: &RegisteredClient,
        form: &BTreeMap<String, String>,
    ) -> HttpReply {
        if !client.grant_types.iter().any(|g| g == "refresh_token") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                "client is not authorized for refresh_token",
            );
        }
        let Some(raw_rt) = form.get("refresh_token").filter(|t| !t.is_empty()) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "refresh_token is required",
            );
        };

        let rt_hash = sha256_b64(raw_rt);
        let now = unix_now();

        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.persisted.prune_expired(now);
        guard.prune_ephemeral(now);

        let mut matched: Option<(usize, usize)> = None;
        for (g_idx, grant) in guard.persisted.grants.iter().enumerate() {
            for (r_idx, rt) in grant.refresh_tokens.iter().enumerate() {
                if rt.expires_at > now && constant_time_eq_str(&rt.token_sha256, &rt_hash) {
                    matched = Some((g_idx, r_idx));
                    break;
                }
            }
            if matched.is_some() {
                break;
            }
        }

        let Some((grant_idx, rt_idx)) = matched else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unknown or expired refresh token",
            );
        };

        if guard.persisted.grants[grant_idx].client_id != client.client_id {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token was not issued to this client",
            );
        }

        if guard.persisted.grants[grant_idx].resource != self.config.mcp_resource_url() {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token targets a previous resource URL",
            );
        }

        let existing_grace = guard.persisted.grants[grant_idx].refresh_tokens[rt_idx].grace_until;
        let r0_expires_at = guard.persisted.grants[grant_idx].refresh_tokens[rt_idx].expires_at;
        let grant_id = guard.persisted.grants[grant_idx].grant_id.clone();

        if let Some(gu) = existing_grace {
            let within_grace = self.config.oauth.refresh_grace_secs > 0 && now <= gu;
            if !within_grace {
                let mut snapshot = guard.persisted.clone();
                snapshot.grants.retain(|g| g.grant_id != grant_id);
                if self.store.save(&snapshot).is_err() {
                    return oauth_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "failed to persist grant revocation",
                    );
                }
                guard.persisted = snapshot;
                guard.grace_cache.retain(|_, e| e.grant_id != grant_id);
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh token reuse detected",
                );
            }

            let grant = &guard.persisted.grants[grant_idx];
            let effective_scopes = match self.validate_refresh_scope_and_resource(grant, form) {
                Ok(scopes) => scopes,
                Err(reply) => return *reply,
            };
            if effective_scopes.len() != grant.scopes.len() {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "refresh retry cannot narrow the current scope",
                );
            }

            if let Some(cached) = guard.grace_cache.get(&rt_hash).cloned()
                && cached.a1_expires_at > now
                && cached.scopes.len() == grant.scopes.len()
                && cached
                    .scopes
                    .iter()
                    .all(|scope| grant.scopes.contains(scope))
            {
                let rem_ttl = cached.a1_expires_at.saturating_sub(now).max(1);
                return token_success_reply(
                    &cached.access_token,
                    rem_ttl,
                    Some(&cached.refresh_token),
                    &cached.scopes,
                );
            }

            let (Ok(a_re), Ok(r_re)) = (random_token_b64(32), random_token_b64(32)) else {
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "random generation failed",
                );
            };
            let access_ttl = self.config.oauth.access_token_ttl_secs;
            let refresh_ttl = self.config.oauth.refresh_token_ttl_secs;
            let a_re_expires = now.saturating_add(access_ttl);
            let ceiling = guard.persisted.grants[grant_idx]
                .refresh_tokens
                .iter()
                .filter(|rt| rt.grace_until.is_none())
                .map(|rt| rt.expires_at)
                .max();
            let r_re_expires = ceiling
                .unwrap_or_else(|| now.saturating_add(refresh_ttl))
                .min(now.saturating_add(refresh_ttl));

            let mut snapshot = guard.persisted.clone();
            let target_grant = &mut snapshot.grants[grant_idx];
            target_grant.access_tokens.push(AccessTokenRecord {
                token_sha256: sha256_b64(&a_re),
                expires_at: a_re_expires,
            });
            target_grant.refresh_tokens.push(RefreshTokenRecord {
                token_sha256: sha256_b64(&r_re),
                expires_at: r_re_expires,
                grace_until: None,
            });
            trim_rotated_refresh_history(target_grant);
            let scopes = target_grant.scopes.clone();

            if self.store.save(&snapshot).is_err() {
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "failed to persist refreshed token",
                );
            }
            guard.persisted = snapshot;
            guard.grace_cache.insert(
                rt_hash,
                GraceCacheEntry {
                    grant_id,
                    access_token: a_re.clone(),
                    refresh_token: r_re.clone(),
                    a1_expires_at: a_re_expires,
                    scopes: scopes.clone(),
                    grace_until: gu,
                },
            );
            return token_success_reply(&a_re, access_ttl, Some(&r_re), &scopes);
        }

        let effective_scopes = match self
            .validate_refresh_scope_and_resource(&guard.persisted.grants[grant_idx], form)
        {
            Ok(s) => s,
            Err(reply) => return *reply,
        };

        let (Ok(a1), Ok(r1)) = (random_token_b64(32), random_token_b64(32)) else {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "random generation failed",
            );
        };

        let grace_secs = self.config.oauth.refresh_grace_secs;
        let grace_until = r0_expires_at.min(now.saturating_add(grace_secs));
        let access_ttl = self.config.oauth.access_token_ttl_secs;
        let refresh_ttl = self.config.oauth.refresh_token_ttl_secs;
        let a1_expires_at = now.saturating_add(access_ttl);
        let r1_expires_at = now.saturating_add(refresh_ttl);

        let mut snapshot = guard.persisted.clone();
        let target_grant = &mut snapshot.grants[grant_idx];
        target_grant.scopes = effective_scopes.clone();
        target_grant.refresh_tokens[rt_idx].grace_until = Some(grace_until);
        target_grant.access_tokens.push(AccessTokenRecord {
            token_sha256: sha256_b64(&a1),
            expires_at: a1_expires_at,
        });
        target_grant.refresh_tokens.push(RefreshTokenRecord {
            token_sha256: sha256_b64(&r1),
            expires_at: r1_expires_at,
            grace_until: None,
        });
        trim_rotated_refresh_history(target_grant);

        if self.store.save(&snapshot).is_err() {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to persist rotated token",
            );
        }
        guard.persisted = snapshot;

        if grace_secs > 0 {
            guard.grace_cache.insert(
                rt_hash,
                GraceCacheEntry {
                    grant_id,
                    access_token: a1.clone(),
                    refresh_token: r1.clone(),
                    a1_expires_at,
                    scopes: effective_scopes.clone(),
                    grace_until,
                },
            );
        }

        token_success_reply(&a1, access_ttl, Some(&r1), &effective_scopes)
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
            Err(reply) => return reply,
        };
        let Ok(form) = parse_unique_form(&body) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "duplicate or malformed form parameter",
            );
        };

        let has_client_creds = req_headers.contains_key(header::AUTHORIZATION)
            || form.contains_key("client_id")
            || form.contains_key("client_secret");

        let authed_client = if has_client_creds {
            match self.authenticate_token_client(&req_headers, &form) {
                Ok(c) => Some(c),
                Err(reply) => return *reply,
            }
        } else {
            None
        };

        let Some(raw_token) = form.get("token") else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token parameter is required",
            );
        };
        if raw_token.is_empty() {
            return empty_ok_reply();
        }

        let token_hash = sha256_b64(raw_token);
        let now = unix_now();

        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.persisted.prune_expired(now);
        guard.prune_ephemeral(now);

        let found_grant = guard
            .persisted
            .grants
            .iter()
            .find(|grant| {
                grant
                    .access_tokens
                    .iter()
                    .any(|at| constant_time_eq_str(&at.token_sha256, &token_hash))
                    || grant
                        .refresh_tokens
                        .iter()
                        .any(|rt| constant_time_eq_str(&rt.token_sha256, &token_hash))
            })
            .map(|g| (g.grant_id.clone(), g.client_id.clone()));

        let Some((grant_id, owner_client_id)) = found_grant else {
            return empty_ok_reply();
        };

        if let Some(client) = authed_client {
            if client.client_id != owner_client_id {
                return empty_ok_reply();
            }
        } else if let Some(owner_client) = guard
            .persisted
            .clients
            .iter()
            .find(|c| c.client_id == owner_client_id)
            && owner_client.token_endpoint_auth_method != "none"
        {
            let basic = owner_client.token_endpoint_auth_method == "client_secret_basic";
            return invalid_client_reply(basic, "client authentication required");
        }

        let mut snapshot = guard.persisted.clone();
        snapshot.grants.retain(|g| g.grant_id != grant_id);
        if self.store.save(&snapshot).is_err() {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to persist grant revocation",
            );
        }
        let _ = guard.revoke_grant_in_memory(&grant_id);
        empty_ok_reply()
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

    fn validate_refresh_scope_and_resource(
        &self,
        grant: &GrantRecord,
        form: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, EarlyReply> {
        if let Some(raw_res) = form.get("resource") {
            let Ok(norm) = self.normalize_resource(Some(raw_res)) else {
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

    fn is_allowed_redirect_uri(&self, raw: &str) -> bool {
        if raw.is_empty() || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
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
        if is_loopback_host(host) {
            return matches!(parsed.scheme(), "http" | "https");
        }
        if parsed.scheme() != "https" {
            return false;
        }
        if self.config.oauth.allowed_redirect_hosts.is_empty() {
            return true;
        }
        let lower_host = host.to_ascii_lowercase();
        self.config
            .oauth
            .allowed_redirect_hosts
            .iter()
            .any(|allowed| allowed == &lower_host)
    }

    fn normalize_resource(&self, raw: Option<&str>) -> Result<String, ()> {
        let mcp_url = self.config.mcp_resource_url();
        match raw {
            None => Ok(mcp_url),
            Some(val) => {
                let pub_url = &self.config.public_url;
                if val == pub_url
                    || val == mcp_url
                    || (val.len() == pub_url.len() + 1
                        && val.starts_with(pub_url.as_str())
                        && val.ends_with('/'))
                {
                    Ok(mcp_url)
                } else {
                    Err(())
                }
            }
        }
    }

    fn authorize_error_redirect(
        &self,
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
            pairs.append_pair("iss", &self.config.public_url);
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

    fn build_ar_cookie(&self, ar_id: &str, csrf_token: &str, max_age: u64) -> String {
        let mut cookie = format!(
            "mcp_ar_{ar_id}={csrf_token}; HttpOnly; SameSite=Lax; Path=/oauth/authorize; Max-Age={max_age}"
        );
        if self.config.public_is_https {
            cookie.push_str("; Secure");
        }
        cookie
    }
}

fn trim_rotated_refresh_history(grant: &mut GrantRecord) {
    if grant.access_tokens.len() > MAX_ACCESS_TOKENS_PER_GRANT {
        let drop_at = grant.access_tokens.len() - MAX_ACCESS_TOKENS_PER_GRANT;
        grant.access_tokens.drain(0..drop_at);
    }
    let rotated_count = grant
        .refresh_tokens
        .iter()
        .filter(|rt| rt.grace_until.is_some())
        .count();
    if rotated_count <= MAX_ROTATED_REFRESH_PER_GRANT {
        return;
    }
    let mut excess = rotated_count - MAX_ROTATED_REFRESH_PER_GRANT;
    grant.refresh_tokens.retain(|rt| {
        if excess > 0 && rt.grace_until.is_some() {
            excess -= 1;
            false
        } else {
            true
        }
    });
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
    let decoded_str = String::from_utf8(decoded_bytes)
        .map_err(|_| Box::new(invalid_client_reply(true, "non-UTF-8 Basic credentials")))?;

    if let Some((raw_id, raw_secret)) = decoded_str.split_once(':') {
        let client_id = form_urldecode_component(raw_id).map_err(|()| {
            Box::new(invalid_client_reply(
                true,
                "invalid URL encoding in client_id",
            ))
        })?;
        let client_secret = form_urldecode_component(raw_secret).map_err(|()| {
            Box::new(invalid_client_reply(
                true,
                "invalid URL encoding in client_secret",
            ))
        })?;
        return Ok(Some((client_id, client_secret)));
    }

    let unescaped = form_urldecode_component(&decoded_str).map_err(|()| {
        Box::new(invalid_client_reply(
            true,
            "invalid Basic credential encoding",
        ))
    })?;
    let Some((client_id, client_secret)) = unescaped.split_once(':') else {
        return Err(Box::new(invalid_client_reply(
            true,
            "Basic credentials missing colon separator",
        )));
    };
    Ok(Some((client_id.to_owned(), client_secret.to_owned())))
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
                let hi = decode_hex_nibble(bytes[idx + 1])?;
                let lo = decode_hex_nibble(bytes[idx + 2])?;
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

fn decode_hex_nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

async fn read_limited_body(req: Request<Incoming>) -> Result<Bytes, HttpReply> {
    if let Some(cl_val) = req.headers().get(header::CONTENT_LENGTH) {
        let Ok(cl_str) = cl_val.to_str() else {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid Content-Length header",
            ));
        };
        let Ok(cl_len) = cl_str.trim_ascii().parse::<usize>() else {
            return Err(oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "request body exceeds 64 KiB limit",
            ));
        };
        if cl_len > MAX_POST_BODY_BYTES {
            return Err(oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "request body exceeds 64 KiB limit",
            ));
        }
    }

    let limited = Limited::new(req.into_body(), MAX_POST_BODY_BYTES);
    match tokio::time::timeout(OAUTH_BODY_TIMEOUT, limited.collect()).await {
        Ok(Ok(collected)) => Ok(collected.to_bytes()),
        Ok(Err(err)) if err.is::<LengthLimitError>() => Err(oauth_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "request body exceeds 64 KiB limit",
        )),
        Ok(Err(_)) => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "failed to read request body",
        )),
        Err(_) => {
            let mut reply = oauth_error(
                StatusCode::REQUEST_TIMEOUT,
                "invalid_request",
                "OAuth request body read timed out",
            );
            reply.headers_mut().insert(
                header::CONNECTION,
                header::HeaderValue::from_static("close"),
            );
            Err(reply)
        }
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

fn extract_cookie(headers: &HeaderMap, target_name: &str) -> Option<String> {
    for val in headers.get_all(header::COOKIE) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let Some((name, cookie_val)) = pair.trim_ascii().split_once('=') else {
                continue;
            };
            if name.trim_ascii() == target_name {
                return Some(cookie_val.trim_ascii().to_owned());
            }
        }
    }
    None
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

fn render_authorize_page(pending: &PendingAuthRequest, error_notice: Option<&str>) -> String {
    let display_raw = pending
        .client_name
        .as_deref()
        .unwrap_or(pending.client_id.as_str());
    let display = escape_html(display_raw);
    let client_id = escape_html(&pending.client_id);
    let redirect_uri = escape_html(&pending.redirect_uri);
    let ar_id = escape_html(&pending.ar_id);
    let csrf_token = escape_html(&pending.csrf_token);

    let mut scope_chips = String::new();
    for scope in &pending.scopes {
        scope_chips.push_str("<span class=\"chip\">");
        scope_chips.push_str(&escape_html(scope));
        scope_chips.push_str("</span>");
    }

    let name_row = match pending.client_name.as_deref() {
        Some(name) if name != pending.client_id => format!(
            "<div class=\"row\"><dt>Client</dt><dd>{}</dd></div>",
            escape_html(name)
        ),
        _ => String::new(),
    };

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
<title>Authorize {display}</title>\
<style>\
*{{box-sizing:border-box;margin:0;padding:0}}\
body{{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem;background:#f8fafc;color:#0f172a;font-family:system-ui,-apple-system,sans-serif;line-height:1.5}}\
main{{width:100%;max-width:40rem;background:#ffffff;border:1px solid #e2e8f0;border-radius:0.75rem;padding:2.5rem;box-shadow:0 10px 30px rgba(15,23,42,0.06)}}\
h1{{font-size:clamp(1.35rem,2.5vw,1.75rem);font-weight:650;letter-spacing:-0.02em;margin-bottom:1.75rem;word-break:break-word}}\
dl{{display:grid;gap:1rem;margin-bottom:1.75rem;padding:1.25rem;background:#f8fafc;border-radius:0.5rem;border:1px solid #e2e8f0}}\
.row{{display:grid;gap:0.25rem}}\
dt{{font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:#475569}}\
dd{{font-size:0.925rem;color:#0f172a;word-break:break-all}}\
code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:0.875rem}}\
.chips{{display:flex;flex-wrap:wrap;gap:0.5rem}}\
.chip{{display:inline-block;padding:0.2rem 0.6rem;background:#e2e8f0;color:#0f172a;border-radius:0.375rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:0.825rem}}\
.alert{{margin-bottom:1.25rem;padding:0.75rem 1rem;border-radius:0.5rem;background:#fef2f2;border:1px solid #fecaca;color:#991b1b;font-size:0.9rem;font-weight:500}}\
label{{display:block;font-size:0.875rem;font-weight:600;margin-bottom:0.5rem;color:#1e293b}}\
input[type=\"password\"]{{width:100%;padding:0.7rem 0.875rem;font-size:1rem;border:1px solid #cbd5e1;border-radius:0.5rem;background:#ffffff;color:#0f172a;margin-bottom:1.5rem}}\
input[type=\"password\"]:focus{{outline:2px solid #0f172a;outline-offset:1px}}\
button{{width:100%;padding:0.8rem 1.25rem;font-size:0.95rem;font-weight:600;color:#ffffff;background:#0f172a;border:none;border-radius:0.5rem;cursor:pointer;transition:background-color 150ms ease}}\
button:hover{{background:#1e293b}}\
@media (prefers-reduced-motion:reduce){{button{{transition:none}}}}\
</style>\
</head>\
<body>\
<main>\
<h1>Authorize {display}</h1>\
<dl>\
{name_row}\
<div class=\"row\"><dt>Client ID</dt><dd><code>{client_id}</code></dd></div>\
<div class=\"row\"><dt>Redirect URI</dt><dd><code>{redirect_uri}</code></dd></div>\
<div class=\"row\"><dt>Scopes</dt><dd class=\"chips\">{scope_chips}</dd></div>\
</dl>\
{alert_block}\
<form method=\"post\" action=\"/oauth/authorize\">\
<input type=\"hidden\" name=\"ar_id\" value=\"{ar_id}\">\
<input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token}\">\
<label for=\"password\">Password</label>\
<input id=\"password\" name=\"password\" type=\"password\" required autofocus autocomplete=\"current-password\">\
<button type=\"submit\">Authorize {display}</button>\
</form>\
</main>\
</body>\
</html>"
    )
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

fn method_not_allowed(allow: &'static str) -> HttpReply {
    let mut reply = text_reply(
        StatusCode::METHOD_NOT_ALLOWED,
        "text/plain; charset=utf-8",
        "method not allowed",
    );
    reply
        .headers_mut()
        .insert(header::ALLOW, header::HeaderValue::from_static(allow));
    reply
}

fn not_found_reply() -> HttpReply {
    text_reply(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        "not found",
    )
}
