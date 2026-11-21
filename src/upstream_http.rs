use crate::config::HttpUpstreamSettings;
use crate::crypto::constant_time_eq_str;
use crate::types::{
    ByteBudget, ByteLease, HttpReply, ReadBodyError, ReplyBody, VerifiedToken, bytes_body,
    empty_body, hex_nibble, leased_bytes, method_not_allowed, read_bounded_body,
    request_overloaded_reply,
};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, header,
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, ResponseFuture, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub const MAX_MCP_BODY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PRIMING_BUFFER_BYTES: usize = 1024 * 1024;
const PRIMING_FLUSH_CHUNK_BYTES: usize = 64 * 1024;

pub const MAX_HTTP_SESSIONS: usize = 4096;
pub const MAX_HTTP_SESSIONS_PER_GRANT: usize = 32;

#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    pub max_priming_buffer_bytes: usize,
    pub max_sessions: usize,
    pub max_sessions_per_grant: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_priming_buffer_bytes: MAX_PRIMING_BUFFER_BYTES,
            max_sessions: MAX_HTTP_SESSIONS,
            max_sessions_per_grant: MAX_HTTP_SESSIONS_PER_GRANT,
        }
    }
}
const MAX_GRANT_EPOCHS: usize = 4096;
const MAX_SESSION_ID_LEN: usize = 1024;
const MCP_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
const REVOKE_DELETE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);
const POOL_MAX_IDLE_PER_HOST: usize = 64;

#[derive(Clone)]
enum HttpClient {
    Plain(Client<HttpConnector, ReplyBody>),
    Tls(Client<HttpsConnector<HttpConnector>, ReplyBody>),
}

impl HttpClient {
    fn request(&self, req: Request<ReplyBody>) -> ResponseFuture {
        match self {
            Self::Plain(c) => c.request(req),
            Self::Tls(c) => c.request(req),
        }
    }
}

struct SessionBinding {
    binding_id: u64,
    grant_id: String,
    pool_slot: usize,
    last_used_seq: u64,
    active_post_streams: usize,
    cancel: CancellationToken,
}

enum BindOutcome {
    Bound {
        binding_id: u64,
        session_cancel: CancellationToken,
        evicted: Option<(String, usize, CancellationToken)>,
    },
    CapacityExhausted,
}

struct ActiveGrantEntry {
    cancel: CancellationToken,
    active_streams: usize,
}

struct HttpSessionState {
    sessions: HashMap<String, SessionBinding>,
    active_grants: HashMap<String, ActiveGrantEntry>,
    grant_epochs: HashMap<String, (u64, u64)>,
    seq: u64,
    shutting_down: bool,
}

impl HttpSessionState {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            active_grants: HashMap::new(),
            grant_epochs: HashMap::new(),
            seq: 0,
            shutting_down: false,
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn grant_epoch(&self, grant_id: &str) -> u64 {
        self.grant_epochs
            .get(grant_id)
            .map(|&(ep, _)| ep)
            .unwrap_or(0)
    }

    fn bump_grant_epoch(&mut self, grant_id: &str) {
        let seq = self.next_seq();
        if let Some(entry) = self.grant_epochs.get_mut(grant_id) {
            entry.0 = entry.0.wrapping_add(1);
            entry.1 = seq;
            return;
        }
        if self.grant_epochs.len() >= MAX_GRANT_EPOCHS
            && let Some(oldest_key) = self
                .grant_epochs
                .iter()
                .min_by_key(|(_, (_, s))| *s)
                .map(|(k, _)| k.clone())
        {
            self.grant_epochs.remove(&oldest_key);
        }
        self.grant_epochs.insert(grant_id.to_owned(), (1, seq));
    }

    fn bind_session(
        &mut self,
        sid: String,
        grant_id: &str,
        pool_slot: usize,
        limits: HttpLimits,
    ) -> BindOutcome {
        if self.sessions.contains_key(&sid) {
            let seq = self.next_seq();
            let existing = self.sessions.get_mut(&sid).expect("checked above");
            existing.grant_id.clear();
            existing.grant_id.push_str(grant_id);
            existing.pool_slot = pool_slot;
            existing.last_used_seq = seq;
            return BindOutcome::Bound {
                binding_id: existing.binding_id,
                session_cancel: existing.cancel.clone(),
                evicted: None,
            };
        }

        let per_grant_cap = limits.max_sessions_per_grant.max(1);
        let global_cap = limits.max_sessions.max(1);
        let grant_count = self
            .sessions
            .values()
            .filter(|b| constant_time_eq_str(&b.grant_id, grant_id))
            .count();

        let mut evicted = None;
        if grant_count >= per_grant_cap {
            let Some(evict_key) = self
                .sessions
                .iter()
                .filter(|(_, b)| {
                    constant_time_eq_str(&b.grant_id, grant_id) && b.active_post_streams == 0
                })
                .min_by_key(|(_, b)| b.last_used_seq)
                .map(|(k, _)| k.clone())
            else {
                return BindOutcome::CapacityExhausted;
            };
            if let Some(removed) = self.sessions.remove(&evict_key) {
                evicted = Some((evict_key, removed.pool_slot, removed.cancel));
            }
        } else if self.sessions.len() >= global_cap {
            let Some(evict_key) = self
                .sessions
                .iter()
                .filter(|(_, b)| b.active_post_streams == 0)
                .min_by_key(|(_, b)| b.last_used_seq)
                .map(|(k, _)| k.clone())
            else {
                return BindOutcome::CapacityExhausted;
            };
            if let Some(removed) = self.sessions.remove(&evict_key) {
                evicted = Some((evict_key, removed.pool_slot, removed.cancel));
            }
        }

        let seq = self.next_seq();
        let cancel = CancellationToken::new();
        self.sessions.insert(
            sid,
            SessionBinding {
                binding_id: seq,
                grant_id: grant_id.to_owned(),
                pool_slot,
                last_used_seq: seq,
                active_post_streams: 0,
                cancel: cancel.clone(),
            },
        );
        BindOutcome::Bound {
            binding_id: seq,
            session_cancel: cancel,
            evicted,
        }
    }

    fn acquire_grant_stream(
        &mut self,
        grant_id: &str,
        root_cancel: &CancellationToken,
        state_arc: &Arc<Mutex<Self>>,
        post_claim: Option<(String, u64)>,
    ) -> (CancellationToken, GrantStreamGuard) {
        let entry = self
            .active_grants
            .entry(grant_id.to_owned())
            .or_insert_with(|| ActiveGrantEntry {
                cancel: root_cancel.child_token(),
                active_streams: 0,
            });
        entry.active_streams += 1;
        let cancel = entry.cancel.clone();
        let guard = GrantStreamGuard {
            state: Arc::clone(state_arc),
            grant_id: grant_id.to_owned(),
            grant_cancel: cancel.clone(),
            post_sessions: [post_claim, None],
            refresh_seq_on_drop: false,
        };
        (cancel, guard)
    }
}

struct GrantStreamGuard {
    state: Arc<Mutex<HttpSessionState>>,
    grant_id: String,
    grant_cancel: CancellationToken,
    post_sessions: [Option<(String, u64)>; 2],
    refresh_seq_on_drop: bool,
}

impl Drop for GrantStreamGuard {
    fn drop(&mut self) {
        let has_post = self.post_sessions.iter().any(Option::is_some);
        if self.grant_cancel.is_cancelled() && !has_post {
            return;
        }
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if has_post {
            let seq = if self.refresh_seq_on_drop {
                Some(st.next_seq())
            } else {
                None
            };
            for slot in &mut self.post_sessions {
                if let Some((sid, bid)) = slot.take()
                    && let Some(binding) = st.sessions.get_mut(&sid)
                    && binding.binding_id == bid
                {
                    binding.active_post_streams = binding.active_post_streams.saturating_sub(1);
                    if let Some(s) = seq {
                        binding.last_used_seq = s;
                    }
                }
            }
        }
        if !self.grant_cancel.is_cancelled()
            && let Some(entry) = st.active_grants.get_mut(&self.grant_id)
            && !entry.cancel.is_cancelled()
        {
            entry.active_streams = entry.active_streams.saturating_sub(1);
            if entry.active_streams == 0 {
                st.active_grants.remove(&self.grant_id);
            }
        }
    }
}

pub struct HttpUpstream {
    settings: HttpUpstreamSettings,
    budget: Arc<ByteBudget>,
    limits: HttpLimits,
    client: HttpClient,
    origin_base_str: String,
    mcp_url_str: String,
    upstream_host: HeaderValue,
    forwarded_proto: HeaderValue,
    state: Arc<Mutex<HttpSessionState>>,
    shutdown_token: CancellationToken,
}

impl HttpUpstream {
    pub fn new(settings: HttpUpstreamSettings) -> Result<Self, String> {
        Self::with_limits(settings, ByteBudget::global(), HttpLimits::default())
    }

    pub fn with_limits(
        settings: HttpUpstreamSettings,
        budget: Arc<ByteBudget>,
        limits: HttpLimits,
    ) -> Result<Self, String> {
        let mut http_connector = HttpConnector::new();
        http_connector.set_connect_timeout(Some(CONNECT_TIMEOUT));
        http_connector.set_nodelay(true);
        http_connector.set_keepalive(Some(TCP_KEEPALIVE));

        let client = if settings.url.scheme() == "http" {
            HttpClient::Plain(
                Client::builder(TokioExecutor::new())
                    .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
                    .build(http_connector),
            )
        } else {
            http_connector.enforce_http(false);
            let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .map_err(|e| format!("failed to load native TLS roots: {e}"))?
                .https_only()
                .enable_http1()
                .wrap_connector(http_connector);
            HttpClient::Tls(
                Client::builder(TokioExecutor::new())
                    .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
                    .build(https_connector),
            )
        };

        let host_str = settings
            .url
            .host_str()
            .ok_or_else(|| "upstream.url must specify a host".to_owned())?;
        let authority = match settings.url.port() {
            Some(port) => format!("{host_str}:{port}"),
            None => host_str.to_owned(),
        };
        let upstream_host = HeaderValue::from_str(&authority)
            .map_err(|e| format!("invalid upstream Host header {authority:?}: {e}"))?;
        let forwarded_proto = if settings.public_is_https {
            HeaderValue::from_static("https")
        } else {
            HeaderValue::from_static("http")
        };
        let origin_base_str = settings
            .origin_base
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        let mcp_url_str = settings.url.as_str().to_owned();

        Ok(Self {
            settings,
            budget,
            limits,
            client,
            origin_base_str,
            mcp_url_str,
            upstream_host,
            forwarded_proto,
            state: Arc::new(Mutex::new(HttpSessionState::new())),
            shutdown_token: CancellationToken::new(),
        })
    }

    pub async fn terminate_grant(&self, grant_id: &str) {
        let (grant_cancel, owned_sessions): (
            Option<CancellationToken>,
            Vec<(String, usize, CancellationToken)>,
        ) = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            st.bump_grant_epoch(grant_id);
            let cancel = st.active_grants.remove(grant_id).map(|e| e.cancel);
            let keys: Vec<String> = st
                .sessions
                .iter()
                .filter(|(_, b)| constant_time_eq_str(&b.grant_id, grant_id))
                .map(|(k, _)| k.clone())
                .collect();
            let mut owned = Vec::with_capacity(keys.len());
            for k in keys {
                if let Some(b) = st.sessions.remove(&k) {
                    owned.push((k, b.pool_slot, b.cancel));
                }
            }
            (cancel, owned)
        };

        if let Some(cancel) = grant_cancel {
            cancel.cancel();
        }
        for (_, _, sc) in &owned_sessions {
            sc.cancel();
        }

        if owned_sessions.is_empty() {
            return;
        }

        let mut deletes = JoinSet::new();
        for (sid, pool_slot, _) in owned_sessions {
            if let Some(req) = self.build_session_delete_request(&sid, pool_slot) {
                let client = self.client.clone();
                let timeout_dur = REVOKE_DELETE_TIMEOUT
                    .min(Duration::from_secs(self.settings.request_timeout_secs));
                deletes.spawn(async move {
                    let _ = tokio::time::timeout(timeout_dur, client.request(req)).await;
                });
            }
        }
        while deletes.join_next().await.is_some() {}
    }

    pub async fn shutdown(&self) {
        self.shutdown_token.cancel();
        let cancels: Vec<CancellationToken> = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            st.shutting_down = true;
            let mut all: Vec<CancellationToken> =
                st.sessions.drain().map(|(_, b)| b.cancel).collect();
            all.extend(st.active_grants.drain().map(|(_, e)| e.cancel));
            all
        };
        for c in cancels {
            c.cancel();
        }
    }

    fn build_session_delete_request(
        &self,
        sid: &str,
        pool_slot: usize,
    ) -> Option<Request<ReplyBody>> {
        let target_uri = self.mcp_url_str.parse::<Uri>().ok()?;
        let sid_hv = HeaderValue::from_str(sid).ok()?;
        let mut builder = Request::builder().method(Method::DELETE).uri(target_uri);
        let headers = builder.headers_mut()?;
        headers.insert(header::HOST, self.upstream_host.clone());
        headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            self.forwarded_proto.clone(),
        );
        headers.insert(HeaderName::from_static("mcp-session-id"), sid_hv);
        if !self.settings.bearer_tokens.is_empty() {
            let slot = pool_slot % self.settings.bearer_tokens.len();
            if let Ok(hv) =
                HeaderValue::from_str(&format!("Bearer {}", self.settings.bearer_tokens[slot]))
            {
                headers.insert(header::AUTHORIZATION, hv);
            }
        }
        builder.body(empty_body()).ok()
    }

    pub fn matches_passthrough(&self, raw_path: &str) -> bool {
        if self.settings.passthrough_prefixes.is_empty() {
            return false;
        }
        let Some(decoded) = validate_and_decode_path(raw_path) else {
            return false;
        };
        let path = raw_path.split('?').next().unwrap_or(raw_path);
        self.settings.passthrough_prefixes.iter().any(|prefix| {
            let pb = prefix.as_bytes();
            path.as_bytes().starts_with(pb) && decoded.starts_with(pb)
        })
    }

    pub async fn handle_passthrough(&self, req: Request<Incoming>) -> HttpReply {
        if self.shutdown_token.is_cancelled() {
            return empty_status_reply(StatusCode::SERVICE_UNAVAILABLE);
        }

        let raw_path = req.uri().path();
        if !is_safe_request_path(raw_path) {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        }
        if !self.matches_passthrough(raw_path) {
            return close_empty_reply(StatusCode::NOT_FOUND);
        }

        let method = req.method().clone();
        if !matches!(method, Method::GET | Method::HEAD | Method::PUT) {
            return method_not_allowed("GET, HEAD, PUT");
        }

        let pq = req
            .uri()
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or(raw_path);
        if pq
            .bytes()
            .any(|b| b == b'\\' || b == 0 || b < 0x20 || b == 0x7f)
        {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        }
        let target_str = format!("{}{pq}", self.origin_base_str);
        let Ok(target_uri) = target_str.parse::<Uri>() else {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        };

        let timeout_dur = Duration::from_secs(self.settings.request_timeout_secs);
        let (parts, incoming) = req.into_parts();
        let mut out_req = Request::builder().method(method).uri(target_uri);
        if let Some(headers) = out_req.headers_mut() {
            copy_filtered_headers(&parts.headers, headers, true, false);
            headers.insert(header::HOST, self.upstream_host.clone());
            headers.insert(
                HeaderName::from_static("x-forwarded-proto"),
                self.forwarded_proto.clone(),
            );
        }

        let stream_body = GrantBoundBody::new(
            incoming.map_err(io::Error::other),
            self.shutdown_token.child_token(),
            None,
            None,
            timeout_dur,
        )
        .boxed();
        let Ok(out_req) = out_req.body(stream_body) else {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        };

        let up_resp = tokio::select! {
            _ = self.shutdown_token.cancelled() => {
                return empty_status_reply(StatusCode::SERVICE_UNAVAILABLE);
            }
            res = tokio::time::timeout(timeout_dur, self.client.request(out_req)) => match res {
                Ok(Ok(resp)) => resp,
                Ok(Err(_)) => return empty_status_reply(StatusCode::BAD_GATEWAY),
                Err(_) => return empty_status_reply(StatusCode::GATEWAY_TIMEOUT),
            },
        };

        let (up_parts, up_body) = up_resp.into_parts();
        let mut reply = Response::builder().status(up_parts.status);
        if let Some(headers) = reply.headers_mut() {
            copy_filtered_headers(&up_parts.headers, headers, false, false);
        }
        let out_body = GrantBoundBody::new(
            up_body.map_err(io::Error::other),
            self.shutdown_token.child_token(),
            None,
            None,
            timeout_dur,
        )
        .boxed();
        reply
            .body(out_body)
            .unwrap_or_else(|_| empty_status_reply(StatusCode::BAD_GATEWAY))
    }

    pub async fn handle_mcp(&self, req: Request<Incoming>, token: &VerifiedToken) -> HttpReply {
        let method = req.method().clone();
        if !matches!(method, Method::POST | Method::GET | Method::DELETE) {
            return method_not_allowed("POST, GET, DELETE");
        }

        match check_content_length_limit(req.headers(), MAX_MCP_BODY_BYTES as u64) {
            ContentLengthCheck::Ok => {}
            ContentLengthCheck::Invalid => return close_empty_reply(StatusCode::BAD_REQUEST),
            ContentLengthCheck::TooLarge => {
                return close_empty_reply(StatusCode::PAYLOAD_TOO_LARGE);
            }
        }
        if req.body().size_hint().lower() > MAX_MCP_BODY_BYTES as u64 {
            return close_empty_reply(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let Ok(req_sid) = extract_mcp_session_id(req.headers()) else {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        };

        let target_str = match req.uri().query() {
            Some(q) if !q.is_empty() => {
                if q.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
                    return close_empty_reply(StatusCode::BAD_REQUEST);
                }
                format!("{}?{q}", self.mcp_url_str)
            }
            _ => self.mcp_url_str.clone(),
        };
        let Ok(target_uri) = target_str.parse::<Uri>() else {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        };

        let (start_epoch, grant_cancel, req_session_cancel, req_binding_id, mut stream_guard) = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if st.shutting_down {
                return empty_status_reply(StatusCode::SERVICE_UNAVAILABLE);
            }
            let mut session_cancel = None;
            let mut binding_id = None;
            let mut post_claim = None;
            if let Some(ref sid) = req_sid {
                let owned = st
                    .sessions
                    .get(sid)
                    .is_some_and(|b| constant_time_eq_str(&b.grant_id, &token.grant_id));
                if !owned {
                    return empty_status_reply(StatusCode::NOT_FOUND);
                }
                let seq = if method == Method::POST {
                    Some(st.next_seq())
                } else {
                    None
                };
                if let Some(b) = st.sessions.get_mut(sid) {
                    if let Some(s) = seq {
                        b.last_used_seq = s;
                    }
                    binding_id = Some(b.binding_id);
                    session_cancel = Some(b.cancel.clone());
                    if method == Method::POST {
                        b.active_post_streams += 1;
                        post_claim = Some((sid.clone(), b.binding_id));
                    }
                }
            }
            let epoch = st.grant_epoch(&token.grant_id);
            let (cancel, guard) = st.acquire_grant_stream(
                &token.grant_id,
                &self.shutdown_token,
                &self.state,
                post_claim,
            );
            (epoch, cancel, session_cancel, binding_id, guard)
        };

        let (parts, incoming) = req.into_parts();
        let body_bytes = tokio::select! {
            _ = grant_cancel.cancelled() => {
                return close_empty_reply(StatusCode::SERVICE_UNAVAILABLE);
            }
            res = tokio::time::timeout(
                MCP_BODY_READ_TIMEOUT,
                read_bounded_body(incoming, &self.budget, MAX_MCP_BODY_BYTES),
            ) => match res {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(ReadBodyError::TooLarge)) => {
                    return close_empty_reply(StatusCode::PAYLOAD_TOO_LARGE);
                }
                Ok(Err(ReadBodyError::Overloaded)) => return request_overloaded_reply(),
                Ok(Err(ReadBodyError::Invalid)) => return close_empty_reply(StatusCode::BAD_REQUEST),
                Err(_) => return close_empty_reply(StatusCode::REQUEST_TIMEOUT),
            },
        };

        let mut out_req = Request::builder().method(method.clone()).uri(target_uri);
        if let Some(headers) = out_req.headers_mut() {
            copy_filtered_headers(&parts.headers, headers, true, false);
            headers.remove(header::CONTENT_LENGTH);
            if !body_bytes.is_empty() || method == Method::POST {
                headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body_bytes.len()));
            }
            if !self.settings.bearer_tokens.is_empty() {
                let slot = token.pool_slot % self.settings.bearer_tokens.len();
                let auth_val = format!("Bearer {}", self.settings.bearer_tokens[slot]);
                if let Ok(hv) = HeaderValue::from_str(&auth_val) {
                    headers.insert(header::AUTHORIZATION, hv);
                }
            }
            headers.insert(header::HOST, self.upstream_host.clone());
            headers.insert(
                HeaderName::from_static("x-forwarded-proto"),
                self.forwarded_proto.clone(),
            );
        }

        let Ok(out_req) = out_req.body(bytes_body(body_bytes)) else {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        };

        let timeout_dur = Duration::from_secs(self.settings.request_timeout_secs);
        let get_session_cancel = req_session_cancel
            .as_ref()
            .filter(|_| method == Method::GET);
        let up_resp = tokio::select! {
            _ = grant_cancel.cancelled() => {
                return empty_status_reply(StatusCode::SERVICE_UNAVAILABLE);
            }
            _ = async {
                match get_session_cancel {
                    Some(sc) => sc.cancelled().await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                return empty_status_reply(StatusCode::NOT_FOUND);
            }
            res = tokio::time::timeout(timeout_dur, self.client.request(out_req)) => match res {
                Ok(Ok(resp)) => resp,
                Ok(Err(_)) => return empty_status_reply(StatusCode::BAD_GATEWAY),
                Err(_) => return empty_status_reply(StatusCode::GATEWAY_TIMEOUT),
            },
        };

        let (up_parts, up_body) = up_resp.into_parts();
        if !self.settings.bearer_tokens.is_empty()
            && matches!(
                up_parts.status,
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            )
        {
            return empty_status_reply(StatusCode::BAD_GATEWAY);
        }

        let Ok(resp_sid) = extract_mcp_session_id(&up_parts.headers) else {
            return empty_status_reply(StatusCode::BAD_GATEWAY);
        };

        let mut pending_deletes: Vec<(String, usize)> = Vec::new();
        let mut cancels_to_fire: Vec<CancellationToken> = Vec::new();
        let mut body_session_cancel: Option<CancellationToken> = None;
        let session_outcome = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if st.shutting_down || st.grant_epoch(&token.grant_id) != start_epoch {
                if let Some(sid) = resp_sid.clone().or_else(|| req_sid.clone()) {
                    pending_deletes.push((sid, token.pool_slot));
                }
                Err(StatusCode::SERVICE_UNAVAILABLE)
            } else if method == Method::DELETE || up_parts.status == StatusCode::NOT_FOUND {
                if let Some(ref sid) = req_sid
                    && st.sessions.get(sid).is_some_and(|b| {
                        Some(b.binding_id) == req_binding_id
                            && constant_time_eq_str(&b.grant_id, &token.grant_id)
                    })
                    && let Some(removed) = st.sessions.remove(sid)
                {
                    cancels_to_fire.push(removed.cancel);
                }
                Ok(())
            } else if let Some(ref sid) = req_sid
                && !st.sessions.get(sid).is_some_and(|b| {
                    Some(b.binding_id) == req_binding_id
                        && constant_time_eq_str(&b.grant_id, &token.grant_id)
                })
            {
                if let Some(ref rsid) = resp_sid
                    && req_sid.as_deref() != Some(rsid.as_str())
                    && !st.sessions.contains_key(rsid)
                {
                    pending_deletes.push((rsid.clone(), token.pool_slot));
                }
                Err(StatusCode::NOT_FOUND)
            } else if let Some(ref rsid) = resp_sid
                && st
                    .sessions
                    .get(rsid)
                    .is_some_and(|b| !constant_time_eq_str(&b.grant_id, &token.grant_id))
            {
                Err(StatusCode::BAD_GATEWAY)
            } else {
                body_session_cancel = req_session_cancel;
                let mut outcome = Ok(());
                if up_parts.status.is_success() {
                    if let Some(ref sid) = req_sid {
                        let seq = if method == Method::POST {
                            Some(st.next_seq())
                        } else {
                            None
                        };
                        if let Some(b) = st.sessions.get_mut(sid) {
                            b.pool_slot = token.pool_slot;
                            if let Some(s) = seq {
                                b.last_used_seq = s;
                            }
                            body_session_cancel = Some(b.cancel.clone());
                        }
                    }
                    if let Some(ref rsid) = resp_sid
                        && req_sid.as_deref() != Some(rsid.as_str())
                    {
                        let was_existing = st.sessions.contains_key(rsid);
                        match st.bind_session(
                            rsid.clone(),
                            &token.grant_id,
                            token.pool_slot,
                            self.limits,
                        ) {
                            BindOutcome::Bound {
                                binding_id,
                                session_cancel,
                                evicted,
                            } => {
                                body_session_cancel = Some(session_cancel);
                                if let Some((ev_sid, ev_slot, ev_cancel)) = evicted {
                                    cancels_to_fire.push(ev_cancel);
                                    pending_deletes.push((ev_sid, ev_slot));
                                }
                                if method == Method::POST
                                    && let Some(b) = st.sessions.get_mut(rsid)
                                {
                                    b.active_post_streams += 1;
                                    stream_guard.post_sessions[1] =
                                        Some((rsid.clone(), binding_id));
                                }
                            }
                            BindOutcome::CapacityExhausted => {
                                if !was_existing {
                                    pending_deletes.push((rsid.clone(), token.pool_slot));
                                }
                                outcome = Err(StatusCode::SERVICE_UNAVAILABLE);
                            }
                        }
                    }
                    if outcome.is_ok() && method == Method::POST {
                        stream_guard.refresh_seq_on_drop = true;
                    }
                }
                outcome
            }
        };

        for c in cancels_to_fire {
            c.cancel();
        }

        for (sid, slot) in pending_deletes {
            if let Some(del_req) = self.build_session_delete_request(&sid, slot) {
                let client = self.client.clone();
                let del_timeout = REVOKE_DELETE_TIMEOUT
                    .min(Duration::from_secs(self.settings.request_timeout_secs));
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(del_timeout, client.request(del_req)).await;
                });
            }
        }

        if let Err(err_status) = session_outcome {
            return empty_status_reply(err_status);
        }

        let is_sse = is_event_stream(&up_parts.headers);
        let mut reply = Response::builder().status(up_parts.status);
        if let Some(headers) = reply.headers_mut() {
            copy_filtered_headers(&up_parts.headers, headers, false, true);
            if is_sse {
                headers.remove(header::CONTENT_LENGTH);
            }
            headers.insert(
                HeaderName::from_static("x-accel-buffering"),
                HeaderValue::from_static("no"),
            );
        }

        let out_body: ReplyBody = if is_sse {
            GrantBoundBody::new(
                SsePrimingFilterBody::new(
                    up_body,
                    Arc::clone(&self.budget),
                    self.limits.max_priming_buffer_bytes,
                ),
                grant_cancel,
                body_session_cancel,
                Some(stream_guard),
                timeout_dur,
            )
            .boxed()
        } else {
            GrantBoundBody::new(
                up_body.map_err(io::Error::other),
                grant_cancel,
                body_session_cancel,
                Some(stream_guard),
                timeout_dur,
            )
            .boxed()
        };

        reply
            .body(out_body)
            .unwrap_or_else(|_| empty_status_reply(StatusCode::BAD_GATEWAY))
    }
}

impl Drop for HttpUpstream {
    fn drop(&mut self) {
        self.shutdown_token.cancel();
    }
}

fn extract_mcp_session_id(headers: &HeaderMap) -> Result<Option<String>, ()> {
    let mut iter = headers.get_all("mcp-session-id").iter();
    let Some(first) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(());
    }
    let text = first.to_str().map_err(|_| ())?.trim();
    if text.is_empty()
        || text.len() > MAX_SESSION_ID_LEN
        || !text.bytes().all(|b| (0x21..=0x7E).contains(&b))
    {
        return Err(());
    }
    Ok(Some(text.to_owned()))
}

struct GrantBoundBody<B> {
    inner: B,
    // Mutex provides Sync for BoxBody while get_mut() polls without locking.
    cancel_fut: Mutex<Pin<Box<dyn Future<Output = ()> + Send>>>,
    frame_timeout: Duration,
    idle_sleep: Pin<Box<tokio::time::Sleep>>,
    guard: Option<GrantStreamGuard>,
    done: bool,
}

impl<B> GrantBoundBody<B> {
    fn new(
        inner: B,
        cancel: CancellationToken,
        session_cancel: Option<CancellationToken>,
        guard: Option<GrantStreamGuard>,
        frame_timeout: Duration,
    ) -> Self {
        let fut: Pin<Box<dyn Future<Output = ()> + Send>> = match session_cancel {
            Some(sc) => Box::pin(async move {
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    _ = sc.cancelled() => {}
                }
            }),
            None => Box::pin(cancel.cancelled_owned()),
        };
        Self {
            inner,
            cancel_fut: Mutex::new(fut),
            frame_timeout,
            idle_sleep: Box::pin(tokio::time::sleep(frame_timeout)),
            guard,
            done: false,
        }
    }
}

impl<B> Body for GrantBoundBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }

        let cancel_pin = this.cancel_fut.get_mut().unwrap_or_else(|p| p.into_inner());
        if cancel_pin.as_mut().poll(cx).is_ready() {
            this.done = true;
            this.guard = None;
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream aborted due to grant revocation or shutdown",
            ))));
        }

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.idle_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + this.frame_timeout);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                this.done = true;
                this.guard = None;
                Poll::Ready(Some(Err(io::Error::other(err))))
            }
            Poll::Ready(None) => {
                this.done = true;
                this.guard = None;
                Poll::Ready(None)
            }
            Poll::Pending => {
                if this.idle_sleep.as_mut().poll(cx).is_ready() {
                    this.done = true;
                    this.guard = None;
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "stream frame timed out",
                    ))));
                }
                Poll::Pending
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pub(crate) fn is_safe_request_path(raw_path: &str) -> bool {
    validate_and_decode_path(raw_path).is_some()
}

const MAX_PERCENT_DECODE_ROUNDS: usize = 8;

fn validate_and_decode_path(raw_path: &str) -> Option<Vec<u8>> {
    if raw_path.is_empty()
        || !raw_path.starts_with('/')
        || raw_path.contains('\\')
        || raw_path.contains('\0')
        || raw_path.contains('#')
        || raw_path.chars().any(char::is_control)
    {
        return None;
    }
    let path = raw_path.split('?').next().unwrap_or(raw_path);
    if !path.starts_with('/') {
        return None;
    }

    let raw_bytes = path.as_bytes();
    if has_malformed_percent(raw_bytes) || !is_safe_path_slice(raw_bytes) {
        return None;
    }

    let mut current = raw_bytes.to_vec();
    let mut settled = false;
    for _ in 0..MAX_PERCENT_DECODE_ROUNDS {
        let (next, changed) = decode_percent_pairs(&current);
        if !is_safe_path_slice(&next) {
            return None;
        }
        current = next;
        if !changed {
            settled = true;
            break;
        }
    }
    if !settled && has_decodable_percent(&current) {
        return None;
    }
    Some(current)
}

fn has_malformed_percent(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || hex_nibble(bytes[i + 1]).is_none()
                || hex_nibble(bytes[i + 2]).is_none()
            {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

fn has_decodable_percent(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%'
            && hex_nibble(bytes[i + 1]).is_some()
            && hex_nibble(bytes[i + 2]).is_some()
        {
            return true;
        }
        i += 1;
    }
    false
}

fn decode_percent_pairs(bytes: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            changed = true;
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    (out, changed)
}

fn is_safe_path_slice(bytes: &[u8]) -> bool {
    if bytes
        .iter()
        .any(|&b| b == 0 || b == b'\\' || b < 0x20 || b == 0x7f)
    {
        return false;
    }
    for seg in bytes.split(|&b| b == b'/') {
        let base = seg.split(|&b| b == b';').next().unwrap_or(seg);
        if seg == b"." || seg == b".." || base == b"." || base == b".." {
            return false;
        }
    }
    true
}

pub(crate) enum ContentLengthCheck {
    Ok,
    Invalid,
    TooLarge,
}

pub(crate) fn check_content_length_limit(headers: &HeaderMap, limit: u64) -> ContentLengthCheck {
    let mut seen: Option<u64> = None;
    for raw in headers.get_all(header::CONTENT_LENGTH) {
        let Ok(text) = raw.to_str() else {
            return ContentLengthCheck::Invalid;
        };
        let trimmed = text.trim();
        if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
            return ContentLengthCheck::Invalid;
        }
        let Ok(val) = trimmed.parse::<u64>() else {
            return ContentLengthCheck::TooLarge;
        };
        if let Some(prev) = seen
            && prev != val
        {
            return ContentLengthCheck::Invalid;
        }
        seen = Some(val);
        if val > limit {
            return ContentLengthCheck::TooLarge;
        }
    }
    ContentLengthCheck::Ok
}

fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CONTENT_TYPE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|ct| {
            let media = ct.split(';').next().unwrap_or(ct).trim();
            media.eq_ignore_ascii_case("text/event-stream")
        })
}

fn copy_filtered_headers(
    src: &HeaderMap,
    dst: &mut HeaderMap,
    is_request: bool,
    strip_www_authenticate: bool,
) {
    let mut connection_tokens: HashSet<Vec<u8>> = HashSet::new();
    for val in src.get_all(header::CONNECTION) {
        for raw_tok in val.as_bytes().split(|&b| b == b',') {
            let trimmed = raw_tok.trim_ascii();
            if trimmed.is_empty() {
                continue;
            }
            let lower: Vec<u8> = trimmed.iter().map(u8::to_ascii_lowercase).collect();
            if !matches!(
                lower.as_slice(),
                b"content-length" | b"content-type" | b"host"
            ) {
                connection_tokens.insert(lower);
            }
        }
    }

    for (name, value) in src.iter() {
        let lower = name.as_str();
        if is_hop_by_hop_header(lower) || connection_tokens.contains(lower.as_bytes()) {
            continue;
        }
        if is_request && is_stripped_request_header(lower) {
            continue;
        }
        if !is_request
            && (lower == "set-cookie" || (strip_www_authenticate && lower == "www-authenticate"))
        {
            continue;
        }
        dst.append(name.clone(), value.clone());
    }
}

fn is_stripped_request_header(lower_name: &str) -> bool {
    lower_name.starts_with("x-user-")
        || matches!(
            lower_name,
            "authorization"
                | "cookie"
                | "origin"
                | "forwarded"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
                | "x-forwarded-port"
                | "x-forwarded-prefix"
                | "x-forwarded-user"
                | "x-real-ip"
                | "x-remote-user"
                | "x-original-url"
                | "x-rewrite-url"
                | "cf-connecting-ip"
                | "true-client-ip"
        )
}

fn is_hop_by_hop_header(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

pub(crate) fn close_empty_reply(status: StatusCode) -> HttpReply {
    Response::builder()
        .status(status)
        .header(header::CONNECTION, "close")
        .header(header::CACHE_CONTROL, "no-store")
        .body(empty_body())
        .expect("valid close reply")
}

fn empty_status_reply(status: StatusCode) -> HttpReply {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .body(empty_body())
        .expect("valid status reply")
}

struct SsePrimingFilterBody<B> {
    inner: B,
    buf: Vec<u8>,
    lease: Option<ByteLease>,
    flushing: Bytes,
    budget: Arc<ByteBudget>,
    max_priming_bytes: usize,
    scan_pos: usize,
    line_start: usize,
    filtering: bool,
    inner_eof: bool,
    pending_frame: Option<Frame<Bytes>>,
}

impl<B> SsePrimingFilterBody<B> {
    fn new(inner: B, budget: Arc<ByteBudget>, max_priming_bytes: usize) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            lease: None,
            flushing: Bytes::new(),
            budget,
            max_priming_bytes,
            scan_pos: 0,
            line_start: 0,
            filtering: true,
            inner_eof: false,
            pending_frame: None,
        }
    }

    fn reserve_buf_lease(&mut self, target_len: usize) -> bool {
        self.lease
            .get_or_insert_with(|| self.budget.try_acquire(0).expect("empty byte lease"))
            .reserve_vec(&mut self.buf, target_len, self.max_priming_bytes)
    }

    fn sync_buf_lease(&mut self) {
        if self.buf.is_empty() {
            self.buf = Vec::new();
            self.lease = None;
        }
    }

    fn clear_buffers(&mut self) {
        self.buf = Vec::new();
        self.lease = None;
        self.flushing = Bytes::new();
        self.pending_frame = None;
    }
}

impl<B> Body for SsePrimingFilterBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            if !this.filtering {
                if !this.buf.is_empty() {
                    this.flushing = leased_bytes(std::mem::take(&mut this.buf), this.lease.take());
                }
                if !this.flushing.is_empty() {
                    let take = this.flushing.len().min(PRIMING_FLUSH_CHUNK_BYTES);
                    let out = this.flushing.split_to(take);
                    if this.flushing.is_empty() {
                        this.flushing = Bytes::new();
                    }
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                if let Some(frame) = this.pending_frame.take() {
                    return Poll::Ready(Some(Ok(frame)));
                }
            }

            if this.inner_eof {
                return Poll::Ready(None);
            }

            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(err))) => {
                    this.clear_buffers();
                    return Poll::Ready(Some(Err(io::Error::other(err))));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if !this.filtering {
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    match frame.into_data() {
                        Ok(mut chunk) => {
                            if chunk.is_empty() {
                                continue;
                            }
                            while this.filtering && !chunk.is_empty() {
                                if this.scan_pos == this.buf.len()
                                    && this.line_start == this.buf.len()
                                    && starts_with_sse_data(&chunk)
                                {
                                    this.filtering = false;
                                    break;
                                }
                                let room = this.max_priming_bytes.saturating_sub(this.buf.len());
                                if room == 0 {
                                    this.filtering = false;
                                    break;
                                }
                                let take = next_priming_step_len(&chunk, room);
                                let target_len = this.buf.len() + take;
                                if !this.reserve_buf_lease(target_len) {
                                    this.clear_buffers();
                                    return Poll::Ready(Some(Err(io::Error::other(
                                        "process active byte budget exceeded",
                                    ))));
                                }
                                this.buf.extend_from_slice(&chunk[..take]);
                                chunk = chunk.slice(take..);
                                scan_priming_buffer(
                                    &mut this.buf,
                                    &mut this.scan_pos,
                                    &mut this.line_start,
                                    &mut this.filtering,
                                    false,
                                );
                                this.sync_buf_lease();
                            }
                            if !this.filtering && !chunk.is_empty() {
                                if this.buf.is_empty() {
                                    return Poll::Ready(Some(Ok(Frame::data(chunk))));
                                }
                                this.pending_frame = Some(Frame::data(chunk));
                            }
                        }
                        Err(non_data_frame) => {
                            scan_priming_buffer(
                                &mut this.buf,
                                &mut this.scan_pos,
                                &mut this.line_start,
                                &mut this.filtering,
                                true,
                            );
                            this.sync_buf_lease();
                            if !this.filtering && !this.buf.is_empty() {
                                this.pending_frame = Some(non_data_frame);
                                continue;
                            }
                            this.filtering = false;
                            this.clear_buffers();
                            return Poll::Ready(Some(Ok(non_data_frame)));
                        }
                    }
                }
                Poll::Ready(None) => {
                    this.inner_eof = true;
                    if this.filtering {
                        scan_priming_buffer(
                            &mut this.buf,
                            &mut this.scan_pos,
                            &mut this.line_start,
                            &mut this.filtering,
                            true,
                        );
                        this.sync_buf_lease();
                        if !this.filtering && !this.buf.is_empty() {
                            continue;
                        }
                        this.filtering = false;
                        this.clear_buffers();
                    }
                    return Poll::Ready(None);
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn starts_with_sse_data(chunk: &[u8]) -> bool {
    chunk.starts_with(b"data:") || chunk.starts_with(b"data\n") || chunk.starts_with(b"data\r")
}

fn next_priming_step_len(chunk: &[u8], room: usize) -> usize {
    let window = &chunk[..chunk.len().min(room)];
    if let Some(pos) = window.iter().position(|&b| b == b'\n' || b == b'\r') {
        if window[pos] == b'\r' && pos + 1 < window.len() && window[pos + 1] == b'\n' {
            pos + 2
        } else {
            pos + 1
        }
    } else {
        window.len()
    }
}

fn scan_priming_buffer(
    buf: &mut Vec<u8>,
    scan_pos: &mut usize,
    line_start: &mut usize,
    filtering: &mut bool,
    eof: bool,
) {
    while *scan_pos < buf.len() {
        let b = buf[*scan_pos];
        let (line_end, after_eol) = if b == b'\n' {
            (*scan_pos, *scan_pos + 1)
        } else if b == b'\r' {
            if *scan_pos + 1 < buf.len() {
                let next = if buf[*scan_pos + 1] == b'\n' {
                    *scan_pos + 2
                } else {
                    *scan_pos + 1
                };
                (*scan_pos, next)
            } else if eof {
                (*scan_pos, *scan_pos + 1)
            } else {
                // Pause at trailing CR in case LF arrives next, unless line is already data.
                if is_sse_data_line(&buf[*line_start..*scan_pos]) {
                    *filtering = false;
                }
                return;
            }
        } else {
            *scan_pos += 1;
            continue;
        };

        let line = &buf[*line_start..line_end];
        if line.is_empty() {
            buf.drain(..after_eol);
            *scan_pos = 0;
            *line_start = 0;
            continue;
        }
        if is_sse_data_line(line) {
            *filtering = false;
            return;
        }
        *line_start = after_eol;
        *scan_pos = after_eol;
    }

    let tail = &buf[*line_start..];
    if tail.starts_with(b"data:") || (eof && is_sse_data_line(tail)) {
        *filtering = false;
    }
}

fn is_sse_data_line(line: &[u8]) -> bool {
    line == b"data" || line.starts_with(b"data:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sse_priming_filter_handles_bare_cr_bare_data_and_large_comments_linearly() {
        let mut buf = Vec::new();
        let mut scan_pos = 0usize;
        let mut line_start = 0usize;
        let mut filtering = true;

        for _ in 0..8000 {
            buf.extend_from_slice(b": keepalive-comment-line-0123456789abcdef\r");
            scan_priming_buffer(
                &mut buf,
                &mut scan_pos,
                &mut line_start,
                &mut filtering,
                false,
            );
            buf.extend_from_slice(b"\r");
            scan_priming_buffer(
                &mut buf,
                &mut scan_pos,
                &mut line_start,
                &mut filtering,
                false,
            );
            assert!(filtering);
        }

        buf.extend_from_slice(b"id: ev-cr\rdata\r\r");
        scan_priming_buffer(
            &mut buf,
            &mut scan_pos,
            &mut line_start,
            &mut filtering,
            false,
        );
        assert!(!filtering);
        assert_eq!(&buf[..], b"id: ev-cr\rdata\r\r");
    }

    #[tokio::test]
    async fn http_priming_keeps_allocated_capacity_leased() {
        let budget = ByteBudget::new(300);
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut filter =
            SsePrimingFilterBody::new(futures_channel_body(rx), Arc::clone(&budget), 300);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        tx.send(Ok(Frame::data(Bytes::from(format!(
            ":{}",
            "a".repeat(129)
        )))))
        .await
        .unwrap();
        assert!(Pin::new(&mut filter).poll_frame(&mut cx).is_pending());
        tx.send(Ok(Frame::data(Bytes::from(vec![b'b'; 100]))))
            .await
            .unwrap();
        assert!(Pin::new(&mut filter).poll_frame(&mut cx).is_pending());
        assert_eq!(budget.used(), filter.buf.capacity());
        tx.send(Ok(Frame::data(Bytes::from_static(b"\ndata: 1\n\n"))))
            .await
            .unwrap();
        drop(tx);
        let mut frames = Vec::new();
        while let Some(frame) = BodyExt::frame(&mut filter).await {
            frames.push(frame.unwrap());
        }
        assert!(budget.used() > 0);
        drop(filter);
        assert!(budget.used() > 0);
        drop(frames);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn sse_priming_filter_enforces_pre_append_cap_and_budget_boundaries() {
        let cap = 128usize;
        let budget = ByteBudget::new(4096);

        for priming_len in [cap - 1, cap] {
            let mut priming = vec![b':'];
            priming.extend(std::iter::repeat_n(b'p', priming_len - 3));
            priming.extend_from_slice(b"\n\n");
            assert_eq!(priming.len(), priming_len);

            let mut single_chunk = priming;
            single_chunk.extend_from_slice(b"data: {\"ok\":true}\n\n");
            let inner = bytes_body(single_chunk);
            let mut filter = SsePrimingFilterBody::new(inner, Arc::clone(&budget), cap);
            let out = BodyExt::collect(&mut filter).await.unwrap().to_bytes();
            assert_eq!(&out[..], b"data: {\"ok\":true}\n\n");
            assert_eq!(budget.used(), 0);
        }

        // N + 1 priming block without blank line stops filtering before exceeding `cap` in `buf`.
        let mut oversized_priming = vec![b':'];
        oversized_priming.extend(std::iter::repeat_n(b'q', cap - 2));
        oversized_priming.extend_from_slice(b"\n\n");
        assert_eq!(oversized_priming.len(), cap + 1);
        let mut big_chunk = oversized_priming.clone();
        big_chunk.extend(std::iter::repeat_n(b'x', 256 * 1024));
        big_chunk.extend_from_slice(b"\ndata: {\"ok\":true}\n\n");

        let expected = big_chunk.clone();
        let mut filter = SsePrimingFilterBody::new(bytes_body(big_chunk), Arc::clone(&budget), cap);
        let mut collected = Vec::new();
        while let Some(frame) = BodyExt::frame(&mut filter).await {
            assert!(
                filter.buf.len() <= cap,
                "priming buf exceeded cap: {}",
                filter.buf.len()
            );
            if let Ok(data) = frame.unwrap().into_data() {
                collected.extend_from_slice(&data);
            }
        }
        assert_eq!(collected, expected);
        assert_eq!(budget.used(), 0);

        // Exact N-1 / N pass and N+1 non-blocking reject on process ByteBudget, releasing held bytes.
        let tight_limit = 64usize;
        let tight_budget = ByteBudget::new(tight_limit);
        for len in [tight_limit - 1, tight_limit] {
            let mut priming = vec![b':'];
            priming.extend(std::iter::repeat_n(b'm', len - 3));
            priming.extend_from_slice(b"\n\ndata: 1\n\n");
            let mut f =
                SsePrimingFilterBody::new(bytes_body(priming), Arc::clone(&tight_budget), 512);
            let out = BodyExt::collect(&mut f).await.unwrap().to_bytes();
            assert_eq!(&out[..], b"data: 1\n\n");
            assert_eq!(tight_budget.used(), 0);
        }

        let (mut tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, io::Error>>(4);
        let rx_body = futures_channel_body(rx);
        let mut f_over = SsePrimingFilterBody::new(rx_body, Arc::clone(&tight_budget), 512);

        let mut part1 = vec![b':'];
        part1.extend(std::iter::repeat_n(b'a', tight_limit - 1));
        assert_eq!(part1.len(), tight_limit);
        tx.send(Ok(Frame::data(Bytes::from(part1)))).await.unwrap();

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(Pin::new(&mut f_over).poll_frame(&mut cx).is_pending());
        assert_eq!(tight_budget.used(), tight_limit);

        // Appending 1 more byte (N + 1) must fail non-blockingly and release all `tight_limit` held bytes.
        tx.send(Ok(Frame::data(Bytes::from_static(b"z"))))
            .await
            .unwrap();
        let res = Pin::new(&mut f_over).poll_frame(&mut cx);
        match res {
            Poll::Ready(Some(Err(err))) => {
                assert!(
                    err.to_string().contains("byte budget"),
                    "unexpected err: {err}"
                );
            }
            other => panic!("expected budget error at N+1, got {other:?}"),
        }
        assert_eq!(
            tight_budget.used(),
            0,
            "failed growth must immediately release previously held lease"
        );
        let _ = &mut tx;
    }

    struct MpscBody {
        rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, io::Error>>,
    }

    impl Body for MpscBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.rx.poll_recv(cx)
        }
    }

    fn futures_channel_body(
        rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, io::Error>>,
    ) -> ReplyBody {
        MpscBody { rx }.boxed()
    }

    #[test]
    fn bind_session_enforces_global_cap_and_active_post_protection() {
        let mut st = HttpSessionState::new();
        let limits = HttpLimits {
            max_priming_buffer_bytes: 1024,
            max_sessions: 2,
            max_sessions_per_grant: 4,
        };

        assert!(matches!(
            st.bind_session("s1".to_owned(), "g1", 0, limits),
            BindOutcome::Bound { evicted: None, .. }
        ));
        assert!(matches!(
            st.bind_session("s2".to_owned(), "g2", 1, limits),
            BindOutcome::Bound { evicted: None, .. }
        ));

        // Mark oldest global session s1 as having an active POST stream; s3 must evict s2 instead of s1.
        st.sessions.get_mut("s1").unwrap().active_post_streams = 1;
        match st.bind_session("s3".to_owned(), "g3", 2, limits) {
            BindOutcome::Bound {
                evicted: Some((ev_sid, ev_slot, ev_cancel)),
                ..
            } => {
                assert_eq!(ev_sid, "s2");
                assert_eq!(ev_slot, 1);
                ev_cancel.cancel();
                assert!(ev_cancel.is_cancelled());
            }
            _ => panic!("expected s2 to be evicted under global cap"),
        }
        assert!(st.sessions.contains_key("s1"));
        assert!(st.sessions.contains_key("s3"));

        // When both global slots have active POST streams, a 3rd distinct session returns CapacityExhausted.
        st.sessions.get_mut("s3").unwrap().active_post_streams = 1;
        assert!(matches!(
            st.bind_session("s4".to_owned(), "g4", 0, limits),
            BindOutcome::CapacityExhausted
        ));
        assert!(!st.sessions.contains_key("s4"));
        assert_eq!(st.sessions.len(), 2);
    }

    #[tokio::test]
    async fn stale_generation_responses_do_not_delete_or_pollute_rebound_same_sid() {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use tokio::net::TcpListener;
        use tokio::sync::{Notify, oneshot};

        type GateEntry = (
            String,
            oneshot::Sender<(StatusCode, Option<&'static str>, &'static str)>,
        );
        let gates: Arc<Mutex<Vec<GateEntry>>> = Arc::new(Mutex::new(Vec::new()));
        let gate_notify = Arc::new(Notify::new());

        let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up_listener.local_addr().unwrap();
        let gates_up = Arc::clone(&gates);
        let notify_up = Arc::clone(&gate_notify);
        let up_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = up_listener.accept().await else {
                    break;
                };
                let gates_conn = Arc::clone(&gates_up);
                let notify_conn = Arc::clone(&notify_up);
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let gates_req = Arc::clone(&gates_conn);
                        let notify_req = Arc::clone(&notify_conn);
                        async move {
                            let method = req.method().clone();
                            let tag = req
                                .headers()
                                .get("x-test-tag")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_owned();
                            let _ = req.into_body().collect().await;
                            if method == Method::DELETE {
                                return Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .body(empty_body())
                                        .unwrap(),
                                );
                            }
                            if tag.starts_with("gated-") {
                                let (tx, rx) = oneshot::channel();
                                gates_req.lock().unwrap().push((tag, tx));
                                notify_req.notify_waiters();
                                let (status, sid_opt, body_str) = rx.await.unwrap();
                                let mut b = Response::builder()
                                    .status(status)
                                    .header(header::CONTENT_TYPE, "application/json");
                                if let Some(sid) = sid_opt {
                                    b = b.header("mcp-session-id", sid);
                                }
                                return Ok(b.body(bytes_body(body_str)).unwrap());
                            }
                            Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/json")
                                .header("mcp-session-id", "reused-sid")
                                .body(bytes_body(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#))
                                .unwrap())
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let up = Arc::new(
            HttpUpstream::new(HttpUpstreamSettings {
                url: url::Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
                origin_base: url::Url::parse(&format!("http://{up_addr}")).unwrap(),
                public_is_https: false,
                bearer_tokens: Vec::new(),
                passthrough_prefixes: Vec::new(),
                request_timeout_secs: 30,
            })
            .unwrap(),
        );

        let gw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw_listener.local_addr().unwrap();
        let up_gw = Arc::clone(&up);
        let gw_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = gw_listener.accept().await else {
                    break;
                };
                let up_conn = Arc::clone(&up_gw);
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let up_req = Arc::clone(&up_conn);
                        async move {
                            let tok = VerifiedToken {
                                grant_id: "g-rebind".to_owned(),
                                client_id: "c1".to_owned(),
                                pool_slot: 0,
                                scopes: vec!["mcp".to_owned()],
                                resource: "https://mcp.example.com/mcp".to_owned(),
                            };
                            Ok::<_, std::convert::Infallible>(up_req.handle_mcp(req, &tok).await)
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let client: Client<HttpConnector, ReplyBody> =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());

        // 1. Bind generation 1 of "reused-sid".
        let init1 = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(init1.status(), StatusCode::OK);
        let _ = init1.into_body().collect().await.unwrap();
        let gen1_bid = up.state.lock().unwrap().sessions["reused-sid"].binding_id;

        // 2. Launch two in-flight POSTs against generation 1 ("gated-404" and "gated-200").
        let spawn_gated = |tag: &'static str| {
            let c = client.clone();
            tokio::spawn(async move {
                let resp = c
                    .request(
                        Request::builder()
                            .method(Method::POST)
                            .uri(format!("http://{gw_addr}/mcp"))
                            .header("mcp-session-id", "reused-sid")
                            .header("x-test-tag", tag)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(bytes_body(
                                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}"#,
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = resp.status();
                let _ = resp.into_body().collect().await.unwrap();
                status
            })
        };
        let fut_404 = spawn_gated("gated-404");
        let fut_200 = spawn_gated("gated-200");

        while gates.lock().unwrap().len() < 2 {
            let n = gate_notify.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if gates.lock().unwrap().len() >= 2 {
                break;
            }
            n.await;
        }
        assert_eq!(
            up.state.lock().unwrap().sessions["reused-sid"].active_post_streams,
            2
        );

        // 3. DELETE generation 1, then re-initialize the exact same session ID ("reused-sid", generation 2).
        let del = client
            .request(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", "reused-sid")
                    .body(empty_body())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del.status(), StatusCode::OK);
        let _ = del.into_body().collect().await.unwrap();

        let init2 = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(init2.status(), StatusCode::OK);
        let _ = init2.into_body().collect().await.unwrap();

        let (gen2_bid, gen2_cancel) = {
            let st = up.state.lock().unwrap();
            let b = &st.sessions["reused-sid"];
            assert_ne!(b.binding_id, gen1_bid);
            assert_eq!(b.active_post_streams, 0);
            (b.binding_id, b.cancel.clone())
        };

        // 4. Release generation 1's late 404 and late 200 responses: neither may delete, cancel, or stream onto generation 2!
        let drained: Vec<GateEntry> = std::mem::take(&mut *gates.lock().unwrap());
        for (tag, tx) in drained {
            if tag == "gated-404" {
                tx.send((StatusCode::NOT_FOUND, None, "")).unwrap();
            } else {
                tx.send((
                    StatusCode::OK,
                    Some("reused-sid"),
                    r#"{"jsonrpc":"2.0","id":2,"result":{"stale":true}}"#,
                ))
                .unwrap();
            }
        }
        assert_eq!(fut_404.await.unwrap(), StatusCode::NOT_FOUND);
        assert_eq!(
            fut_200.await.unwrap(),
            StatusCode::NOT_FOUND,
            "stale generation-1 200 response must be rejected with 404 instead of streaming onto generation 2"
        );

        {
            let st = up.state.lock().unwrap();
            let b = st
                .sessions
                .get("reused-sid")
                .expect("generation 2 must survive stale generation 1 404");
            assert_eq!(b.binding_id, gen2_bid);
            assert_eq!(b.active_post_streams, 0);
            assert!(!gen2_cancel.is_cancelled());
        }

        // 5. Generation 2 remains usable for fresh POST calls.
        let fresh = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", "reused-sid")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fresh.status(), StatusCode::OK);
        let _ = fresh.into_body().collect().await.unwrap();
        assert_eq!(
            up.state.lock().unwrap().sessions["reused-sid"].active_post_streams,
            0
        );

        up.shutdown().await;
        gw_task.abort();
        up_task.abort();
    }
}
