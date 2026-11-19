use crate::config::HttpUpstreamSettings;
use crate::crypto::constant_time_eq_str;
use crate::types::{HttpReply, ReplyBody, VerifiedToken, bytes_body, empty_body};
use bytes::{Bytes, BytesMut};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, header,
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, LengthLimitError, Limited};
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
const MAX_PRIMING_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_HTTP_SESSIONS: usize = 4096;
const MAX_HTTP_SESSIONS_PER_GRANT: usize = 32;
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
    grant_id: String,
    pool_slot: usize,
    last_used_seq: u64,
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
    ) -> Option<(String, usize)> {
        let seq = self.next_seq();
        if let Some(existing) = self.sessions.get_mut(&sid) {
            existing.grant_id.clear();
            existing.grant_id.push_str(grant_id);
            existing.pool_slot = pool_slot;
            existing.last_used_seq = seq;
            return None;
        }
        let mut evicted = None;
        let grant_count = self
            .sessions
            .values()
            .filter(|b| b.grant_id == grant_id)
            .count();
        if grant_count >= MAX_HTTP_SESSIONS_PER_GRANT {
            if let Some((evict_key, evict_slot)) = self
                .sessions
                .iter()
                .filter(|(_, b)| b.grant_id == grant_id)
                .min_by_key(|(_, b)| b.last_used_seq)
                .map(|(k, b)| (k.clone(), b.pool_slot))
            {
                self.sessions.remove(&evict_key);
                evicted = Some((evict_key, evict_slot));
            }
        } else if self.sessions.len() >= MAX_HTTP_SESSIONS
            && let Some((evict_key, evict_slot)) = self
                .sessions
                .iter()
                .min_by_key(|(_, b)| b.last_used_seq)
                .map(|(k, b)| (k.clone(), b.pool_slot))
        {
            self.sessions.remove(&evict_key);
            evicted = Some((evict_key, evict_slot));
        }
        self.sessions.insert(
            sid,
            SessionBinding {
                grant_id: grant_id.to_owned(),
                pool_slot,
                last_used_seq: seq,
            },
        );
        evicted
    }

    fn acquire_grant_stream(
        &mut self,
        grant_id: &str,
        root_cancel: &CancellationToken,
        state_arc: &Arc<Mutex<Self>>,
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
            cancel: cancel.clone(),
        };
        (cancel, guard)
    }
}

struct GrantStreamGuard {
    state: Arc<Mutex<HttpSessionState>>,
    grant_id: String,
    cancel: CancellationToken,
}

impl Drop for GrantStreamGuard {
    fn drop(&mut self) {
        if self.cancel.is_cancelled() {
            return;
        }
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = st.active_grants.get_mut(&self.grant_id)
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
        let (grant_cancel, owned_sessions): (Option<CancellationToken>, Vec<(String, usize)>) = {
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
                    owned.push((k, b.pool_slot));
                }
            }
            (cancel, owned)
        };

        if let Some(cancel) = grant_cancel {
            cancel.cancel();
        }

        if owned_sessions.is_empty() {
            return;
        }

        let mut deletes = JoinSet::new();
        for (sid, pool_slot) in owned_sessions {
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
            st.sessions.clear();
            st.active_grants.drain().map(|(_, e)| e.cancel).collect()
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

        let (start_epoch, grant_cancel, stream_guard) = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if st.shutting_down {
                return empty_status_reply(StatusCode::SERVICE_UNAVAILABLE);
            }
            if let Some(ref sid) = req_sid {
                let owned = st
                    .sessions
                    .get(sid)
                    .is_some_and(|b| constant_time_eq_str(&b.grant_id, &token.grant_id));
                if !owned {
                    return empty_status_reply(StatusCode::NOT_FOUND);
                }
                let seq = st.next_seq();
                if let Some(b) = st.sessions.get_mut(sid) {
                    b.last_used_seq = seq;
                }
            }
            let epoch = st.grant_epoch(&token.grant_id);
            let (cancel, guard) =
                st.acquire_grant_stream(&token.grant_id, &self.shutdown_token, &self.state);
            (epoch, cancel, guard)
        };

        let (parts, incoming) = req.into_parts();
        let body_bytes = tokio::select! {
            _ = grant_cancel.cancelled() => {
                return close_empty_reply(StatusCode::SERVICE_UNAVAILABLE);
            }
            res = tokio::time::timeout(
                MCP_BODY_READ_TIMEOUT,
                Limited::new(incoming, MAX_MCP_BODY_BYTES).collect(),
            ) => match res {
                Ok(Ok(collected)) => collected.to_bytes(),
                Ok(Err(err)) if err.is::<LengthLimitError>() => {
                    return close_empty_reply(StatusCode::PAYLOAD_TOO_LARGE);
                }
                Ok(Err(_)) => return close_empty_reply(StatusCode::BAD_REQUEST),
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
        let up_resp = tokio::select! {
            _ = grant_cancel.cancelled() => {
                return empty_status_reply(StatusCode::SERVICE_UNAVAILABLE);
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
        let session_outcome = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if st.shutting_down || st.grant_epoch(&token.grant_id) != start_epoch {
                if let Some(sid) = resp_sid.clone().or_else(|| req_sid.clone()) {
                    pending_deletes.push((sid, token.pool_slot));
                }
                Err(StatusCode::SERVICE_UNAVAILABLE)
            } else if method == Method::DELETE || up_parts.status == StatusCode::NOT_FOUND {
                if let Some(ref sid) = req_sid
                    && st
                        .sessions
                        .get(sid)
                        .is_some_and(|b| constant_time_eq_str(&b.grant_id, &token.grant_id))
                {
                    st.sessions.remove(sid);
                }
                Ok(())
            } else if let Some(ref sid) = req_sid
                && !st
                    .sessions
                    .get(sid)
                    .is_some_and(|b| constant_time_eq_str(&b.grant_id, &token.grant_id))
            {
                Err(StatusCode::NOT_FOUND)
            } else if let Some(ref rsid) = resp_sid
                && st
                    .sessions
                    .get(rsid)
                    .is_some_and(|b| !constant_time_eq_str(&b.grant_id, &token.grant_id))
            {
                Err(StatusCode::BAD_GATEWAY)
            } else {
                if up_parts.status.is_success() {
                    if let Some(ref sid) = req_sid
                        && let Some(evicted) =
                            st.bind_session(sid.clone(), &token.grant_id, token.pool_slot)
                    {
                        pending_deletes.push(evicted);
                    }
                    if let Some(ref rsid) = resp_sid
                        && let Some(evicted) =
                            st.bind_session(rsid.clone(), &token.grant_id, token.pool_slot)
                    {
                        pending_deletes.push(evicted);
                    }
                }
                Ok(())
            }
        };

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
                SsePrimingFilterBody::new(up_body),
                grant_cancel,
                Some(stream_guard),
                timeout_dur,
            )
            .boxed()
        } else {
            GrantBoundBody::new(
                up_body.map_err(io::Error::other),
                grant_cancel,
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
        guard: Option<GrantStreamGuard>,
        frame_timeout: Duration,
    ) -> Self {
        Self {
            inner,
            cancel_fut: Mutex::new(Box::pin(cancel.cancelled_owned())),
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

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
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

pub(crate) fn method_not_allowed(allow: &'static str) -> HttpReply {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::ALLOW, allow)
        .header(header::CACHE_CONTROL, "no-store")
        .body(empty_body())
        .expect("valid 405 reply")
}

struct SsePrimingFilterBody<B> {
    inner: B,
    buf: BytesMut,
    scan_pos: usize,
    line_start: usize,
    filtering: bool,
    pending_frame: Option<Frame<Bytes>>,
}

impl<B> SsePrimingFilterBody<B> {
    fn new(inner: B) -> Self {
        Self {
            inner,
            buf: BytesMut::new(),
            scan_pos: 0,
            line_start: 0,
            filtering: true,
            pending_frame: None,
        }
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
            if !this.filtering && !this.buf.is_empty() {
                let out = this.buf.split().freeze();
                return Poll::Ready(Some(Ok(Frame::data(out))));
            }
            if let Some(frame) = this.pending_frame.take() {
                return Poll::Ready(Some(Ok(frame)));
            }

            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Some(Err(io::Error::other(err))));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if !this.filtering {
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    match frame.into_data() {
                        Ok(chunk) => {
                            if chunk.is_empty() {
                                continue;
                            }
                            this.buf.extend_from_slice(&chunk);
                            scan_priming_buffer(
                                &mut this.buf,
                                &mut this.scan_pos,
                                &mut this.line_start,
                                &mut this.filtering,
                                false,
                            );
                            if !this.filtering && !this.buf.is_empty() {
                                let out = this.buf.split().freeze();
                                return Poll::Ready(Some(Ok(Frame::data(out))));
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
                            if !this.filtering && !this.buf.is_empty() {
                                this.pending_frame = Some(non_data_frame);
                                let out = this.buf.split().freeze();
                                return Poll::Ready(Some(Ok(Frame::data(out))));
                            }
                            this.filtering = false;
                            this.buf.clear();
                            return Poll::Ready(Some(Ok(non_data_frame)));
                        }
                    }
                }
                Poll::Ready(None) => {
                    if this.filtering {
                        scan_priming_buffer(
                            &mut this.buf,
                            &mut this.scan_pos,
                            &mut this.line_start,
                            &mut this.filtering,
                            true,
                        );
                        if !this.filtering && !this.buf.is_empty() {
                            let out = this.buf.split().freeze();
                            return Poll::Ready(Some(Ok(Frame::data(out))));
                        }
                        this.filtering = false;
                        this.buf.clear();
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

fn scan_priming_buffer(
    buf: &mut BytesMut,
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
                if is_sse_data_line(&buf[*line_start..*scan_pos])
                    || buf.len() > MAX_PRIMING_BUFFER_BYTES
                {
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
            let _ = buf.split_to(after_eol);
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
    if tail.starts_with(b"data:")
        || (eof && is_sse_data_line(tail))
        || buf.len() > MAX_PRIMING_BUFFER_BYTES
    {
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
        let mut buf = BytesMut::new();
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
}
