use crate::config::StdioUpstreamSettings;
use crate::crypto::{constant_time_eq_str, random_token_b64};
use crate::types::{HttpReply, VerifiedToken, bytes_body, empty_body};
use crate::upstream_http::{
    ContentLengthCheck, MAX_MCP_BODY_BYTES, check_content_length_limit, close_empty_reply,
    method_not_allowed,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, Method, Request, Response, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
const INIT_TIMEOUT: Duration = Duration::from_secs(30);
const STDIN_GRACE_WAIT: Duration = Duration::from_millis(200);
#[cfg(unix)]
const SIGTERM_WAIT: Duration = Duration::from_secs(2);
const STDIN_CHANNEL_CAPACITY: usize = 64;
const NOTIF_CHANNEL_CAPACITY: usize = 256;
const MAX_STDOUT_LINE_BYTES: usize = 64 * 1024 * 1024;
const SESSIONLESS_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const MIN_SESSIONLESS_PROTOCOL_VERSION: &str = "2026-07-28";

pub struct StdioUpstream {
    inner: Arc<StdioInner>,
    reaper_cancel: CancellationToken,
}

struct StdioInner {
    settings: StdioUpstreamSettings,
    epoch: Instant,
    table: Mutex<SessionTable>,
}

struct SessionTable {
    sessions: HashMap<String, Arc<StdioSession>>,
    reserved_slots: usize,
    shutting_down: bool,
}

struct InFlightEntry {
    wire_id: u64,
    client_id: Value,
    progress_token: Option<Value>,
    notif_tx: mpsc::Sender<String>,
    resp_tx: oneshot::Sender<String>,
}

#[cfg(windows)]
struct WindowsJobObject(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
unsafe impl Send for WindowsJobObject {}

#[cfg(windows)]
unsafe impl Sync for WindowsJobObject {}

#[cfg(windows)]
impl WindowsJobObject {
    fn create_and_assign(child: &Child) -> Option<Self> {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let raw_handle = child.raw_handle()?;
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return None;
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            unsafe {
                CloseHandle(job);
            }
            return None;
        }

        let assigned = unsafe { AssignProcessToJobObject(job, raw_handle as HANDLE) };
        if assigned == 0 {
            unsafe {
                CloseHandle(job);
            }
            return None;
        }

        Some(Self(job))
    }
}

#[cfg(windows)]
impl Drop for WindowsJobObject {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

struct StdioSession {
    grant_id: String,
    stdin_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    in_flight: Arc<Mutex<Vec<InFlightEntry>>>,
    next_wire_id: AtomicU64,
    alive: Arc<AtomicBool>,
    active_requests: Arc<AtomicUsize>,
    last_active_ms: Arc<AtomicU64>,
    child: tokio::sync::Mutex<Option<Child>>,
    #[cfg(windows)]
    job: Mutex<Option<WindowsJobObject>>,
    epoch: Instant,
}

impl StdioUpstream {
    pub fn new(settings: StdioUpstreamSettings) -> Result<Self, String> {
        let inner = Arc::new(StdioInner {
            settings,
            epoch: Instant::now(),
            table: Mutex::new(SessionTable {
                sessions: HashMap::new(),
                reserved_slots: 0,
                shutting_down: false,
            }),
        });
        let reaper_cancel = CancellationToken::new();

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let weak_inner = Arc::downgrade(&inner);
            let cancel = reaper_cancel.clone();
            let interval_secs = (inner.settings.session_idle_secs / 2).clamp(1, 15);
            handle.spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = ticker.tick() => {
                            let Some(strong) = weak_inner.upgrade() else {
                                break;
                            };
                            evict_idle_sessions(&strong).await;
                        }
                    }
                }
            });
        }

        Ok(Self {
            inner,
            reaper_cancel,
        })
    }

    pub async fn handle_mcp(&self, req: Request<Incoming>, token: &VerifiedToken) -> HttpReply {
        match *req.method() {
            Method::GET => method_not_allowed("POST, DELETE"),
            Method::DELETE => self.handle_delete(req.headers(), token).await,
            Method::POST => self.handle_post(req, token).await,
            _ => method_not_allowed("POST, DELETE"),
        }
    }

    pub async fn terminate_grant(&self, grant_id: &str) {
        let matched: Vec<Arc<StdioSession>> = {
            let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            let keys: Vec<String> = tbl
                .sessions
                .iter()
                .filter(|(_, s)| constant_time_eq_str(&s.grant_id, grant_id))
                .map(|(k, _)| k.clone())
                .collect();
            keys.into_iter()
                .filter_map(|k| tbl.sessions.remove(&k))
                .collect()
        };
        terminate_all(matched).await;
    }

    pub async fn shutdown(&self) {
        self.reaper_cancel.cancel();
        let drained: Vec<Arc<StdioSession>> = {
            let mut guard = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            guard.shutting_down = true;
            guard.sessions.drain().map(|(_, s)| s).collect()
        };
        terminate_all(drained).await;
    }

    async fn handle_delete(&self, headers: &HeaderMap, token: &VerifiedToken) -> HttpReply {
        let Some(sid) = extract_single_header(headers, "mcp-session-id") else {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        };
        let removed = {
            let mut guard = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            match guard.sessions.get(sid) {
                Some(sess) if constant_time_eq_str(&sess.grant_id, &token.grant_id) => {
                    guard.sessions.remove(sid)
                }
                _ => None,
            }
        };
        let Some(session) = removed else {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CACHE_CONTROL, "no-store")
                .body(empty_body())
                .expect("valid 404 reply");
        };
        session.terminate().await;
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CACHE_CONTROL, "no-store")
            .body(empty_body())
            .expect("valid 200 reply")
    }

    async fn handle_post(&self, req: Request<Incoming>, token: &VerifiedToken) -> HttpReply {
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

        let (parts, incoming) = req.into_parts();
        if has_multiple_headers(&parts.headers, "mcp-session-id") {
            return jsonrpc_error_reply(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32600,
                "duplicate Mcp-Session-Id header",
            );
        }
        let session_id_hdr = match parts.headers.get("mcp-session-id") {
            Some(raw) => match raw.to_str() {
                Ok(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                _ => {
                    return jsonrpc_error_reply(
                        StatusCode::BAD_REQUEST,
                        Value::Null,
                        -32600,
                        "invalid Mcp-Session-Id header",
                    );
                }
            },
            None => None,
        };

        let body_bytes = match tokio::time::timeout(
            BODY_READ_TIMEOUT,
            Limited::new(incoming, MAX_MCP_BODY_BYTES).collect(),
        )
        .await
        {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(err)) if err.is::<LengthLimitError>() => {
                return close_empty_reply(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Ok(Err(_)) => return close_empty_reply(StatusCode::BAD_REQUEST),
            Err(_) => return close_empty_reply(StatusCode::REQUEST_TIMEOUT),
        };

        let payload: Value = match serde_json::from_slice(&body_bytes) {
            Ok(val) => val,
            Err(_) => {
                return jsonrpc_error_reply(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    -32700,
                    "invalid JSON payload",
                );
            }
        };
        let Some(obj) = payload.as_object() else {
            return jsonrpc_error_reply(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32600,
                "JSON-RPC message must be an object",
            );
        };

        let method = obj.get("method").and_then(Value::as_str);
        let req_id = obj.get("id").filter(|v| !v.is_null()).cloned();

        if let Some(sid) = session_id_hdr {
            return self
                .handle_in_session(&sid, &parts.headers, token, &payload, method, req_id)
                .await;
        }

        if method == Some("initialize") {
            return self
                .handle_initialize(&parts.headers, token, &payload, req_id)
                .await;
        }

        if let Some(proto_ver) = detect_sessionless_version(&parts.headers, obj) {
            return self
                .handle_sessionless(&parts.headers, &proto_ver, &payload, method, req_id)
                .await;
        }

        jsonrpc_error_reply(
            StatusCode::BAD_REQUEST,
            req_id.unwrap_or(Value::Null),
            -32600,
            "missing Mcp-Session-Id header",
        )
    }

    async fn handle_initialize(
        &self,
        headers: &HeaderMap,
        token: &VerifiedToken,
        payload: &Value,
        req_id: Option<Value>,
    ) -> HttpReply {
        let Some(id) = req_id else {
            return jsonrpc_error_reply(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32600,
                "initialize request requires an id",
            );
        };

        let Some(reservation) = acquire_slot(&self.inner).await else {
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                id,
                -32000,
                "session limit reached",
            );
        };

        let session = match StdioSession::spawn(&self.inner, token.grant_id.clone()) {
            Ok(s) => s,
            Err(err) => {
                drop(reservation);
                return jsonrpc_error_reply(StatusCode::BAD_GATEWAY, id, -32000, &err);
            }
        };
        let mut ephemeral = EphemeralGuard::new(Arc::clone(&session));

        let (wire_id, mut guard, notif_rx, resp_rx) =
            session.register_request(id.clone(), extract_progress_token(payload));
        drop(notif_rx);
        if session.send_request_line(payload, wire_id).is_err() {
            guard.disarm();
            ephemeral.terminate_now().await;
            drop(reservation);
            return jsonrpc_error_reply(
                StatusCode::BAD_GATEWAY,
                id,
                -32000,
                "upstream child closed stdin during initialize",
            );
        }

        let init_line = match tokio::time::timeout(INIT_TIMEOUT, resp_rx).await {
            Ok(Ok(line)) => {
                guard.mark_completed();
                line
            }
            Ok(Err(_)) => {
                guard.disarm();
                ephemeral.terminate_now().await;
                drop(reservation);
                return jsonrpc_error_reply(
                    StatusCode::BAD_GATEWAY,
                    id,
                    -32000,
                    "upstream child exited before responding to initialize",
                );
            }
            Err(_) => {
                guard.disarm();
                ephemeral.terminate_now().await;
                drop(reservation);
                return jsonrpc_error_reply(
                    StatusCode::GATEWAY_TIMEOUT,
                    id,
                    -32000,
                    "upstream initialize timed out",
                );
            }
        };

        let session_id = match random_token_b64(24) {
            Ok(s) => s,
            Err(err) => {
                ephemeral.terminate_now().await;
                drop(reservation);
                return jsonrpc_error_reply(StatusCode::INTERNAL_SERVER_ERROR, id, -32603, &err);
            }
        };

        let inserted = {
            let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            if tbl.shutting_down {
                false
            } else {
                tbl.sessions
                    .insert(session_id.clone(), Arc::clone(&session));
                reservation.commit(&mut tbl);
                ephemeral.disarm();
                true
            }
        };
        if !inserted {
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                id,
                -32000,
                "gateway is shutting down",
            );
        }

        single_rpc_reply(headers, Some(&session_id), init_line)
    }

    async fn handle_in_session(
        &self,
        session_id: &str,
        headers: &HeaderMap,
        token: &VerifiedToken,
        payload: &Value,
        method: Option<&str>,
        req_id: Option<Value>,
    ) -> HttpReply {
        let session = {
            let tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            tbl.sessions
                .get(session_id)
                .filter(|s| {
                    s.alive.load(Ordering::Acquire)
                        && constant_time_eq_str(&s.grant_id, &token.grant_id)
                })
                .cloned()
        };

        let err_id = req_id.clone().unwrap_or(Value::Null);
        let Some(session) = session else {
            return jsonrpc_error_reply(StatusCode::NOT_FOUND, err_id, -32001, "session not found");
        };
        session.touch();

        let is_request = method.is_some() && req_id.is_some();
        if !is_request {
            let rewritten = if method == Some("notifications/cancelled") {
                session.rewrite_cancel_notification(payload)
            } else {
                None
            };
            let outbound = rewritten.as_ref().unwrap_or(payload);
            if session.send_json_line(outbound).is_err() {
                if !session.alive.load(Ordering::Acquire) {
                    remove_and_terminate(&self.inner, session_id, &session).await;
                    return jsonrpc_error_reply(
                        StatusCode::BAD_GATEWAY,
                        Value::Null,
                        -32000,
                        "upstream child closed stdin",
                    );
                }
                return jsonrpc_error_reply(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Value::Null,
                    -32000,
                    "upstream stdin queue is full",
                );
            }
            return Response::builder()
                .status(StatusCode::ACCEPTED)
                .header(HeaderName::from_static("mcp-session-id"), session_id)
                .header(HeaderName::from_static("x-accel-buffering"), "no")
                .header(header::CACHE_CONTROL, "no-store")
                .body(empty_body())
                .expect("valid 202 reply");
        }

        let id = req_id.unwrap();
        let (wire_id, mut guard, notif_rx, resp_rx) =
            session.register_request(id.clone(), extract_progress_token(payload));
        if session.send_request_line(payload, wire_id).is_err() {
            guard.disarm();
            if !session.alive.load(Ordering::Acquire) {
                remove_and_terminate(&self.inner, session_id, &session).await;
                return jsonrpc_error_reply(
                    StatusCode::BAD_GATEWAY,
                    id,
                    -32000,
                    "upstream child closed stdin",
                );
            }
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                id,
                -32000,
                "upstream stdin queue is full",
            );
        }

        let call_timeout = Duration::from_secs(self.inner.settings.session_idle_secs);

        if client_accepts_sse(headers) {
            let stream =
                StdioSseStreamBody::new(notif_rx, resp_rx, guard, session, call_timeout, None);
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header(header::CACHE_CONTROL, "no-store")
                .header(HeaderName::from_static("x-accel-buffering"), "no")
                .header(HeaderName::from_static("mcp-session-id"), session_id)
                .body(stream.boxed())
                .expect("valid SSE reply");
        }

        drop(notif_rx);
        match tokio::time::timeout(call_timeout, resp_rx).await {
            Ok(Ok(line)) => {
                guard.mark_completed();
                session.touch();
                single_rpc_reply(headers, Some(session_id), line)
            }
            Ok(Err(_)) => {
                guard.disarm();
                if !session.alive.load(Ordering::Acquire) {
                    remove_and_terminate(&self.inner, session_id, &session).await;
                }
                jsonrpc_error_reply(
                    StatusCode::BAD_GATEWAY,
                    id,
                    -32000,
                    "upstream child exited before responding",
                )
            }
            Err(_) => {
                guard.cancel("request timed out");
                jsonrpc_error_reply(
                    StatusCode::GATEWAY_TIMEOUT,
                    id,
                    -32000,
                    "upstream request timed out",
                )
            }
        }
    }

    async fn handle_sessionless(
        &self,
        headers: &HeaderMap,
        protocol_version: &str,
        payload: &Value,
        method: Option<&str>,
        req_id: Option<Value>,
    ) -> HttpReply {
        let err_id = req_id.clone().unwrap_or(Value::Null);
        let Some(reservation) = acquire_slot(&self.inner).await else {
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                err_id,
                -32000,
                "session limit reached",
            );
        };

        let session = match StdioSession::spawn(&self.inner, String::new()) {
            Ok(s) => s,
            Err(err) => {
                drop(reservation);
                return jsonrpc_error_reply(StatusCode::BAD_GATEWAY, err_id, -32000, &err);
            }
        };
        let mut ephemeral = EphemeralGuard::new(Arc::clone(&session));

        let synth_init = json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {
                    "name": "oauth2-mcp-gateway",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        });

        let (init_wire_id, mut init_guard, init_notif_rx, init_resp_rx) =
            session.register_request(json!(0), None);
        drop(init_notif_rx);
        if session
            .send_request_line(&synth_init, init_wire_id)
            .is_err()
        {
            init_guard.disarm();
            ephemeral.terminate_now().await;
            drop(reservation);
            return jsonrpc_error_reply(
                StatusCode::BAD_GATEWAY,
                err_id,
                -32000,
                "ephemeral child closed stdin during initialize",
            );
        }

        match tokio::time::timeout(INIT_TIMEOUT, init_resp_rx).await {
            Ok(Ok(_)) => init_guard.mark_completed(),
            Ok(Err(_)) => {
                init_guard.disarm();
                ephemeral.terminate_now().await;
                drop(reservation);
                return jsonrpc_error_reply(
                    StatusCode::BAD_GATEWAY,
                    err_id,
                    -32000,
                    "ephemeral child exited during initialize",
                );
            }
            Err(_) => {
                init_guard.disarm();
                ephemeral.terminate_now().await;
                drop(reservation);
                return jsonrpc_error_reply(
                    StatusCode::GATEWAY_TIMEOUT,
                    err_id,
                    -32000,
                    "ephemeral initialize timed out",
                );
            }
        }

        let initialized_note = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        if session.send_json_line(&initialized_note).is_err() {
            ephemeral.terminate_now().await;
            drop(reservation);
            return jsonrpc_error_reply(
                StatusCode::BAD_GATEWAY,
                err_id,
                -32000,
                "ephemeral child closed stdin",
            );
        }

        let is_request = method.is_some() && req_id.is_some();
        if !is_request {
            let send_res = session.send_json_line(payload);
            ephemeral.terminate_now().await;
            drop(reservation);
            if send_res.is_err() {
                return jsonrpc_error_reply(
                    StatusCode::BAD_GATEWAY,
                    Value::Null,
                    -32000,
                    "ephemeral child closed stdin",
                );
            }
            return Response::builder()
                .status(StatusCode::ACCEPTED)
                .header(HeaderName::from_static("x-accel-buffering"), "no")
                .header(header::CACHE_CONTROL, "no-store")
                .body(empty_body())
                .expect("valid 202 reply");
        }

        let id = req_id.unwrap();
        let (wire_id, mut guard, notif_rx, resp_rx) =
            session.register_request(id.clone(), extract_progress_token(payload));
        if session.send_request_line(payload, wire_id).is_err() {
            guard.disarm();
            ephemeral.terminate_now().await;
            drop(reservation);
            return jsonrpc_error_reply(
                StatusCode::BAD_GATEWAY,
                id,
                -32000,
                "ephemeral child closed stdin",
            );
        }

        let call_timeout = Duration::from_secs(self.inner.settings.session_idle_secs);

        if client_accepts_sse(headers) {
            ephemeral.attach_slot(reservation);
            let stream = StdioSseStreamBody::new(
                notif_rx,
                resp_rx,
                guard,
                session,
                call_timeout,
                Some(ephemeral),
            );
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header(header::CACHE_CONTROL, "no-store")
                .header(HeaderName::from_static("x-accel-buffering"), "no")
                .body(stream.boxed())
                .expect("valid SSE reply");
        }

        drop(notif_rx);
        let resp_line = match tokio::time::timeout(call_timeout, resp_rx).await {
            Ok(Ok(line)) => line,
            Ok(Err(_)) => {
                guard.disarm();
                ephemeral.terminate_now().await;
                drop(reservation);
                return jsonrpc_error_reply(
                    StatusCode::BAD_GATEWAY,
                    id,
                    -32000,
                    "ephemeral child exited before responding",
                );
            }
            Err(_) => {
                guard.cancel("request timed out");
                ephemeral.terminate_now().await;
                drop(reservation);
                return jsonrpc_error_reply(
                    StatusCode::GATEWAY_TIMEOUT,
                    id,
                    -32000,
                    "ephemeral request timed out",
                );
            }
        };

        guard.mark_completed();
        ephemeral.terminate_now().await;
        drop(reservation);

        single_rpc_reply(headers, None, resp_line)
    }
}

impl Drop for StdioUpstream {
    fn drop(&mut self) {
        self.reaper_cancel.cancel();
    }
}

struct EphemeralGuard {
    session: Option<Arc<StdioSession>>,
    slot: Option<SlotReservation>,
}

impl EphemeralGuard {
    fn new(session: Arc<StdioSession>) -> Self {
        Self {
            session: Some(session),
            slot: None,
        }
    }

    fn attach_slot(&mut self, slot: SlotReservation) {
        self.slot = Some(slot);
    }

    fn disarm(&mut self) {
        self.session = None;
        self.slot = None;
    }

    async fn terminate_now(&mut self) {
        if let Some(sess) = self.session.take() {
            sess.terminate().await;
        }
        let _ = self.slot.take();
    }
}

impl Drop for EphemeralGuard {
    fn drop(&mut self) {
        let slot = self.slot.take();
        if let Some(sess) = self.session.take()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                sess.terminate().await;
                drop(slot);
            });
        }
    }
}

struct SlotReservation {
    inner: Arc<StdioInner>,
    committed: bool,
}

impl SlotReservation {
    fn commit(mut self, tbl: &mut SessionTable) {
        tbl.reserved_slots = tbl.reserved_slots.saturating_sub(1);
        self.committed = true;
    }
}

impl Drop for SlotReservation {
    fn drop(&mut self) {
        if !self.committed {
            let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            tbl.reserved_slots = tbl.reserved_slots.saturating_sub(1);
        }
    }
}

async fn acquire_slot(inner: &Arc<StdioInner>) -> Option<SlotReservation> {
    if try_reserve_slot(inner) {
        return Some(SlotReservation {
            inner: Arc::clone(inner),
            committed: false,
        });
    }
    evict_idle_sessions(inner).await;
    if try_reserve_slot(inner) {
        Some(SlotReservation {
            inner: Arc::clone(inner),
            committed: false,
        })
    } else {
        None
    }
}

fn try_reserve_slot(inner: &StdioInner) -> bool {
    let mut tbl = inner.table.lock().unwrap_or_else(|p| p.into_inner());
    if tbl.shutting_down {
        return false;
    }
    tbl.sessions.retain(|_, s| s.alive.load(Ordering::Acquire));
    if tbl.sessions.len() + tbl.reserved_slots < inner.settings.max_sessions {
        tbl.reserved_slots += 1;
        true
    } else {
        false
    }
}

async fn evict_idle_sessions(inner: &StdioInner) {
    let now_ms = elapsed_ms(inner.epoch);
    let idle_limit_ms = inner.settings.session_idle_secs.saturating_mul(1000);
    let evicted: Vec<Arc<StdioSession>> = {
        let mut tbl = inner.table.lock().unwrap_or_else(|p| p.into_inner());
        let mut stale_ids = Vec::new();
        for (sid, sess) in &tbl.sessions {
            let dead = !sess.alive.load(Ordering::Acquire);
            let idle = sess.active_requests.load(Ordering::Acquire) == 0
                && now_ms.saturating_sub(sess.last_active_ms.load(Ordering::Acquire))
                    >= idle_limit_ms;
            if dead || idle {
                stale_ids.push(sid.clone());
            }
        }
        stale_ids
            .into_iter()
            .filter_map(|id| tbl.sessions.remove(&id))
            .collect()
    };
    terminate_all(evicted).await;
}

async fn remove_and_terminate(inner: &StdioInner, session_id: &str, session: &Arc<StdioSession>) {
    {
        let mut tbl = inner.table.lock().unwrap_or_else(|p| p.into_inner());
        if tbl
            .sessions
            .get(session_id)
            .is_some_and(|cur| Arc::ptr_eq(cur, session))
        {
            tbl.sessions.remove(session_id);
        }
    }
    session.terminate().await;
}

async fn terminate_all(sessions: Vec<Arc<StdioSession>>) {
    if sessions.is_empty() {
        return;
    }
    let mut set = JoinSet::new();
    for sess in sessions {
        set.spawn(async move {
            sess.terminate().await;
        });
    }
    while set.join_next().await.is_some() {}
}

impl StdioSession {
    fn spawn(inner: &Arc<StdioInner>, grant_id: String) -> Result<Arc<Self>, String> {
        let mut cmd = Command::new(&inner.settings.command);
        cmd.args(&inner.settings.args)
            .envs(&inner.settings.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if let Some(cwd) = &inner.settings.cwd {
            cmd.current_dir(cwd);
        }

        #[cfg(unix)]
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn upstream process: {e}"))?;

        #[cfg(windows)]
        let job = WindowsJobObject::create_and_assign(&child);

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "failed to capture child stdin".to_owned())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "failed to capture child stdout".to_owned())?;

        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(STDIN_CHANNEL_CAPACITY);
        let alive = Arc::new(AtomicBool::new(true));
        let in_flight = Arc::new(Mutex::new(Vec::<InFlightEntry>::new()));
        let active_requests = Arc::new(AtomicUsize::new(0));
        let last_active_ms = Arc::new(AtomicU64::new(elapsed_ms(inner.epoch)));

        let writer_alive = Arc::clone(&alive);
        tokio::spawn(async move {
            while let Some(buf) = stdin_rx.recv().await {
                if stdin.write_all(&buf).await.is_err() || stdin.flush().await.is_err() {
                    writer_alive.store(false, Ordering::Release);
                    break;
                }
            }
            drop(stdin);
        });

        let session = Arc::new(Self {
            grant_id,
            stdin_tx: Mutex::new(Some(stdin_tx)),
            in_flight: Arc::clone(&in_flight),
            next_wire_id: AtomicU64::new(1),
            alive: Arc::clone(&alive),
            active_requests,
            last_active_ms: Arc::clone(&last_active_ms),
            child: tokio::sync::Mutex::new(Some(child)),
            #[cfg(windows)]
            job: Mutex::new(job),
            epoch: inner.epoch,
        });

        let reader_inner = Arc::downgrade(inner);
        let reader_session = Arc::downgrade(&session);
        let epoch = inner.epoch;
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout);
            let mut raw = Vec::new();
            while let Ok(n) = read_bounded_line(&mut lines, &mut raw).await {
                if n == 0 {
                    break;
                }
                if let Ok(text) = std::str::from_utf8(&raw) {
                    let trimmed = text.trim_end_matches(['\r', '\n']);
                    if !trimmed.trim().is_empty() {
                        last_active_ms.store(elapsed_ms(epoch), Ordering::Release);
                        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                            dispatch_stdout_message(&in_flight, trimmed, val);
                        }
                    }
                }
                if raw.capacity() > 64 * 1024 {
                    raw.shrink_to(64 * 1024);
                }
            }
            alive.store(false, Ordering::Release);
            in_flight.lock().unwrap_or_else(|p| p.into_inner()).clear();
            if let (Some(up), Some(sess)) = (reader_inner.upgrade(), reader_session.upgrade()) {
                let matched_key = {
                    let mut tbl = up.table.lock().unwrap_or_else(|p| p.into_inner());
                    let found = tbl
                        .sessions
                        .iter()
                        .find(|(_, v)| Arc::ptr_eq(v, &sess))
                        .map(|(k, _)| k.clone());
                    if let Some(ref k) = found {
                        tbl.sessions.remove(k);
                    }
                    found
                };
                if matched_key.is_some() {
                    sess.terminate().await;
                }
            }
        });

        Ok(session)
    }

    fn touch(&self) {
        self.last_active_ms
            .store(elapsed_ms(self.epoch), Ordering::Release);
    }

    fn send_request_line(&self, payload: &Value, wire_id: u64) -> Result<(), ()> {
        let mut rewritten = payload.clone();
        if let Some(obj) = rewritten.as_object_mut() {
            obj.insert("id".to_owned(), Value::from(wire_id));
        }
        self.send_json_line(&rewritten)
    }

    fn send_json_line(&self, value: &Value) -> Result<(), ()> {
        if !self.alive.load(Ordering::Acquire) {
            return Err(());
        }
        let mut line = serde_json::to_vec(value).map_err(|_| ())?;
        line.push(b'\n');
        self.send_raw_line(line)
    }

    fn rewrite_cancel_notification(&self, payload: &Value) -> Option<Value> {
        let client_req_id = payload.get("params")?.get("requestId")?;
        let wire_id = {
            let waiters = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
            waiters
                .iter()
                .rev()
                .find(|w| json_id_eq(&w.client_id, client_req_id))
                .map(|w| w.wire_id)
        }?;
        let mut cloned = payload.clone();
        cloned
            .get_mut("params")?
            .as_object_mut()?
            .insert("requestId".to_owned(), json!(wire_id));
        Some(cloned)
    }

    fn send_raw_line(&self, line: Vec<u8>) -> Result<(), ()> {
        let guard = self.stdin_tx.lock().unwrap_or_else(|p| p.into_inner());
        let Some(tx) = guard.as_ref() else {
            return Err(());
        };
        tx.try_send(line).map_err(|_| ())
    }

    fn register_request(
        self: &Arc<Self>,
        client_id: Value,
        progress_token: Option<Value>,
    ) -> (
        u64,
        RequestGuard,
        mpsc::Receiver<String>,
        oneshot::Receiver<String>,
    ) {
        let wire_id = self.next_wire_id.fetch_add(1, Ordering::Relaxed);
        let (notif_tx, notif_rx) = mpsc::channel(NOTIF_CHANNEL_CAPACITY);
        let (resp_tx, resp_rx) = oneshot::channel();
        self.active_requests.fetch_add(1, Ordering::AcqRel);
        {
            let mut waiters = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
            waiters.push(InFlightEntry {
                wire_id,
                client_id,
                progress_token,
                notif_tx,
                resp_tx,
            });
        }
        let guard = RequestGuard {
            session: Arc::clone(self),
            wire_id,
            state: GuardState::Armed,
        };
        (wire_id, guard, notif_rx, resp_rx)
    }

    async fn terminate(&self) {
        self.alive.store(false, Ordering::Release);
        {
            let mut tx_guard = self.stdin_tx.lock().unwrap_or_else(|p| p.into_inner());
            let _ = tx_guard.take();
        }
        self.in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();

        let mut child_guard = self.child.lock().await;
        let Some(mut child) = child_guard.take() else {
            #[cfg(windows)]
            {
                let _ = self.job.lock().unwrap_or_else(|p| p.into_inner()).take();
            }
            return;
        };

        #[cfg(unix)]
        {
            let raw_pid_opt = child
                .id()
                .and_then(|p| libc::pid_t::try_from(p).ok())
                .filter(|&p| p > 1);
            if let Some(raw_pid) = raw_pid_opt {
                // Keep raw_pid unreaped via WNOWAIT until SIGTERM is sent to -raw_pid.
                wait_unreaped_exit(raw_pid, STDIN_GRACE_WAIT).await;
                signal_process_group(raw_pid, libc::SIGTERM);
                if tokio::time::timeout(SIGTERM_WAIT, child.wait())
                    .await
                    .is_err()
                {
                    signal_process_group(raw_pid, libc::SIGKILL);
                    let _ = child.wait().await;
                }
                cleanup_remaining_process_group(raw_pid).await;
            } else {
                let _ = child.wait().await;
            }
        }

        #[cfg(windows)]
        {
            let job = self.job.lock().unwrap_or_else(|p| p.into_inner()).take();
            if tokio::time::timeout(STDIN_GRACE_WAIT, child.wait())
                .await
                .is_err()
            {
                drop(job);
                let _ = child.kill().await;
                let _ = child.wait().await;
            } else {
                drop(job);
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            if tokio::time::timeout(STDIN_GRACE_WAIT, child.wait())
                .await
                .is_err()
            {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
        }
    }
}

#[cfg(unix)]
fn poll_unreaped_exit(raw_pid: libc::pid_t) -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            raw_pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc == 0 {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let has_pid = unsafe { info.si_pid() != 0 };
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
        let has_pid = info.si_pid != 0;
        info.si_signo != 0 || has_pid
    } else {
        io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
    }
}

#[cfg(unix)]
async fn wait_unreaped_exit(raw_pid: libc::pid_t, timeout: Duration) {
    if raw_pid <= 1 {
        return;
    }
    let deadline = Instant::now() + timeout;
    loop {
        if poll_unreaped_exit(raw_pid) || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[cfg(unix)]
fn signal_process_group(raw_pid: libc::pid_t, sig: libc::c_int) {
    if raw_pid > 1 {
        unsafe {
            let _ = libc::kill(-raw_pid, sig);
        }
    }
}

#[cfg(unix)]
async fn cleanup_remaining_process_group(raw_pid: libc::pid_t) {
    if raw_pid <= 1 || unsafe { libc::kill(-raw_pid, 0) } != 0 {
        return;
    }
    unsafe {
        let _ = libc::kill(-raw_pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + STDIN_GRACE_WAIT;
    while Instant::now() < deadline {
        if unsafe { libc::kill(-raw_pid, 0) } != 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    unsafe {
        let _ = libc::kill(-raw_pid, libc::SIGKILL);
    }
}

enum GuardState {
    Armed,
    Completed,
    Disarmed,
}

struct RequestGuard {
    session: Arc<StdioSession>,
    wire_id: u64,
    state: GuardState,
}

impl RequestGuard {
    fn mark_completed(&mut self) {
        if matches!(self.state, GuardState::Armed) {
            self.state = GuardState::Completed;
            self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn disarm(&mut self) {
        if matches!(self.state, GuardState::Armed) {
            self.state = GuardState::Disarmed;
            let mut waiters = self
                .session
                .in_flight
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            waiters.retain(|w| w.wire_id != self.wire_id);
            drop(waiters);
            self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn cancel(&mut self, reason: &str) {
        if !matches!(self.state, GuardState::Armed) {
            return;
        }
        self.state = GuardState::Disarmed;
        {
            let mut waiters = self
                .session
                .in_flight
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            waiters.retain(|w| w.wire_id != self.wire_id);
        }
        self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
        self.session.touch();

        if self.session.alive.load(Ordering::Acquire) {
            let cancel = json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {
                    "requestId": self.wire_id,
                    "reason": reason
                }
            });
            let _ = self.session.send_json_line(&cancel);
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.cancel("client disconnected");
    }
}

struct StdioSseStreamBody {
    notif_rx: mpsc::Receiver<String>,
    resp_rx: Option<oneshot::Receiver<String>>,
    pending_resp: Option<String>,
    notif_done: bool,
    guard: RequestGuard,
    session: Arc<StdioSession>,
    idle_timeout: Duration,
    idle_sleep: Pin<Box<tokio::time::Sleep>>,
    ephemeral: Option<EphemeralGuard>,
    finished: bool,
}

impl StdioSseStreamBody {
    fn new(
        notif_rx: mpsc::Receiver<String>,
        resp_rx: oneshot::Receiver<String>,
        guard: RequestGuard,
        session: Arc<StdioSession>,
        idle_timeout: Duration,
        ephemeral: Option<EphemeralGuard>,
    ) -> Self {
        Self {
            notif_rx,
            resp_rx: Some(resp_rx),
            pending_resp: None,
            notif_done: false,
            guard,
            session,
            idle_timeout,
            idle_sleep: Box::pin(tokio::time::sleep(idle_timeout)),
            ephemeral,
            finished: false,
        }
    }

    fn release_ephemeral(&mut self) {
        let _ = self.ephemeral.take();
    }
}

impl Body for StdioSseStreamBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            if this.finished {
                return Poll::Ready(None);
            }

            if !this.notif_done {
                match this.notif_rx.poll_recv(cx) {
                    Poll::Ready(Some(line)) => {
                        this.session.touch();
                        this.idle_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + this.idle_timeout);
                        let formatted = format!("data: {line}\n\n");
                        return Poll::Ready(Some(Ok(Frame::data(Bytes::from(formatted)))));
                    }
                    Poll::Ready(None) => {
                        this.notif_done = true;
                    }
                    Poll::Pending => {}
                }
            }

            if let Some(rx) = this.resp_rx.as_mut() {
                match Pin::new(rx).poll(cx) {
                    Poll::Ready(Ok(line)) => {
                        this.resp_rx = None;
                        this.pending_resp = Some(line);
                        if !this.notif_done {
                            continue;
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        this.resp_rx = None;
                        if !this.notif_done {
                            continue;
                        }
                    }
                    Poll::Pending => {
                        if this.idle_sleep.as_mut().poll(cx).is_ready() {
                            this.finished = true;
                            this.guard.cancel("request timed out");
                            this.release_ephemeral();
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "upstream SSE idle timeout",
                            ))));
                        }
                        return Poll::Pending;
                    }
                }
            }

            if this.notif_done {
                if let Some(line) = this.pending_resp.take() {
                    this.finished = true;
                    this.guard.mark_completed();
                    this.session.touch();
                    this.release_ephemeral();
                    let formatted = format!("data: {line}\n\n");
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(formatted)))));
                }
                if this.resp_rx.is_none() {
                    this.finished = true;
                    this.guard.disarm();
                    this.release_ephemeral();
                    return Poll::Ready(None);
                }
            }

            if this.idle_sleep.as_mut().poll(cx).is_ready() {
                this.finished = true;
                this.guard.cancel("request timed out");
                this.release_ephemeral();
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "upstream SSE idle timeout",
                ))));
            }

            return Poll::Pending;
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn dispatch_stdout_message(in_flight: &Mutex<Vec<InFlightEntry>>, raw_line: &str, mut val: Value) {
    let Some(obj) = val.as_object() else {
        return;
    };
    let has_method = obj.get("method").and_then(Value::as_str).is_some();
    let resp_wire_id = obj.get("id").and_then(Value::as_u64);

    let mut waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
    if !has_method && let Some(wire_id) = resp_wire_id {
        if let Some(pos) = waiters.iter().position(|w| w.wire_id == wire_id) {
            let entry = waiters.remove(pos);
            if let Some(map) = val.as_object_mut() {
                map.insert("id".to_owned(), entry.client_id);
            }
            let out = serde_json::to_string(&val).unwrap_or_else(|_| raw_line.to_owned());
            let _ = entry.resp_tx.send(out);
        }
        return;
    }

    if !has_method {
        return;
    }

    if let Some(rel_wire_id) = obj
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("relatedRequestId"))
        .and_then(Value::as_u64)
    {
        if let Some(entry) = waiters.iter().find(|w| w.wire_id == rel_wire_id) {
            let client_id = entry.client_id.clone();
            if let Some(meta) = val
                .get_mut("params")
                .and_then(|p| p.get_mut("_meta"))
                .and_then(Value::as_object_mut)
            {
                meta.insert("relatedRequestId".to_owned(), client_id);
            }
            let out = serde_json::to_string(&val).unwrap_or_else(|_| raw_line.to_owned());
            let _ = entry.notif_tx.try_send(out);
        }
        return;
    }

    if obj.get("method").and_then(Value::as_str) == Some("notifications/progress")
        && let Some(ptok) = obj
            .get("params")
            .and_then(|p| p.get("progressToken"))
            .filter(|v| !v.is_null())
    {
        if let Some(entry) = waiters.iter().find(|w| {
            w.progress_token
                .as_ref()
                .is_some_and(|t| json_id_eq(t, ptok))
        }) {
            let _ = entry.notif_tx.try_send(raw_line.to_owned());
        }
        return;
    }

    for entry in waiters.iter() {
        let _ = entry.notif_tx.try_send(raw_line.to_owned());
    }
}

fn extract_progress_token(payload: &Value) -> Option<Value> {
    payload
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("progressToken"))
        .filter(|v| !v.is_null())
        .cloned()
}

fn supports_sessionless_version(ver: &str) -> bool {
    let bytes = ver.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
        && ver >= MIN_SESSIONLESS_PROTOCOL_VERSION
}

fn detect_sessionless_version(
    headers: &HeaderMap,
    obj: &serde_json::Map<String, Value>,
) -> Option<String> {
    if let Some(meta_ver) = obj
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(SESSIONLESS_META_KEY))
        .and_then(Value::as_str)
    {
        let trimmed = meta_ver.trim();
        if supports_sessionless_version(trimmed) {
            return Some(trimmed.to_owned());
        }
    }
    if let Some(hdr) = extract_single_header(headers, "mcp-protocol-version")
        && supports_sessionless_version(hdr)
    {
        return Some(hdr.to_owned());
    }
    None
}

fn extract_single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut iter = headers.get_all(name).iter();
    let first = iter.next()?;
    if iter.next().is_some() {
        return None;
    }
    let text = first.to_str().ok()?.trim();
    if text.is_empty() {
        return None;
    }
    Some(text)
}

fn has_multiple_headers(headers: &HeaderMap, name: &'static str) -> bool {
    headers.get_all(name).iter().nth(1).is_some()
}

fn client_accepts_sse(headers: &HeaderMap) -> bool {
    accept_contains(headers, "text/event-stream")
}

fn client_prefers_sse_only(headers: &HeaderMap) -> bool {
    accept_contains(headers, "text/event-stream")
        && !accept_contains(headers, "application/json")
        && !accept_contains(headers, "*/*")
}

fn accept_contains(headers: &HeaderMap, target: &str) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .any(|item| {
            let mut parts = item.split(';');
            let media = parts.next().unwrap_or("").trim();
            if !media.eq_ignore_ascii_case(target) {
                return false;
            }
            !parts.any(|param| {
                let p = param.trim();
                p.strip_prefix("q=")
                    .or_else(|| p.strip_prefix("Q="))
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .is_some_and(|q| q <= 0.0)
            })
        })
}

fn single_rpc_reply(headers: &HeaderMap, session_id: Option<&str>, json_line: String) -> HttpReply {
    let sse = client_prefers_sse_only(headers);
    let (content_type, payload) = if sse {
        (
            "text/event-stream",
            Bytes::from(format!("data: {json_line}\n\n")),
        )
    } else {
        ("application/json", Bytes::from(json_line))
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(HeaderName::from_static("x-accel-buffering"), "no");
    if let Some(sid) = session_id {
        builder = builder.header(HeaderName::from_static("mcp-session-id"), sid);
    }
    builder.body(bytes_body(payload)).expect("valid RPC reply")
}

fn jsonrpc_error_reply(status: StatusCode, id: Value, code: i64, message: &str) -> HttpReply {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    });
    let encoded = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(HeaderName::from_static("x-accel-buffering"), "no")
        .body(bytes_body(encoded))
        .expect("valid JSON-RPC error reply")
}

fn json_id_eq(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => {
            a == b || (a.as_i64().is_some() && a.as_i64() == b.as_i64())
        }
        _ => left == right,
    }
}

async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> io::Result<usize> {
    out.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(out.len());
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if out.len() + take > MAX_STDOUT_LINE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream stdout line exceeds limit",
                ));
            }
            out.extend_from_slice(&available[..take]);
            reader.consume(take);
            return Ok(out.len());
        }
        let len = available.len();
        if out.len() + len > MAX_STDOUT_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream stdout line exceeds limit",
            ));
        }
        out.extend_from_slice(available);
        reader.consume(len);
    }
}

fn elapsed_ms(epoch: Instant) -> u64 {
    u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Waker;

    #[tokio::test]
    async fn sse_stream_handles_resp_drop_before_notif_close_without_panic() {
        let now = Instant::now();
        let session = Arc::new(StdioSession {
            grant_id: "g".to_owned(),
            stdin_tx: Mutex::new(None),
            in_flight: Arc::new(Mutex::new(Vec::new())),
            next_wire_id: AtomicU64::new(2),
            alive: Arc::new(AtomicBool::new(false)),
            active_requests: Arc::new(AtomicUsize::new(1)),
            last_active_ms: Arc::new(AtomicU64::new(0)),
            child: tokio::sync::Mutex::new(None),
            #[cfg(windows)]
            job: Mutex::new(None),
            epoch: now,
        });

        let (notif_tx, notif_rx) = mpsc::channel(8);
        let (resp_tx, resp_rx) = oneshot::channel::<String>();
        drop(resp_tx);

        let mut body = StdioSseStreamBody::new(
            notif_rx,
            resp_rx,
            RequestGuard {
                session: Arc::clone(&session),
                wire_id: 1,
                state: GuardState::Armed,
            },
            Arc::clone(&session),
            Duration::from_secs(30),
            None,
        );

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        assert!(Pin::new(&mut body).poll_frame(&mut cx).is_pending());
        notif_tx
            .try_send(r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#.to_owned())
            .unwrap();
        drop(notif_tx);

        let first = Pin::new(&mut body).poll_frame(&mut cx);
        assert!(matches!(first, Poll::Ready(Some(Ok(_)))));

        let eof = Pin::new(&mut body).poll_frame(&mut cx);
        assert!(matches!(eof, Poll::Ready(None)));
        assert_eq!(session.active_requests.load(Ordering::Acquire), 0);
    }
}
