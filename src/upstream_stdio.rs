use crate::config::StdioUpstreamSettings;
use crate::crypto::{constant_time_eq_str, random_token_b64};
use crate::types::{HttpReply, VerifiedToken, bytes_body, empty_body, method_not_allowed};
use crate::upstream_http::{
    ContentLengthCheck, MAX_MCP_BODY_BYTES, check_content_length_limit, close_empty_reply,
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
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
const INIT_TIMEOUT: Duration = Duration::from_secs(30);
const STDIN_GRACE_WAIT: Duration = Duration::from_millis(200);
#[cfg(unix)]
const SIGTERM_WAIT: Duration = Duration::from_secs(2);
const STDIN_CHANNEL_CAPACITY: usize = 64;
const NOTIF_CHANNEL_CAPACITY: usize = 256;
const MAX_IN_FLIGHT_PER_SESSION: usize = 64;
const MAX_STDOUT_LINE_BYTES: usize = MAX_MCP_BODY_BYTES;
const MAX_GRANT_EPOCHS: usize = 4096;
const SESSIONLESS_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const MIN_SESSIONLESS_PROTOCOL_VERSION: &str = "2026-07-28";

const SAFE_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TZ",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "USER",
    "LOGNAME",
    "XDG_RUNTIME_DIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramData",
    "CommonProgramFiles",
    "SYSTEMDRIVE",
];

static NEXT_SESSION_UID: AtomicU64 = AtomicU64::new(1);

pub struct StdioUpstream {
    inner: Arc<StdioInner>,
    reaper_cancel: CancellationToken,
}

struct StdioInner {
    settings: StdioUpstreamSettings,
    epoch: Instant,
    table: Mutex<SessionTable>,
    bg_terminations: Mutex<Vec<(String, JoinHandle<()>)>>,
}

struct SessionTable {
    sessions: HashMap<String, Arc<StdioSession>>,
    live_sessions: Vec<Arc<StdioSession>>,
    grant_epochs: HashMap<String, (u64, u64)>,
    epoch_seq: u64,
    reserved_slots: usize,
    shutting_down: bool,
}

impl SessionTable {
    fn grant_epoch(&self, grant_id: &str) -> u64 {
        self.grant_epochs
            .get(grant_id)
            .map(|&(ep, _)| ep)
            .unwrap_or(0)
    }

    fn bump_grant_epoch(&mut self, grant_id: &str) {
        self.epoch_seq = self.epoch_seq.wrapping_add(1);
        let seq = self.epoch_seq;
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
}

struct InFlightEntry {
    wire_id: u64,
    client_id: Value,
    client_progress_token: Option<Value>,
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
    fn create() -> Result<Self, String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(format!(
                "CreateJobObjectW failed: {}",
                io::Error::last_os_error()
            ));
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
            let err = io::Error::last_os_error();
            unsafe {
                CloseHandle(job);
            }
            return Err(format!("SetInformationJobObject failed: {err}"));
        }

        Ok(Self(job))
    }

    fn assign(&self, child: &Child) -> Result<(), String> {
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        let raw_handle = child
            .raw_handle()
            .ok_or_else(|| "child process handle unavailable".to_owned())?;
        let assigned = unsafe { AssignProcessToJobObject(self.0, raw_handle as HANDLE) };
        if assigned == 0 {
            return Err(format!(
                "AssignProcessToJobObject failed: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
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
    uid: u64,
    grant_id: String,
    weak_inner: Weak<StdioInner>,
    writer_cancel: CancellationToken,
    stdin_tx: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
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
                live_sessions: Vec::new(),
                grant_epochs: HashMap::new(),
                epoch_seq: 0,
                reserved_slots: 0,
                shutting_down: false,
            }),
            bg_terminations: Mutex::new(Vec::new()),
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
            tbl.bump_grant_epoch(grant_id);
            let keys: Vec<String> = tbl
                .sessions
                .iter()
                .filter(|(_, s)| constant_time_eq_str(&s.grant_id, grant_id))
                .map(|(k, _)| k.clone())
                .collect();
            for k in keys {
                tbl.sessions.remove(&k);
            }
            tbl.live_sessions
                .iter()
                .filter(|s| constant_time_eq_str(&s.grant_id, grant_id))
                .cloned()
                .collect()
        };
        terminate_all(matched).await;

        let bg_handles = drain_bg_terminations(&self.inner, Some(grant_id));
        for h in bg_handles {
            let _ = h.await;
        }
    }

    pub async fn shutdown(&self) {
        self.reaper_cancel.cancel();
        loop {
            let live: Vec<Arc<StdioSession>> = {
                let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
                tbl.shutting_down = true;
                tbl.sessions.clear();
                tbl.live_sessions.clone()
            };
            let bg_handles = drain_bg_terminations(&self.inner, None);
            if live.is_empty() && bg_handles.is_empty() {
                break;
            }
            terminate_all(live).await;
            for h in bg_handles {
                let _ = h.await;
            }
        }
    }

    async fn handle_delete(&self, headers: &HeaderMap, token: &VerifiedToken) -> HttpReply {
        let Some(sid) = extract_valid_session_id(headers) else {
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
        let session_id_hdr = if parts.headers.contains_key("mcp-session-id") {
            match extract_valid_session_id(&parts.headers) {
                Some(sid) => Some(sid.to_owned()),
                None => {
                    return jsonrpc_error_reply(
                        StatusCode::BAD_REQUEST,
                        Value::Null,
                        -32600,
                        "invalid Mcp-Session-Id header",
                    );
                }
            }
        } else {
            None
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

        let fallback_err_id = obj
            .get("id")
            .filter(|v| v.is_string() || v.is_number())
            .cloned()
            .unwrap_or(Value::Null);

        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return jsonrpc_error_reply(
                StatusCode::BAD_REQUEST,
                fallback_err_id,
                -32600,
                "invalid JSON-RPC version",
            );
        }

        let (method, req_id) = if let Some(raw_method) = obj.get("method") {
            let Some(m) = raw_method.as_str().filter(|m| !m.is_empty()) else {
                return jsonrpc_error_reply(
                    StatusCode::BAD_REQUEST,
                    fallback_err_id,
                    -32600,
                    "invalid JSON-RPC method",
                );
            };
            let req_id = match obj.get("id") {
                None => None,
                Some(id) if id.is_string() || id.is_number() => Some(id.clone()),
                Some(_) => {
                    return jsonrpc_error_reply(
                        StatusCode::BAD_REQUEST,
                        Value::Null,
                        -32600,
                        "invalid JSON-RPC id",
                    );
                }
            };
            (Some(m), req_id)
        } else {
            if !obj.contains_key("result") && !obj.contains_key("error") {
                return jsonrpc_error_reply(
                    StatusCode::BAD_REQUEST,
                    fallback_err_id,
                    -32600,
                    "invalid JSON-RPC message",
                );
            }
            if let Some(id) = obj.get("id")
                && !(id.is_string() || id.is_number() || id.is_null())
            {
                return jsonrpc_error_reply(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    -32600,
                    "invalid JSON-RPC id",
                );
            }
            (None, None)
        };

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
                .handle_sessionless(&parts.headers, token, &proto_ver, &payload, method, req_id)
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

        let start_epoch = {
            let tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            tbl.grant_epoch(&token.grant_id)
        };

        let Some(reservation) = acquire_slot(&self.inner).await else {
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                id,
                -32000,
                "session limit reached",
            );
        };

        let session =
            match StdioSession::spawn(&self.inner, token.grant_id.clone(), start_epoch).await {
                Ok(s) => s,
                Err(err) => {
                    drop(reservation);
                    return jsonrpc_error_reply(StatusCode::BAD_GATEWAY, id, -32000, &err);
                }
            };
        let mut ephemeral = EphemeralGuard::new(Arc::clone(&session));

        let Some((wire_id, mut guard, notif_rx, resp_rx)) =
            session.register_request(id.clone(), extract_progress_token(payload))
        else {
            ephemeral.terminate_now().await;
            drop(reservation);
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                id,
                -32000,
                "too many concurrent requests in session",
            );
        };
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

        match classify_init_response(&init_line) {
            InitOutcome::Ok => {}
            InitOutcome::RpcError => {
                ephemeral.terminate_now().await;
                drop(reservation);
                return single_rpc_reply(headers, None, init_line);
            }
            InitOutcome::Malformed => {
                ephemeral.terminate_now().await;
                drop(reservation);
                return jsonrpc_error_reply(
                    StatusCode::BAD_GATEWAY,
                    id,
                    -32000,
                    "invalid initialize response from upstream",
                );
            }
        }

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
            if tbl.shutting_down
                || !session.alive.load(Ordering::Acquire)
                || tbl.grant_epoch(&token.grant_id) != start_epoch
            {
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
                "session terminated during initialize",
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

        if method == Some("initialize") {
            return jsonrpc_error_reply(
                StatusCode::BAD_REQUEST,
                err_id,
                -32600,
                "session is already initialized",
            );
        }

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
        let Some((wire_id, mut guard, notif_rx, resp_rx)) =
            session.register_request(id.clone(), extract_progress_token(payload))
        else {
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                id,
                -32000,
                "too many concurrent requests in session",
            );
        };
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
        token: &VerifiedToken,
        protocol_version: &str,
        payload: &Value,
        method: Option<&str>,
        req_id: Option<Value>,
    ) -> HttpReply {
        let err_id = req_id.clone().unwrap_or(Value::Null);
        let start_epoch = {
            let tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            tbl.grant_epoch(&token.grant_id)
        };

        let Some(reservation) = acquire_slot(&self.inner).await else {
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                err_id,
                -32000,
                "session limit reached",
            );
        };

        let session =
            match StdioSession::spawn(&self.inner, token.grant_id.clone(), start_epoch).await {
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

        let Some((init_wire_id, mut init_guard, init_notif_rx, init_resp_rx)) =
            session.register_request(json!(0), None)
        else {
            ephemeral.terminate_now().await;
            drop(reservation);
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                err_id,
                -32000,
                "too many concurrent requests in session",
            );
        };
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

        let init_line = match tokio::time::timeout(INIT_TIMEOUT, init_resp_rx).await {
            Ok(Ok(line)) => {
                init_guard.mark_completed();
                line
            }
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
        };

        if !matches!(classify_init_response(&init_line), InitOutcome::Ok) {
            ephemeral.terminate_now().await;
            drop(reservation);
            return jsonrpc_error_reply(
                StatusCode::BAD_GATEWAY,
                err_id,
                -32000,
                "ephemeral initialize rejected by upstream",
            );
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
        let Some((wire_id, mut guard, notif_rx, resp_rx)) =
            session.register_request(id.clone(), extract_progress_token(payload))
        else {
            ephemeral.terminate_now().await;
            drop(reservation);
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                id,
                -32000,
                "too many concurrent requests in session",
            );
        };
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

enum InitOutcome {
    Ok,
    RpcError,
    Malformed,
}

fn classify_init_response(raw_line: &str) -> InitOutcome {
    let Ok(val) = serde_json::from_str::<Value>(raw_line) else {
        return InitOutcome::Malformed;
    };
    let Some(obj) = val.as_object() else {
        return InitOutcome::Malformed;
    };
    if obj.contains_key("result") && !obj.contains_key("error") {
        InitOutcome::Ok
    } else if obj.get("error").is_some_and(Value::is_object) && !obj.contains_key("result") {
        InitOutcome::RpcError
    } else {
        InitOutcome::Malformed
    }
}

fn drain_bg_terminations(inner: &StdioInner, only_grant: Option<&str>) -> Vec<JoinHandle<()>> {
    let mut bg = inner
        .bg_terminations
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut out = Vec::new();
    let mut i = 0;
    while i < bg.len() {
        if bg[i].1.is_finished() {
            let (_, h) = bg.swap_remove(i);
            drop(h);
        } else if only_grant.is_none_or(|gid| constant_time_eq_str(&bg[i].0, gid)) {
            let (_, h) = bg.swap_remove(i);
            out.push(h);
        } else {
            i += 1;
        }
    }
    out
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
            let weak_inner = sess.weak_inner.clone();
            let grant_id = sess.grant_id.clone();
            let jh = handle.spawn(async move {
                sess.terminate().await;
                drop(slot);
            });
            if let Some(inner) = weak_inner.upgrade() {
                let mut bg = inner
                    .bg_terminations
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                bg.retain(|(_, h)| !h.is_finished());
                bg.push((grant_id, jh));
            }
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
            .is_some_and(|cur| cur.uid == session.uid)
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
    async fn spawn(
        inner: &Arc<StdioInner>,
        grant_id: String,
        expected_grant_epoch: u64,
    ) -> Result<Arc<Self>, String> {
        #[cfg(windows)]
        let job = WindowsJobObject::create()?;

        let mut cmd = Command::new(&inner.settings.command);
        cmd.env_clear();
        for &key in SAFE_ENV_ALLOWLIST {
            if let Some(val) = std::env::var_os(key) {
                cmd.env(key, val);
            }
        }
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
        if let Err(err) = job.assign(&child) {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(err);
        }

        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err("failed to capture child stdin".to_owned());
        };
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err("failed to capture child stdout".to_owned());
        };

        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(STDIN_CHANNEL_CAPACITY);
        let stdin_tx_arc = Arc::new(Mutex::new(Some(stdin_tx)));
        let writer_cancel = CancellationToken::new();
        let alive = Arc::new(AtomicBool::new(true));
        let in_flight = Arc::new(Mutex::new(Vec::<InFlightEntry>::new()));
        let active_requests = Arc::new(AtomicUsize::new(0));
        let last_active_ms = Arc::new(AtomicU64::new(elapsed_ms(inner.epoch)));
        let uid = NEXT_SESSION_UID.fetch_add(1, Ordering::Relaxed);

        let session = Arc::new(Self {
            uid,
            grant_id,
            weak_inner: Arc::downgrade(inner),
            writer_cancel: writer_cancel.clone(),
            stdin_tx: Arc::clone(&stdin_tx_arc),
            in_flight: Arc::clone(&in_flight),
            next_wire_id: AtomicU64::new(1),
            alive: Arc::clone(&alive),
            active_requests,
            last_active_ms: Arc::clone(&last_active_ms),
            child: tokio::sync::Mutex::new(Some(child)),
            #[cfg(windows)]
            job: Mutex::new(Some(job)),
            epoch: inner.epoch,
        });

        let rejected = {
            let mut tbl = inner.table.lock().unwrap_or_else(|p| p.into_inner());
            if tbl.shutting_down || tbl.grant_epoch(&session.grant_id) != expected_grant_epoch {
                true
            } else {
                tbl.live_sessions.push(Arc::clone(&session));
                false
            }
        };
        if rejected {
            drop(stdin);
            drop(stdout);
            session.terminate().await;
            return Err("session aborted due to shutdown or grant revocation".to_owned());
        }

        let writer_alive = Arc::clone(&alive);
        tokio::spawn(async move {
            loop {
                let Some(buf) = (tokio::select! {
                    _ = writer_cancel.cancelled() => None,
                    msg = stdin_rx.recv() => msg,
                }) else {
                    break;
                };
                let write_ok = tokio::select! {
                    _ = writer_cancel.cancelled() => false,
                    res = async {
                        stdin.write_all(&buf).await.is_ok() && stdin.flush().await.is_ok()
                    } => res,
                };
                if !write_ok {
                    writer_alive.store(false, Ordering::Release);
                    break;
                }
            }
            drop(stdin);
        });

        let reader_inner = Arc::downgrade(inner);
        let reader_session = Arc::downgrade(&session);
        let reader_stdin = Arc::clone(&stdin_tx_arc);
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
                            dispatch_stdout_message(&in_flight, &reader_stdin, &alive, val);
                        }
                    }
                }
                if raw.capacity() > 64 * 1024 {
                    raw.shrink_to(64 * 1024);
                }
            }
            drop(lines);
            alive.store(false, Ordering::Release);
            in_flight.lock().unwrap_or_else(|p| p.into_inner()).clear();
            if let (Some(up), Some(sess)) = (reader_inner.upgrade(), reader_session.upgrade()) {
                let matched = {
                    let mut tbl = up.table.lock().unwrap_or_else(|p| p.into_inner());
                    let found = tbl
                        .sessions
                        .iter()
                        .find(|(_, v)| v.uid == sess.uid)
                        .map(|(k, _)| k.clone());
                    if let Some(ref k) = found {
                        tbl.sessions.remove(k);
                    }
                    found.is_some()
                };
                if matched {
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
            if let Some(meta) = obj
                .get_mut("params")
                .and_then(Value::as_object_mut)
                .and_then(|p| p.get_mut("_meta"))
                .and_then(Value::as_object_mut)
                && meta.get("progressToken").is_some_and(|v| !v.is_null())
            {
                meta.insert(
                    "progressToken".to_owned(),
                    Value::String(format!("gw_pt_{wire_id}")),
                );
            }
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
        client_progress_token: Option<Value>,
    ) -> Option<(
        u64,
        RequestGuard,
        mpsc::Receiver<String>,
        oneshot::Receiver<String>,
    )> {
        let mut waiters = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if waiters.len() >= MAX_IN_FLIGHT_PER_SESSION {
            return None;
        }
        let wire_id = self.next_wire_id.fetch_add(1, Ordering::Relaxed);
        let (notif_tx, notif_rx) = mpsc::channel(NOTIF_CHANNEL_CAPACITY);
        let (resp_tx, resp_rx) = oneshot::channel();
        self.active_requests.fetch_add(1, Ordering::AcqRel);
        waiters.push(InFlightEntry {
            wire_id,
            client_id,
            client_progress_token,
            notif_tx,
            resp_tx,
        });
        drop(waiters);

        let guard = RequestGuard {
            session: Arc::clone(self),
            wire_id,
            state: GuardState::Armed,
        };
        Some((wire_id, guard, notif_rx, resp_rx))
    }

    async fn terminate(&self) {
        self.alive.store(false, Ordering::Release);
        {
            let mut tx_guard = self.stdin_tx.lock().unwrap_or_else(|p| p.into_inner());
            let _ = tx_guard.take();
        }
        self.writer_cancel.cancel();
        self.in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();

        let mut child_guard = self.child.lock().await;
        if let Some(mut child) = child_guard.take() {
            #[cfg(unix)]
            {
                let raw_pid_opt = child
                    .id()
                    .and_then(|p| libc::pid_t::try_from(p).ok())
                    .filter(|&p| p > 1);
                if let Some(raw_pid) = raw_pid_opt {
                    // Keep raw_pid unreaped via WNOWAIT until SIGKILL finishes so -raw_pid cannot be reused.
                    wait_unreaped_exit(raw_pid, STDIN_GRACE_WAIT).await;
                    signal_process_group(raw_pid, libc::SIGTERM);
                    wait_unreaped_exit(raw_pid, SIGTERM_WAIT).await;
                    signal_process_group(raw_pid, libc::SIGKILL);
                    let _ = child.wait().await;
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
        } else {
            #[cfg(windows)]
            {
                let _ = self.job.lock().unwrap_or_else(|p| p.into_inner()).take();
            }
        }

        if let Some(inner) = self.weak_inner.upgrade() {
            let mut tbl = inner.table.lock().unwrap_or_else(|p| p.into_inner());
            tbl.live_sessions.retain(|s| s.uid != self.uid);
        }
    }
}

#[cfg(unix)]
fn poll_unreaped_exit(raw_pid: libc::pid_t) -> bool {
    loop {
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
            return info.si_signo != 0 || has_pid;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return true;
        }
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
    guard: Arc<Mutex<RequestGuard>>,
    session: Arc<StdioSession>,
    idle_timeout: Duration,
    idle_sleep: Pin<Box<tokio::time::Sleep>>,
    last_frame_ms: Arc<AtomicU64>,
    stream_done: CancellationToken,
    timed_out_fut: Mutex<Pin<Box<dyn Future<Output = ()> + Send>>>,
    ephemeral: Arc<Mutex<Option<EphemeralGuard>>>,
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
        let guard_arc = Arc::new(Mutex::new(guard));
        let ephem_arc = Arc::new(Mutex::new(ephemeral));
        let last_frame_ms = Arc::new(AtomicU64::new(elapsed_ms(session.epoch)));
        let stream_done = CancellationToken::new();
        let timed_out = CancellationToken::new();
        let timed_out_fut = Mutex::new(Box::pin(timed_out.clone().cancelled_owned())
            as Pin<Box<dyn Future<Output = ()> + Send>>);

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let wd_guard = Arc::clone(&guard_arc);
            let wd_ephem = Arc::clone(&ephem_arc);
            let wd_last = Arc::clone(&last_frame_ms);
            let wd_done = stream_done.clone();
            let wd_timed_out = timed_out;
            let epoch = session.epoch;
            let timeout_ms = u64::try_from(idle_timeout.as_millis()).unwrap_or(u64::MAX);
            // Release active_requests and ephemeral child at call_timeout even if TCP stalls.
            handle.spawn(async move {
                loop {
                    let last = wd_last.load(Ordering::Acquire);
                    let now = elapsed_ms(epoch);
                    let elapsed = now.saturating_sub(last);
                    if elapsed >= timeout_ms {
                        wd_guard
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .cancel("request timed out");
                        let ephem_opt = wd_ephem.lock().unwrap_or_else(|p| p.into_inner()).take();
                        if let Some(mut ephem) = ephem_opt {
                            ephem.terminate_now().await;
                        }
                        wd_timed_out.cancel();
                        break;
                    }
                    let wait = Duration::from_millis(timeout_ms - elapsed);
                    tokio::select! {
                        _ = wd_done.cancelled() => break,
                        _ = tokio::time::sleep(wait) => {}
                    }
                }
            });
        }

        Self {
            notif_rx,
            resp_rx: Some(resp_rx),
            pending_resp: None,
            notif_done: false,
            guard: guard_arc,
            session,
            idle_timeout,
            idle_sleep: Box::pin(tokio::time::sleep(idle_timeout)),
            last_frame_ms,
            stream_done,
            timed_out_fut,
            ephemeral: ephem_arc,
            finished: false,
        }
    }

    fn finish_completed(&mut self) {
        self.finished = true;
        self.stream_done.cancel();
        self.guard
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .mark_completed();
        let _ = self
            .ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
    }

    fn finish_disarmed(&mut self) {
        self.finished = true;
        self.stream_done.cancel();
        self.guard
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .disarm();
        let _ = self
            .ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
    }

    fn finish_timed_out(&mut self) {
        self.finished = true;
        self.stream_done.cancel();
        self.guard
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cancel("request timed out");
        let _ = self
            .ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
    }
}

impl Drop for StdioSseStreamBody {
    fn drop(&mut self) {
        self.stream_done.cancel();
        self.guard
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cancel("client disconnected");
        let _ = self
            .ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
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

            let timed_out_pin = this
                .timed_out_fut
                .get_mut()
                .unwrap_or_else(|p| p.into_inner());
            if timed_out_pin.as_mut().poll(cx).is_ready() {
                this.finish_timed_out();
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "upstream SSE idle timeout",
                ))));
            }

            if !this.notif_done {
                match this.notif_rx.poll_recv(cx) {
                    Poll::Ready(Some(line)) => {
                        this.session.touch();
                        this.last_frame_ms
                            .store(elapsed_ms(this.session.epoch), Ordering::Release);
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
                            this.finish_timed_out();
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
                    this.finish_completed();
                    this.session.touch();
                    let formatted = format!("data: {line}\n\n");
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(formatted)))));
                }
                if this.resp_rx.is_none() {
                    this.finish_disarmed();
                    return Poll::Ready(None);
                }
            }

            if this.idle_sleep.as_mut().poll(cx).is_ready() {
                this.finish_timed_out();
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

fn dispatch_stdout_message(
    in_flight: &Mutex<Vec<InFlightEntry>>,
    stdin_tx: &Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    alive: &AtomicBool,
    mut val: Value,
) {
    let Some(obj) = val.as_object() else {
        return;
    };
    let method_opt = obj.get("method").and_then(Value::as_str);
    let has_method = method_opt.is_some();

    if has_method && obj.contains_key("id") {
        let id = obj.get("id").cloned().unwrap_or(Value::Null);
        let reply = if method_opt == Some("ping") {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {}
            })
        } else {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "client requests are not supported by gateway"
                }
            })
        };
        send_child_stdin_reply(stdin_tx, alive, &reply);
        return;
    }

    if !has_method {
        let Some(wire_id) = obj.get("id").and_then(Value::as_u64) else {
            return;
        };
        let entry = {
            let mut waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
            waiters
                .iter()
                .position(|w| w.wire_id == wire_id)
                .map(|pos| waiters.remove(pos))
        };
        if let Some(entry) = entry {
            if let Some(map) = val.as_object_mut() {
                map.insert("id".to_owned(), entry.client_id);
            }
            if let Ok(out) = serde_json::to_string(&val) {
                let _ = entry.resp_tx.send(out);
            }
        }
        return;
    }

    let is_progress = method_opt == Some("notifications/progress");
    if let Some(rel_wire_id) = obj
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("relatedRequestId"))
        .and_then(Value::as_u64)
    {
        let matched = {
            let waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
            waiters.iter().find(|w| w.wire_id == rel_wire_id).map(|w| {
                (
                    w.client_id.clone(),
                    w.client_progress_token.clone(),
                    w.notif_tx.clone(),
                )
            })
        };
        if let Some((client_id, client_ptok, notif_tx)) = matched {
            if let Some(params) = val.get_mut("params").and_then(Value::as_object_mut) {
                if let Some(meta) = params.get_mut("_meta").and_then(Value::as_object_mut) {
                    meta.insert("relatedRequestId".to_owned(), client_id);
                }
                if is_progress
                    && let Some(orig_ptok) = client_ptok
                    && params.get("progressToken").and_then(Value::as_str)
                        == Some(&format!("gw_pt_{rel_wire_id}"))
                {
                    params.insert("progressToken".to_owned(), orig_ptok);
                }
            }
            if let Ok(out) = serde_json::to_string(&val) {
                let _ = notif_tx.try_send(out);
            }
        }
        return;
    }

    if is_progress
        && let Some(ptok) = obj
            .get("params")
            .and_then(|p| p.get("progressToken"))
            .filter(|v| !v.is_null())
    {
        let Some(wire_id) = ptok
            .as_str()
            .and_then(|s| s.strip_prefix("gw_pt_"))
            .and_then(|s| s.parse::<u64>().ok())
        else {
            return;
        };
        let matched = {
            let waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
            waiters.iter().find(|w| w.wire_id == wire_id).and_then(|w| {
                w.client_progress_token
                    .clone()
                    .map(|orig| (orig, w.notif_tx.clone()))
            })
        };
        if let Some((orig_ptok, notif_tx)) = matched {
            if let Some(params) = val.get_mut("params").and_then(Value::as_object_mut) {
                params.insert("progressToken".to_owned(), orig_ptok);
            }
            if let Ok(out) = serde_json::to_string(&val) {
                let _ = notif_tx.try_send(out);
            }
        }
        return;
    }

    let targets: Vec<mpsc::Sender<String>> = {
        let waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        waiters.iter().map(|w| w.notif_tx.clone()).collect()
    };
    if !targets.is_empty()
        && let Ok(out) = serde_json::to_string(&val)
    {
        for tx in targets {
            let _ = tx.try_send(out.clone());
        }
    }
}

fn send_child_stdin_reply(
    stdin_tx: &Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    alive: &AtomicBool,
    reply: &Value,
) {
    if !alive.load(Ordering::Acquire) {
        return;
    }
    let Ok(mut line) = serde_json::to_vec(reply) else {
        return;
    };
    line.push(b'\n');
    let tx_clone = {
        let guard = stdin_tx.lock().unwrap_or_else(|p| p.into_inner());
        let Some(tx) = guard.as_ref() else {
            return;
        };
        match tx.try_send(line) {
            Ok(()) | Err(TrySendError::Closed(_)) => return,
            Err(TrySendError::Full(unsent)) => (tx.clone(), unsent),
        }
    };
    let (tx, unsent) = tx_clone;
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(5), tx.send(unsent)).await;
        });
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

fn extract_valid_session_id(headers: &HeaderMap) -> Option<&str> {
    let sid = extract_single_header(headers, "mcp-session-id")?;
    if sid.len() > 1024 || !sid.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return None;
    }
    Some(sid)
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
            uid: 1,
            grant_id: "g".to_owned(),
            weak_inner: Weak::new(),
            writer_cancel: CancellationToken::new(),
            stdin_tx: Arc::new(Mutex::new(None)),
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
