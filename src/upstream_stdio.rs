use crate::config::StdioUpstreamSettings;
use crate::crypto::{constant_time_eq_str, random_token_b64};
use crate::types::{
    ByteBudget, ByteLease, HttpReply, LeasedFrameCursor, VerifiedToken, bytes_body, empty_body,
    hex_nibble, leased_body, method_not_allowed,
};
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
const MAX_IN_FLIGHT_PER_SESSION: usize = 64;
pub const MAX_STDOUT_LINE_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_CONTROL_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_NOTIF_QUEUE_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_PRESSURE_IDLE: Duration = Duration::from_secs(600);
const RAW_RETAIN_CAP_BYTES: usize = 64 * 1024;
const MAX_GRANT_EPOCHS: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct StdioLimits {
    pub max_stdout_line_bytes: usize,
    pub max_control_line_bytes: usize,
    pub max_notif_queue_bytes: usize,
    pub pressure_idle: Duration,
}

impl Default for StdioLimits {
    fn default() -> Self {
        Self {
            max_stdout_line_bytes: MAX_STDOUT_LINE_BYTES,
            max_control_line_bytes: MAX_CONTROL_LINE_BYTES,
            max_notif_queue_bytes: MAX_NOTIF_QUEUE_BYTES,
            pressure_idle: DEFAULT_PRESSURE_IDLE,
        }
    }
}
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
static NEXT_CLIENT_SEQ: AtomicU64 = AtomicU64::new(1);

pub struct StdioUpstream {
    inner: Arc<StdioInner>,
    reaper_cancel: CancellationToken,
}

struct StdioInner {
    settings: StdioUpstreamSettings,
    budget: Arc<ByteBudget>,
    limits: StdioLimits,
    epoch: Instant,
    table: Mutex<SessionTable>,
    slot_notify: tokio::sync::Notify,
    bg_terminations: Mutex<Vec<(String, JoinHandle<()>)>>,
}

struct SessionTable {
    sessions: HashMap<String, Arc<StdioSession>>,
    live_sessions: Vec<Arc<StdioSession>>,
    grant_epochs: HashMap<String, (u64, u64)>,
    epoch_seq: u64,
    reserved_slots: usize,
    terminating_slots: usize,
    shutting_down: bool,
}

impl SessionTable {
    fn used_slots(&self) -> usize {
        self.sessions.len() + self.reserved_slots + self.terminating_slots
    }

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

struct QueuedNotif {
    line: String,
    _lease: ByteLease,
}

enum RespDelivery {
    Ok {
        json_bytes: Vec<u8>,
        lease: Option<ByteLease>,
    },
    HardError {
        status: StatusCode,
        message: String,
        json_bytes: Vec<u8>,
    },
}

#[derive(Clone, Copy)]
enum SendLineErr {
    Closed,
    Full,
}

struct InFlightEntry {
    wire_id: u64,
    client_id: Value,
    client_progress_token: Option<Value>,
    notif_tx: mpsc::UnboundedSender<QueuedNotif>,
    resp_tx: oneshot::Sender<RespDelivery>,
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
    terminal_error: Arc<Mutex<Option<(StatusCode, String)>>>,
    next_wire_id: AtomicU64,
    alive: Arc<AtomicBool>,
    active_requests: Arc<AtomicUsize>,
    last_client_active_ms: AtomicU64,
    last_client_seq: AtomicU64,
    child: tokio::sync::Mutex<Option<Child>>,
    #[cfg(windows)]
    job: Mutex<Option<WindowsJobObject>>,
    epoch: Instant,
}

impl StdioUpstream {
    pub fn new(settings: StdioUpstreamSettings) -> Result<Self, String> {
        Self::with_limits(settings, ByteBudget::global(), StdioLimits::default())
    }

    pub fn with_limits(
        settings: StdioUpstreamSettings,
        budget: Arc<ByteBudget>,
        limits: StdioLimits,
    ) -> Result<Self, String> {
        let inner = Arc::new(StdioInner {
            settings,
            budget,
            limits,
            epoch: Instant::now(),
            table: Mutex::new(SessionTable {
                sessions: HashMap::new(),
                live_sessions: Vec::new(),
                grant_epochs: HashMap::new(),
                epoch_seq: 0,
                reserved_slots: 0,
                terminating_slots: 0,
                shutting_down: false,
            }),
            slot_notify: tokio::sync::Notify::new(),
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
        let (matched, removed_count): (Vec<Arc<StdioSession>>, usize) = {
            let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            tbl.bump_grant_epoch(grant_id);
            let keys: Vec<String> = tbl
                .sessions
                .iter()
                .filter(|(_, s)| constant_time_eq_str(&s.grant_id, grant_id))
                .map(|(k, _)| k.clone())
                .collect();
            let mut count = 0usize;
            for k in keys {
                if tbl.sessions.remove(&k).is_some() {
                    count += 1;
                }
            }
            tbl.terminating_slots += count;
            let live = tbl
                .live_sessions
                .iter()
                .filter(|s| constant_time_eq_str(&s.grant_id, grant_id))
                .cloned()
                .collect();
            (live, count)
        };
        let _ = reap_sessions(&self.inner, matched, removed_count, None).await;

        let bg_handles = drain_bg_terminations(&self.inner, Some(grant_id));
        for h in bg_handles {
            let _ = h.await;
        }
    }

    pub async fn shutdown(&self) {
        self.reaper_cancel.cancel();
        self.inner.slot_notify.notify_waiters();
        loop {
            let (live, removed_count): (Vec<Arc<StdioSession>>, usize) = {
                let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
                tbl.shutting_down = true;
                let count = tbl.sessions.len();
                tbl.sessions.clear();
                tbl.terminating_slots += count;
                (tbl.live_sessions.clone(), count)
            };
            self.inner.slot_notify.notify_waiters();
            let bg_handles = drain_bg_terminations(&self.inner, None);
            if live.is_empty() && bg_handles.is_empty() && removed_count == 0 {
                break;
            }
            let term_guard = TerminatingSlotsGuard::new(Arc::clone(&self.inner), removed_count);
            terminate_all(live).await;
            drop(term_guard);
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
                    let s = guard.sessions.remove(sid);
                    if s.is_some() {
                        guard.terminating_slots += 1;
                    }
                    s
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
        let _ = reap_sessions(&self.inner, vec![session], 1, None).await;
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

        let Some(reservation) = acquire_slot(&self.inner, &token.grant_id).await else {
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                id,
                -32000,
                "session limit reached",
            );
        };

        let (session, mut ephemeral) = match StdioSession::spawn(
            &self.inner,
            token.grant_id.clone(),
            start_epoch,
            reservation,
        )
        .await
        {
            Ok(pair) => pair,
            Err(err) => {
                return jsonrpc_error_reply(StatusCode::BAD_GATEWAY, id, -32000, &err);
            }
        };

        let Some((wire_id, mut guard, notif_rx, resp_rx)) =
            session.register_request(id.clone(), extract_progress_token(payload))
        else {
            let (status, msg) = session
                .map_register_failure("upstream child exited before responding to initialize");
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(status, id, -32000, &msg);
        };
        drop(notif_rx);
        if let Err(err) = session.send_request_line(payload, wire_id) {
            guard.disarm();
            let (status, msg) =
                session.map_send_failure(err, "upstream child closed stdin during initialize");
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(status, id, -32000, &msg);
        }

        let (init_bytes, init_lease) = match tokio::time::timeout(INIT_TIMEOUT, resp_rx).await {
            Ok(Ok(RespDelivery::Ok { json_bytes, lease })) => {
                guard.mark_completed();
                (json_bytes, lease)
            }
            Ok(Ok(RespDelivery::HardError {
                status, message, ..
            })) => {
                guard.disarm();
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(status, id, -32000, &message);
            }
            Ok(Err(_)) => {
                guard.disarm();
                let (status, msg) = session.map_dead_session_error(
                    "upstream child exited before responding to initialize",
                );
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(status, id, -32000, &msg);
            }
            Err(_) => {
                guard.disarm();
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(
                    StatusCode::GATEWAY_TIMEOUT,
                    id,
                    -32000,
                    "upstream initialize timed out",
                );
            }
        };

        match classify_init_response(&init_bytes) {
            InitOutcome::Ok => {}
            InitOutcome::RpcError => {
                ephemeral.terminate_now().await;
                return single_rpc_reply(headers, None, init_bytes, init_lease);
            }
            InitOutcome::Malformed => {
                drop(init_bytes);
                drop(init_lease);
                ephemeral.terminate_now().await;
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
                drop(init_bytes);
                drop(init_lease);
                ephemeral.terminate_now().await;
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
                session.touch_client();
                tbl.sessions
                    .insert(session_id.clone(), Arc::clone(&session));
                ephemeral.commit(&mut tbl);
                true
            }
        };
        if !inserted {
            drop(init_bytes);
            drop(init_lease);
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                id,
                -32000,
                "session terminated during initialize",
            );
        }

        single_rpc_reply(headers, Some(&session_id), init_bytes, init_lease)
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
        enum InSessionLookup {
            NotFound,
            AlreadyInitialized,
            Claimed(Arc<StdioSession>, ActiveRequestClaim),
        }

        let lookup = {
            let tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            match tbl.sessions.get(session_id).filter(|s| {
                s.alive.load(Ordering::Acquire)
                    && constant_time_eq_str(&s.grant_id, &token.grant_id)
            }) {
                None => InSessionLookup::NotFound,
                Some(_) if method == Some("initialize") => InSessionLookup::AlreadyInitialized,
                Some(s) => {
                    s.touch_client();
                    let claim = ActiveRequestClaim::new(s);
                    InSessionLookup::Claimed(Arc::clone(s), claim)
                }
            }
        };

        let err_id = req_id.clone().unwrap_or(Value::Null);
        let (session, claim) = match lookup {
            InSessionLookup::NotFound => {
                return jsonrpc_error_reply(
                    StatusCode::NOT_FOUND,
                    err_id,
                    -32001,
                    "session not found",
                );
            }
            InSessionLookup::AlreadyInitialized => {
                return jsonrpc_error_reply(
                    StatusCode::BAD_REQUEST,
                    err_id,
                    -32600,
                    "session is already initialized",
                );
            }
            InSessionLookup::Claimed(s, c) => (s, c),
        };

        let is_request = method.is_some() && req_id.is_some();
        if !is_request {
            let rewritten = if method == Some("notifications/cancelled") {
                session.rewrite_cancel_notification(payload)
            } else {
                None
            };
            let outbound = rewritten.as_ref().unwrap_or(payload);
            let send_res = session.send_json_line(outbound);
            if send_res.is_ok() {
                session.touch_client();
            }
            drop(claim);
            if let Err(err) = send_res {
                let (status, msg) = session.map_send_failure(err, "upstream child closed stdin");
                if matches!(err, SendLineErr::Closed) || !session.alive.load(Ordering::Acquire) {
                    remove_and_terminate(&self.inner, session_id, &session).await;
                }
                return jsonrpc_error_reply(status, Value::Null, -32000, &msg);
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
            session.register_request_with_claim(claim, id.clone(), extract_progress_token(payload))
        else {
            let (status, msg) = session.map_register_failure("upstream child closed stdin");
            if !session.alive.load(Ordering::Acquire) {
                remove_and_terminate(&self.inner, session_id, &session).await;
            }
            return jsonrpc_error_reply(status, id, -32000, &msg);
        };
        if let Err(err) = session.send_request_line(payload, wire_id) {
            guard.disarm();
            let (status, msg) = session.map_send_failure(err, "upstream child closed stdin");
            if matches!(err, SendLineErr::Closed) || !session.alive.load(Ordering::Acquire) {
                remove_and_terminate(&self.inner, session_id, &session).await;
            }
            return jsonrpc_error_reply(status, id, -32000, &msg);
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
            Ok(Ok(RespDelivery::Ok { json_bytes, lease })) => {
                session.touch_client();
                guard.mark_completed();
                single_rpc_reply(headers, Some(session_id), json_bytes, lease)
            }
            Ok(Ok(RespDelivery::HardError {
                status, message, ..
            })) => {
                guard.disarm();
                if !session.alive.load(Ordering::Acquire) {
                    remove_and_terminate(&self.inner, session_id, &session).await;
                }
                jsonrpc_error_reply(status, id, -32000, &message)
            }
            Ok(Err(_)) => {
                guard.disarm();
                let (status, msg) =
                    session.map_dead_session_error("upstream child exited before responding");
                if !session.alive.load(Ordering::Acquire) {
                    remove_and_terminate(&self.inner, session_id, &session).await;
                }
                jsonrpc_error_reply(status, id, -32000, &msg)
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

        let Some(reservation) = acquire_slot(&self.inner, &token.grant_id).await else {
            return jsonrpc_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                err_id,
                -32000,
                "session limit reached",
            );
        };

        let (session, mut ephemeral) = match StdioSession::spawn(
            &self.inner,
            token.grant_id.clone(),
            start_epoch,
            reservation,
        )
        .await
        {
            Ok(pair) => pair,
            Err(err) => {
                return jsonrpc_error_reply(StatusCode::BAD_GATEWAY, err_id, -32000, &err);
            }
        };

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
            let (status, msg) =
                session.map_register_failure("ephemeral child exited during initialize");
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(status, err_id, -32000, &msg);
        };
        drop(init_notif_rx);
        if let Err(err) = session.send_request_line(&synth_init, init_wire_id) {
            init_guard.disarm();
            let (status, msg) =
                session.map_send_failure(err, "ephemeral child closed stdin during initialize");
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(status, err_id, -32000, &msg);
        }

        let (init_bytes, init_lease) = match tokio::time::timeout(INIT_TIMEOUT, init_resp_rx).await
        {
            Ok(Ok(RespDelivery::Ok { json_bytes, lease })) => {
                init_guard.mark_completed();
                (json_bytes, lease)
            }
            Ok(Ok(RespDelivery::HardError {
                status, message, ..
            })) => {
                init_guard.disarm();
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(status, err_id, -32000, &message);
            }
            Ok(Err(_)) => {
                init_guard.disarm();
                let (status, msg) =
                    session.map_dead_session_error("ephemeral child exited during initialize");
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(status, err_id, -32000, &msg);
            }
            Err(_) => {
                init_guard.disarm();
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(
                    StatusCode::GATEWAY_TIMEOUT,
                    err_id,
                    -32000,
                    "ephemeral initialize timed out",
                );
            }
        };

        let init_ok = matches!(classify_init_response(&init_bytes), InitOutcome::Ok);
        drop(init_bytes);
        drop(init_lease);
        if !init_ok {
            ephemeral.terminate_now().await;
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
        if let Err(err) = session.send_json_line(&initialized_note) {
            let (status, msg) = session.map_send_failure(err, "ephemeral child closed stdin");
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(status, err_id, -32000, &msg);
        }

        let is_request = method.is_some() && req_id.is_some();
        if !is_request {
            let send_res = session.send_json_line(payload);
            if let Err(err) = send_res {
                let (status, msg) = session.map_send_failure(err, "ephemeral child closed stdin");
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(status, Value::Null, -32000, &msg);
            }
            ephemeral.terminate_now().await;
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
            let (status, msg) = session.map_register_failure("ephemeral child closed stdin");
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(status, id, -32000, &msg);
        };
        if let Err(err) = session.send_request_line(payload, wire_id) {
            guard.disarm();
            let (status, msg) = session.map_send_failure(err, "ephemeral child closed stdin");
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(status, id, -32000, &msg);
        }

        let call_timeout = Duration::from_secs(self.inner.settings.session_idle_secs);

        if client_accepts_sse(headers) {
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
        let (resp_bytes, resp_lease) = match tokio::time::timeout(call_timeout, resp_rx).await {
            Ok(Ok(RespDelivery::Ok { json_bytes, lease })) => (json_bytes, lease),
            Ok(Ok(RespDelivery::HardError {
                status, message, ..
            })) => {
                guard.disarm();
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(status, id, -32000, &message);
            }
            Ok(Err(_)) => {
                guard.disarm();
                let (status, msg) =
                    session.map_dead_session_error("ephemeral child exited before responding");
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(status, id, -32000, &msg);
            }
            Err(_) => {
                guard.cancel("request timed out");
                ephemeral.terminate_now().await;
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

        single_rpc_reply(headers, None, resp_bytes, resp_lease)
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

fn classify_init_response(raw_line: &[u8]) -> InitOutcome {
    let Ok(val) = serde_json::from_slice::<Value>(raw_line) else {
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

type ReapFallback = (
    Vec<Arc<StdioSession>>,
    TerminatingSlotsGuard,
    Option<SlotReservation>,
);

fn spawn_reap_task(
    inner: &Arc<StdioInner>,
    sessions: Vec<Arc<StdioSession>>,
    term_guard: TerminatingSlotsGuard,
    slot_for_caller: Option<SlotReservation>,
) -> Result<oneshot::Receiver<Option<SlotReservation>>, ReapFallback> {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return Err((sessions, term_guard, slot_for_caller));
    };
    let grant_tag = sessions
        .first()
        .map(|s| s.grant_id.clone())
        .unwrap_or_default();
    let (tx, rx) = oneshot::channel();
    // Run termination inside a tracked task so caller cancellation cannot leak children or release slots early.
    let jh = handle.spawn(async move {
        terminate_all(sessions).await;
        drop(term_guard);
        let _ = tx.send(slot_for_caller);
    });
    {
        let mut bg = inner
            .bg_terminations
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        bg.retain(|(_, h)| !h.is_finished());
        bg.push((grant_tag, jh));
    }
    Ok(rx)
}

struct EphemeralGuard {
    session: Option<Arc<StdioSession>>,
    slot: Option<SlotReservation>,
}

impl EphemeralGuard {
    fn new(session: Arc<StdioSession>, slot: SlotReservation) -> Self {
        Self {
            session: Some(session),
            slot: Some(slot),
        }
    }

    fn commit(&mut self, tbl: &mut SessionTable) {
        self.session = None;
        if let Some(slot) = self.slot.take() {
            slot.commit(tbl);
        }
    }

    fn begin_reap(
        &mut self,
    ) -> Option<Result<oneshot::Receiver<Option<SlotReservation>>, ReapFallback>> {
        let slot = self.slot.take();
        let Some(sess) = self.session.take() else {
            drop(slot);
            return None;
        };
        let (inner, term_guard) = match slot {
            Some(s) => {
                let tg = s.into_terminating();
                let inner = Arc::clone(&tg.inner);
                (inner, tg)
            }
            None => {
                let up = sess.weak_inner.upgrade()?;
                let tg = TerminatingSlotsGuard::new(Arc::clone(&up), 0);
                (up, tg)
            }
        };
        Some(spawn_reap_task(&inner, vec![sess], term_guard, None))
    }

    async fn terminate_now(&mut self) {
        if let Some(started) = self.begin_reap() {
            match started {
                Ok(rx) => {
                    let _ = rx.await;
                }
                Err((sessions, term_guard, _)) => {
                    terminate_all(sessions).await;
                    drop(term_guard);
                }
            }
        }
    }
}

impl Drop for EphemeralGuard {
    fn drop(&mut self) {
        let _ = self.begin_reap();
    }
}

struct SlotReservation {
    inner: Arc<StdioInner>,
    committed: bool,
}

impl SlotReservation {
    fn new(inner: &Arc<StdioInner>) -> Self {
        Self {
            inner: Arc::clone(inner),
            committed: false,
        }
    }

    fn commit(mut self, tbl: &mut SessionTable) {
        tbl.reserved_slots = tbl.reserved_slots.saturating_sub(1);
        self.committed = true;
    }

    fn into_terminating(mut self) -> TerminatingSlotsGuard {
        self.committed = true;
        {
            let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            tbl.reserved_slots = tbl.reserved_slots.saturating_sub(1);
            tbl.terminating_slots += 1;
        }
        TerminatingSlotsGuard::new(Arc::clone(&self.inner), 1)
    }
}

impl Drop for SlotReservation {
    fn drop(&mut self) {
        if !self.committed {
            {
                let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
                tbl.reserved_slots = tbl.reserved_slots.saturating_sub(1);
            }
            self.inner.slot_notify.notify_waiters();
        }
    }
}

struct TerminatingSlotsGuard {
    inner: Arc<StdioInner>,
    count: usize,
}

impl TerminatingSlotsGuard {
    fn new(inner: Arc<StdioInner>, count: usize) -> Self {
        Self { inner, count }
    }
}

impl Drop for TerminatingSlotsGuard {
    fn drop(&mut self) {
        if self.count > 0 {
            let count = std::mem::take(&mut self.count);
            {
                let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
                tbl.terminating_slots = tbl.terminating_slots.saturating_sub(count);
            }
            self.inner.slot_notify.notify_waiters();
        }
    }
}

fn is_routine_gc_candidate(sess: &StdioSession, now_ms: u64, idle_limit_ms: u64) -> bool {
    !sess.alive.load(Ordering::Acquire)
        || (sess.active_requests.load(Ordering::Acquire) == 0
            && now_ms.saturating_sub(sess.last_client_active_ms.load(Ordering::Acquire))
                >= idle_limit_ms)
}

async fn reap_sessions(
    inner: &Arc<StdioInner>,
    sessions: Vec<Arc<StdioSession>>,
    extra_terminating: usize,
    slot_for_caller: Option<SlotReservation>,
) -> Option<SlotReservation> {
    if sessions.is_empty() && extra_terminating == 0 {
        return slot_for_caller;
    }
    let term_guard = TerminatingSlotsGuard::new(Arc::clone(inner), extra_terminating);
    match spawn_reap_task(inner, sessions, term_guard, slot_for_caller) {
        Ok(rx) => rx.await.ok().flatten(),
        Err((sessions, term_guard, slot_for_caller)) => {
            terminate_all(sessions).await;
            drop(term_guard);
            slot_for_caller
        }
    }
}

async fn acquire_slot(inner: &Arc<StdioInner>, grant_id: &str) -> Option<SlotReservation> {
    enum Plan {
        Immediate(SlotReservation),
        Reap {
            victims: Vec<Arc<StdioSession>>,
            reservation: SlotReservation,
            extra_terminating: usize,
        },
        WaitTerminating,
        Full,
    }

    let deadline = Instant::now() + INIT_TIMEOUT;
    loop {
        let notified = inner.slot_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let plan = {
            let mut tbl = inner.table.lock().unwrap_or_else(|p| p.into_inner());
            if tbl.shutting_down {
                Plan::Full
            } else if tbl.used_slots() < inner.settings.max_sessions {
                tbl.reserved_slots += 1;
                Plan::Immediate(SlotReservation::new(inner))
            } else {
                let now_ms = elapsed_ms(inner.epoch);
                let idle_limit_ms = inner.settings.session_idle_secs.saturating_mul(1000);
                let stale_ids: Vec<String> = tbl
                    .sessions
                    .iter()
                    .filter(|(_, sess)| is_routine_gc_candidate(sess, now_ms, idle_limit_ms))
                    .map(|(sid, _)| sid.clone())
                    .collect();
                if !stale_ids.is_empty() {
                    let victims: Vec<Arc<StdioSession>> = stale_ids
                        .into_iter()
                        .filter_map(|id| tbl.sessions.remove(&id))
                        .collect();
                    tbl.reserved_slots += 1;
                    let extra = victims.len().saturating_sub(1);
                    tbl.terminating_slots += extra;
                    Plan::Reap {
                        victims,
                        reservation: SlotReservation::new(inner),
                        extra_terminating: extra,
                    }
                } else {
                    let effective_pressure = inner
                        .limits
                        .pressure_idle
                        .min(Duration::from_secs(inner.settings.session_idle_secs));
                    let pressure_ms =
                        u64::try_from(effective_pressure.as_millis()).unwrap_or(u64::MAX);
                    let victim_sid = tbl
                        .sessions
                        .iter()
                        .filter(|(_, sess)| {
                            constant_time_eq_str(&sess.grant_id, grant_id)
                                && sess.alive.load(Ordering::Acquire)
                                && sess.active_requests.load(Ordering::Acquire) == 0
                                && now_ms.saturating_sub(
                                    sess.last_client_active_ms.load(Ordering::Acquire),
                                ) >= pressure_ms
                        })
                        .min_by_key(|(_, sess)| {
                            (
                                sess.last_client_active_ms.load(Ordering::Acquire),
                                sess.last_client_seq.load(Ordering::Acquire),
                                sess.uid,
                            )
                        })
                        .map(|(sid, _)| sid.clone());
                    if let Some(sid) = victim_sid
                        && let Some(victim) = tbl.sessions.remove(&sid)
                    {
                        tbl.reserved_slots += 1;
                        Plan::Reap {
                            victims: vec![victim],
                            reservation: SlotReservation::new(inner),
                            extra_terminating: 0,
                        }
                    } else if tbl.terminating_slots > 0 {
                        Plan::WaitTerminating
                    } else {
                        Plan::Full
                    }
                }
            }
        };

        match plan {
            Plan::Immediate(res) => return Some(res),
            Plan::Full => return None,
            Plan::WaitTerminating => {
                let rem = deadline.checked_duration_since(Instant::now())?;
                if tokio::time::timeout(rem, notified).await.is_err() {
                    return None;
                }
            }
            Plan::Reap {
                victims,
                reservation,
                extra_terminating,
            } => {
                let res =
                    reap_sessions(inner, victims, extra_terminating, Some(reservation)).await?;
                let shutting_down = inner
                    .table
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .shutting_down;
                return if shutting_down {
                    drop(res);
                    None
                } else {
                    Some(res)
                };
            }
        }
    }
}

async fn evict_idle_sessions(inner: &Arc<StdioInner>) {
    let now_ms = elapsed_ms(inner.epoch);
    let idle_limit_ms = inner.settings.session_idle_secs.saturating_mul(1000);
    let evicted: Vec<Arc<StdioSession>> = {
        let mut tbl = inner.table.lock().unwrap_or_else(|p| p.into_inner());
        let stale_ids: Vec<String> = tbl
            .sessions
            .iter()
            .filter(|(_, sess)| is_routine_gc_candidate(sess, now_ms, idle_limit_ms))
            .map(|(sid, _)| sid.clone())
            .collect();
        let removed: Vec<Arc<StdioSession>> = stale_ids
            .into_iter()
            .filter_map(|id| tbl.sessions.remove(&id))
            .collect();
        tbl.terminating_slots += removed.len();
        removed
    };
    if !evicted.is_empty() {
        let count = evicted.len();
        let _ = reap_sessions(inner, evicted, count, None).await;
    }
}

async fn remove_and_terminate(
    inner: &Arc<StdioInner>,
    session_id: &str,
    session: &Arc<StdioSession>,
) {
    let removed_count = {
        let mut tbl = inner.table.lock().unwrap_or_else(|p| p.into_inner());
        if tbl
            .sessions
            .get(session_id)
            .is_some_and(|cur| cur.uid == session.uid)
        {
            tbl.sessions.remove(session_id);
            tbl.terminating_slots += 1;
            1
        } else {
            0
        }
    };
    let _ = reap_sessions(inner, vec![Arc::clone(session)], removed_count, None).await;
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
        reservation: SlotReservation,
    ) -> Result<(Arc<Self>, EphemeralGuard), String> {
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
        let notif_budget = ByteBudget::new(inner.limits.max_notif_queue_bytes);
        let terminal_error = Arc::new(Mutex::new(None));
        let active_requests = Arc::new(AtomicUsize::new(0));
        let initial_seq = NEXT_CLIENT_SEQ.fetch_add(1, Ordering::Relaxed);
        let initial_ms = elapsed_ms(inner.epoch);
        let uid = NEXT_SESSION_UID.fetch_add(1, Ordering::Relaxed);

        let session = Arc::new(Self {
            uid,
            grant_id,
            weak_inner: Arc::downgrade(inner),
            writer_cancel: writer_cancel.clone(),
            stdin_tx: Arc::clone(&stdin_tx_arc),
            in_flight: Arc::clone(&in_flight),
            terminal_error: Arc::clone(&terminal_error),
            next_wire_id: AtomicU64::new(1),
            alive: Arc::clone(&alive),
            active_requests,
            last_client_active_ms: AtomicU64::new(initial_ms),
            last_client_seq: AtomicU64::new(initial_seq),
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
            let mut ephem = EphemeralGuard::new(session, reservation);
            ephem.terminate_now().await;
            return Err("session aborted due to shutdown or grant revocation".to_owned());
        }
        let ephemeral = EphemeralGuard::new(Arc::clone(&session), reservation);

        let writer_alive = Arc::clone(&alive);
        tokio::spawn(async move {
            while let Some(buf) = tokio::select! {
                _ = writer_cancel.cancelled() => None,
                msg = stdin_rx.recv() => msg,
            } {
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
        let reader_budget = Arc::clone(&inner.budget);
        let reader_limits = inner.limits;
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout);
            let mut raw = Vec::new();
            let mut had_hard_err = false;
            loop {
                match read_stdout_line(
                    &mut lines,
                    &mut raw,
                    &in_flight,
                    &reader_budget,
                    reader_limits,
                )
                .await
                {
                    Ok(outcome) => {
                        if outcome.len == 0 {
                            release_raw_buf(&mut raw);
                            drop(outcome.lease);
                            break;
                        }
                        if outcome.len > reader_limits.max_control_line_bytes {
                            dispatch_large_response_line(&mut raw, outcome, &in_flight);
                            continue;
                        }
                        let Ok(text) = std::str::from_utf8(&raw) else {
                            release_raw_buf(&mut raw);
                            drop(outcome.lease);
                            continue;
                        };
                        let trimmed = text.trim_end_matches(['\r', '\n']);
                        if trimmed.trim().is_empty() {
                            release_raw_buf(&mut raw);
                            drop(outcome.lease);
                            continue;
                        }
                        let parsed = serde_json::from_str::<Value>(trimmed);
                        release_raw_buf(&mut raw);
                        drop(outcome.lease);
                        if let Ok(val) = parsed {
                            dispatch_stdout_message(
                                &in_flight,
                                &reader_stdin,
                                &alive,
                                &notif_budget,
                                val,
                            );
                        }
                    }
                    Err(ReadStdoutErr::Io) => {
                        release_raw_buf(&mut raw);
                        break;
                    }
                    Err(ReadStdoutErr::Hard(hard_err)) => {
                        had_hard_err = true;
                        release_raw_buf(&mut raw);
                        fail_session_waiters(&alive, &terminal_error, &in_flight, hard_err);
                        break;
                    }
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
                        tbl.terminating_slots += 1;
                    }
                    found.is_some()
                };
                if matched {
                    let _guard = TerminatingSlotsGuard::new(Arc::clone(&up), 1);
                    sess.terminate().await;
                } else if had_hard_err {
                    sess.terminate().await;
                }
            } else if had_hard_err && let Some(sess) = reader_session.upgrade() {
                sess.terminate().await;
            }
        });

        Ok((session, ephemeral))
    }

    fn touch_client(&self) {
        let seq = NEXT_CLIENT_SEQ.fetch_add(1, Ordering::Relaxed);
        let now = elapsed_ms(self.epoch);
        self.last_client_seq.store(seq, Ordering::Release);
        self.last_client_active_ms.store(now, Ordering::Release);
    }

    fn send_request_line(&self, payload: &Value, wire_id: u64) -> Result<(), SendLineErr> {
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

    fn send_json_line(&self, value: &Value) -> Result<(), SendLineErr> {
        if !self.alive.load(Ordering::Acquire) {
            return Err(SendLineErr::Closed);
        }
        let mut line = serde_json::to_vec(value).map_err(|_| SendLineErr::Closed)?;
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

    fn send_raw_line(&self, line: Vec<u8>) -> Result<(), SendLineErr> {
        let guard = self.stdin_tx.lock().unwrap_or_else(|p| p.into_inner());
        let Some(tx) = guard.as_ref() else {
            return Err(SendLineErr::Closed);
        };
        tx.try_send(line).map_err(|err| match err {
            TrySendError::Full(_) => SendLineErr::Full,
            TrySendError::Closed(_) => SendLineErr::Closed,
        })
    }

    fn take_or_clone_terminal_error(&self) -> Option<(StatusCode, String)> {
        self.terminal_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn map_dead_session_error(&self, fallback_msg: &str) -> (StatusCode, String) {
        if let Some(term_err) = self.take_or_clone_terminal_error() {
            term_err
        } else {
            (StatusCode::BAD_GATEWAY, fallback_msg.to_owned())
        }
    }

    fn map_register_failure(&self, fallback_dead_msg: &str) -> (StatusCode, String) {
        if !self.alive.load(Ordering::Acquire) {
            self.map_dead_session_error(fallback_dead_msg)
        } else {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "too many concurrent requests in session".to_owned(),
            )
        }
    }

    fn map_send_failure(&self, err: SendLineErr, fallback_dead_msg: &str) -> (StatusCode, String) {
        if matches!(err, SendLineErr::Closed) || !self.alive.load(Ordering::Acquire) {
            self.map_dead_session_error(fallback_dead_msg)
        } else {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream stdin queue is full".to_owned(),
            )
        }
    }

    fn register_request(
        self: &Arc<Self>,
        client_id: Value,
        client_progress_token: Option<Value>,
    ) -> Option<(
        u64,
        RequestGuard,
        mpsc::UnboundedReceiver<QueuedNotif>,
        oneshot::Receiver<RespDelivery>,
    )> {
        let claim = ActiveRequestClaim::new(self);
        self.register_request_with_claim(claim, client_id, client_progress_token)
    }

    fn register_request_with_claim(
        self: &Arc<Self>,
        mut claim: ActiveRequestClaim,
        client_id: Value,
        client_progress_token: Option<Value>,
    ) -> Option<(
        u64,
        RequestGuard,
        mpsc::UnboundedReceiver<QueuedNotif>,
        oneshot::Receiver<RespDelivery>,
    )> {
        let mut waiters = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if !self.alive.load(Ordering::Acquire) || waiters.len() >= MAX_IN_FLIGHT_PER_SESSION {
            return None;
        }
        let wire_id = self.next_wire_id.fetch_add(1, Ordering::Relaxed);
        let (notif_tx, notif_rx) = mpsc::unbounded_channel();
        let (resp_tx, resp_rx) = oneshot::channel();
        // Adopt the pre-incremented active_requests count without dipping to zero.
        claim.disarm_into_guard();
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

struct ActiveRequestClaim {
    session: Arc<StdioSession>,
    armed: bool,
}

impl ActiveRequestClaim {
    fn new(session: &Arc<StdioSession>) -> Self {
        session.active_requests.fetch_add(1, Ordering::AcqRel);
        Self {
            session: Arc::clone(session),
            armed: true,
        }
    }

    fn disarm_into_guard(&mut self) {
        self.armed = false;
    }
}

impl Drop for ActiveRequestClaim {
    fn drop(&mut self) {
        if self.armed {
            self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
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
    notif_rx: mpsc::UnboundedReceiver<QueuedNotif>,
    resp_rx: Option<oneshot::Receiver<RespDelivery>>,
    pending_resp: Option<RespDelivery>,
    active_resp_cursor: Option<LeasedFrameCursor>,
    active_resp_is_error: bool,
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
        notif_rx: mpsc::UnboundedReceiver<QueuedNotif>,
        resp_rx: oneshot::Receiver<RespDelivery>,
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
            active_resp_cursor: None,
            active_resp_is_error: false,
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
        self.active_resp_cursor = None;
        self.pending_resp = None;
        self.stream_done.cancel();
        self.session.touch_client();
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
        self.active_resp_cursor = None;
        self.pending_resp = None;
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
        let had_resp =
            self.active_resp_cursor.take().is_some() || self.pending_resp.take().is_some();
        self.stream_done.cancel();
        let mut g = self.guard.lock().unwrap_or_else(|p| p.into_inner());
        if had_resp {
            g.disarm();
        } else {
            g.cancel("request timed out");
        }
        drop(g);
        let _ = self
            .ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
    }
}

impl Drop for StdioSseStreamBody {
    fn drop(&mut self) {
        let had_resp =
            self.active_resp_cursor.take().is_some() || self.pending_resp.take().is_some();
        self.stream_done.cancel();
        let mut g = self.guard.lock().unwrap_or_else(|p| p.into_inner());
        if had_resp {
            g.disarm();
        } else {
            g.cancel("client disconnected");
        }
        drop(g);
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

            if let Some(ref mut cursor) = this.active_resp_cursor {
                if let Some(frame) = cursor.next_frame() {
                    if !this.active_resp_is_error {
                        this.session.touch_client();
                    }
                    this.last_frame_ms
                        .store(elapsed_ms(this.session.epoch), Ordering::Release);
                    this.idle_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + this.idle_timeout);
                    return Poll::Ready(Some(Ok(frame)));
                }
                this.active_resp_cursor = None;
                if this.active_resp_is_error {
                    this.finish_disarmed();
                } else {
                    this.finish_completed();
                }
                return Poll::Ready(None);
            }

            if !this.notif_done {
                match this.notif_rx.poll_recv(cx) {
                    Poll::Ready(Some(queued)) => {
                        this.session.touch_client();
                        this.last_frame_ms
                            .store(elapsed_ms(this.session.epoch), Ordering::Release);
                        this.idle_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + this.idle_timeout);
                        let formatted = format!("data: {}\n\n", queued.line);
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
                    Poll::Ready(Ok(delivery)) => {
                        this.resp_rx = None;
                        this.pending_resp = Some(delivery);
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
                if let Some(delivery) = this.pending_resp.take() {
                    let (json_bytes, lease, is_err) = match delivery {
                        RespDelivery::Ok { json_bytes, lease } => (json_bytes, lease, false),
                        RespDelivery::HardError { json_bytes, .. } => (json_bytes, None, true),
                    };
                    this.active_resp_is_error = is_err;
                    let mut cursor = LeasedFrameCursor::new(b"data: ", json_bytes, b"\n\n", lease);
                    if let Some(first) = cursor.next_frame() {
                        if cursor.is_done() {
                            if is_err {
                                this.finish_disarmed();
                            } else {
                                this.finish_completed();
                            }
                        } else {
                            this.active_resp_cursor = Some(cursor);
                        }
                        if !is_err {
                            this.session.touch_client();
                        }
                        this.last_frame_ms
                            .store(elapsed_ms(this.session.epoch), Ordering::Release);
                        this.idle_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + this.idle_timeout);
                        return Poll::Ready(Some(Ok(first)));
                    }
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

fn enqueue_notif(
    notif_budget: &Arc<ByteBudget>,
    tx: &mpsc::UnboundedSender<QueuedNotif>,
    line: String,
) {
    if tx.is_closed() {
        return;
    }
    let cost = line.len().max(1);
    let Some(lease) = ByteBudget::try_acquire(notif_budget, cost) else {
        return;
    };
    let _ = tx.send(QueuedNotif {
        line,
        _lease: lease,
    });
}

fn dispatch_large_response_line(
    raw: &mut Vec<u8>,
    outcome: ReadLineOutcome,
    in_flight: &Mutex<Vec<InFlightEntry>>,
) {
    let Some(mut lease) = outcome.lease else {
        release_raw_buf(raw);
        return;
    };
    if outcome.saw_method || outcome.id_count != 1 {
        release_raw_buf(raw);
        drop(lease);
        return;
    }
    let Some(top_id) = outcome.top_id else {
        release_raw_buf(raw);
        drop(lease);
        return;
    };
    let Some(wire_id) = top_id.wire_id else {
        release_raw_buf(raw);
        drop(lease);
        return;
    };
    let Ok(text) = std::str::from_utf8(raw) else {
        release_raw_buf(raw);
        drop(lease);
        return;
    };
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.trim().is_empty() || serde_json::from_str::<serde::de::IgnoredAny>(trimmed).is_err()
    {
        release_raw_buf(raw);
        drop(lease);
        return;
    }
    let trimmed_len = trimmed.len();
    if top_id.end > trimmed_len || top_id.start >= top_id.end {
        release_raw_buf(raw);
        drop(lease);
        return;
    }
    let entry = {
        let mut waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        waiters
            .iter()
            .position(|w| w.wire_id == wire_id)
            .map(|pos| waiters.remove(pos))
    };
    let Some(entry) = entry else {
        release_raw_buf(raw);
        drop(lease);
        return;
    };
    let client_id_for_err = entry.client_id.clone();
    let Ok(client_id_bytes) = serde_json::to_vec(&entry.client_id) else {
        release_raw_buf(raw);
        drop(lease);
        return;
    };
    raw.truncate(trimmed_len);
    let old_id_len = top_id.end - top_id.start;
    let final_len = trimmed_len - old_id_len + client_id_bytes.len();
    if !lease.try_reserve(final_len) {
        release_raw_buf(raw);
        drop(lease);
        let msg = "process active byte budget exceeded".to_owned();
        let err_bytes = build_jsonrpc_error_bytes(client_id_for_err, -32000, &msg);
        let _ = entry.resp_tx.send(RespDelivery::HardError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: msg,
            json_bytes: err_bytes,
        });
        return;
    }
    if final_len > raw.capacity() {
        raw.reserve_exact(final_len - raw.len());
    }
    raw.splice(top_id.start..top_id.end, client_id_bytes);
    let mut json_bytes = std::mem::take(raw);
    if json_bytes.capacity().saturating_sub(json_bytes.len()) > 1024 * 1024 {
        json_bytes.shrink_to_fit();
    }
    let _ = entry.resp_tx.send(RespDelivery::Ok {
        json_bytes,
        lease: Some(lease),
    });
}

fn dispatch_stdout_message(
    in_flight: &Mutex<Vec<InFlightEntry>>,
    stdin_tx: &Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    alive: &AtomicBool,
    notif_budget: &Arc<ByteBudget>,
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
        drop(val);
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
        let Some(entry) = entry else {
            return;
        };
        if let Some(map) = val.as_object_mut() {
            map.insert("id".to_owned(), entry.client_id);
        }
        if let Ok(out) = serde_json::to_vec(&val) {
            drop(val);
            let _ = entry.resp_tx.send(RespDelivery::Ok {
                json_bytes: out,
                lease: None,
            });
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
            if !notif_tx.is_closed()
                && let Ok(out) = serde_json::to_string(&val)
            {
                enqueue_notif(notif_budget, &notif_tx, out);
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
            if !notif_tx.is_closed()
                && let Ok(out) = serde_json::to_string(&val)
            {
                enqueue_notif(notif_budget, &notif_tx, out);
            }
        }
        return;
    }

    let targets: Vec<mpsc::UnboundedSender<QueuedNotif>> = {
        let waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        waiters
            .iter()
            .filter(|w| !w.notif_tx.is_closed())
            .map(|w| w.notif_tx.clone())
            .collect()
    };
    if !targets.is_empty()
        && let Ok(out) = serde_json::to_string(&val)
    {
        let mut iter = targets.into_iter();
        if let Some(first_tx) = iter.next() {
            for tx in iter {
                enqueue_notif(notif_budget, &tx, out.clone());
            }
            enqueue_notif(notif_budget, &first_tx, out);
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

fn single_rpc_reply(
    headers: &HeaderMap,
    session_id: Option<&str>,
    json_bytes: Vec<u8>,
    lease: Option<ByteLease>,
) -> HttpReply {
    let sse = client_prefers_sse_only(headers);
    let (content_type, body) = if sse {
        (
            "text/event-stream",
            leased_body(b"data: ", json_bytes, b"\n\n", lease),
        )
    } else {
        ("application/json", leased_body(b"", json_bytes, b"", lease))
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(HeaderName::from_static("x-accel-buffering"), "no");
    if let Some(sid) = session_id {
        builder = builder.header(HeaderName::from_static("mcp-session-id"), sid);
    }
    builder.body(body).expect("valid RPC reply")
}

fn build_jsonrpc_error_bytes(id: Value, code: i64, message: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    }))
    .unwrap_or_else(|_| {
        br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"internal error"}}"#
            .to_vec()
    })
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

fn release_raw_buf(raw: &mut Vec<u8>) {
    raw.clear();
    if raw.capacity() > RAW_RETAIN_CAP_BYTES {
        *raw = Vec::new();
    }
}

fn reserve_bounded(out: &mut Vec<u8>, additional: usize, max_cap: usize) {
    let needed = out.len().saturating_add(additional);
    if needed <= out.capacity() {
        return;
    }
    let doubled = out.capacity().saturating_mul(2).max(RAW_RETAIN_CAP_BYTES);
    let target = doubled.max(needed).min(max_cap);
    out.reserve_exact(target - out.len());
}

fn has_in_flight(in_flight: &Mutex<Vec<InFlightEntry>>) -> bool {
    !in_flight
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty()
}

#[derive(Debug)]
enum HardRejectError {
    BudgetExhausted,
    LineTooLarge(usize),
    ControlMessageTooLarge(usize),
    UnexpectedLargeOutput(usize),
}

impl HardRejectError {
    fn into_status_and_message(self) -> (StatusCode, String) {
        match self {
            Self::BudgetExhausted => (
                StatusCode::SERVICE_UNAVAILABLE,
                "process active byte budget exceeded".to_owned(),
            ),
            Self::LineTooLarge(limit) => (
                StatusCode::BAD_GATEWAY,
                format!("upstream stdout line exceeds {limit} byte limit"),
            ),
            Self::ControlMessageTooLarge(limit) => (
                StatusCode::BAD_GATEWAY,
                format!(
                    "upstream stdout control or notification message exceeds {limit} byte limit"
                ),
            ),
            Self::UnexpectedLargeOutput(limit) => (
                StatusCode::BAD_GATEWAY,
                format!("upstream stdout exceeded {limit} bytes with no active request"),
            ),
        }
    }
}

#[derive(Debug)]
enum ReadStdoutErr {
    Io,
    Hard(HardRejectError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TopIdSpan {
    start: usize,
    end: usize,
    wire_id: Option<u64>,
}

struct ReadLineOutcome {
    len: usize,
    lease: Option<ByteLease>,
    saw_method: bool,
    id_count: usize,
    top_id: Option<TopIdSpan>,
}

fn fail_session_waiters(
    alive: &AtomicBool,
    terminal_error: &Mutex<Option<(StatusCode, String)>>,
    in_flight: &Mutex<Vec<InFlightEntry>>,
    hard_err: HardRejectError,
) {
    let (status, message) = hard_err.into_status_and_message();
    {
        let mut slot = terminal_error.lock().unwrap_or_else(|p| p.into_inner());
        *slot = Some((status, message.clone()));
    }
    alive.store(false, Ordering::Release);
    let drained: Vec<InFlightEntry> = {
        let mut waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut *waiters)
    };
    for entry in drained {
        let json_bytes = build_jsonrpc_error_bytes(entry.client_id, -32000, &message);
        let _ = entry.resp_tx.send(RespDelivery::HardError {
            status,
            message: message.clone(),
            json_bytes,
        });
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TopObjPhase {
    ExpectKeyOrEnd,
    ExpectColon,
    ExpectIdValue,
    InIdPrimitive,
    InIdCompound,
    InOtherValue,
}

struct TopLevelJsonScanner {
    pos: usize,
    started: bool,
    top_is_object: bool,
    depth: usize,
    phase: TopObjPhase,
    last_key_was_id: bool,
    in_string: bool,
    escaped: bool,
    unicode_rem: u8,
    unicode_val: u16,
    capturing_key: bool,
    key_overflow: bool,
    key_buf: [u8; 16],
    key_len: usize,
    id_span_start: usize,
    id_raw_buf: [u8; 24],
    id_raw_len: usize,
    id_raw_overflow: bool,
    id_count: usize,
    top_id: Option<TopIdSpan>,
    saw_method: bool,
}

impl TopLevelJsonScanner {
    fn new() -> Self {
        Self {
            pos: 0,
            started: false,
            top_is_object: false,
            depth: 0,
            phase: TopObjPhase::ExpectKeyOrEnd,
            last_key_was_id: false,
            in_string: false,
            escaped: false,
            unicode_rem: 0,
            unicode_val: 0,
            capturing_key: false,
            key_overflow: false,
            key_buf: [0; 16],
            key_len: 0,
            id_span_start: 0,
            id_raw_buf: [0; 24],
            id_raw_len: 0,
            id_raw_overflow: false,
            id_count: 0,
            top_id: None,
            saw_method: false,
        }
    }

    fn push_key_byte(&mut self, b: u8) {
        if self.capturing_key && !self.key_overflow {
            if self.key_len < self.key_buf.len() {
                self.key_buf[self.key_len] = b;
                self.key_len += 1;
            } else {
                self.key_overflow = true;
            }
        }
    }

    fn finalize_primitive_id(&mut self, end_pos: usize) {
        let wire_id = if !self.id_raw_overflow {
            std::str::from_utf8(&self.id_raw_buf[..self.id_raw_len])
                .ok()
                .filter(|s| {
                    !s.is_empty()
                        && s.bytes().all(|b| b.is_ascii_digit())
                        && (*s == "0" || !s.starts_with('0'))
                })
                .and_then(|s| s.parse::<u64>().ok())
        } else {
            None
        };
        self.id_count = self.id_count.saturating_add(1);
        self.top_id = Some(TopIdSpan {
            start: self.id_span_start,
            end: end_pos,
            wire_id,
        });
    }

    fn feed(&mut self, bytes: &[u8]) {
        if self.saw_method {
            return;
        }
        for &b in bytes {
            let idx = self.pos;
            self.pos += 1;

            if self.in_string {
                if self.unicode_rem > 0 {
                    if let Some(nib) = hex_nibble(b) {
                        self.unicode_val = (self.unicode_val << 4) | u16::from(nib);
                        self.unicode_rem -= 1;
                        if self.unicode_rem == 0 {
                            let decoded = u8::try_from(self.unicode_val).unwrap_or(0xFF);
                            self.push_key_byte(decoded);
                        }
                    } else {
                        self.unicode_rem = 0;
                        self.key_overflow = true;
                    }
                    continue;
                }
                if self.escaped {
                    self.escaped = false;
                    if b == b'u' && self.capturing_key {
                        self.unicode_rem = 4;
                        self.unicode_val = 0;
                    } else {
                        let mapped = match b {
                            b'"' | b'\\' | b'/' => b,
                            b'b' => 0x08,
                            b'f' => 0x0c,
                            b'n' => b'\n',
                            b'r' => b'\r',
                            b't' => b'\t',
                            _ => b,
                        };
                        self.push_key_byte(mapped);
                    }
                    continue;
                }
                if b == b'\\' {
                    self.escaped = true;
                } else if b == b'"' {
                    self.in_string = false;
                    if self.capturing_key {
                        self.capturing_key = false;
                        let key = &self.key_buf[..self.key_len];
                        if !self.key_overflow && key == b"method" {
                            self.saw_method = true;
                            return;
                        }
                        self.last_key_was_id = !self.key_overflow && key == b"id";
                        self.phase = TopObjPhase::ExpectColon;
                    } else if self.depth == 1 && self.phase == TopObjPhase::InIdCompound {
                        self.id_count = self.id_count.saturating_add(1);
                        self.top_id = Some(TopIdSpan {
                            start: self.id_span_start,
                            end: idx + 1,
                            wire_id: None,
                        });
                        self.phase = TopObjPhase::InOtherValue;
                    }
                } else {
                    self.push_key_byte(b);
                }
                continue;
            }

            if !self.started {
                if b.is_ascii_whitespace() {
                    continue;
                }
                self.started = true;
                if b == b'{' {
                    self.top_is_object = true;
                    self.depth = 1;
                    self.phase = TopObjPhase::ExpectKeyOrEnd;
                }
                continue;
            }

            if !self.top_is_object || self.depth == 0 {
                continue;
            }

            if self.depth == 1 && self.phase == TopObjPhase::InIdPrimitive {
                if b.is_ascii_whitespace() {
                    self.finalize_primitive_id(idx);
                    self.phase = TopObjPhase::InOtherValue;
                    continue;
                }
                if b == b',' {
                    self.finalize_primitive_id(idx);
                    self.phase = TopObjPhase::ExpectKeyOrEnd;
                    continue;
                }
                if b == b'}' {
                    self.finalize_primitive_id(idx);
                    self.depth = 0;
                    self.top_is_object = false;
                    continue;
                }
                if !self.id_raw_overflow {
                    if self.id_raw_len < self.id_raw_buf.len() {
                        self.id_raw_buf[self.id_raw_len] = b;
                        self.id_raw_len += 1;
                    } else {
                        self.id_raw_overflow = true;
                    }
                }
                continue;
            }

            if self.depth == 1 && self.phase == TopObjPhase::ExpectIdValue {
                if b.is_ascii_whitespace() {
                    continue;
                }
                if b == b'"' {
                    self.in_string = true;
                    self.escaped = false;
                    self.unicode_rem = 0;
                    self.capturing_key = false;
                    self.id_span_start = idx;
                    self.phase = TopObjPhase::InIdCompound;
                    continue;
                }
                if b == b'{' || b == b'[' {
                    self.id_span_start = idx;
                    self.depth = 2;
                    self.phase = TopObjPhase::InIdCompound;
                    continue;
                }
                if b != b',' && b != b'}' && b != b']' {
                    self.id_span_start = idx;
                    self.id_raw_buf[0] = b;
                    self.id_raw_len = 1;
                    self.id_raw_overflow = false;
                    self.phase = TopObjPhase::InIdPrimitive;
                    continue;
                }
            }

            match b {
                b'"' => {
                    self.in_string = true;
                    self.escaped = false;
                    self.unicode_rem = 0;
                    if self.depth == 1 && self.phase == TopObjPhase::ExpectKeyOrEnd {
                        self.capturing_key = true;
                        self.key_overflow = false;
                        self.key_len = 0;
                        self.last_key_was_id = false;
                    } else {
                        self.capturing_key = false;
                    }
                }
                b':' if self.depth == 1 && self.phase == TopObjPhase::ExpectColon => {
                    self.phase = if self.last_key_was_id {
                        TopObjPhase::ExpectIdValue
                    } else {
                        TopObjPhase::InOtherValue
                    };
                }
                b'{' | b'[' => {
                    if self.depth == 1 {
                        self.phase = TopObjPhase::InOtherValue;
                    }
                    self.depth = self.depth.saturating_add(1);
                }
                b'}' | b']' => {
                    self.depth = self.depth.saturating_sub(1);
                    if self.depth == 0 {
                        self.top_is_object = false;
                    } else if self.depth == 1 && self.phase == TopObjPhase::InIdCompound {
                        self.id_count = self.id_count.saturating_add(1);
                        self.top_id = Some(TopIdSpan {
                            start: self.id_span_start,
                            end: idx + 1,
                            wire_id: None,
                        });
                        self.phase = TopObjPhase::InOtherValue;
                    }
                }
                b',' if self.depth == 1 => {
                    self.phase = TopObjPhase::ExpectKeyOrEnd;
                }
                _ => {}
            }
        }
    }
}

async fn read_stdout_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    out: &mut Vec<u8>,
    in_flight: &Mutex<Vec<InFlightEntry>>,
    budget: &Arc<ByteBudget>,
    limits: StdioLimits,
) -> Result<ReadLineOutcome, ReadStdoutErr> {
    out.clear();
    let control_limit = limits
        .max_control_line_bytes
        .min(limits.max_stdout_line_bytes);
    let mut lease: Option<ByteLease> = None;
    let mut scanner = TopLevelJsonScanner::new();
    let mut speculative = false;

    loop {
        let available = match reader.fill_buf().await {
            Ok(buf) => buf,
            Err(_) => {
                release_raw_buf(out);
                return Err(ReadStdoutErr::Io);
            }
        };
        if available.is_empty() {
            if speculative && !out.is_empty() {
                release_raw_buf(out);
                drop(lease);
                return Ok(ReadLineOutcome {
                    len: 0,
                    lease: None,
                    saw_method: false,
                    id_count: 0,
                    top_id: None,
                });
            }
            return Ok(ReadLineOutcome {
                len: out.len(),
                lease,
                saw_method: scanner.saw_method,
                id_count: scanner.id_count,
                top_id: scanner.top_id,
            });
        }

        if !speculative {
            let rem_ctrl = control_limit.saturating_sub(out.len());
            if rem_ctrl > 0 {
                let window = &available[..available.len().min(rem_ctrl)];
                if let Some(pos) = window.iter().position(|&b| b == b'\n') {
                    let take = pos + 1;
                    out.extend_from_slice(&window[..take]);
                    reader.consume(take);
                    return Ok(ReadLineOutcome {
                        len: out.len(),
                        lease: None,
                        saw_method: false,
                        id_count: 0,
                        top_id: None,
                    });
                }
                let n = window.len();
                out.extend_from_slice(window);
                reader.consume(n);
                continue;
            }

            if control_limit >= limits.max_stdout_line_bytes {
                release_raw_buf(out);
                return Err(ReadStdoutErr::Hard(HardRejectError::LineTooLarge(
                    limits.max_stdout_line_bytes,
                )));
            }
            if !has_in_flight(in_flight) {
                release_raw_buf(out);
                return Err(ReadStdoutErr::Hard(HardRejectError::UnexpectedLargeOutput(
                    limits.max_control_line_bytes,
                )));
            }
            scanner.feed(out);
            if scanner.saw_method {
                release_raw_buf(out);
                return Err(ReadStdoutErr::Hard(
                    HardRejectError::ControlMessageTooLarge(limits.max_control_line_bytes),
                ));
            }
            let Some(l) = ByteBudget::try_acquire(budget, out.len()) else {
                release_raw_buf(out);
                return Err(ReadStdoutErr::Hard(HardRejectError::BudgetExhausted));
            };
            lease = Some(l);
            speculative = true;
        }

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            let Some(new_len) = out
                .len()
                .checked_add(take)
                .filter(|&n| n <= limits.max_stdout_line_bytes)
            else {
                release_raw_buf(out);
                drop(lease);
                return Err(ReadStdoutErr::Hard(HardRejectError::LineTooLarge(
                    limits.max_stdout_line_bytes,
                )));
            };
            if !lease
                .as_mut()
                .expect("speculative lease")
                .try_reserve(new_len)
            {
                release_raw_buf(out);
                drop(lease);
                return Err(ReadStdoutErr::Hard(HardRejectError::BudgetExhausted));
            }
            reserve_bounded(out, take, limits.max_stdout_line_bytes);
            scanner.feed(&available[..take]);
            out.extend_from_slice(&available[..take]);
            reader.consume(take);
            return Ok(ReadLineOutcome {
                len: out.len(),
                lease,
                saw_method: scanner.saw_method,
                id_count: scanner.id_count,
                top_id: scanner.top_id,
            });
        }

        let len = available.len();
        let Some(new_len) = out
            .len()
            .checked_add(len)
            .filter(|&n| n <= limits.max_stdout_line_bytes)
        else {
            release_raw_buf(out);
            drop(lease);
            return Err(ReadStdoutErr::Hard(HardRejectError::LineTooLarge(
                limits.max_stdout_line_bytes,
            )));
        };
        if !lease
            .as_mut()
            .expect("speculative lease")
            .try_reserve(new_len)
        {
            release_raw_buf(out);
            drop(lease);
            return Err(ReadStdoutErr::Hard(HardRejectError::BudgetExhausted));
        }
        reserve_bounded(out, len, limits.max_stdout_line_bytes);
        scanner.feed(available);
        out.extend_from_slice(available);
        reader.consume(len);
        if scanner.saw_method {
            release_raw_buf(out);
            drop(lease);
            return Err(ReadStdoutErr::Hard(
                HardRejectError::ControlMessageTooLarge(limits.max_control_line_bytes),
            ));
        }
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
        let notif_budget = ByteBudget::new(MAX_NOTIF_QUEUE_BYTES);
        let session = Arc::new(StdioSession {
            uid: 1,
            grant_id: "g".to_owned(),
            weak_inner: Weak::new(),
            writer_cancel: CancellationToken::new(),
            stdin_tx: Arc::new(Mutex::new(None)),
            in_flight: Arc::new(Mutex::new(Vec::new())),
            terminal_error: Arc::new(Mutex::new(None)),
            next_wire_id: AtomicU64::new(2),
            alive: Arc::new(AtomicBool::new(false)),
            active_requests: Arc::new(AtomicUsize::new(1)),
            last_client_active_ms: AtomicU64::new(0),
            last_client_seq: AtomicU64::new(1),
            child: tokio::sync::Mutex::new(None),
            #[cfg(windows)]
            job: Mutex::new(None),
            epoch: now,
        });

        let (notif_tx, notif_rx) = mpsc::unbounded_channel();
        let (resp_tx, resp_rx) = oneshot::channel::<RespDelivery>();
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
        enqueue_notif(
            &notif_budget,
            &notif_tx,
            r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#.to_owned(),
        );
        drop(notif_tx);

        let first = Pin::new(&mut body).poll_frame(&mut cx);
        assert!(matches!(first, Poll::Ready(Some(Ok(_)))));

        let eof = Pin::new(&mut body).poll_frame(&mut cx);
        assert!(matches!(eof, Poll::Ready(None)));
        assert_eq!(session.active_requests.load(Ordering::Acquire), 0);
        assert_eq!(notif_budget.used(), 0);
    }

    #[test]
    fn top_level_json_scanner_handles_escapes_unicode_depth_id_spans_and_byte_splits() {
        let cases: &[(&str, bool, usize, Option<u64>)] = &[
            (r#"{"jsonrpc":"2.0","method":"ping"}"#, true, 0, None),
            (
                r#"{"jsonrpc":"2.0","params":{"nested":1},"method":"notifications/progress"}"#,
                true,
                0,
                None,
            ),
            (
                r#"{"jsonrpc":"2.0","meth\u006fd":"roots/list","id":1}"#,
                true,
                0,
                None,
            ),
            (
                r#"{"jsonrpc":"2.0","result":"method","id":1}"#,
                false,
                1,
                Some(1),
            ),
            (
                r#"{"jsonrpc":"2.0","id":0,"result":{"id":999,"method":"GET"}}"#,
                false,
                1,
                Some(0),
            ),
            (
                r#"{"jsonrpc":"2.0","i\u0064":  42 , "result":{"method":"GET","arr":[{"method":true}],"escaped":"\"}\",\"method\":\"fake\""}}"#,
                false,
                1,
                Some(42),
            ),
            (
                r#"{"jsonrpc":"2.0","escaped_key_\"method\"":1,"result":{"ok":true},"id":"str-id"}"#,
                false,
                1,
                None,
            ),
        ];

        for &(input, expected_method, expected_id_cnt, expected_wid) in cases {
            let mut whole = TopLevelJsonScanner::new();
            whole.feed(input.as_bytes());
            assert_eq!(
                whole.saw_method, expected_method,
                "whole scan mismatch on {input}"
            );
            if !expected_method {
                assert_eq!(whole.id_count, expected_id_cnt, "id_count on {input}");
                assert_eq!(
                    whole.top_id.and_then(|s| s.wire_id),
                    expected_wid,
                    "wire_id on {input}"
                );
            }

            let mut byte_by_byte = TopLevelJsonScanner::new();
            for b in input.bytes() {
                byte_by_byte.feed(&[b]);
            }
            assert_eq!(
                byte_by_byte.saw_method, expected_method,
                "byte-by-byte scan mismatch on {input}"
            );
            if !expected_method {
                assert_eq!(byte_by_byte.id_count, expected_id_cnt);
                assert_eq!(byte_by_byte.top_id, whole.top_id);
            }
        }
    }

    #[tokio::test]
    async fn read_stdout_line_inplace_rewrite_and_raw_shrink_across_all_exits() {
        let budget = ByteBudget::new(140 * 1024);
        let limits = StdioLimits {
            max_stdout_line_bytes: 512 * 1024,
            max_control_line_bytes: 1024,
            max_notif_queue_bytes: 64 * 1024,
            ..StdioLimits::default()
        };
        let in_flight: Mutex<Vec<InFlightEntry>> = Mutex::new(Vec::new());
        let push_waiter = |wire_id: u64, client_id: Value| {
            let (notif_tx, _notif_rx) = mpsc::unbounded_channel();
            let (resp_tx, resp_rx) = oneshot::channel();
            in_flight.lock().unwrap().push(InFlightEntry {
                wire_id,
                client_id,
                client_progress_token: None,
                notif_tx,
                resp_tx,
            });
            resp_rx
        };

        let mut raw = Vec::new();

        // 1. Valid 120 KiB response under tight 140 KiB budget (would fail if 2x AST coexisted) splices `id` in place and resets `raw` to 0 capacity.
        let rx1 = push_waiter(1, json!("client-long-id-rewrite-0001"));
        let big_str = "A".repeat(120 * 1024);
        let valid_line =
            format!(r#"{{"jsonrpc":"2.0","result":{{"blob":"{big_str}"}},"id":1}}"#) + "\n";
        let (mut w, r) = tokio::io::duplex(256 * 1024);
        w.write_all(valid_line.as_bytes()).await.unwrap();
        drop(w);
        let mut reader = BufReader::new(r);
        let out1 = read_stdout_line(&mut reader, &mut raw, &in_flight, &budget, limits)
            .await
            .unwrap();
        assert!(raw.capacity() > RAW_RETAIN_CAP_BYTES);
        dispatch_large_response_line(&mut raw, out1, &in_flight);
        assert_eq!(raw.capacity(), 0);
        let delivered = rx1.await.unwrap();
        match delivered {
            RespDelivery::Ok { json_bytes, lease } => {
                assert_eq!(budget.used(), json_bytes.len());
                let parsed: Value = serde_json::from_slice(&json_bytes).unwrap();
                assert_eq!(parsed["id"], "client-long-id-rewrite-0001");
                assert_eq!(parsed["result"]["blob"].as_str().unwrap().len(), 120 * 1024);
                drop(json_bytes);
                drop(lease);
            }
            RespDelivery::HardError { message, .. } => panic!("unexpected hard error: {message}"),
        }
        assert_eq!(budget.used(), 0);

        // 2. Invalid UTF-8 > 64 KiB line resets `raw` and releases lease.
        let _rx2 = push_waiter(2, json!(2));
        let mut bad_utf8 = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"".to_vec();
        bad_utf8.extend(std::iter::repeat_n(0xFFu8, 100 * 1024));
        bad_utf8.extend_from_slice(b"\"}\n");
        let (mut w, r) = tokio::io::duplex(256 * 1024);
        w.write_all(&bad_utf8).await.unwrap();
        drop(w);
        let mut reader = BufReader::new(r);
        let out2 = read_stdout_line(&mut reader, &mut raw, &in_flight, &budget, limits)
            .await
            .unwrap();
        dispatch_large_response_line(&mut raw, out2, &in_flight);
        assert_eq!(raw.capacity(), 0);
        assert_eq!(budget.used(), 0);

        // 3a. Oversized line > max_stdout_line_bytes hard-rejects and resets `raw` + lease.
        let line_cap_limits = StdioLimits {
            max_stdout_line_bytes: 80 * 1024,
            ..limits
        };
        let too_big = vec![b'x'; line_cap_limits.max_stdout_line_bytes + 1];
        let (mut w, r) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            let _ = w.write_all(&too_big).await;
        });
        let mut reader = BufReader::new(r);
        let err3 =
            read_stdout_line(&mut reader, &mut raw, &in_flight, &budget, line_cap_limits).await;
        assert!(matches!(
            err3,
            Err(ReadStdoutErr::Hard(HardRejectError::LineTooLarge(_)))
        ));
        assert_eq!(raw.capacity(), 0);
        assert_eq!(budget.used(), 0);

        // 3b. Line exceeding process ByteBudget (< max_stdout_line_bytes) hard-rejects with BudgetExhausted and resets `raw` + lease.
        let over_budget = vec![b'y'; budget.limit() + 1];
        let (mut w, r) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            let _ = w.write_all(&over_budget).await;
        });
        let mut reader = BufReader::new(r);
        let err3b = read_stdout_line(&mut reader, &mut raw, &in_flight, &budget, limits).await;
        assert!(matches!(
            err3b,
            Err(ReadStdoutErr::Hard(HardRejectError::BudgetExhausted))
        ));
        assert_eq!(raw.capacity(), 0);
        assert_eq!(budget.used(), 0);

        // 4. EOF mid-speculative line (> 64 KiB without '\n') resets `raw` + lease cleanly.
        let partial = format!(
            r#"{{"jsonrpc":"2.0","result":"{}"}}"#,
            "B".repeat(90 * 1024)
        );
        let (mut w, r) = tokio::io::duplex(256 * 1024);
        w.write_all(partial.as_bytes()).await.unwrap();
        drop(w);
        let mut reader = BufReader::new(r);
        let out4 = read_stdout_line(&mut reader, &mut raw, &in_flight, &budget, limits)
            .await
            .unwrap();
        assert_eq!(out4.len, 0);
        assert_eq!(raw.capacity(), 0);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn concurrent_byte_budget_contention_is_nonblocking_and_deadlock_free() {
        let budget = ByteBudget::new(4096);
        let mut tasks = JoinSet::new();
        for i in 0..24usize {
            let b = Arc::clone(&budget);
            tasks.spawn(async move {
                for step in 0..50usize {
                    let initial = ((i + step) % 5 + 1) * 512;
                    if let Some(mut lease) = ByteBudget::try_acquire(&b, initial) {
                        assert!(b.used() <= b.limit());
                        tokio::task::yield_now().await;
                        let grown = initial + 1536;
                        if lease.try_reserve(grown) {
                            assert_eq!(lease.held(), grown);
                            assert!(b.used() <= b.limit());
                            // Simulate buffer handoff without double charging.
                            let handed_off = lease;
                            tokio::task::yield_now().await;
                            drop(handed_off);
                        } else {
                            assert_eq!(
                                lease.held(),
                                0,
                                "failed try_reserve must release all held bytes immediately"
                            );
                        }
                    }
                }
            });
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(res) = tasks.join_next().await {
                res.unwrap();
            }
        })
        .await
        .expect("concurrent try_acquire / try_reserve must never deadlock");
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn notif_queue_byte_budget_tracks_enqueued_copies_and_reclaims_on_recv_or_drop() {
        let notif_budget = ByteBudget::new(900);
        let in_flight: Mutex<Vec<InFlightEntry>> = Mutex::new(Vec::new());
        let stdin_tx = Mutex::new(None);
        let alive = AtomicBool::new(true);

        // Register 2 open SSE waiters + 1 closed JSON waiter.
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (rtx1, _rrx1) = oneshot::channel();
        let (tx2, rx2) = mpsc::unbounded_channel();
        let (rtx2, _rrx2) = oneshot::channel();
        let (tx_closed, rx_closed) = mpsc::unbounded_channel();
        drop(rx_closed);
        let (rtx3, _rrx3) = oneshot::channel();

        {
            let mut w = in_flight.lock().unwrap();
            w.push(InFlightEntry {
                wire_id: 1,
                client_id: json!("sse-1"),
                client_progress_token: None,
                notif_tx: tx1,
                resp_tx: rtx1,
            });
            w.push(InFlightEntry {
                wire_id: 2,
                client_id: json!("sse-2"),
                client_progress_token: None,
                notif_tx: tx2,
                resp_tx: rtx2,
            });
            w.push(InFlightEntry {
                wire_id: 3,
                client_id: json!("json-closed"),
                client_progress_token: None,
                notif_tx: tx_closed,
                resp_tx: rtx3,
            });
        }

        let make_notif = |target_len: usize, tag: usize| -> Value {
            let base = format!(
                r#"{{"jsonrpc":"2.0","method":"notifications/message","params":{{"i":{tag},"p":""}}}}"#
            );
            let pad = "N".repeat(target_len - base.len());
            serde_json::from_str(&format!(
                r#"{{"jsonrpc":"2.0","method":"notifications/message","params":{{"i":{tag},"p":"{pad}"}}}}"#
            ))
            .unwrap()
        };

        // Broadcast 450 B across 2 open SSE waiters -> 2 * 450 = 900 B (exact N limit; closed waiter = 0 B).
        dispatch_stdout_message(
            &in_flight,
            &stdin_tx,
            &alive,
            &notif_budget,
            make_notif(450, 1),
        );
        assert_eq!(notif_budget.used(), 900);

        // Next notification exceeds 900 B -> dropped for both waiters, budget stays 900 B.
        dispatch_stdout_message(
            &in_flight,
            &stdin_tx,
            &alive,
            &notif_budget,
            make_notif(100, 2),
        );
        assert_eq!(notif_budget.used(), 900);

        // Popping from rx1 frees 450 B immediately.
        let q1 = rx1.try_recv().unwrap();
        assert_eq!(q1.line.len(), 450);
        drop(q1);
        assert_eq!(notif_budget.used(), 450);
        assert!(rx1.try_recv().is_err());

        // Dropping rx2 frees the remaining 450 B immediately.
        drop(rx2);
        assert_eq!(notif_budget.used(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ephemeral_guard_survives_mid_reap_cancellation_and_zeros_live_sessions() {
        let up = StdioUpstream::with_limits(
            StdioUpstreamSettings {
                command: "/bin/sh".to_owned(),
                // Ignore stdin EOF so reaping blocks across STDIN_GRACE_WAIT (200 ms) and requires SIGTERM.
                args: vec!["-c".to_owned(), "sleep 10".to_owned()],
                env: std::collections::BTreeMap::new(),
                cwd: None,
                max_sessions: 1,
                session_idle_secs: 30,
            },
            ByteBudget::new(1024 * 1024),
            StdioLimits::default(),
        )
        .unwrap();

        let slot = acquire_slot(&up.inner, "g1").await.unwrap();
        let (_sess, mut ephem) = StdioSession::spawn(&up.inner, "g1".to_owned(), 0, slot)
            .await
            .unwrap();
        assert_eq!(up.inner.table.lock().unwrap().live_sessions.len(), 1);
        assert_eq!(up.inner.table.lock().unwrap().reserved_slots, 1);

        // Start terminate_now() and cancel the caller future 20 ms into STDIN_GRACE_WAIT (200 ms).
        let caller = tokio::spawn(async move {
            ephem.terminate_now().await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        caller.abort();
        let _ = caller.await;

        // Immediately after caller abort, slot transitioned into terminating_slots while child is inside STDIN_GRACE_WAIT.
        {
            let tbl = up.inner.table.lock().unwrap();
            assert_eq!(tbl.reserved_slots, 0);
            assert_eq!(tbl.terminating_slots, 1);
            assert_eq!(tbl.live_sessions.len(), 1);
        }

        // A serial/concurrent caller does NOT over-spawn during the reap window, then wakes and claims the slot once reaping finishes.
        let inner_wait = Arc::clone(&up.inner);
        let waiter = tokio::spawn(async move { acquire_slot(&inner_wait, "g2").await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());

        let reclaimed = tokio::time::timeout(Duration::from_secs(3), waiter)
            .await
            .expect("waiter must wake after SIGTERM reap")
            .unwrap();
        assert!(reclaimed.is_some());
        drop(reclaimed);

        // Shutdown awaits bg_terminations and verifies live_sessions and slot counters reach 0.
        up.shutdown().await;
        let tbl = up.inner.table.lock().unwrap();
        assert!(tbl.live_sessions.is_empty());
        assert_eq!(tbl.reserved_slots, 0);
        assert_eq!(tbl.terminating_slots, 0);
    }
}
