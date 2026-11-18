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

const INIT_TIMEOUT: Duration = Duration::from_secs(30);
const STDIN_GRACE_WAIT: Duration = Duration::from_millis(200);
const SIGTERM_WAIT: Duration = Duration::from_secs(2);
const STDIN_CHANNEL_CAPACITY: usize = 64;
const NOTIF_CHANNEL_CAPACITY: usize = 256;
const MAX_STDOUT_LINE_BYTES: usize = 64 * 1024 * 1024;
const SESSIONLESS_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";

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
    id: Value,
    progress_token: Option<Value>,
    notif_tx: mpsc::Sender<String>,
    resp_tx: oneshot::Sender<String>,
}

struct StdioSession {
    grant_id: String,
    stdin_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    in_flight: Arc<Mutex<Vec<InFlightEntry>>>,
    alive: Arc<AtomicBool>,
    active_requests: Arc<AtomicUsize>,
    last_active_ms: Arc<AtomicU64>,
    child: tokio::sync::Mutex<Option<Child>>,
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

    pub async fn shutdown(&self) {
        self.reaper_cancel.cancel();
        let drained: Vec<Arc<StdioSession>> = {
            let mut guard = self.inner.table.lock().unwrap();
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
            let mut guard = self.inner.table.lock().unwrap();
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

        let body_bytes = match Limited::new(incoming, MAX_MCP_BODY_BYTES).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) if err.is::<LengthLimitError>() => {
                return close_empty_reply(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Err(_) => return close_empty_reply(StatusCode::BAD_REQUEST),
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

        let (mut guard, notif_rx, resp_rx) =
            session.register_request(id.clone(), extract_progress_token(payload));
        drop(notif_rx);
        if session.send_json_line(payload).is_err() {
            guard.disarm();
            session.terminate().await;
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
                session.terminate().await;
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
                session.terminate().await;
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
                session.terminate().await;
                drop(reservation);
                return jsonrpc_error_reply(StatusCode::INTERNAL_SERVER_ERROR, id, -32603, &err);
            }
        };

        let inserted = {
            let mut tbl = self.inner.table.lock().unwrap();
            if tbl.shutting_down {
                false
            } else {
                tbl.sessions
                    .insert(session_id.clone(), Arc::clone(&session));
                reservation.commit(&mut tbl);
                true
            }
        };
        if !inserted {
            session.terminate().await;
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
            let tbl = self.inner.table.lock().unwrap();
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
            if session.send_json_line(payload).is_err() {
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
        let (mut guard, notif_rx, resp_rx) =
            session.register_request(id.clone(), extract_progress_token(payload));
        if session.send_json_line(payload).is_err() {
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

        if client_accepts_sse(headers) {
            let stream = StdioSseStreamBody {
                notif_rx,
                resp_rx: Some(resp_rx),
                pending_resp: None,
                notif_done: false,
                guard,
                session,
                finished: false,
            };
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
        match resp_rx.await {
            Ok(line) => {
                guard.mark_completed();
                session.touch();
                single_rpc_reply(headers, Some(session_id), line)
            }
            Err(_) => {
                guard.disarm();
                remove_and_terminate(&self.inner, session_id, &session).await;
                jsonrpc_error_reply(
                    StatusCode::BAD_GATEWAY,
                    id,
                    -32000,
                    "upstream child exited before responding",
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
        let Some(_reservation) = acquire_slot(&self.inner).await else {
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
                return jsonrpc_error_reply(StatusCode::BAD_GATEWAY, err_id, -32000, &err);
            }
        };
        let mut ephemeral = EphemeralGuard(Some(Arc::clone(&session)));

        let init_id = if req_id.as_ref().is_some_and(|v| json_id_eq(v, &json!(0))) {
            json!(-1)
        } else {
            json!(0)
        };
        let synth_init = json!({
            "jsonrpc": "2.0",
            "id": init_id,
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

        let (mut init_guard, init_notif_rx, init_resp_rx) = session.register_request(init_id, None);
        drop(init_notif_rx);
        if session.send_json_line(&synth_init).is_err() {
            init_guard.disarm();
            ephemeral.terminate_now().await;
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
        let (mut guard, mut notif_rx, resp_rx) =
            session.register_request(id.clone(), extract_progress_token(payload));
        if session.send_json_line(payload).is_err() {
            guard.disarm();
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(
                StatusCode::BAD_GATEWAY,
                id,
                -32000,
                "ephemeral child closed stdin",
            );
        }

        let wants_sse = client_prefers_sse_only(headers) || client_accepts_sse(headers);
        let mut events: Vec<String> = Vec::new();
        let mut buffered_bytes: usize = 0;
        let call_timeout = Duration::from_secs(self.inner.settings.session_idle_secs);

        let wait_res = tokio::time::timeout(call_timeout, async {
            if !wants_sse {
                drop(notif_rx);
                return resp_rx.await.ok();
            }
            while let Some(line) = notif_rx.recv().await {
                if buffered_bytes.saturating_add(line.len()) <= MAX_MCP_BODY_BYTES {
                    buffered_bytes += line.len();
                    events.push(line);
                }
            }
            resp_rx.await.ok()
        })
        .await;

        let resp_line = match wait_res {
            Ok(Some(line)) => line,
            Ok(None) => {
                guard.disarm();
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(
                    StatusCode::BAD_GATEWAY,
                    id,
                    -32000,
                    "ephemeral child exited before responding",
                );
            }
            Err(_) => {
                guard.disarm();
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

        if client_prefers_sse_only(headers) || (!events.is_empty() && client_accepts_sse(headers)) {
            let mut body = String::new();
            for note in events {
                body.push_str("data: ");
                body.push_str(&note);
                body.push_str("\n\n");
            }
            body.push_str("data: ");
            body.push_str(&resp_line);
            body.push_str("\n\n");
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header(header::CACHE_CONTROL, "no-store")
                .header(HeaderName::from_static("x-accel-buffering"), "no")
                .body(bytes_body(Bytes::from(body)))
                .expect("valid SSE reply");
        }

        single_rpc_reply(headers, None, resp_line)
    }
}

impl Drop for StdioUpstream {
    fn drop(&mut self) {
        self.reaper_cancel.cancel();
    }
}

struct EphemeralGuard(Option<Arc<StdioSession>>);

impl EphemeralGuard {
    async fn terminate_now(&mut self) {
        if let Some(sess) = self.0.take() {
            sess.terminate().await;
        }
    }
}

impl Drop for EphemeralGuard {
    fn drop(&mut self) {
        if let Some(sess) = self.0.take()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                sess.terminate().await;
            });
        }
    }
}

struct SlotReservation<'a> {
    inner: &'a StdioInner,
    committed: bool,
}

impl<'a> SlotReservation<'a> {
    fn commit(mut self, tbl: &mut SessionTable) {
        tbl.reserved_slots = tbl.reserved_slots.saturating_sub(1);
        self.committed = true;
    }
}

impl Drop for SlotReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let mut tbl = self.inner.table.lock().unwrap();
            tbl.reserved_slots = tbl.reserved_slots.saturating_sub(1);
        }
    }
}

async fn acquire_slot(inner: &StdioInner) -> Option<SlotReservation<'_>> {
    if try_reserve_slot(inner) {
        return Some(SlotReservation {
            inner,
            committed: false,
        });
    }
    evict_idle_sessions(inner).await;
    if try_reserve_slot(inner) {
        Some(SlotReservation {
            inner,
            committed: false,
        })
    } else {
        None
    }
}

fn try_reserve_slot(inner: &StdioInner) -> bool {
    let mut tbl = inner.table.lock().unwrap();
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
        let mut tbl = inner.table.lock().unwrap();
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
        let mut tbl = inner.table.lock().unwrap();
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
            alive: Arc::clone(&alive),
            active_requests,
            last_active_ms: Arc::clone(&last_active_ms),
            child: tokio::sync::Mutex::new(Some(child)),
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
                            dispatch_stdout_message(&in_flight, trimmed, &val);
                        }
                    }
                }
                if raw.capacity() > 64 * 1024 {
                    raw.shrink_to(64 * 1024);
                }
            }
            alive.store(false, Ordering::Release);
            in_flight.lock().unwrap().clear();
            if let (Some(up), Some(sess)) = (reader_inner.upgrade(), reader_session.upgrade()) {
                let matched_key = {
                    let mut tbl = up.table.lock().unwrap();
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

    fn send_json_line(&self, value: &Value) -> Result<(), ()> {
        if !self.alive.load(Ordering::Acquire) {
            return Err(());
        }
        let mut line = serde_json::to_vec(value).map_err(|_| ())?;
        line.push(b'\n');
        self.send_raw_line(line)
    }

    fn send_raw_line(&self, line: Vec<u8>) -> Result<(), ()> {
        let guard = self.stdin_tx.lock().unwrap();
        let Some(tx) = guard.as_ref() else {
            return Err(());
        };
        tx.try_send(line).map_err(|_| ())
    }

    fn register_request(
        self: &Arc<Self>,
        id: Value,
        progress_token: Option<Value>,
    ) -> (
        RequestGuard,
        mpsc::Receiver<String>,
        oneshot::Receiver<String>,
    ) {
        let (notif_tx, notif_rx) = mpsc::channel(NOTIF_CHANNEL_CAPACITY);
        let (resp_tx, resp_rx) = oneshot::channel();
        self.active_requests.fetch_add(1, Ordering::AcqRel);
        {
            let mut waiters = self.in_flight.lock().unwrap();
            waiters.retain(|w| !json_id_eq(&w.id, &id));
            waiters.push(InFlightEntry {
                id: id.clone(),
                progress_token,
                notif_tx,
                resp_tx,
            });
        }
        let guard = RequestGuard {
            session: Arc::clone(self),
            request_id: id,
            state: GuardState::Armed,
        };
        (guard, notif_rx, resp_rx)
    }

    async fn terminate(&self) {
        self.alive.store(false, Ordering::Release);
        {
            let mut tx_guard = self.stdin_tx.lock().unwrap();
            let _ = tx_guard.take();
        }
        self.in_flight.lock().unwrap().clear();

        let mut child_guard = self.child.lock().await;
        let Some(mut child) = child_guard.take() else {
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

        #[cfg(not(unix))]
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
        info.si_signo != 0 || unsafe { info.si_pid() != 0 }
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
    request_id: Value,
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
            let mut waiters = self.session.in_flight.lock().unwrap();
            waiters.retain(|w| !json_id_eq(&w.id, &self.request_id));
            drop(waiters);
            self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if !matches!(self.state, GuardState::Armed) {
            return;
        }
        {
            let mut waiters = self.session.in_flight.lock().unwrap();
            waiters.retain(|w| !json_id_eq(&w.id, &self.request_id));
        }
        self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
        self.session.touch();

        if self.session.alive.load(Ordering::Acquire) {
            let cancel = json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {
                    "requestId": self.request_id,
                    "reason": "client disconnected"
                }
            });
            let _ = self.session.send_json_line(&cancel);
        }
    }
}

struct StdioSseStreamBody {
    notif_rx: mpsc::Receiver<String>,
    resp_rx: Option<oneshot::Receiver<String>>,
    pending_resp: Option<String>,
    notif_done: bool,
    guard: RequestGuard,
    session: Arc<StdioSession>,
    finished: bool,
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
                    Poll::Pending => return Poll::Pending,
                }
            }

            if this.notif_done {
                if let Some(line) = this.pending_resp.take() {
                    this.finished = true;
                    this.guard.mark_completed();
                    this.session.touch();
                    let formatted = format!("data: {line}\n\n");
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(formatted)))));
                }
                if this.resp_rx.is_none() {
                    this.finished = true;
                    this.guard.disarm();
                    return Poll::Ready(None);
                }
            }

            return Poll::Pending;
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn dispatch_stdout_message(in_flight: &Mutex<Vec<InFlightEntry>>, raw_line: &str, val: &Value) {
    let Some(obj) = val.as_object() else {
        return;
    };
    let has_method = obj.get("method").and_then(Value::as_str).is_some();
    let resp_id = obj.get("id").filter(|v| !v.is_null());

    let mut waiters = in_flight.lock().unwrap();
    if !has_method && let Some(id) = resp_id {
        if let Some(pos) = waiters.iter().position(|w| json_id_eq(&w.id, id)) {
            let entry = waiters.remove(pos);
            let _ = entry.resp_tx.send(raw_line.to_owned());
        }
        return;
    }

    if !has_method {
        return;
    }

    if let Some(rel_id) = obj
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("relatedRequestId"))
    {
        if let Some(entry) = waiters.iter().find(|w| json_id_eq(&w.id, rel_id)) {
            let _ = entry.notif_tx.try_send(raw_line.to_owned());
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
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    if let Some(hdr) = extract_single_header(headers, "mcp-protocol-version") {
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
            alive: Arc::new(AtomicBool::new(false)),
            active_requests: Arc::new(AtomicUsize::new(1)),
            last_active_ms: Arc::new(AtomicU64::new(0)),
            child: tokio::sync::Mutex::new(None),
            epoch: now,
        });

        let (notif_tx, notif_rx) = mpsc::channel(8);
        let (resp_tx, resp_rx) = oneshot::channel::<String>();
        drop(resp_tx);

        let mut body = StdioSseStreamBody {
            notif_rx,
            resp_rx: Some(resp_rx),
            pending_resp: None,
            notif_done: false,
            guard: RequestGuard {
                session: Arc::clone(&session),
                request_id: json!(1),
                state: GuardState::Armed,
            },
            session: Arc::clone(&session),
            finished: false,
        };

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
