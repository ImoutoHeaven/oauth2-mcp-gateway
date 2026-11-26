use crate::config::StdioUpstreamSettings;
use crate::crypto::{constant_time_eq_str, random_token_b64};
use crate::types::{
    ByteBudget, ByteLease, HttpReply, JsonEncodeError, LeasedFrameCursor, ReadBodyError,
    VerifiedToken, bytes_body, empty_body, encode_json_leased, hex_nibble, json_encoded_len,
    leased_body, leased_bytes, method_not_allowed, read_bounded_body, request_overloaded_reply,
};
use crate::upstream_http::{
    ContentLengthCheck, MAX_MCP_BODY_BYTES, check_content_length_limit, close_empty_reply,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, Method, Request, Response, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
const INIT_TIMEOUT: Duration = Duration::from_secs(30);
const STDIN_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const STDIN_GRACE_WAIT: Duration = Duration::from_millis(200);
#[cfg(unix)]
const SIGTERM_WAIT: Duration = Duration::from_secs(2);
const STDIN_CHANNEL_CAPACITY: usize = 64;
const MAX_IN_FLIGHT_PER_SESSION: usize = 64;
pub const MAX_STDOUT_LINE_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_CONTROL_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_NOTIF_QUEUE_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_PRESSURE_IDLE: Duration = Duration::from_secs(600);
const MAX_GRANT_EPOCHS: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct StdioLimits {
    pub max_stdout_line_bytes: usize,
    pub max_control_line_bytes: usize,
    pub max_notif_queue_bytes: usize,
    pub pressure_idle: Duration,
    pub stdin_write_timeout: Duration,
    pub stdin_channel_capacity: usize,
    pub max_in_flight_per_session: usize,
}

impl Default for StdioLimits {
    fn default() -> Self {
        Self {
            max_stdout_line_bytes: MAX_STDOUT_LINE_BYTES,
            max_control_line_bytes: MAX_CONTROL_LINE_BYTES,
            max_notif_queue_bytes: MAX_NOTIF_QUEUE_BYTES,
            pressure_idle: DEFAULT_PRESSURE_IDLE,
            stdin_write_timeout: STDIN_WRITE_TIMEOUT,
            stdin_channel_capacity: STDIN_CHANNEL_CAPACITY,
            max_in_flight_per_session: MAX_IN_FLIGHT_PER_SESSION,
        }
    }
}
const SESSIONLESS_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPS_META_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const CLIENT_INFO_META_KEY: &str = "io.modelcontextprotocol/clientInfo";
const SERVER_DISCOVER_METHOD: &str = "server/discover";
const MIN_SESSIONLESS_PROTOCOL_VERSION: &str = "2026-07-28";
const EVENTS_STREAM_METHOD: &str = "events/stream";
const SUBSCRIPTION_ID_META_KEY: &str = "io.modelcontextprotocol/subscriptionId";

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
    #[cfg(all(windows, test))]
    spawn_hook: Mutex<Option<WindowsSpawnHook>>,
    #[cfg(all(windows, test))]
    failed_spawn_reap_gate: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}

struct SessionTable {
    sessions: HashMap<String, Arc<StdioSession>>,
    live_sessions: Vec<Arc<StdioSession>>,
    grant_epochs: HashMap<String, (u64, u64)>,
    epoch_seq: u64,
    reserved_slots: usize,
    pending_spawns: usize,
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
    _process_lease: Option<ByteLease>,
}

impl QueuedNotif {
    fn into_sse(self, budget: &Arc<ByteBudget>) -> Result<Bytes, SendLineErr> {
        let mut lease = match self._process_lease {
            Some(lease) => lease,
            None => budget
                .try_acquire(self.line.capacity())
                .ok_or(SendLineErr::Overloaded)?,
        };
        let mut bytes = self.line.into_bytes();
        let len = bytes.len();
        let needed = len.checked_add(8).ok_or(SendLineErr::Overloaded)?;
        let capacity = bytes.capacity().max(needed);
        if !lease.reserve_vec(&mut bytes, needed, capacity) {
            return Err(SendLineErr::Overloaded);
        }
        bytes.resize(needed, 0);
        bytes.copy_within(..len, 6);
        bytes[..6].copy_from_slice(b"data: ");
        bytes[6 + len..].copy_from_slice(b"\n\n");
        // The queue lease ends here; the same allocation's process lease follows the frame.
        Ok(leased_bytes(bytes, Some(lease)))
    }
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
        lease: Option<ByteLease>,
    },
}

/// Payload strings and object keys, excluding Value/container metadata.
fn json_text_capacity(value: &Value) -> usize {
    match value {
        Value::String(text) => text.capacity(),
        Value::Array(values) => values.iter().fold(0usize, |sum, value| {
            sum.saturating_add(json_text_capacity(value))
        }),
        Value::Object(values) => values.iter().fold(0usize, |sum, (key, value)| {
            sum.saturating_add(key.capacity())
                .saturating_add(json_text_capacity(value))
        }),
        _ => 0,
    }
}

struct LeasedJson {
    value: Value,
    _lease: ByteLease,
}

impl LeasedJson {
    fn parse(bytes: &[u8], budget: &Arc<ByteBudget>) -> Result<Self, JsonEncodeError> {
        // Value text fits in R; escaped-string scratch has at most a 2R growth allowance.
        // The caller separately owns and charges the raw body throughout parsing.
        let mut lease = budget
            .try_acquire(bytes.len().saturating_mul(3))
            .ok_or(JsonEncodeError::Overloaded)?;
        let value = serde_json::from_slice(bytes).map_err(|_| JsonEncodeError::Invalid)?;
        let text_bytes = json_text_capacity(&value);
        debug_assert!(text_bytes <= lease.held());
        lease.shrink_to(text_bytes);
        Ok(Self {
            value,
            _lease: lease,
        })
    }

    fn copy(value: &Value, budget: &Arc<ByteBudget>, extra: usize) -> Result<Self, SendLineErr> {
        let lease = budget
            .try_acquire(json_text_capacity(value).saturating_add(extra))
            .ok_or(SendLineErr::Overloaded)?;
        Ok(Self {
            value: value.clone(),
            _lease: lease,
        })
    }

    fn finish_rewrite(&mut self) {
        let text_bytes = json_text_capacity(&self.value);
        debug_assert!(text_bytes <= self._lease.held());
        self._lease.shrink_to(text_bytes);
    }
}

#[derive(Clone, Copy, Debug)]
enum SendLineErr {
    Closed,
    Full,
    Overloaded,
}

#[derive(serde::Serialize)]
struct RpcErrorPayload<'a> {
    jsonrpc: &'static str,
    id: &'a Value,
    error: RpcErrorData<'a>,
}

#[derive(serde::Serialize)]
struct RpcErrorData<'a> {
    code: i64,
    message: &'a str,
}

fn rpc_error_payload<'a>(id: &'a Value, code: i64, message: &'a str) -> RpcErrorPayload<'a> {
    RpcErrorPayload {
        jsonrpc: "2.0",
        id,
        error: RpcErrorData { code, message },
    }
}

// All HardRejectError messages, including a usize limit, fit with JSON keys in 256 bytes.
const ERROR_REPLY_OVERHEAD: usize = 256;
struct ErrorBuffer {
    bytes: Vec<u8>,
    lease: ByteLease,
}

impl ErrorBuffer {
    fn new(id: &Value, budget: &Arc<ByteBudget>) -> Result<Self, SendLineErr> {
        let len = json_encoded_len(id)
            .map_err(|_| SendLineErr::Closed)?
            .checked_add(ERROR_REPLY_OVERHEAD)
            .ok_or(SendLineErr::Overloaded)?;
        let mut owned = Self {
            bytes: Vec::new(),
            lease: budget.try_acquire(len).ok_or(SendLineErr::Overloaded)?,
        };
        if !owned.lease.reserve_vec(&mut owned.bytes, len, len) {
            return Err(SendLineErr::Overloaded);
        }
        Ok(owned)
    }

    fn finish(mut self, id: &Value, message: &str) -> (Vec<u8>, ByteLease) {
        self.bytes.clear();
        let payload = rpc_error_payload(id, -32000, message);
        // Fixed-capacity writing cannot grow on a future error-message change.
        struct Writer<'a>(&'a mut Vec<u8>);
        impl io::Write for Writer<'_> {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                if data.len() > self.0.capacity().saturating_sub(self.0.len()) {
                    return Err(io::Error::other("error reply exceeds reserved buffer"));
                }
                self.0.extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        if serde_json::to_writer(Writer(&mut self.bytes), &payload).is_err() {
            self.bytes.clear();
            serde_json::to_writer(
                Writer(&mut self.bytes),
                &rpc_error_payload(id, -32000, "process active byte budget exceeded"),
            )
            .expect("fixed overload reply fits reserved buffer");
        }
        (self.bytes, self.lease)
    }
}

struct NotifQueueInner {
    queue: VecDeque<QueuedNotif>,
    closed: bool,
    failed: Option<String>,
    waker: Option<Waker>,
}

struct NotifQueue {
    inner: Mutex<NotifQueueInner>,
}

impl NotifQueue {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(NotifQueueInner {
                queue: VecDeque::new(),
                closed: false,
                failed: None,
                waker: None,
            }),
        })
    }

    fn is_closed(&self) -> bool {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.closed || guard.failed.is_some()
    }

    fn close_normal(&self) {
        let waker = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.closed = true;
            guard.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn close_and_drain(&self) {
        let (dropped, waker) = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.closed = true;
            (std::mem::take(&mut guard.queue), guard.waker.take())
        };
        drop(dropped);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    // Discard unsent gateway-owned frames immediately so cleanup does not wait for a body poll.
    fn fail(&self, reason: &str) {
        let (dropped, waker) = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if guard.failed.is_none() {
                guard.failed = Some(reason.to_owned());
            }
            guard.closed = true;
            (std::mem::take(&mut guard.queue), guard.waker.take())
        };
        drop(dropped);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn take_failure(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .failed
            .clone()
    }

    fn enqueue(
        &self,
        notif_budget: &Arc<ByteBudget>,
        line: String,
        process_lease: Option<ByteLease>,
    ) -> Result<(), SendLineErr> {
        if self.is_closed() {
            drop(line);
            drop(process_lease);
            return Err(SendLineErr::Closed);
        }
        let cost = line.capacity().max(1);
        let Some(lease) = ByteBudget::try_acquire(notif_budget, cost) else {
            drop(line);
            drop(process_lease);
            return Err(SendLineErr::Overloaded);
        };
        let (rejected, waker) = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if guard.closed || guard.failed.is_some() {
                (
                    Some(QueuedNotif {
                        line,
                        _lease: lease,
                        _process_lease: process_lease,
                    }),
                    None,
                )
            } else {
                guard.queue.push_back(QueuedNotif {
                    line,
                    _lease: lease,
                    _process_lease: process_lease,
                });
                (None, guard.waker.take())
            }
        };
        if let Some(item) = rejected {
            drop(item);
            return Err(SendLineErr::Closed);
        }
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }

    fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<Result<Option<QueuedNotif>, String>> {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(reason) = guard.failed.clone() {
            return Poll::Ready(Err(reason));
        }
        if let Some(item) = guard.queue.pop_front() {
            return Poll::Ready(Ok(Some(item)));
        }
        if guard.closed {
            return Poll::Ready(Ok(None));
        }
        guard.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    #[cfg(test)]
    fn try_pop(&self) -> Option<QueuedNotif> {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if guard.failed.is_some() {
            return None;
        }
        guard.queue.pop_front()
    }
}

struct NotifQueueTx {
    queue: Arc<NotifQueue>,
}

impl NotifQueueTx {
    fn is_closed(&self) -> bool {
        self.queue.is_closed()
    }

    fn queue(&self) -> Arc<NotifQueue> {
        Arc::clone(&self.queue)
    }
}

impl Drop for NotifQueueTx {
    fn drop(&mut self) {
        self.queue.close_normal();
    }
}

struct NotifQueueRx {
    queue: Arc<NotifQueue>,
}

impl NotifQueueRx {
    fn take_failure(&self) -> Option<String> {
        self.queue.take_failure()
    }

    fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<Result<Option<QueuedNotif>, String>> {
        self.queue.poll_pop(cx)
    }

    #[cfg(test)]
    fn try_recv(&self) -> Result<QueuedNotif, ()> {
        self.queue.try_pop().ok_or(())
    }
}

impl Drop for NotifQueueRx {
    fn drop(&mut self) {
        self.queue.close_and_drain();
    }
}

fn notif_channel() -> (NotifQueueTx, NotifQueueRx) {
    let queue = NotifQueue::new();
    (
        NotifQueueTx {
            queue: Arc::clone(&queue),
        },
        NotifQueueRx { queue },
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StopOutcome {
    Pending,
    SettledByResponse,
    SettledByReceipt,
    RetireChild,
}

struct StopSettlement {
    outcome: Mutex<StopOutcome>,
    notify: tokio::sync::Notify,
}

impl StopSettlement {
    fn new() -> Self {
        Self {
            outcome: Mutex::new(StopOutcome::Pending),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn is_settled(&self) -> bool {
        *self.outcome.lock().unwrap_or_else(|p| p.into_inner()) != StopOutcome::Pending
    }

    async fn wait_settled(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_settled() {
                return;
            }
            notified.await;
        }
    }

    fn observe_final_response(&self) -> bool {
        let mut outcome = self.outcome.lock().unwrap_or_else(|p| p.into_inner());
        if *outcome == StopOutcome::Pending {
            *outcome = StopOutcome::SettledByResponse;
            drop(outcome);
            self.notify.notify_waiters();
            true
        } else {
            false
        }
    }

    fn try_decide_receipt(&self) -> StopOutcome {
        let mut outcome = self.outcome.lock().unwrap_or_else(|p| p.into_inner());
        if *outcome == StopOutcome::Pending {
            *outcome = StopOutcome::SettledByReceipt;
            let decided = *outcome;
            drop(outcome);
            self.notify.notify_waiters();
            decided
        } else {
            *outcome
        }
    }

    fn try_decide_retire(&self) -> StopOutcome {
        let mut outcome = self.outcome.lock().unwrap_or_else(|p| p.into_inner());
        if *outcome == StopOutcome::Pending {
            *outcome = StopOutcome::RetireChild;
            let decided = *outcome;
            drop(outcome);
            self.notify.notify_waiters();
            decided
        } else {
            *outcome
        }
    }
}

struct LiveInFlight {
    client_id: Value,
    client_progress_token: Option<Value>,
    is_events_stream: bool,
    notif_tx: NotifQueueTx,
    resp_tx: oneshot::Sender<RespDelivery>,
    error_buffer: ErrorBuffer,
    stop: Weak<RequestStopOwner>,
    _lease: ByteLease,
}

struct StoppingInFlight {
    is_events_stream: bool,
    settled: Arc<StopSettlement>,
}

enum InFlightState {
    Live(Box<LiveInFlight>),
    Stopping(StoppingInFlight),
}

struct InFlightEntry {
    wire_id: u64,
    state: InFlightState,
}

impl InFlightEntry {
    #[allow(clippy::too_many_arguments)]
    fn new(
        wire_id: u64,
        client_id: &Value,
        client_progress_token: Option<&Value>,
        is_events_stream: bool,
        notif_tx: NotifQueueTx,
        resp_tx: oneshot::Sender<RespDelivery>,
        stop: Weak<RequestStopOwner>,
        budget: &Arc<ByteBudget>,
    ) -> Result<Self, SendLineErr> {
        let bytes = json_text_capacity(client_id)
            .saturating_add(client_progress_token.map_or(0, json_text_capacity));
        let lease = budget.try_acquire(bytes).ok_or(SendLineErr::Overloaded)?;
        let error_buffer = ErrorBuffer::new(client_id, budget)?;
        let mut live = LiveInFlight {
            client_id: client_id.clone(),
            client_progress_token: client_progress_token.cloned(),
            is_events_stream,
            notif_tx,
            resp_tx,
            error_buffer,
            stop,
            _lease: lease,
        };
        live._lease.shrink_to(
            json_text_capacity(&live.client_id).saturating_add(
                live.client_progress_token
                    .as_ref()
                    .map_or(0, json_text_capacity),
            ),
        );
        Ok(Self {
            wire_id,
            state: InFlightState::Live(Box::new(live)),
        })
    }

    fn as_live(&self) -> Option<&LiveInFlight> {
        match &self.state {
            InFlightState::Live(live) => Some(live),
            InFlightState::Stopping(_) => None,
        }
    }

    fn is_events_stream(&self) -> bool {
        match &self.state {
            InFlightState::Live(live) => live.is_events_stream,
            InFlightState::Stopping(stopping) => stopping.is_events_stream,
        }
    }
}

#[cfg(all(windows, test))]
#[derive(Clone, Copy, PartialEq)]
enum WindowsSpawnStage {
    BeforeAssign,
    BeforeResume,
}

#[cfg(all(windows, test))]
type WindowsSpawnHook =
    Box<dyn Fn(WindowsSpawnStage, &WindowsJobObject, &Child) -> Result<(), String> + Send + Sync>;

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
fn with_owned_child_threads(
    pid: u32,
    mut visit: impl FnMut(windows_sys::Win32::Foundation::HANDLE) -> io::Result<()>,
) -> io::Result<()> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessIdOfThread, OpenThread, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
    };

    // The suspended primary thread has not run user code. Snapshot handles stay owned here.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut found = false;
    let mut more = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            let raw = unsafe {
                OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                    0,
                    entry.th32ThreadID,
                )
            };
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
            // A thread ID from a snapshot may have been reused; check its live owner.
            if unsafe { GetProcessIdOfThread(thread.as_raw_handle()) } != pid {
                return Err(io::Error::other("upstream child thread ownership changed"));
            }
            visit(thread.as_raw_handle())?;
            found = true;
        }
        more = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) } != 0;
    }
    if !found {
        return Err(io::Error::other(
            "cannot find the suspended upstream child thread",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn resume_windows_child(child: &Child) -> Result<(), String> {
    let pid = child.id().ok_or("child process ID unavailable")?;
    with_owned_child_threads(pid, |thread| {
        if unsafe { windows_sys::Win32::System::Threading::ResumeThread(thread) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
    .map_err(|e| format!("failed to resume upstream process: {e}"))
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

#[derive(Debug)]
struct StdinLine {
    bytes: Bytes,
    flushed: Option<oneshot::Sender<()>>,
}

struct StdioSession {
    uid: u64,
    grant_id: String,
    weak_inner: Weak<StdioInner>,
    budget: Arc<ByteBudget>,
    limits: StdioLimits,
    writer_cancel: CancellationToken,
    stdin_tx: Arc<Mutex<Option<mpsc::Sender<StdinLine>>>>,
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
                pending_spawns: 0,
                terminating_slots: 0,
                shutting_down: false,
            }),
            slot_notify: tokio::sync::Notify::new(),
            bg_terminations: Mutex::new(Vec::new()),
            #[cfg(all(windows, test))]
            spawn_hook: Mutex::new(None),
            #[cfg(all(windows, test))]
            failed_spawn_reap_gate: Mutex::new(None),
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
        self.inner
            .table
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .shutting_down = true;
        self.inner.slot_notify.notify_waiters();
        loop {
            // Register before inspecting counters so a concurrent spawn/reap cannot lose the wakeup.
            let released = self.inner.slot_notify.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            let (live, removed_count, pending): (Vec<Arc<StdioSession>>, usize, usize) = {
                let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
                let count = tbl.sessions.len();
                tbl.sessions.clear();
                tbl.terminating_slots += count;
                (
                    tbl.live_sessions.clone(),
                    count,
                    tbl.pending_spawns + tbl.terminating_slots,
                )
            };
            let bg_handles = drain_bg_terminations(&self.inner, None);
            if live.is_empty() && bg_handles.is_empty() && removed_count == 0 {
                if pending != 0 {
                    released.await;
                    continue;
                }
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
                &self.inner.budget,
                StatusCode::BAD_REQUEST,
                &Value::Null,
                -32600,
                "duplicate Mcp-Session-Id header",
            );
        }
        let session_id_hdr = if parts.headers.contains_key("mcp-session-id") {
            match extract_valid_session_id(&parts.headers) {
                Some(sid) => Some(sid.to_owned()),
                None => {
                    return jsonrpc_error_reply(
                        &self.inner.budget,
                        StatusCode::BAD_REQUEST,
                        &Value::Null,
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
            read_bounded_body(incoming, &self.inner.budget, MAX_MCP_BODY_BYTES),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(ReadBodyError::TooLarge)) => {
                return close_empty_reply(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Ok(Err(ReadBodyError::Overloaded)) => return request_overloaded_reply(),
            Ok(Err(ReadBodyError::Invalid)) => return close_empty_reply(StatusCode::BAD_REQUEST),
            Err(_) => return close_empty_reply(StatusCode::REQUEST_TIMEOUT),
        };

        let parsed = LeasedJson::parse(&body_bytes, &self.inner.budget);
        drop(body_bytes);
        let payload_owner = match parsed {
            Ok(payload) => payload,
            Err(JsonEncodeError::Overloaded) => return request_overloaded_reply(),
            Err(JsonEncodeError::Invalid) => {
                return jsonrpc_error_reply(
                    &self.inner.budget,
                    StatusCode::BAD_REQUEST,
                    &Value::Null,
                    -32700,
                    "invalid JSON payload",
                );
            }
        };
        let payload = &payload_owner.value;
        let Some(obj) = payload.as_object() else {
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::BAD_REQUEST,
                &Value::Null,
                -32600,
                "JSON-RPC message must be an object",
            );
        };

        let fallback_err_id = obj
            .get("id")
            .filter(|v| v.is_string() || v.is_number())
            .unwrap_or(&Value::Null);

        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::BAD_REQUEST,
                fallback_err_id,
                -32600,
                "invalid JSON-RPC version",
            );
        }

        let (method, req_id) = if let Some(raw_method) = obj.get("method") {
            let Some(m) = raw_method.as_str().filter(|m| !m.is_empty()) else {
                return jsonrpc_error_reply(
                    &self.inner.budget,
                    StatusCode::BAD_REQUEST,
                    fallback_err_id,
                    -32600,
                    "invalid JSON-RPC method",
                );
            };
            let req_id = match obj.get("id") {
                None => None,
                Some(id) if id.is_string() || id.is_number() => Some(id),
                Some(_) => {
                    return jsonrpc_error_reply(
                        &self.inner.budget,
                        StatusCode::BAD_REQUEST,
                        &Value::Null,
                        -32600,
                        "invalid JSON-RPC id",
                    );
                }
            };
            (Some(m), req_id)
        } else {
            if !obj.contains_key("result") && !obj.contains_key("error") {
                return jsonrpc_error_reply(
                    &self.inner.budget,
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
                    &self.inner.budget,
                    StatusCode::BAD_REQUEST,
                    &Value::Null,
                    -32600,
                    "invalid JSON-RPC id",
                );
            }
            (None, None)
        };

        if let Some(sid) = session_id_hdr {
            return self
                .handle_in_session(&sid, &parts.headers, token, payload, method, req_id)
                .await;
        }

        if method == Some("initialize") {
            return self
                .handle_initialize(&parts.headers, token, payload, req_id)
                .await;
        }

        if method == Some(SERVER_DISCOVER_METHOD) {
            return self
                .handle_server_discover(&parts.headers, token, payload, obj, req_id)
                .await;
        }

        if detect_sessionless_version(&parts.headers, obj).is_some() {
            return self
                .handle_sessionless(&parts.headers, token, payload, method, req_id)
                .await;
        }

        jsonrpc_error_reply(
            &self.inner.budget,
            StatusCode::BAD_REQUEST,
            req_id.unwrap_or(&Value::Null),
            -32600,
            "missing Mcp-Session-Id header",
        )
    }

    async fn handle_initialize(
        &self,
        headers: &HeaderMap,
        token: &VerifiedToken,
        payload: &Value,
        req_id: Option<&Value>,
    ) -> HttpReply {
        let Some(id) = req_id else {
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::BAD_REQUEST,
                &Value::Null,
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
                &self.inner.budget,
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
                return jsonrpc_error_reply(
                    &self.inner.budget,
                    StatusCode::BAD_GATEWAY,
                    id,
                    -32000,
                    &err,
                );
            }
        };

        let (wire_id, mut guard, notif_rx, resp_rx) =
            match session.register_request(id, extract_progress_token(payload)) {
                Ok(registered) => registered,
                Err(err) => {
                    let (status, msg) = session.map_register_failure(
                        err,
                        "upstream child exited before responding to initialize",
                    );
                    ephemeral.terminate_now().await;
                    return jsonrpc_error_reply(&self.inner.budget, status, id, -32000, &msg);
                }
            };
        drop(notif_rx);
        if let Err(err) = session.send_request_line(payload, wire_id) {
            guard.disarm();
            let (status, msg) =
                session.map_send_failure(err, "upstream child closed stdin during initialize");
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(&self.inner.budget, status, id, -32000, &msg);
        }

        let (init_bytes, init_lease) = match tokio::time::timeout(INIT_TIMEOUT, resp_rx).await {
            Ok(Ok(RespDelivery::Ok { json_bytes, lease })) => {
                guard.mark_completed();
                (json_bytes, lease)
            }
            Ok(Ok(RespDelivery::HardError {
                status,
                message: _message,
                json_bytes,
                lease,
            })) => {
                guard.disarm();
                let reply = jsonrpc_error_bytes_reply(status, json_bytes, lease);
                ephemeral.terminate_now().await;
                return reply;
            }
            Ok(Err(_)) => {
                guard.disarm();
                let (status, msg) = session.map_dead_session_error(
                    "upstream child exited before responding to initialize",
                );
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(&self.inner.budget, status, id, -32000, &msg);
            }
            Err(_) => {
                guard.disarm();
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(
                    &self.inner.budget,
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
                let reply = single_rpc_reply(headers, None, init_bytes, init_lease);
                ephemeral.terminate_now().await;
                return reply;
            }
            InitOutcome::Malformed => {
                drop(init_bytes);
                drop(init_lease);
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(
                    &self.inner.budget,
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
                return jsonrpc_error_reply(
                    &self.inner.budget,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    id,
                    -32603,
                    &err,
                );
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
                &self.inner.budget,
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
        req_id: Option<&Value>,
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

        let err_id = req_id.unwrap_or(&Value::Null);
        let (session, claim) = match lookup {
            InSessionLookup::NotFound => {
                return jsonrpc_error_reply(
                    &self.inner.budget,
                    StatusCode::NOT_FOUND,
                    err_id,
                    -32001,
                    "session not found",
                );
            }
            InSessionLookup::AlreadyInitialized => {
                return jsonrpc_error_reply(
                    &self.inner.budget,
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
            let send_res = if method == Some("notifications/cancelled") {
                session
                    .rewrite_cancel_notification(payload)
                    .and_then(|rewritten| {
                        rewritten.map_or(Ok(()), |value| session.send_json_line(&value.value))
                    })
            } else {
                session.send_json_line(payload)
            };
            if send_res.is_ok() {
                session.touch_client();
            }
            drop(claim);
            if let Err(err) = send_res {
                let (status, msg) = session.map_send_failure(err, "upstream child closed stdin");
                if matches!(err, SendLineErr::Closed) || !session.alive.load(Ordering::Acquire) {
                    remove_and_terminate(&self.inner, session_id, &session).await;
                }
                return jsonrpc_error_reply(&self.inner.budget, status, &Value::Null, -32000, &msg);
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
        let is_events_stream = method == Some(EVENTS_STREAM_METHOD);
        if is_events_stream && !client_accepts_sse(headers) {
            drop(claim);
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::NOT_ACCEPTABLE,
                id,
                -32600,
                "events/stream requires Accept: text/event-stream",
            );
        }
        let (wire_id, mut guard, notif_rx, resp_rx) = match session.register_request_with_claim(
            claim,
            id,
            extract_progress_token(payload),
            is_events_stream,
            Some(session_id.to_owned()),
        ) {
            Ok(registered) => registered,
            Err(err) => {
                let (status, msg) =
                    session.map_register_failure(err, "upstream child closed stdin");
                if !session.alive.load(Ordering::Acquire) {
                    remove_and_terminate(&self.inner, session_id, &session).await;
                }
                return jsonrpc_error_reply(&self.inner.budget, status, id, -32000, &msg);
            }
        };
        if let Err(err) = session.send_request_line(payload, wire_id) {
            guard.disarm();
            let (status, msg) = session.map_send_failure(err, "upstream child closed stdin");
            if matches!(err, SendLineErr::Closed) || !session.alive.load(Ordering::Acquire) {
                remove_and_terminate(&self.inner, session_id, &session).await;
            }
            return jsonrpc_error_reply(&self.inner.budget, status, id, -32000, &msg);
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
                status,
                message: _message,
                json_bytes,
                lease,
            })) => {
                guard.disarm();
                let reply = jsonrpc_error_bytes_reply(status, json_bytes, lease);
                if !session.alive.load(Ordering::Acquire) {
                    remove_and_terminate(&self.inner, session_id, &session).await;
                }
                reply
            }
            Ok(Err(_)) => {
                guard.disarm();
                let (status, msg) =
                    session.map_dead_session_error("upstream child exited before responding");
                if !session.alive.load(Ordering::Acquire) {
                    remove_and_terminate(&self.inner, session_id, &session).await;
                }
                jsonrpc_error_reply(&self.inner.budget, status, id, -32000, &msg)
            }
            Err(_) => {
                guard.cancel("request timed out");
                jsonrpc_error_reply(
                    &self.inner.budget,
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
        payload: &Value,
        method: Option<&str>,
        req_id: Option<&Value>,
    ) -> HttpReply {
        let err_id = req_id.unwrap_or(&Value::Null);
        let is_events_stream = method == Some(EVENTS_STREAM_METHOD) && req_id.is_some();
        if is_events_stream && !client_accepts_sse(headers) {
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::NOT_ACCEPTABLE,
                err_id,
                -32600,
                "events/stream requires Accept: text/event-stream",
            );
        }
        let start_epoch = {
            let tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            tbl.grant_epoch(&token.grant_id)
        };

        let Some(reservation) = acquire_slot(&self.inner, &token.grant_id).await else {
            return jsonrpc_error_reply(
                &self.inner.budget,
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
                return jsonrpc_error_reply(
                    &self.inner.budget,
                    StatusCode::BAD_GATEWAY,
                    err_id,
                    -32000,
                    &err,
                );
            }
        };

        let is_request = method.is_some() && req_id.is_some();
        if !is_request {
            return session
                .send_sessionless_notification(
                    payload,
                    ephemeral,
                    self.inner.limits.stdin_write_timeout,
                )
                .await;
        }

        let id = req_id.unwrap();
        let (wire_id, mut guard, notif_rx, resp_rx) = match session.register_request_opts(
            id,
            extract_progress_token(payload),
            is_events_stream,
            None,
        ) {
            Ok(registered) => registered,
            Err(err) => {
                let (status, msg) =
                    session.map_register_failure(err, "ephemeral child closed stdin");
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(&self.inner.budget, status, id, -32000, &msg);
            }
        };
        if let Err(err) = session.send_request_line(payload, wire_id) {
            guard.disarm();
            let (status, msg) = session.map_send_failure(err, "ephemeral child closed stdin");
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(&self.inner.budget, status, id, -32000, &msg);
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
                status,
                message: _message,
                json_bytes,
                lease,
            })) => {
                guard.disarm();
                let reply = jsonrpc_error_bytes_reply(status, json_bytes, lease);
                ephemeral.terminate_now().await;
                return reply;
            }
            Ok(Err(_)) => {
                guard.disarm();
                let (status, msg) =
                    session.map_dead_session_error("ephemeral child exited before responding");
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(&self.inner.budget, status, id, -32000, &msg);
            }
            Err(_) => {
                guard.cancel("request timed out");
                ephemeral.terminate_now().await;
                return jsonrpc_error_reply(
                    &self.inner.budget,
                    StatusCode::GATEWAY_TIMEOUT,
                    id,
                    -32000,
                    "ephemeral request timed out",
                );
            }
        };

        guard.mark_completed();
        let reply = single_rpc_reply(headers, None, resp_bytes, resp_lease);
        ephemeral.terminate_now().await;
        reply
    }

    async fn handle_server_discover(
        &self,
        headers: &HeaderMap,
        token: &VerifiedToken,
        payload: &Value,
        obj: &serde_json::Map<String, Value>,
        req_id: Option<&Value>,
    ) -> HttpReply {
        let Some(id) = req_id else {
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::BAD_REQUEST,
                &Value::Null,
                -32600,
                "server/discover request requires an id",
            );
        };
        if has_multiple_headers(headers, "mcp-protocol-version") {
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::BAD_REQUEST,
                id,
                -32600,
                "duplicate MCP-Protocol-Version header",
            );
        }

        let Some(meta) = obj
            .get("params")
            .and_then(Value::as_object)
            .and_then(|p| p.get("_meta"))
            .and_then(Value::as_object)
        else {
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::BAD_REQUEST,
                id,
                -32602,
                "server/discover requires params._meta object",
            );
        };

        let Some(meta_ver) = meta
            .get(SESSIONLESS_META_KEY)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| supports_sessionless_version(v))
        else {
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::BAD_REQUEST,
                id,
                -32602,
                "server/discover requires valid io.modelcontextprotocol/protocolVersion in params._meta",
            );
        };

        if meta
            .get(CLIENT_CAPS_META_KEY)
            .is_some_and(|v| !v.is_object())
            || meta
                .get("clientCapabilities")
                .is_some_and(|v| !v.is_object())
            || meta
                .get(CLIENT_INFO_META_KEY)
                .is_some_and(|v| !v.is_object())
            || meta.get("clientInfo").is_some_and(|v| !v.is_object())
        {
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::BAD_REQUEST,
                id,
                -32602,
                "invalid client metadata in params._meta",
            );
        }

        if let Some(hdr_ver) = extract_single_header(headers, "mcp-protocol-version")
            && hdr_ver != meta_ver
        {
            return jsonrpc_error_reply(
                &self.inner.budget,
                StatusCode::BAD_REQUEST,
                id,
                -32602,
                "MCP-Protocol-Version header does not match params._meta protocolVersion",
            );
        }

        self.handle_sessionless(
            headers,
            token,
            payload,
            Some(SERVER_DISCOVER_METHOD),
            Some(id),
        )
        .await
    }
}

impl Drop for StdioUpstream {
    fn drop(&mut self) {
        self.reaper_cancel.cancel();
    }
}

#[derive(Debug, PartialEq, Eq)]
enum InitOutcome {
    Ok,
    RpcError,
    Malformed,
}

fn classify_init_response(raw_line: &[u8]) -> InitOutcome {
    use serde::de::{IgnoredAny, MapAccess, Visitor};

    #[derive(serde::Deserialize)]
    #[serde(field_identifier, rename_all = "lowercase")]
    enum Field {
        Result,
        Error,
        #[serde(other)]
        Other,
    }

    struct InitVisitor;
    impl<'de> Visitor<'de> for InitVisitor {
        type Value = InitOutcome;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an initialize response object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut has_result = false;
            let mut error_is_object = None;
            while let Some(key) = map.next_key::<&'de serde_json::value::RawValue>()? {
                // Six ASCII letters need at most 38 bytes as a quoted Unicode-escaped key.
                let field = if key.get().len() <= 38 {
                    serde_json::from_str::<Field>(key.get()).map_err(serde::de::Error::custom)?
                } else {
                    Field::Other
                };
                match field {
                    Field::Result => {
                        map.next_value::<IgnoredAny>()?;
                        has_result = true;
                    }
                    Field::Error => {
                        let value: &'de serde_json::value::RawValue = map.next_value()?;
                        error_is_object = Some(value.get().starts_with('{'));
                    }
                    Field::Other => {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
            }
            Ok(match (has_result, error_is_object) {
                (true, None) => InitOutcome::Ok,
                (false, Some(true)) => InitOutcome::RpcError,
                _ => InitOutcome::Malformed,
            })
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(raw_line);
    serde::Deserializer::deserialize_map(&mut deserializer, InitVisitor)
        .and_then(|outcome| deserializer.end().map(|()| outcome))
        .unwrap_or(InitOutcome::Malformed)
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

#[cfg(windows)]
async fn reap_failed_windows_spawn(
    inner: &Arc<StdioInner>,
    grant_id: &str,
    mut child: Child,
    job: WindowsJobObject,
    reservation: SlotReservation,
) {
    let term_guard = reservation.into_terminating();
    #[cfg(test)]
    let gate = inner.failed_spawn_reap_gate.lock().unwrap().take();
    let (done, waited) = oneshot::channel();
    let jh = tokio::spawn(async move {
        // Own the child, job, and slot through wait even if the spawning request is cancelled.
        drop(job);
        let _ = child.start_kill();
        #[cfg(test)]
        if let Some((entered, resume)) = gate {
            let _ = entered.send(());
            let _ = resume.await;
        }
        let _ = child.wait().await;
        drop(term_guard);
        let _ = done.send(());
    });
    {
        let mut bg = inner
            .bg_terminations
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        bg.retain(|(_, h)| !h.is_finished());
        bg.push((grant_id.to_owned(), jh));
    }
    let _ = waited.await;
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
    registered: bool,
    committed: bool,
}

impl SlotReservation {
    fn new(inner: &Arc<StdioInner>, tbl: &mut SessionTable) -> Self {
        tbl.reserved_slots += 1;
        tbl.pending_spawns += 1;
        Self {
            inner: Arc::clone(inner),
            registered: false,
            committed: false,
        }
    }

    fn commit(mut self, tbl: &mut SessionTable) {
        debug_assert!(self.registered);
        tbl.reserved_slots = tbl.reserved_slots.saturating_sub(1);
        self.committed = true;
    }

    fn into_terminating(mut self) -> TerminatingSlotsGuard {
        self.committed = true;
        {
            let mut tbl = self.inner.table.lock().unwrap_or_else(|p| p.into_inner());
            tbl.reserved_slots = tbl.reserved_slots.saturating_sub(1);
            if !self.registered {
                tbl.pending_spawns = tbl.pending_spawns.saturating_sub(1);
            }
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
                if !self.registered {
                    tbl.pending_spawns = tbl.pending_spawns.saturating_sub(1);
                }
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
                Plan::Immediate(SlotReservation::new(inner, &mut tbl))
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
                    let extra = victims.len().saturating_sub(1);
                    tbl.terminating_slots += extra;
                    Plan::Reap {
                        victims,
                        reservation: SlotReservation::new(inner, &mut tbl),
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
                        Plan::Reap {
                            victims: vec![victim],
                            reservation: SlotReservation::new(inner, &mut tbl),
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

async fn write_stdin_lines(
    mut stdin: impl AsyncWrite + Unpin,
    mut stdin_rx: mpsc::Receiver<StdinLine>,
    writer_cancel: CancellationToken,
    writer_alive: Arc<AtomicBool>,
) {
    while let Some(StdinLine { bytes, flushed }) = tokio::select! {
        _ = writer_cancel.cancelled() => None,
        msg = stdin_rx.recv() => msg,
    } {
        let write_ok = tokio::select! {
            _ = writer_cancel.cancelled() => false,
            res = async {
                stdin.write_all(&bytes).await.is_ok() && stdin.flush().await.is_ok()
            } => res,
        };
        drop(bytes);
        if !write_ok {
            writer_alive.store(false, Ordering::Release);
            break;
        }
        // A FIFO receipt covers this line and every earlier initialized/control line.
        if let Some(flushed) = flushed {
            let _ = flushed.send(());
        }
    }
}

impl StdioSession {
    async fn spawn(
        inner: &Arc<StdioInner>,
        grant_id: String,
        expected_grant_epoch: u64,
        mut reservation: SlotReservation,
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

        #[cfg(windows)]
        cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED);

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn upstream process: {e}"))?;

        #[cfg(windows)]
        {
            let started = (|| {
                #[cfg(test)]
                if let Some(hook) = inner.spawn_hook.lock().unwrap().as_ref() {
                    hook(WindowsSpawnStage::BeforeAssign, &job, &child)?;
                }
                job.assign(&child)?;
                #[cfg(test)]
                if let Some(hook) = inner.spawn_hook.lock().unwrap().as_ref() {
                    hook(WindowsSpawnStage::BeforeResume, &job, &child)?;
                }
                resume_windows_child(&child)
            })();
            if let Err(err) = started {
                reap_failed_windows_spawn(inner, &grant_id, child, job, reservation).await;
                return Err(err);
            }
        }

        let Some(stdin) = child.stdin.take() else {
            #[cfg(windows)]
            reap_failed_windows_spawn(inner, &grant_id, child, job, reservation).await;
            #[cfg(not(windows))]
            {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
            return Err("failed to capture child stdin".to_owned());
        };
        let Some(stdout) = child.stdout.take() else {
            #[cfg(windows)]
            reap_failed_windows_spawn(inner, &grant_id, child, job, reservation).await;
            #[cfg(not(windows))]
            {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
            return Err("failed to capture child stdout".to_owned());
        };

        let (stdin_tx, stdin_rx) =
            mpsc::channel::<StdinLine>(inner.limits.stdin_channel_capacity.max(1));
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
            budget: Arc::clone(&inner.budget),
            limits: inner.limits,
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
                tbl.pending_spawns = tbl.pending_spawns.saturating_sub(1);
                reservation.registered = true;
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

        tokio::spawn(write_stdin_lines(
            stdin,
            stdin_rx,
            writer_cancel,
            Arc::clone(&alive),
        ));

        let reader_inner = Arc::downgrade(inner);
        let reader_session = Arc::downgrade(&session);
        let reader_stdin = Arc::clone(&stdin_tx_arc);
        let reader_budget = Arc::clone(&inner.budget);
        let reader_limits = inner.limits;
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout);
            let mut had_hard_err = false;
            loop {
                let result =
                    read_stdout_line(&mut lines, &in_flight, &reader_budget, reader_limits).await;
                let result = match result {
                    Ok(outcome) => {
                        if outcome.len == 0 {
                            break;
                        }
                        if outcome.len > reader_limits.max_control_line_bytes {
                            dispatch_large_response_line(outcome, &in_flight);
                            continue;
                        }
                        if outcome.raw.iter().all(u8::is_ascii_whitespace) {
                            continue;
                        }
                        let parsed = LeasedJson::parse(&outcome.raw, &reader_budget);
                        drop(outcome);
                        match parsed {
                            Ok(mut parsed) => dispatch_stdout_message(
                                &in_flight,
                                &reader_stdin,
                                &alive,
                                &notif_budget,
                                &reader_budget,
                                std::mem::take(&mut parsed.value),
                            )
                            .map_err(ReadStdoutErr::Hard),
                            Err(JsonEncodeError::Invalid) => continue,
                            Err(JsonEncodeError::Overloaded) => {
                                Err(ReadStdoutErr::Hard(HardRejectError::BudgetExhausted))
                            }
                        }
                    }
                    Err(error) => Err(error),
                };
                match result {
                    Ok(()) => {}
                    Err(ReadStdoutErr::Io) => break,
                    Err(ReadStdoutErr::Hard(hard_err)) => {
                        had_hard_err = true;
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
        // New wire progress tokens and keys need at most 64 additional text bytes.
        let mut rewritten = LeasedJson::copy(payload, &self.budget, 64)?;
        if let Some(obj) = rewritten.value.as_object_mut() {
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
        rewritten.finish_rewrite();
        self.send_json_line(&rewritten.value)
    }

    fn send_json_line(&self, value: &Value) -> Result<(), SendLineErr> {
        self.send_json_line_with_receipt(value, None)
    }

    fn send_json_line_with_receipt(
        &self,
        value: &Value,
        flushed: Option<oneshot::Sender<()>>,
    ) -> Result<(), SendLineErr> {
        if !self.alive.load(Ordering::Acquire) {
            return Err(SendLineErr::Closed);
        }
        let (line, lease) =
            encode_json_leased(value, b"\n", &self.budget).map_err(|err| match err {
                JsonEncodeError::Overloaded => SendLineErr::Overloaded,
                JsonEncodeError::Invalid => SendLineErr::Closed,
            })?;
        self.send_raw_line(StdinLine {
            bytes: leased_bytes(line, Some(lease)),
            flushed,
        })
    }

    async fn send_sessionless_notification(
        &self,
        payload: &Value,
        mut ephemeral: EphemeralGuard,
        write_timeout: Duration,
    ) -> HttpReply {
        let (flushed, receipt) = oneshot::channel();
        if let Err(err) = self.send_json_line_with_receipt(payload, Some(flushed)) {
            let (status, msg) = self.map_send_failure(err, "ephemeral child closed stdin");
            ephemeral.terminate_now().await;
            return jsonrpc_error_reply(&self.budget, status, &Value::Null, -32000, &msg);
        }
        let failure = match tokio::time::timeout(write_timeout, receipt).await {
            Ok(Ok(())) => None,
            Ok(Err(_)) => Some((
                StatusCode::BAD_GATEWAY,
                "ephemeral child stdin write failed",
            )),
            Err(_) => Some((
                StatusCode::GATEWAY_TIMEOUT,
                "ephemeral notification write timed out",
            )),
        };
        ephemeral.terminate_now().await;
        if let Some((status, message)) = failure {
            return jsonrpc_error_reply(&self.budget, status, &Value::Null, -32000, message);
        }
        Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(HeaderName::from_static("x-accel-buffering"), "no")
            .header(header::CACHE_CONTROL, "no-store")
            .body(empty_body())
            .expect("valid 202 reply")
    }

    // Locally generated disconnect/timeout cancellation stays available at main-pool capacity.
    fn send_cancel_line(&self, value: &Value) -> Result<(), SendLineErr> {
        let mut line = serde_json::to_vec(value).map_err(|_| SendLineErr::Closed)?;
        line.push(b'\n');
        self.send_raw_line(StdinLine {
            bytes: Bytes::from(line),
            flushed: None,
        })
    }

    fn rewrite_cancel_notification(
        &self,
        payload: &Value,
    ) -> Result<Option<LeasedJson>, SendLineErr> {
        let Some(client_req_id) = payload
            .get("params")
            .and_then(|params| params.get("requestId"))
        else {
            return Ok(None);
        };
        let wire_id = {
            let waiters = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
            waiters.iter().rev().find_map(|w| {
                w.as_live()
                    .filter(|live| json_id_eq(&live.client_id, client_req_id))
                    .map(|_| w.wire_id)
            })
        };
        let Some(wire_id) = wire_id else {
            return Ok(None);
        };
        let mut cloned = LeasedJson::copy(payload, &self.budget, "requestId".len())?;
        let Some(params) = cloned
            .value
            .get_mut("params")
            .and_then(Value::as_object_mut)
        else {
            return Ok(None);
        };
        params.insert("requestId".to_owned(), json!(wire_id));
        cloned.finish_rewrite();
        Ok(Some(cloned))
    }

    fn send_raw_line(&self, line: StdinLine) -> Result<(), SendLineErr> {
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

    fn map_register_failure(
        &self,
        err: SendLineErr,
        fallback_dead_msg: &str,
    ) -> (StatusCode, String) {
        if !self.alive.load(Ordering::Acquire) {
            self.map_dead_session_error(fallback_dead_msg)
        } else if matches!(err, SendLineErr::Overloaded) {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "process active byte budget exceeded".to_owned(),
            )
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
        } else if matches!(err, SendLineErr::Overloaded) {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "process active byte budget exceeded".to_owned(),
            )
        } else {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream stdin queue is full".to_owned(),
            )
        }
    }

    fn register_request(
        self: &Arc<Self>,
        client_id: &Value,
        client_progress_token: Option<&Value>,
    ) -> Result<
        (
            u64,
            RequestGuard,
            NotifQueueRx,
            oneshot::Receiver<RespDelivery>,
        ),
        SendLineErr,
    > {
        self.register_request_opts(client_id, client_progress_token, false, None)
    }

    fn register_request_opts(
        self: &Arc<Self>,
        client_id: &Value,
        client_progress_token: Option<&Value>,
        is_events_stream: bool,
        session_id: Option<String>,
    ) -> Result<
        (
            u64,
            RequestGuard,
            NotifQueueRx,
            oneshot::Receiver<RespDelivery>,
        ),
        SendLineErr,
    > {
        let claim = ActiveRequestClaim::new(self);
        self.register_request_with_claim(
            claim,
            client_id,
            client_progress_token,
            is_events_stream,
            session_id,
        )
    }

    fn register_request_with_claim(
        self: &Arc<Self>,
        mut claim: ActiveRequestClaim,
        client_id: &Value,
        client_progress_token: Option<&Value>,
        is_events_stream: bool,
        session_id: Option<String>,
    ) -> Result<
        (
            u64,
            RequestGuard,
            NotifQueueRx,
            oneshot::Receiver<RespDelivery>,
        ),
        SendLineErr,
    > {
        let mut waiters = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if !self.alive.load(Ordering::Acquire) {
            return Err(SendLineErr::Closed);
        }
        if waiters.len() >= self.limits.max_in_flight_per_session.max(1) {
            return Err(SendLineErr::Full);
        }
        let wire_id = self.next_wire_id.fetch_add(1, Ordering::Relaxed);
        let (notif_tx, notif_rx) = notif_channel();
        let (resp_tx, resp_rx) = oneshot::channel();
        let stop = Arc::new(RequestStopOwner::new(
            Arc::clone(self),
            session_id,
            wire_id,
            is_events_stream,
            notif_tx.queue(),
        ));
        let entry = InFlightEntry::new(
            wire_id,
            client_id,
            client_progress_token,
            is_events_stream,
            notif_tx,
            resp_tx,
            Arc::downgrade(&stop),
            &self.budget,
        )?;
        // Adopt the pre-incremented active_requests count without dipping to zero.
        claim.disarm_into_guard();
        waiters.push(entry);
        drop(waiters);

        let guard = RequestGuard { stop: Some(stop) };
        Ok((wire_id, guard, notif_rx, resp_rx))
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

enum StopOwnerState {
    Armed { ephemeral: Option<EphemeralGuard> },
    Completed,
    Disarmed,
    Stopping,
}

struct ActiveRequestDrop(Arc<StdioSession>);

impl Drop for ActiveRequestDrop {
    fn drop(&mut self) {
        self.0.active_requests.fetch_sub(1, Ordering::AcqRel);
    }
}

struct RequestStopOwner {
    session: Arc<StdioSession>,
    session_id: Option<String>,
    wire_id: u64,
    is_events_stream: bool,
    notif_queue: Arc<NotifQueue>,
    state: Mutex<StopOwnerState>,
}

impl RequestStopOwner {
    fn new(
        session: Arc<StdioSession>,
        session_id: Option<String>,
        wire_id: u64,
        is_events_stream: bool,
        notif_queue: Arc<NotifQueue>,
    ) -> Self {
        Self {
            session,
            session_id,
            wire_id,
            is_events_stream,
            notif_queue,
            state: Mutex::new(StopOwnerState::Armed { ephemeral: None }),
        }
    }

    fn attach_ephemeral(&self, ephemeral: EphemeralGuard) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let StopOwnerState::Armed {
            ephemeral: ref mut slot,
        } = *state
        {
            *slot = Some(ephemeral);
        } else {
            drop(state);
            drop(ephemeral);
        }
    }

    fn mark_completed(&self) {
        let ephemeral = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match std::mem::replace(&mut *state, StopOwnerState::Completed) {
                StopOwnerState::Armed { ephemeral } => ephemeral,
                other => {
                    *state = other;
                    return;
                }
            }
        };
        self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
        drop(ephemeral);
    }

    fn disarm(&self) {
        let ephemeral = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match std::mem::replace(&mut *state, StopOwnerState::Disarmed) {
                StopOwnerState::Armed { ephemeral } => ephemeral,
                other => {
                    *state = other;
                    return;
                }
            }
        };
        let removed = {
            let mut waiters = self
                .session
                .in_flight
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            waiters
                .iter()
                .position(|w| w.wire_id == self.wire_id)
                .map(|pos| waiters.remove(pos))
        };
        drop(removed);
        self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
        drop(ephemeral);
    }

    // Used when stdout already delivered a malformed or oversized completion for this request.
    fn fail_without_cancel(&self, reason: &str) {
        self.notif_queue.fail(reason);
        self.disarm();
    }

    fn stop(&self, reason: &str, fail_body: Option<&str>) {
        if let Some(err_msg) = fail_body {
            self.notif_queue.fail(err_msg);
        }
        let ephemeral = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match std::mem::replace(&mut *state, StopOwnerState::Stopping) {
                StopOwnerState::Armed { ephemeral } => ephemeral,
                other => {
                    *state = other;
                    return;
                }
            }
        };
        if fail_body.is_none() {
            self.notif_queue.close_and_drain();
        }

        let cancel = json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": self.wire_id,
                "reason": reason
            }
        });

        if ephemeral.is_some() || self.session_id.is_none() {
            let removed = {
                let mut waiters = self
                    .session
                    .in_flight
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                waiters
                    .iter()
                    .position(|w| w.wire_id == self.wire_id)
                    .map(|pos| waiters.remove(pos))
            };
            drop(removed);
            self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
            if self.session.alive.load(Ordering::Acquire) {
                let _ = self.session.send_cancel_line(&cancel);
            }
            if let Some(mut ephemeral) = ephemeral {
                let _ = ephemeral.begin_reap();
                drop(ephemeral);
            }
            return;
        }

        let settled = Arc::new(StopSettlement::new());
        let (entered_stopping, old_state) = {
            let mut waiters = self
                .session
                .in_flight
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(pos) = waiters.iter().position(|w| w.wire_id == self.wire_id) {
                if !self.session.alive.load(Ordering::Acquire) {
                    (false, Some(waiters.remove(pos).state))
                } else {
                    let prev = std::mem::replace(
                        &mut waiters[pos].state,
                        InFlightState::Stopping(StoppingInFlight {
                            is_events_stream: self.is_events_stream,
                            settled: Arc::clone(&settled),
                        }),
                    );
                    (true, Some(prev))
                }
            } else {
                (false, None)
            }
        };
        drop(old_state);
        if !entered_stopping {
            self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
            return;
        }

        let Ok(mut line_bytes) = serde_json::to_vec(&cancel) else {
            remove_stopping_entry(&self.session.in_flight, self.wire_id);
            self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
            return;
        };
        line_bytes.push(b'\n');
        let (flushed_tx, flushed_rx) = oneshot::channel();
        let line = StdinLine {
            bytes: Bytes::from(line_bytes),
            flushed: Some(flushed_tx),
        };
        let tx_opt = self
            .session
            .stdin_tx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();

        enum SendStart {
            Flushing(oneshot::Receiver<()>),
            NeedSend(mpsc::Sender<StdinLine>, StdinLine, oneshot::Receiver<()>),
            Closed,
        }

        let start = match tx_opt {
            None => SendStart::Closed,
            Some(tx) => match tx.try_send(line) {
                Ok(()) => SendStart::Flushing(flushed_rx),
                Err(TrySendError::Full(unsent)) => SendStart::NeedSend(tx, unsent, flushed_rx),
                Err(TrySendError::Closed(_)) => SendStart::Closed,
            },
        };

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            remove_stopping_entry(&self.session.in_flight, self.wire_id);
            self.session.active_requests.fetch_sub(1, Ordering::AcqRel);
            return;
        };

        let session = Arc::clone(&self.session);
        let session_id = self.session_id.clone();
        let wire_id = self.wire_id;
        let deadline = tokio::time::Instant::now() + session.limits.stdin_write_timeout;

        handle.spawn(async move {
            let _active_drop = ActiveRequestDrop(Arc::clone(&session));
            let receipt_rx = match start {
                SendStart::Flushing(rx) => Some(rx),
                SendStart::NeedSend(tx, unsent, rx) => {
                    let admitted = tokio::select! {
                        biased;
                        () = settled.wait_settled() => return,
                        res = tokio::time::timeout_at(deadline, tx.send(unsent)) => res,
                    };
                    match admitted {
                        Ok(Ok(())) => Some(rx),
                        Ok(Err(_)) | Err(_) => None,
                    }
                }
                SendStart::Closed => None,
            };

            if let Some(rx) = receipt_rx {
                let flushed = tokio::select! {
                    biased;
                    () = settled.wait_settled() => return,
                    res = tokio::time::timeout_at(deadline, rx) => res,
                };
                if matches!(flushed, Ok(Ok(()))) {
                    let _ = settled.try_decide_receipt();
                    remove_stopping_entry(&session.in_flight, wire_id);
                    return;
                }
            }

            if settled.try_decide_retire() != StopOutcome::RetireChild {
                return;
            }
            remove_stopping_entry(&session.in_flight, wire_id);
            retire_shared_session(&session, session_id.as_deref()).await;
        });
    }
}

fn remove_stopping_entry(in_flight: &Mutex<Vec<InFlightEntry>>, wire_id: u64) {
    let removed = {
        let mut waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        waiters
            .iter()
            .position(|w| w.wire_id == wire_id && matches!(w.state, InFlightState::Stopping(_)))
            .map(|pos| waiters.remove(pos))
    };
    drop(removed);
}

async fn retire_shared_session(session: &Arc<StdioSession>, session_id: Option<&str>) {
    if let Some(inner) = session.weak_inner.upgrade() {
        let removed_count = {
            let mut tbl = inner.table.lock().unwrap_or_else(|p| p.into_inner());
            let key = session_id
                .filter(|sid| {
                    tbl.sessions
                        .get(*sid)
                        .is_some_and(|cur| cur.uid == session.uid)
                })
                .map(str::to_owned)
                .or_else(|| {
                    tbl.sessions
                        .iter()
                        .find(|(_, cur)| cur.uid == session.uid)
                        .map(|(k, _)| k.clone())
                });
            if let Some(k) = key {
                tbl.sessions.remove(&k);
                tbl.terminating_slots += 1;
                1
            } else {
                0
            }
        };
        let _ = reap_sessions(&inner, vec![Arc::clone(session)], removed_count, None).await;
    } else {
        session.terminate().await;
    }
}

struct RequestGuard {
    stop: Option<Arc<RequestStopOwner>>,
}

impl RequestGuard {
    fn mark_completed(&mut self) {
        self.stop.as_ref().expect("request owner").mark_completed();
    }

    fn disarm(&mut self) {
        self.stop.as_ref().expect("request owner").disarm();
    }

    fn cancel(&mut self, reason: &str) {
        self.stop
            .as_ref()
            .expect("request owner")
            .stop(reason, None);
    }

    fn into_stop(mut self) -> Arc<RequestStopOwner> {
        self.stop.take().expect("request owner")
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.as_ref() {
            stop.stop("client disconnected", None);
        }
    }
}

struct StdioSseStreamBody {
    notif_rx: NotifQueueRx,
    resp_rx: Option<oneshot::Receiver<RespDelivery>>,
    pending_resp: Option<RespDelivery>,
    active_resp_cursor: Option<LeasedFrameCursor>,
    active_resp_is_error: bool,
    notif_done: bool,
    stop: Arc<RequestStopOwner>,
    session: Arc<StdioSession>,
    idle_timeout: Duration,
    idle_sleep: Pin<Box<tokio::time::Sleep>>,
    last_frame_ms: Arc<AtomicU64>,
    stream_done: CancellationToken,
    timed_out_fut: Mutex<Pin<Box<dyn Future<Output = ()> + Send>>>,
    finished: bool,
}

impl StdioSseStreamBody {
    fn new(
        notif_rx: NotifQueueRx,
        resp_rx: oneshot::Receiver<RespDelivery>,
        guard: RequestGuard,
        session: Arc<StdioSession>,
        idle_timeout: Duration,
        ephemeral: Option<EphemeralGuard>,
    ) -> Self {
        let stop = guard.into_stop();
        if let Some(ephem) = ephemeral {
            stop.attach_ephemeral(ephem);
        }
        let last_frame_ms = Arc::new(AtomicU64::new(elapsed_ms(session.epoch)));
        let stream_done = CancellationToken::new();
        let timed_out = CancellationToken::new();
        let timed_out_fut = Mutex::new(Box::pin(timed_out.clone().cancelled_owned())
            as Pin<Box<dyn Future<Output = ()> + Send>>);

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let wd_stop = Arc::clone(&stop);
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
                        wd_timed_out.cancel();
                        wd_stop.stop("request timed out", None);
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
            stop,
            session,
            idle_timeout,
            idle_sleep: Box::pin(tokio::time::sleep(idle_timeout)),
            last_frame_ms,
            stream_done,
            timed_out_fut,
            finished: false,
        }
    }

    fn finish_completed(&mut self) {
        self.finished = true;
        self.active_resp_cursor = None;
        self.pending_resp = None;
        self.stream_done.cancel();
        self.session.touch_client();
        self.stop.mark_completed();
    }

    fn finish_disarmed(&mut self) {
        self.finished = true;
        self.active_resp_cursor = None;
        self.pending_resp = None;
        self.stream_done.cancel();
        self.stop.disarm();
    }

    fn finish_failed(&mut self) {
        self.finished = true;
        self.active_resp_cursor = None;
        self.pending_resp = None;
        self.stream_done.cancel();
    }

    fn finish_timed_out(&mut self) {
        self.finished = true;
        let had_resp =
            self.active_resp_cursor.take().is_some() || self.pending_resp.take().is_some();
        self.stream_done.cancel();
        if had_resp {
            self.stop.disarm();
        } else {
            self.stop.stop("request timed out", None);
        }
    }
}

impl Drop for StdioSseStreamBody {
    fn drop(&mut self) {
        let had_resp =
            self.active_resp_cursor.take().is_some() || self.pending_resp.take().is_some();
        self.stream_done.cancel();
        if had_resp {
            self.stop.disarm();
        } else {
            self.stop.stop("client disconnected", None);
        }
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

            if let Some(reason) = this.notif_rx.take_failure() {
                this.finish_failed();
                return Poll::Ready(Some(Err(io::Error::other(reason))));
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
                match this.notif_rx.poll_pop(cx) {
                    Poll::Ready(Err(reason)) => {
                        this.finish_failed();
                        return Poll::Ready(Some(Err(io::Error::other(reason))));
                    }
                    Poll::Ready(Ok(Some(queued))) => {
                        this.session.touch_client();
                        this.last_frame_ms
                            .store(elapsed_ms(this.session.epoch), Ordering::Release);
                        this.idle_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + this.idle_timeout);
                        let frame = match queued.into_sse(&this.session.budget) {
                            Ok(bytes) => bytes,
                            Err(_) => {
                                this.stop.stop(
                                    "process active byte budget exceeded",
                                    Some("process active byte budget exceeded"),
                                );
                                this.finish_failed();
                                return Poll::Ready(Some(Err(io::Error::other(
                                    "process active byte budget exceeded",
                                ))));
                            }
                        };
                        return Poll::Ready(Some(Ok(Frame::data(frame))));
                    }
                    Poll::Ready(Ok(None)) => {
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
                if let Some(reason) = this.notif_rx.take_failure() {
                    this.finish_failed();
                    return Poll::Ready(Some(Err(io::Error::other(reason))));
                }
                if let Some(delivery) = this.pending_resp.take() {
                    let (json_bytes, lease, is_err) = match delivery {
                        RespDelivery::Ok { json_bytes, lease } => (json_bytes, lease, false),
                        RespDelivery::HardError {
                            json_bytes, lease, ..
                        } => (json_bytes, lease, true),
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
    tx: &NotifQueue,
    line: String,
    process_lease: Option<ByteLease>,
) {
    let _ = tx.enqueue(notif_budget, line, process_lease);
}

fn encode_notification(value: &Value, budget: &Arc<ByteBudget>) -> Option<(String, ByteLease)> {
    encode_json_leased(value, b"", budget)
        .ok()
        .map(|(bytes, lease)| {
            (
                String::from_utf8(bytes).expect("JSON encoding is UTF-8"),
                lease,
            )
        })
}

fn is_events_push_notification(method: &str) -> bool {
    matches!(
        method,
        "notifications/events/active"
            | "notifications/events/event"
            | "notifications/events/heartbeat"
            | "notifications/events/error"
            | "notifications/events/terminated"
    )
}

fn is_valid_rpc_error(obj: &serde_json::Map<String, Value>) -> bool {
    !obj.contains_key("result") && obj.get("error").is_some_and(Value::is_object)
}

fn is_valid_final_response(obj: &serde_json::Map<String, Value>) -> bool {
    (obj.contains_key("result") && !obj.contains_key("error")) || is_valid_rpc_error(obj)
}

fn is_valid_events_complete(obj: &serde_json::Map<String, Value>, wire_id: u64) -> bool {
    obj.contains_key("result")
        && !obj.contains_key("error")
        && obj
            .get("result")
            .and_then(Value::as_object)
            .is_some_and(|res| {
                res.get("resultType").and_then(Value::as_str) == Some("complete")
                    && res
                        .get("_meta")
                        .and_then(Value::as_object)
                        .and_then(|meta| meta.get(SUBSCRIPTION_ID_META_KEY))
                        .and_then(Value::as_u64)
                        == Some(wire_id)
            })
}

// Signal failure before dropping live so closing channels cannot race into a clean EOF.
fn fail_live_events_waiter(live: LiveInFlight, reason: &str) {
    if let Some(stop) = live.stop.upgrade() {
        stop.fail_without_cancel(reason);
    } else {
        live.notif_tx.queue().fail(reason);
    }
    drop(live);
}

fn dispatch_large_response_line(
    mut outcome: ReadLineOutcome,
    in_flight: &Mutex<Vec<InFlightEntry>>,
) {
    if outcome.saw_method || outcome.id_count != 1 {
        return;
    }
    let Some(top_id) = outcome.top_id else {
        return;
    };
    let Some(wire_id) = top_id.wire_id else {
        return;
    };

    enum LargeWaiter {
        EventsLive(Box<LiveInFlight>),
        EventsStopping,
        Other,
    }

    // Events completions never bypass structured validation via raw splice.
    let events_match = {
        let mut waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        match waiters.iter().position(|w| w.wire_id == wire_id) {
            Some(pos) if waiters[pos].is_events_stream() => match &waiters[pos].state {
                InFlightState::Live(_) => {
                    let InFlightState::Live(live) = waiters.remove(pos).state else {
                        unreachable!();
                    };
                    Some(LargeWaiter::EventsLive(live))
                }
                InFlightState::Stopping(_) => Some(LargeWaiter::EventsStopping),
            },
            Some(_) => Some(LargeWaiter::Other),
            None => None,
        }
    };
    match events_match {
        None => return,
        Some(LargeWaiter::EventsLive(live)) => {
            drop(outcome);
            fail_live_events_waiter(*live, "events/stream completion exceeds control line limit");
            return;
        }
        Some(LargeWaiter::EventsStopping) => {
            drop(outcome);
            return;
        }
        Some(LargeWaiter::Other) => {}
    }

    if outcome.discarded {
        return;
    }
    let Ok(text) = std::str::from_utf8(&outcome.raw) else {
        return;
    };
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.trim().is_empty() || serde_json::from_str::<serde::de::IgnoredAny>(trimmed).is_err()
    {
        return;
    }
    let trimmed_len = trimmed.len();
    if top_id.end > trimmed_len || top_id.start >= top_id.end {
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
        return;
    };
    let mut live = match entry.state {
        InFlightState::Live(live) => *live,
        InFlightState::Stopping(stopping) => {
            drop(outcome);
            stopping.settled.observe_final_response();
            return;
        }
    };
    // Reuse the already charged error workspace for the temporary encoded ID.
    serde_json::to_writer(&mut live.error_buffer.bytes, &live.client_id)
        .expect("valid ID fits its reserved encoding workspace");
    outcome.raw.truncate(trimmed_len);
    let old_id_len = top_id.end - top_id.start;
    let final_len = trimmed_len - old_id_len + live.error_buffer.bytes.len();
    if outcome.reserve(final_len, final_len).is_err() {
        drop(outcome);
        send_request_error(
            live,
            StatusCode::SERVICE_UNAVAILABLE,
            "process active byte budget exceeded".to_owned(),
        );
        return;
    }
    outcome.raw.splice(
        top_id.start..top_id.end,
        live.error_buffer.bytes.iter().copied(),
    );
    let _ = live.resp_tx.send(RespDelivery::Ok {
        json_bytes: outcome.raw,
        lease: outcome.lease,
    });
}

fn dispatch_stdout_message(
    in_flight: &Mutex<Vec<InFlightEntry>>,
    stdin_tx: &Mutex<Option<mpsc::Sender<StdinLine>>>,
    alive: &AtomicBool,
    notif_budget: &Arc<ByteBudget>,
    budget: &Arc<ByteBudget>,
    mut val: Value,
) -> Result<(), HardRejectError> {
    let Some(obj) = val.as_object() else {
        return Ok(());
    };
    let method_opt = obj.get("method").and_then(Value::as_str);
    let has_method = method_opt.is_some();

    if has_method && obj.contains_key("id") {
        let id = obj.get("id").expect("checked id");
        let sent = if method_opt == Some("ping") {
            #[derive(serde::Serialize)]
            struct Pong<'a> {
                jsonrpc: &'static str,
                id: &'a Value,
                result: serde_json::Map<String, Value>,
            }
            let reply = Pong {
                jsonrpc: "2.0",
                id,
                result: serde_json::Map::new(),
            };
            send_child_stdin_reply(stdin_tx, alive, &reply, budget)
        } else {
            let reply =
                rpc_error_payload(id, -32601, "client requests are not supported by gateway");
            send_child_stdin_reply(stdin_tx, alive, &reply, budget)
        };
        return sent.map_err(|_| HardRejectError::BudgetExhausted);
    }

    if !has_method {
        let Some(wire_id) = obj.get("id").and_then(Value::as_u64) else {
            return Ok(());
        };
        let valid_final = is_valid_final_response(obj);
        let valid_events_final = is_valid_rpc_error(obj) || is_valid_events_complete(obj, wire_id);
        enum RemovedWaiter {
            Live(Box<LiveInFlight>),
            Stopping(Arc<StopSettlement>),
        }
        let removed = {
            let mut waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(pos) = waiters.iter().position(|w| w.wire_id == wire_id) {
                match &waiters[pos].state {
                    InFlightState::Live(_) => {
                        let InFlightState::Live(live) = waiters.remove(pos).state else {
                            unreachable!();
                        };
                        Some(RemovedWaiter::Live(live))
                    }
                    InFlightState::Stopping(stopping)
                        if if stopping.is_events_stream {
                            valid_events_final
                        } else {
                            valid_final
                        } =>
                    {
                        let InFlightState::Stopping(stopping) = waiters.remove(pos).state else {
                            unreachable!();
                        };
                        Some(RemovedWaiter::Stopping(stopping.settled))
                    }
                    InFlightState::Stopping(_) => None,
                }
            } else {
                None
            }
        };
        let Some(removed) = removed else {
            return Ok(());
        };
        let mut live = match removed {
            RemovedWaiter::Stopping(settled) => {
                settled.observe_final_response();
                return Ok(());
            }
            RemovedWaiter::Live(live) => *live,
        };
        if live.is_events_stream {
            let is_rpc_error = is_valid_rpc_error(obj);
            let is_valid_complete = is_valid_events_complete(obj, wire_id);
            if !is_rpc_error && !is_valid_complete {
                drop(val);
                fail_live_events_waiter(live, "malformed events/stream completion");
                return Ok(());
            }
            let mut sub_id_copy_lease = None;
            if is_valid_complete {
                let Ok(sub_id_copy) = LeasedJson::copy(&live.client_id, budget, 0) else {
                    drop(val);
                    fail_live_events_waiter(live, "process active byte budget exceeded");
                    return Ok(());
                };
                sub_id_copy_lease = Some(sub_id_copy._lease);
                if let Some(sub_id) = val
                    .get_mut("result")
                    .and_then(Value::as_object_mut)
                    .and_then(|res| res.get_mut("_meta"))
                    .and_then(Value::as_object_mut)
                    .and_then(|meta| meta.get_mut(SUBSCRIPTION_ID_META_KEY))
                {
                    *sub_id = sub_id_copy.value;
                }
            }
            if let Some(id) = val.get_mut("id") {
                *id = std::mem::take(&mut live.client_id);
            }
            match encode_json_leased(&val, b"", budget) {
                Ok((out, lease)) => {
                    drop(val);
                    drop(sub_id_copy_lease);
                    let _ = live.resp_tx.send(RespDelivery::Ok {
                        json_bytes: out,
                        lease: Some(lease),
                    });
                }
                Err(_) => {
                    drop(val);
                    drop(sub_id_copy_lease);
                    fail_live_events_waiter(live, "process active byte budget exceeded");
                }
            }
            return Ok(());
        }
        if let Some(id) = val.get_mut("id") {
            *id = std::mem::take(&mut live.client_id);
        }
        match encode_json_leased(&val, b"", budget) {
            Ok((out, lease)) => {
                drop(val);
                let _ = live.resp_tx.send(RespDelivery::Ok {
                    json_bytes: out,
                    lease: Some(lease),
                });
            }
            Err(_) => {
                live.client_id = val
                    .as_object_mut()
                    .and_then(|map| map.remove("id"))
                    .unwrap_or(Value::Null);
                drop(val);
                send_request_error(
                    live,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "process active byte budget exceeded".to_owned(),
                );
            }
        }
        return Ok(());
    }

    if let Some(method) = method_opt
        && is_events_push_notification(method)
    {
        let Some(sub_wire_id) = obj
            .get("params")
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get(SUBSCRIPTION_ID_META_KEY))
            .and_then(Value::as_u64)
        else {
            return Ok(());
        };
        let matched = {
            let waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
            waiters
                .iter()
                .find(|w| w.wire_id == sub_wire_id)
                .and_then(InFlightEntry::as_live)
                .filter(|live| live.is_events_stream && !live.notif_tx.is_closed())
                .map(|live| {
                    let copied = LeasedJson::copy(&live.client_id, budget, 0).ok();
                    (copied, live.notif_tx.queue(), live.stop.upgrade())
                })
        };
        let Some((copied_id, queue, stop)) = matched else {
            return Ok(());
        };
        let fail_stream = |reason: &str| {
            if let Some(ref stop) = stop {
                stop.stop(reason, Some(reason));
            } else {
                queue.fail(reason);
            }
        };
        let Some(client_id) = copied_id else {
            drop(val);
            fail_stream("process active byte budget exceeded");
            return Ok(());
        };
        if let Some(sub_id) = val
            .get_mut("params")
            .and_then(Value::as_object_mut)
            .and_then(|p| p.get_mut("_meta"))
            .and_then(Value::as_object_mut)
            .and_then(|meta| meta.get_mut(SUBSCRIPTION_ID_META_KEY))
        {
            *sub_id = client_id.value;
        }
        let Some((out, lease)) = encode_notification(&val, budget) else {
            drop(val);
            fail_stream("process active byte budget exceeded");
            return Ok(());
        };
        drop(val);
        if let Err(SendLineErr::Overloaded) = queue.enqueue(notif_budget, out, Some(lease)) {
            fail_stream("events notification queue budget exceeded");
        }
        return Ok(());
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
            waiters
                .iter()
                .find(|w| w.wire_id == rel_wire_id)
                .and_then(InFlightEntry::as_live)
                .and_then(|live| {
                    let client_id = LeasedJson::copy(&live.client_id, budget, 0).ok()?;
                    let progress = match &live.client_progress_token {
                        Some(value) => Some(LeasedJson::copy(value, budget, 0).ok()?),
                        None => None,
                    };
                    Some((client_id, progress, live.notif_tx.queue()))
                })
        };
        if let Some((client_id, mut client_ptok, notif_tx)) = matched {
            if let Some(params) = val.get_mut("params").and_then(Value::as_object_mut) {
                if let Some(related_id) = params
                    .get_mut("_meta")
                    .and_then(Value::as_object_mut)
                    .and_then(|meta| meta.get_mut("relatedRequestId"))
                {
                    *related_id = client_id.value;
                }
                if is_progress && let Some(orig_ptok) = client_ptok.as_mut() {
                    use std::io::Write as _;
                    const MAX_TOKEN_BYTES: usize = "gw_pt_".len() + 20;
                    let mut token = [0u8; MAX_TOKEN_BYTES];
                    let mut remaining = token.as_mut_slice();
                    write!(&mut remaining, "gw_pt_{rel_wire_id}")
                        .expect("u64 progress token fits buffer");
                    let len = MAX_TOKEN_BYTES - remaining.len();
                    if let Some(progress_token) = params.get_mut("progressToken")
                        && progress_token.as_str().map(str::as_bytes) == Some(&token[..len])
                    {
                        *progress_token = std::mem::take(&mut orig_ptok.value);
                    }
                }
            }
            if !notif_tx.is_closed()
                && let Some((out, lease)) = encode_notification(&val, budget)
            {
                enqueue_notif(notif_budget, &notif_tx, out, Some(lease));
            }
            drop(val);
        }
        return Ok(());
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
            return Ok(());
        };
        let matched = {
            let waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
            waiters
                .iter()
                .find(|w| w.wire_id == wire_id)
                .and_then(InFlightEntry::as_live)
                .and_then(|live| {
                    let original = live.client_progress_token.as_ref()?;
                    LeasedJson::copy(original, budget, 0)
                        .ok()
                        .map(|orig| (orig, live.notif_tx.queue()))
                })
        };
        if let Some((orig_ptok, notif_tx)) = matched {
            if let Some(progress_token) = val
                .get_mut("params")
                .and_then(Value::as_object_mut)
                .and_then(|params| params.get_mut("progressToken"))
            {
                *progress_token = orig_ptok.value;
            }
            if !notif_tx.is_closed()
                && let Some((out, lease)) = encode_notification(&val, budget)
            {
                enqueue_notif(notif_budget, &notif_tx, out, Some(lease));
            }
            drop(val);
        }
        return Ok(());
    }

    let targets: Vec<Arc<NotifQueue>> = {
        let waiters = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        waiters
            .iter()
            .filter_map(InFlightEntry::as_live)
            .filter(|live| !live.notif_tx.is_closed())
            .map(|live| live.notif_tx.queue())
            .collect()
    };
    for tx in targets {
        let Some((out, lease)) = encode_notification(&val, budget) else {
            break;
        };
        enqueue_notif(notif_budget, &tx, out, Some(lease));
    }
    Ok(())
}

fn send_child_stdin_reply<T: serde::Serialize + ?Sized>(
    stdin_tx: &Mutex<Option<mpsc::Sender<StdinLine>>>,
    alive: &AtomicBool,
    reply: &T,
    budget: &Arc<ByteBudget>,
) -> Result<(), JsonEncodeError> {
    if !alive.load(Ordering::Acquire) {
        return Ok(());
    }
    let (line, lease) = encode_json_leased(reply, b"\n", budget)?;
    let line = StdinLine {
        bytes: leased_bytes(line, Some(lease)),
        flushed: None,
    };
    let tx_clone = {
        let guard = stdin_tx.lock().unwrap_or_else(|p| p.into_inner());
        let Some(tx) = guard.as_ref() else {
            return Ok(());
        };
        match tx.try_send(line) {
            Ok(()) | Err(TrySendError::Closed(_)) => return Ok(()),
            Err(TrySendError::Full(unsent)) => (tx.clone(), unsent),
        }
    };
    let (tx, unsent) = tx_clone;
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(5), tx.send(unsent)).await;
        });
    }
    Ok(())
}

fn extract_progress_token(payload: &Value) -> Option<&Value> {
    payload
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("progressToken"))
        .filter(|v| !v.is_null())
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
                let Some((key, value)) = param.split_once('=') else {
                    return false;
                };
                if !key.trim().eq_ignore_ascii_case("q") {
                    return false;
                }
                !matches!(value.trim().parse::<f32>(), Ok(q) if q.is_finite() && q > 0.0)
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

fn send_request_error(entry: LiveInFlight, status: StatusCode, message: String) {
    let (json_bytes, lease) = entry.error_buffer.finish(&entry.client_id, &message);
    let _ = entry.resp_tx.send(RespDelivery::HardError {
        status,
        message,
        json_bytes,
        lease: Some(lease),
    });
}

fn jsonrpc_error_reply(
    budget: &Arc<ByteBudget>,
    status: StatusCode,
    id: &Value,
    code: i64,
    message: &str,
) -> HttpReply {
    let body = rpc_error_payload(id, code, message);
    let Ok((encoded, lease)) = encode_json_leased(&body, b"", budget) else {
        return request_overloaded_reply();
    };
    jsonrpc_error_bytes_reply(status, encoded, Some(lease))
}

fn jsonrpc_error_bytes_reply(
    status: StatusCode,
    encoded: Vec<u8>,
    lease: Option<ByteLease>,
) -> HttpReply {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(HeaderName::from_static("x-accel-buffering"), "no")
        .body(bytes_body(leased_bytes(encoded, lease)))
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

fn is_events_waiter(in_flight: &Mutex<Vec<InFlightEntry>>, wire_id: u64) -> bool {
    in_flight
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .any(|w| w.wire_id == wire_id && w.is_events_stream())
}

struct ReadLineOutcome {
    // Keep the allocation and its lease together across reads and cancellation.
    raw: Vec<u8>,
    len: usize,
    discarded: bool,
    saw_method: bool,
    id_count: usize,
    top_id: Option<TopIdSpan>,
    lease: Option<ByteLease>,
}

impl ReadLineOutcome {
    fn empty(budget: &Arc<ByteBudget>) -> Self {
        Self {
            raw: Vec::new(),
            len: 0,
            discarded: false,
            saw_method: false,
            id_count: 0,
            top_id: None,
            lease: budget.try_acquire(0),
        }
    }

    fn reserve(&mut self, needed: usize, limit: usize) -> Result<(), ReadStdoutErr> {
        if self
            .lease
            .as_mut()
            .expect("line lease")
            .reserve_vec(&mut self.raw, needed, limit)
        {
            Ok(())
        } else {
            Err(ReadStdoutErr::Hard(HardRejectError::BudgetExhausted))
        }
    }

    fn discard_buffer(&mut self) {
        self.discarded = true;
        self.raw = Vec::new();
        if let Some(lease) = self.lease.as_mut() {
            lease.shrink_to(0);
        }
    }

    fn finish(mut self, scanner: &TopLevelJsonScanner) -> Self {
        if !self.discarded {
            self.len = self.raw.len();
        }
        self.saw_method = scanner.saw_method;
        self.id_count = scanner.id_count;
        self.top_id = scanner.top_id;
        self
    }
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
        if let InFlightState::Live(live) = entry.state {
            send_request_error(*live, status, message.clone());
        }
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
    in_flight: &Mutex<Vec<InFlightEntry>>,
    budget: &Arc<ByteBudget>,
    limits: StdioLimits,
) -> Result<ReadLineOutcome, ReadStdoutErr> {
    let mut out = ReadLineOutcome::empty(budget);
    let control_limit = limits
        .max_control_line_bytes
        .min(limits.max_stdout_line_bytes);
    let mut scanner = TopLevelJsonScanner::new();
    let mut speculative = false;
    let mut total_len = 0usize;

    loop {
        let available = reader.fill_buf().await.map_err(|_| ReadStdoutErr::Io)?;
        if available.is_empty() {
            if speculative && total_len > 0 {
                return Ok(ReadLineOutcome::empty(budget));
            }
            out.len = total_len;
            return Ok(out.finish(&scanner));
        }

        if !speculative {
            let rem_ctrl = control_limit.saturating_sub(out.raw.len());
            if rem_ctrl > 0 {
                let window = &available[..available.len().min(rem_ctrl)];
                let newline = window.iter().position(|&b| b == b'\n');
                let take = newline.map_or(window.len(), |pos| pos + 1);
                out.reserve(out.raw.len() + take, control_limit)?;
                out.raw.extend_from_slice(&window[..take]);
                total_len += take;
                reader.consume(take);
                if newline.is_some() {
                    out.len = total_len;
                    return Ok(out.finish(&scanner));
                }
                continue;
            }

            if control_limit >= limits.max_stdout_line_bytes {
                return Err(ReadStdoutErr::Hard(HardRejectError::LineTooLarge(
                    limits.max_stdout_line_bytes,
                )));
            }
            if !has_in_flight(in_flight) {
                return Err(ReadStdoutErr::Hard(HardRejectError::UnexpectedLargeOutput(
                    limits.max_control_line_bytes,
                )));
            }
            scanner.feed(&out.raw);
            if scanner.saw_method {
                return Err(ReadStdoutErr::Hard(
                    HardRejectError::ControlMessageTooLarge(limits.max_control_line_bytes),
                ));
            }
            if scanner.id_count == 1
                && let Some(wire_id) = scanner.top_id.and_then(|s| s.wire_id)
                && is_events_waiter(in_flight, wire_id)
            {
                out.discard_buffer();
            }
            speculative = true;
        }

        let newline = available.iter().position(|&b| b == b'\n');
        let take = newline.map_or(available.len(), |pos| pos + 1);
        let Some(new_len) = total_len
            .checked_add(take)
            .filter(|&n| n <= limits.max_stdout_line_bytes)
        else {
            return Err(ReadStdoutErr::Hard(HardRejectError::LineTooLarge(
                limits.max_stdout_line_bytes,
            )));
        };
        if !out.discarded {
            out.reserve(new_len, limits.max_stdout_line_bytes)?;
            out.raw.extend_from_slice(&available[..take]);
        }
        scanner.feed(&available[..take]);
        total_len = new_len;
        reader.consume(take);
        if newline.is_some() {
            out.len = total_len;
            return Ok(out.finish(&scanner));
        }
        if scanner.saw_method {
            return Err(ReadStdoutErr::Hard(
                HardRejectError::ControlMessageTooLarge(limits.max_control_line_bytes),
            ));
        }
        if !out.discarded
            && scanner.id_count == 1
            && let Some(wire_id) = scanner.top_id.and_then(|s| s.wire_id)
            && is_events_waiter(in_flight, wire_id)
        {
            out.discard_buffer();
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

    fn request_test_session(budget: &Arc<ByteBudget>) -> Arc<StdioSession> {
        Arc::new(StdioSession {
            uid: 1,
            grant_id: "g".to_owned(),
            weak_inner: Weak::new(),
            budget: Arc::clone(budget),
            limits: StdioLimits::default(),
            writer_cancel: CancellationToken::new(),
            stdin_tx: Arc::new(Mutex::new(None)),
            in_flight: Arc::new(Mutex::new(Vec::new())),
            terminal_error: Arc::new(Mutex::new(None)),
            next_wire_id: AtomicU64::new(1),
            alive: Arc::new(AtomicBool::new(true)),
            active_requests: Arc::new(AtomicUsize::new(0)),
            last_client_active_ms: AtomicU64::new(0),
            last_client_seq: AtomicU64::new(1),
            child: tokio::sync::Mutex::new(None),
            #[cfg(windows)]
            job: Mutex::new(None),
            epoch: Instant::now(),
        })
    }

    struct GatedNotificationWriter {
        written: Arc<Mutex<Vec<u8>>>,
        flushed_len: Arc<AtomicUsize>,
        first_flush: bool,
        gate: Option<oneshot::Receiver<io::Result<()>>>,
    }

    impl AsyncWrite for GatedNotificationWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.first_flush {
                self.first_flush = false;
            } else if let Some(gate) = self.gate.as_mut() {
                let result = std::task::ready!(Pin::new(gate).poll(cx))
                    .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                self.gate = None;
                if let Err(err) = result {
                    return Poll::Ready(Err(err));
                }
            }
            self.flushed_len
                .store(self.written.lock().unwrap().len(), Ordering::Release);
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn notification_test_session(
        budget: &Arc<ByteBudget>,
    ) -> (
        StdioUpstream,
        Arc<StdioSession>,
        EphemeralGuard,
        mpsc::Receiver<StdinLine>,
    ) {
        let up = StdioUpstream::with_limits(
            StdioUpstreamSettings {
                command: "unused-test-child".to_owned(),
                args: Vec::new(),
                env: std::collections::BTreeMap::new(),
                cwd: None,
                max_sessions: 1,
                session_idle_secs: 30,
            },
            Arc::clone(budget),
            StdioLimits::default(),
        )
        .unwrap();
        let mut session = request_test_session(budget);
        Arc::get_mut(&mut session).unwrap().weak_inner = Arc::downgrade(&up.inner);
        let (tx, rx) = mpsc::channel(STDIN_CHANNEL_CAPACITY);
        *session.stdin_tx.lock().unwrap() = Some(tx);
        let slot = {
            let mut table = up.inner.table.lock().unwrap();
            let mut slot = SlotReservation::new(&up.inner, &mut table);
            table.live_sessions.push(Arc::clone(&session));
            table.pending_spawns -= 1;
            slot.registered = true;
            slot
        };
        let ephemeral = EphemeralGuard::new(Arc::clone(&session), slot);
        (up, session, ephemeral, rx)
    }

    #[tokio::test]
    async fn sessionless_notification_receipt_controls_status_and_reaping() {
        for outcome in ["flushed", "flush_error", "writer_closed", "timeout"] {
            let budget = ByteBudget::new(4096);
            let (up, session, ephemeral, rx) = notification_test_session(&budget);
            let initialized = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
            let payload = json!({"jsonrpc":"2.0","method":"notifications/roots/list_changed"});
            let initialized_len = json_encoded_len(&initialized).unwrap() + 1;
            let payload_len = json_encoded_len(&payload).unwrap() + 1;
            session.send_json_line(&initialized).unwrap();
            let written = Arc::new(Mutex::new(Vec::new()));
            let flushed_len = Arc::new(AtomicUsize::new(0));
            let (release, gate) = oneshot::channel();
            let mut writer = Box::pin(write_stdin_lines(
                GatedNotificationWriter {
                    written: Arc::clone(&written),
                    flushed_len: Arc::clone(&flushed_len),
                    first_flush: true,
                    gate: Some(gate),
                },
                rx,
                session.writer_cancel.clone(),
                Arc::clone(&session.alive),
            ));
            let deadline = if outcome == "timeout" {
                Duration::from_millis(50)
            } else {
                Duration::from_secs(2)
            };
            let mut notification =
                Box::pin(session.send_sessionless_notification(&payload, ephemeral, deadline));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(notification.as_mut().poll(&mut cx).is_pending());
            assert!(writer.as_mut().poll(&mut cx).is_pending());
            assert!(notification.as_mut().poll(&mut cx).is_pending());
            assert_eq!(flushed_len.load(Ordering::Acquire), initialized_len);
            assert_eq!(
                budget.used(),
                payload_len,
                "the pending write keeps its bytes"
            );
            {
                let table = up.inner.table.lock().unwrap();
                assert_eq!(table.reserved_slots, 1);
                assert_eq!(table.terminating_slots, 0, "reaping must wait for flush");
            }
            assert!(!session.writer_cancel.is_cancelled());
            let lines: Vec<Value> = written
                .lock()
                .unwrap()
                .split(|&byte| byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice(line).unwrap())
                .collect();
            assert_eq!(lines, vec![initialized, payload.clone()]);

            let expected_status = match outcome {
                "flushed" => {
                    release.send(Ok(())).unwrap();
                    StatusCode::ACCEPTED
                }
                "flush_error" => {
                    release
                        .send(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
                        .unwrap();
                    StatusCode::BAD_GATEWAY
                }
                "writer_closed" => {
                    session.writer_cancel.cancel();
                    StatusCode::BAD_GATEWAY
                }
                "timeout" => StatusCode::GATEWAY_TIMEOUT,
                _ => unreachable!(),
            };
            let (reply, ()) = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(notification, writer)
            })
            .await
            .expect("notification and writer must finish after receipt or cancellation");
            assert_eq!(reply.status(), expected_status, "{outcome}");
            let body = reply.into_body().collect().await.unwrap().to_bytes();
            if expected_status == StatusCode::ACCEPTED {
                assert!(body.is_empty());
                assert_eq!(
                    flushed_len.load(Ordering::Acquire),
                    initialized_len + payload_len
                );
            } else {
                let error: Value = serde_json::from_slice(&body).unwrap();
                assert!(error["id"].is_null());
                let message = error["error"]["message"].as_str().unwrap();
                assert_eq!(
                    message,
                    if outcome == "timeout" {
                        "ephemeral notification write timed out"
                    } else {
                        "ephemeral child stdin write failed"
                    }
                );
                assert_eq!(flushed_len.load(Ordering::Acquire), initialized_len);
            }
            drop(body);
            up.shutdown().await;
            let table = up.inner.table.lock().unwrap();
            assert_eq!(table.used_slots(), 0);
            assert!(table.live_sessions.is_empty());
            assert_eq!(budget.used(), 0);
        }
    }

    #[tokio::test]
    async fn sessionless_notification_cancellation_reaps_pending_writer() {
        let budget = ByteBudget::new(4096);
        let (up, session, ephemeral, rx) = notification_test_session(&budget);
        let initialized = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        let payload = json!({"jsonrpc":"2.0","method":"notifications/roots/list_changed"});
        session.send_json_line(&initialized).unwrap();
        let flushed_len = Arc::new(AtomicUsize::new(0));
        let (release, gate) = oneshot::channel();
        let mut writer = Box::pin(write_stdin_lines(
            GatedNotificationWriter {
                written: Arc::new(Mutex::new(Vec::new())),
                flushed_len: Arc::clone(&flushed_len),
                first_flush: true,
                gate: Some(gate),
            },
            rx,
            session.writer_cancel.clone(),
            Arc::clone(&session.alive),
        ));
        let mut notification = Box::pin(session.send_sessionless_notification(
            &payload,
            ephemeral,
            STDIN_WRITE_TIMEOUT,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(notification.as_mut().poll(&mut cx).is_pending());
        assert!(writer.as_mut().poll(&mut cx).is_pending());
        assert!(budget.used() > 0);
        drop(notification);
        assert_eq!(budget.used(), json_encoded_len(&payload).unwrap() + 1);
        assert_eq!(up.inner.table.lock().unwrap().terminating_slots, 1);
        tokio::time::timeout(Duration::from_secs(2), writer)
            .await
            .expect("the ephemeral reaper must cancel the pending writer");
        assert!(release.send(Ok(())).is_err());
        assert_eq!(
            flushed_len.load(Ordering::Acquire),
            json_encoded_len(&initialized).unwrap() + 1
        );
        up.shutdown().await;
        let table = up.inner.table.lock().unwrap();
        assert_eq!(table.used_slots(), 0);
        assert!(table.live_sessions.is_empty());
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn sessionless_notification_reaches_child_before_reap() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("notifications.jsonl");
        let script = r#"import json, sys
with open(sys.argv[1], "w", encoding="utf-8") as log:
    for raw in sys.stdin:
        message = json.loads(raw)
        log.write(json.dumps(message) + "\n")
        log.flush()
        if message.get("method") == "initialize":
            print(json.dumps({"jsonrpc":"2.0", "id":message["id"], "result":{
                "protocolVersion":"2026-07-28", "capabilities":{},
                "serverInfo":{"name":"notification-fixture", "version":"1"}
            }}), flush=True)
"#;
        let budget = ByteBudget::new(16 * 1024);
        let up = StdioUpstream::with_limits(
            StdioUpstreamSettings {
                command: if cfg!(windows) { "python" } else { "python3" }.to_owned(),
                args: vec![
                    "-u".to_owned(),
                    "-c".to_owned(),
                    script.to_owned(),
                    log.to_string_lossy().into_owned(),
                ],
                env: std::collections::BTreeMap::new(),
                cwd: None,
                max_sessions: 1,
                session_idle_secs: 30,
            },
            Arc::clone(&budget),
            StdioLimits::default(),
        )
        .unwrap();
        let token = VerifiedToken {
            grant_id: "notification-grant".to_owned(),
            client_id: "test-client".to_owned(),
            pool_slot: 0,
            scopes: vec!["mcp".to_owned()],
            resource: "https://mcp.example.com/mcp".to_owned(),
        };
        let payload = json!({"jsonrpc":"2.0","method":"notifications/roots/list_changed"});
        let reply = tokio::time::timeout(
            Duration::from_secs(5),
            up.handle_sessionless(
                &HeaderMap::new(),
                &token,
                &payload,
                Some("notifications/roots/list_changed"),
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(reply.status(), StatusCode::ACCEPTED);
        assert!(reply.headers().get("mcp-session-id").is_none());
        drop(reply);
        up.shutdown().await;
        let received: Vec<Value> = std::fs::read_to_string(log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(received, vec![payload]);
        assert_eq!(up.inner.table.lock().unwrap().used_slots(), 0);
        tokio::time::timeout(Duration::from_secs(2), async {
            while budget.used() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reader and writer must release their final byte owners");
    }

    const NORMAL_REQUEST: &[u8] = br#"{"jsonrpc":"2.0","id":"call-one","method":"tools/call","params":{"_meta":{"progressToken":"progress-one"},"arguments":{"text":"hello"}}}"#;

    #[test]
    fn request_value_reserves_parse_workspace_and_copy_capacity() {
        let tight = ByteBudget::new(NORMAL_REQUEST.len() * 3 - 1);
        assert!(matches!(
            LeasedJson::parse(NORMAL_REQUEST, &tight),
            Err(JsonEncodeError::Overloaded),
        ));
        assert_eq!(tight.used(), 0);

        let budget = ByteBudget::new(4096);
        let parsed = LeasedJson::parse(NORMAL_REQUEST, &budget).unwrap();
        assert_eq!(budget.used(), json_text_capacity(&parsed.value));
        assert_eq!(parsed.value["params"]["arguments"]["text"], "hello");
        drop(parsed);
        assert_eq!(budget.used(), 0);

        let mut text = String::with_capacity(64);
        text.push_str("ready");
        let value = Value::String(text);
        let too_tight = ByteBudget::new(63);
        assert!(matches!(
            LeasedJson::copy(&value, &too_tight, 0),
            Err(SendLineErr::Overloaded)
        ));
        assert_eq!(too_tight.used(), 0);
        let copy = LeasedJson::copy(&value, &budget, 0).unwrap();
        assert_eq!(budget.used(), 64);
        assert_eq!(copy.value, value);
        drop(copy);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn request_stdin_queue_keeps_its_lease_after_caller_cancellation() {
        let budget = ByteBudget::new(4096);
        let session = request_test_session(&budget);
        let (tx, mut rx) = mpsc::channel(4);
        *session.stdin_tx.lock().unwrap() = Some(tx);
        let parsed = LeasedJson::parse(NORMAL_REQUEST, &budget).unwrap();
        let (wire_id, mut guard, _notifications, _response) = session
            .register_request(&parsed.value["id"], extract_progress_token(&parsed.value))
            .unwrap();
        session.send_request_line(&parsed.value, wire_id).unwrap();
        drop(parsed);

        let queued = rx.try_recv().unwrap().bytes;
        let encoded: Value = serde_json::from_slice(&queued).unwrap();
        assert_eq!(encoded["id"], wire_id);
        assert_eq!(
            encoded["params"]["_meta"]["progressToken"],
            format!("gw_pt_{wire_id}")
        );
        let retained = queued.clone();
        guard.cancel("client disconnected");
        let cancellation: Value = serde_json::from_slice(&rx.try_recv().unwrap().bytes).unwrap();
        assert_eq!(cancellation["params"]["requestId"], wire_id);
        assert_eq!(
            budget.used(),
            queued.len(),
            "only the encoded queue allocation remains"
        );
        drop(queued);
        assert_eq!(budget.used(), retained.len());
        drop(retained);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn request_error_workspace_preserves_id_when_the_process_pool_is_full() {
        let budget = ByteBudget::new(2048);
        let session = request_test_session(&budget);
        let id = json!("reader \"one\"\n");
        let (_, mut guard, _notifications, mut response) =
            session.register_request(&id, None).unwrap();
        let entry = session.in_flight.lock().unwrap().pop().unwrap();
        let InFlightState::Live(live) = entry.state else {
            panic!("expected live entry");
        };
        let occupied = budget.try_acquire(budget.limit() - budget.used()).unwrap();
        assert_eq!(budget.used(), budget.limit());
        send_request_error(
            *live,
            StatusCode::SERVICE_UNAVAILABLE,
            "process active byte budget exceeded".to_owned(),
        );
        guard.disarm();
        let RespDelivery::HardError {
            status,
            json_bytes,
            lease,
            ..
        } = response.try_recv().unwrap()
        else {
            panic!("expected the reserved error response");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let error: Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(error["id"], id);
        assert_eq!(
            error["error"]["message"],
            "process active byte budget exceeded"
        );
        let held = lease.as_ref().unwrap().held();
        assert_eq!(json_bytes.capacity(), held);
        let frame = leased_bytes(json_bytes, lease);
        let retained = frame.clone();
        drop(occupied);
        drop(frame);
        assert_eq!(budget.used(), held);
        drop(retained);
        assert_eq!(budget.used(), 0);

        for reason in [
            HardRejectError::BudgetExhausted,
            HardRejectError::LineTooLarge(usize::MAX),
            HardRejectError::ControlMessageTooLarge(usize::MAX),
            HardRejectError::UnexpectedLargeOutput(usize::MAX),
        ] {
            let (_, message) = reason.into_status_and_message();
            let workspace = ErrorBuffer::new(&id, &budget).unwrap();
            assert!(
                json_encoded_len(&rpc_error_payload(&id, -32000, &message)).unwrap()
                    <= workspace.bytes.capacity()
            );
            let (bytes, lease) = workspace.finish(&id, &message);
            let decoded: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(decoded["error"]["message"], message);
            drop(bytes);
            drop(lease);
        }
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn request_metadata_copies_and_notification_frames_keep_their_owners() {
        let budget = ByteBudget::new(4096);
        let notif_budget = ByteBudget::new(4096);
        let session = request_test_session(&budget);
        let parsed = LeasedJson::parse(NORMAL_REQUEST, &budget).unwrap();
        let (wire_id, mut guard, notifications, _response) = session
            .register_request(&parsed.value["id"], extract_progress_token(&parsed.value))
            .unwrap();
        drop(parsed);
        dispatch_stdout_message(
            &session.in_flight,
            &session.stdin_tx,
            &session.alive,
            &notif_budget,
            &budget,
            json!({"jsonrpc":"2.0","method":"notifications/progress","params":{
                "_meta":{"relatedRequestId":wire_id},
                "progressToken":format!("gw_pt_{wire_id}"),"progress":1
            }}),
        )
        .unwrap();
        let queued = notifications.try_recv().unwrap();
        assert_eq!(notif_budget.used(), queued.line.capacity());
        let frame = queued.into_sse(&budget).unwrap();
        assert_eq!(
            notif_budget.used(),
            0,
            "the session queue owner ends at dequeue"
        );
        let value: Value = serde_json::from_slice(&frame[6..frame.len() - 2]).unwrap();
        assert_eq!(value["params"]["_meta"]["relatedRequestId"], "call-one");
        assert_eq!(value["params"]["progressToken"], "progress-one");
        guard.cancel("client disconnected");
        assert_eq!(budget.used(), frame.len());
        let retained = frame.slice(6..);
        drop(frame);
        assert!(budget.used() > 0);
        drop(retained);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn stdout_small_line_charges_capacity_and_parse_workspace() {
        let line = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"text\":\"hello\"}}\n";
        let limits = StdioLimits {
            max_control_line_bytes: 128,
            max_stdout_line_bytes: 256,
            ..StdioLimits::default()
        };
        let in_flight = Mutex::new(Vec::new());
        let budget = ByteBudget::new(1024);
        let mut reader = BufReader::new(line.as_slice());
        let outcome = read_stdout_line(&mut reader, &in_flight, &budget, limits)
            .await
            .unwrap();
        assert_eq!(budget.used(), outcome.raw.capacity());
        let parsed = LeasedJson::parse(&outcome.raw, &budget).unwrap();
        assert_eq!(
            budget.used(),
            outcome.raw.capacity() + json_text_capacity(&parsed.value)
        );
        drop(outcome);
        assert_eq!(budget.used(), json_text_capacity(&parsed.value));
        assert_eq!(parsed.value["result"]["text"], "hello");
        drop(parsed);
        assert_eq!(budget.used(), 0);

        let budget = ByteBudget::new(line.len() - 1);
        let mut reader = BufReader::new(line.as_slice());
        assert!(matches!(
            read_stdout_line(&mut reader, &in_flight, &budget, limits).await,
            Err(ReadStdoutErr::Hard(HardRejectError::BudgetExhausted))
        ));
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn stdout_small_line_cancellation_releases_owned_capacity() {
        use std::future::Future;

        let prefix = b"{\"jsonrpc\":\"2.0\",";
        let limits = StdioLimits {
            max_control_line_bytes: 128,
            max_stdout_line_bytes: 256,
            ..StdioLimits::default()
        };
        for poll in [false, true] {
            let budget = ByteBudget::new(1024);
            let in_flight = Mutex::new(Vec::new());
            let (mut write, read) = tokio::io::duplex(128);
            write.write_all(prefix).await.unwrap();
            let mut reader = BufReader::new(read);
            let mut pending = Box::pin(read_stdout_line(&mut reader, &in_flight, &budget, limits));
            if poll {
                let mut cx = Context::from_waker(Waker::noop());
                assert!(pending.as_mut().poll(&mut cx).is_pending());
                assert_eq!(budget.used(), prefix.len());
            } else {
                assert_eq!(budget.used(), 0);
            }
            drop(pending);
            assert_eq!(budget.used(), 0);
        }
    }

    #[tokio::test]
    async fn stdout_child_reply_owns_encoded_id_through_queue() {
        for method in ["ping", "roots/list"] {
            for full_queue in [false, true] {
                let budget = ByteBudget::new(4096);
                let source = json!({"jsonrpc":"2.0","id":"child-\"id","method":method});
                let mut parsed = LeasedJson::copy(&source, &budget, 0).unwrap();
                let (tx, mut rx) = mpsc::channel(1);
                if full_queue {
                    tx.try_send(StdinLine {
                        bytes: Bytes::from_static(b"ready\n"),
                        flushed: None,
                    })
                    .unwrap();
                }
                let stdin = Mutex::new(Some(tx));
                dispatch_stdout_message(
                    &Mutex::new(Vec::new()),
                    &stdin,
                    &AtomicBool::new(true),
                    &ByteBudget::new(1024),
                    &budget,
                    std::mem::take(&mut parsed.value),
                )
                .unwrap();
                drop(parsed);
                let charged = budget.used();
                assert!(charged > 0);
                if full_queue {
                    assert_eq!(rx.recv().await.unwrap().bytes, b"ready\n".as_slice());
                }
                let line = rx.recv().await.unwrap().bytes;
                assert_eq!(charged, line.len());
                let value: Value = serde_json::from_slice(&line).unwrap();
                assert_eq!(value["id"], source["id"]);
                if method == "ping" {
                    assert_eq!(value["result"], json!({}));
                } else {
                    assert_eq!(value["error"]["code"], -32601);
                }
                let retained = line.slice(..);
                drop(line);
                assert_eq!(budget.used(), charged);
                drop(retained);
                assert_eq!(budget.used(), 0);
            }
        }
    }

    #[test]
    fn request_reply_owner_survives_unpolled_and_pending_cleanup() {
        use std::future::Future;

        for error in [false, true] {
            for poll in [false, true] {
                let budget = ByteBudget::new(4096);
                let (bytes, lease) = encode_json_leased(
                    &json!({"jsonrpc":"2.0","id":"normal-id","result":{}}),
                    b"",
                    &budget,
                )
                .unwrap();
                let charged = bytes.capacity();
                let reply = if error {
                    jsonrpc_error_bytes_reply(StatusCode::BAD_GATEWAY, bytes, Some(lease))
                } else {
                    single_rpc_reply(&HeaderMap::new(), None, bytes, Some(lease))
                };
                // Cleanup may never start, or may be cancelled while awaiting the child.
                // Capturing the completed body keeps bytes and lease in the same owner.
                let mut cleanup = Box::pin(async move {
                    std::future::pending::<()>().await;
                    reply
                });
                assert_eq!(budget.used(), charged);
                if poll {
                    let mut cx = Context::from_waker(Waker::noop());
                    assert!(cleanup.as_mut().poll(&mut cx).is_pending());
                    assert_eq!(budget.used(), charged);
                }
                drop(cleanup);
                assert_eq!(budget.used(), 0);
            }
        }
    }

    #[test]
    fn request_rewrite_respects_exact_available_budget() {
        const AVAILABLE: usize = 40_000;
        let id = json!("long-client-id-expanded-by-30b");
        assert_eq!(json_encoded_len(&id).unwrap(), 32);
        for final_len in [AVAILABLE, AVAILABLE + 1] {
            let budget = ByteBudget::new(2 * AVAILABLE + 4096);
            let (notif_tx, _notif_rx) = notif_channel();
            let (resp_tx, mut resp_rx) = oneshot::channel();
            let entry =
                InFlightEntry::new(2, &id, None, false, notif_tx, resp_tx, Weak::new(), &budget)
                    .unwrap();
            let in_flight = Mutex::new(vec![entry]);
            let line_len = final_len - 30; // Drop LF, then replace one digit with 32 bytes.
            let mut lease = budget.try_acquire(0).unwrap();
            let mut raw = Vec::new();
            assert!(lease.reserve_vec(&mut raw, line_len, line_len));
            let prefix = br#"{"jsonrpc":"2.0","result":{"_meta":{"explicit_null":null},"text":""#;
            let suffix = b"\"},\"id\":2}\n";
            raw.extend_from_slice(prefix);
            raw.resize(line_len - suffix.len(), b'x');
            raw.extend_from_slice(suffix);
            // The original response, retained ID, and error workspace remain charged.
            // Leave exactly AVAILABLE more bytes for the replacement allocation.
            let occupied = budget
                .try_acquire(budget.limit() - budget.used() - AVAILABLE)
                .unwrap();
            let outcome = ReadLineOutcome {
                len: raw.len(),
                raw,
                discarded: false,
                lease: Some(lease),
                saw_method: false,
                id_count: 1,
                top_id: Some(TopIdSpan {
                    start: line_len - 3,
                    end: line_len - 2,
                    wire_id: Some(2),
                }),
            };
            dispatch_large_response_line(outcome, &in_flight);
            let delivery = resp_rx.try_recv().unwrap();
            let (bytes, lease) = match delivery {
                RespDelivery::Ok { json_bytes, lease } => {
                    assert_eq!(final_len, AVAILABLE);
                    assert_eq!(json_bytes.len(), AVAILABLE);
                    let value: Value = serde_json::from_slice(&json_bytes).unwrap();
                    assert_eq!(value["id"], id);
                    assert!(value["result"]["_meta"]["explicit_null"].is_null());
                    (json_bytes, lease)
                }
                RespDelivery::HardError {
                    status,
                    json_bytes,
                    lease,
                    ..
                } => {
                    assert_eq!(final_len, AVAILABLE + 1);
                    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                    let value: Value = serde_json::from_slice(&json_bytes).unwrap();
                    assert_eq!(value["id"], id);
                    assert_eq!(
                        value["error"]["message"],
                        "process active byte budget exceeded"
                    );
                    (json_bytes, lease)
                }
            };
            let held = lease.as_ref().unwrap().held();
            let frame = leased_bytes(bytes, lease);
            drop(occupied);
            assert_eq!(budget.used(), held);
            drop(frame);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn request_id_owner_transfers_to_the_encoded_response() {
        let budget = ByteBudget::new(4096);
        let session = request_test_session(&budget);
        let (wire_id, mut guard, _notifications, mut response) =
            session.register_request(&json!("normal-id"), None).unwrap();
        dispatch_stdout_message(
            &session.in_flight,
            &session.stdin_tx,
            &session.alive,
            &ByteBudget::new(4096),
            &budget,
            json!({"jsonrpc":"2.0","id":wire_id,"result":{"text":"done"}}),
        )
        .unwrap();
        guard.mark_completed();
        let RespDelivery::Ok { json_bytes, lease } = response.try_recv().unwrap() else {
            panic!("expected response");
        };
        assert_eq!(
            serde_json::from_slice::<Value>(&json_bytes).unwrap()["id"],
            "normal-id"
        );
        assert_eq!(budget.used(), json_bytes.capacity());
        let bytes = leased_bytes(json_bytes, lease);
        assert!(budget.used() > 0);
        drop(bytes);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn init_response_classification_skips_payloads_and_keeps_last_error_shape() {
        let cases = [
            (
                r#"{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"nested\\server","version":"1"},"capabilities":{},"extensions":[{"error":null},true,3]}}"#,
                InitOutcome::Ok,
            ),
            (r#"{"result":[1,true,null]}"#, InitOutcome::Ok),
            (r#"{"result":null}"#, InitOutcome::Ok),
            (r#"{"result":"ready"}"#, InitOutcome::Ok),
            (r#"{"result":3}"#, InitOutcome::Ok),
            (r#"{"result":false}"#, InitOutcome::Ok),
            (
                r#"{"error": {"code":-32601,"message":"unavailable","data":{"result":[1,2]}}}"#,
                InitOutcome::RpcError,
            ),
            (
                r#"{"error":"earlier\\value","error":{}}"#,
                InitOutcome::RpcError,
            ),
            (r#"{"error":{},"error":null}"#, InitOutcome::Malformed),
            (r#"{"result":null,"result":false}"#, InitOutcome::Ok),
            (r#"{"result":null,"error":{}}"#, InitOutcome::Malformed),
            (
                r#"{"\u0072esult":{},"extension":{"error":{}}}"#,
                InitOutcome::Ok,
            ),
            (
                r#"{"\u0072\u0065\u0073\u0075\u006c\u0074":null}"#,
                InitOutcome::Ok,
            ),
            (
                r#"{"\u0065\u0078\u0074\u0065\u006e\u0073\u0069\u006f\u006e":{"note":"ready"},"result":{}}"#,
                InitOutcome::Ok,
            ),
            (r#"{}"#, InitOutcome::Malformed),
            (r#"[]"#, InitOutcome::Malformed),
        ];
        for (json, expected) in cases {
            assert_eq!(classify_init_response(json.as_bytes()), expected, "{json}");
        }
    }

    #[tokio::test]
    async fn sse_request_owner_is_released_after_complete_disconnect_and_timeout() {
        for is_events_stream in [false, true] {
            for ending in ["complete", "disconnect", "timeout"] {
                let budget = ByteBudget::new(4096);
                let notif_budget = ByteBudget::new(4096);
                let session = request_test_session(&budget);
                let weak_session = Arc::downgrade(&session);
                let (stdin_tx, mut stdin_rx) = mpsc::channel(4);
                *session.stdin_tx.lock().unwrap() = Some(stdin_tx);
                let (wire_id, guard, notif_rx, resp_rx) = session
                    .register_request_opts(
                        &json!("owner-request"),
                        None,
                        is_events_stream,
                        Some("owner-session".to_owned()),
                    )
                    .unwrap();
                let weak_stop = session.in_flight.lock().unwrap()[0]
                    .as_live()
                    .unwrap()
                    .stop
                    .clone();
                let mut body = StdioSseStreamBody::new(
                    notif_rx,
                    resp_rx,
                    guard,
                    Arc::clone(&session),
                    Duration::from_millis(20),
                    None,
                );

                if ending == "complete" {
                    let result = if is_events_stream {
                        json!({
                            "resultType": "complete",
                            "_meta": { SUBSCRIPTION_ID_META_KEY: wire_id }
                        })
                    } else {
                        json!({})
                    };
                    dispatch_stdout_message(
                        &session.in_flight,
                        &session.stdin_tx,
                        &session.alive,
                        &notif_budget,
                        &budget,
                        json!({ "jsonrpc": "2.0", "id": wire_id, "result": result }),
                    )
                    .unwrap();
                    drop(body.collect().await.unwrap());
                } else {
                    if ending == "timeout" {
                        let error = tokio::time::timeout(Duration::from_secs(1), body.frame())
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap_err();
                        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                    }
                    drop(body);
                    let cancel = tokio::time::timeout(Duration::from_secs(1), stdin_rx.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    let value: Value = serde_json::from_slice(&cancel.bytes).unwrap();
                    assert_eq!(value["method"], "notifications/cancelled");
                    assert_eq!(value["params"]["requestId"], wire_id);
                    cancel.flushed.unwrap().send(()).unwrap();
                }

                tokio::time::timeout(Duration::from_secs(1), async {
                    while weak_stop.upgrade().is_some()
                        || session.active_requests.load(Ordering::Acquire) != 0
                    {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap_or_else(|_| {
                    panic!("request owner retained: events={is_events_stream}, ending={ending}")
                });
                assert!(session.in_flight.lock().unwrap().is_empty());
                assert_eq!(budget.used(), 0);
                assert_eq!(notif_budget.used(), 0);
                drop(session);
                assert!(
                    weak_session.upgrade().is_none(),
                    "session retained: events={is_events_stream}, ending={ending}"
                );
            }
        }
    }

    #[tokio::test]
    async fn sse_stream_handles_resp_drop_before_notif_close_without_panic() {
        let now = Instant::now();
        let notif_budget = ByteBudget::new(MAX_NOTIF_QUEUE_BYTES);
        let session = Arc::new(StdioSession {
            uid: 1,
            grant_id: "g".to_owned(),
            weak_inner: Weak::new(),
            budget: ByteBudget::new(4096),
            limits: StdioLimits::default(),
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

        let (notif_tx, notif_rx) = notif_channel();
        let (resp_tx, resp_rx) = oneshot::channel::<RespDelivery>();
        drop(resp_tx);

        let mut body = StdioSseStreamBody::new(
            notif_rx,
            resp_rx,
            RequestGuard {
                stop: Some(Arc::new(RequestStopOwner::new(
                    Arc::clone(&session),
                    None,
                    1,
                    false,
                    notif_tx.queue(),
                ))),
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
            &notif_tx.queue(),
            r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#.to_owned(),
            None,
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
    async fn stdout_line_growth_requires_old_and_new_capacity() {
        const FIRST: &[u8] = br#"{"jsonrpc":"2.0","id":1,"#;
        const LAST: &[u8] = b"\"result\":{}}\n";
        let peak = FIRST.len() * 2 + LAST.len();
        for limit in [peak - 1, peak, peak + 1] {
            let budget = ByteBudget::new(limit);
            let limits = StdioLimits {
                max_control_line_bytes: 128,
                max_stdout_line_bytes: 256,
                ..StdioLimits::default()
            };
            let in_flight = Mutex::new(Vec::new());
            let (mut write, read) = tokio::io::duplex(128);
            write.write_all(FIRST).await.unwrap();
            let mut reader = BufReader::with_capacity(128, read);
            let mut reading = Box::pin(read_stdout_line(&mut reader, &in_flight, &budget, limits));
            assert!(
                reading
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert_eq!(budget.used(), FIRST.len());
            write.write_all(LAST).await.unwrap();
            drop(write);
            let result = reading.await;
            if limit < peak {
                assert!(matches!(
                    result,
                    Err(ReadStdoutErr::Hard(HardRejectError::BudgetExhausted))
                ));
            } else {
                let outcome = result.unwrap();
                assert_eq!(outcome.raw, [FIRST, LAST].concat());
                assert_eq!(budget.used(), outcome.raw.capacity());
                drop(outcome);
            }
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn large_response_keeps_spare_capacity_leased_without_shrinking() {
        let capacity = MAX_CONTROL_LINE_BYTES + 512;
        let budget = ByteBudget::new(capacity + 4096);
        let session = request_test_session(&budget);
        let (wire_id, mut guard, _notifications, mut response) =
            session.register_request(&json!("client"), None).unwrap();
        assert_eq!(wire_id, 1);
        let line = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
        let mut outcome = ReadLineOutcome::empty(&budget);
        outcome.reserve(capacity, capacity).unwrap();
        outcome.raw.extend_from_slice(line);
        let original = outcome.raw.as_ptr();
        let mut scanner = TopLevelJsonScanner::new();
        scanner.feed(line);
        dispatch_large_response_line(outcome.finish(&scanner), &session.in_flight);
        guard.mark_completed();
        let RespDelivery::Ok { json_bytes, lease } = response.try_recv().unwrap() else {
            panic!("the response must keep its original allocation");
        };
        assert_eq!(json_bytes.as_ptr(), original);
        assert_eq!(json_bytes.capacity(), capacity);
        assert_eq!(
            serde_json::from_slice::<Value>(&json_bytes).unwrap()["id"],
            "client"
        );
        assert_eq!(budget.used(), capacity);
        let frame = leased_bytes(json_bytes, lease);
        let retained = frame.clone();
        drop(frame);
        assert_eq!(budget.used(), capacity);
        drop(retained);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn stdio_large_line_keeps_allocated_capacity_leased() {
        let budget = ByteBudget::new(260 * 1024);
        let limits = StdioLimits {
            max_stdout_line_bytes: 512 * 1024,
            max_control_line_bytes: 1024,
            ..StdioLimits::default()
        };
        let (notif_tx, _notif_rx) = notif_channel();
        let (resp_tx, resp_rx) = oneshot::channel();
        let in_flight = Mutex::new(vec![
            InFlightEntry::new(
                1,
                &json!("client"),
                None,
                false,
                notif_tx,
                resp_tx,
                Weak::new(),
                &ByteBudget::new(4096),
            )
            .unwrap(),
        ]);
        let line = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{}\"}}\n",
            "x".repeat(129 * 1024),
        );
        let mut reader = BufReader::new(line.as_bytes());
        let outcome = read_stdout_line(&mut reader, &in_flight, &budget, limits)
            .await
            .unwrap();
        assert_eq!(budget.used(), outcome.raw.capacity());
        assert!(outcome.raw.capacity() <= budget.limit());
        dispatch_large_response_line(outcome, &in_flight);
        let RespDelivery::Ok { json_bytes, lease } = resp_rx.await.unwrap() else {
            panic!("response should fit the tight capacity budget");
        };
        assert_eq!(budget.used(), json_bytes.capacity());
        drop(json_bytes);
        drop(lease);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn read_stdout_line_inplace_rewrite_and_raw_shrink_across_all_exits() {
        let budget = ByteBudget::new(192 * 1024);
        let limits = StdioLimits {
            max_stdout_line_bytes: 512 * 1024,
            max_control_line_bytes: 1024,
            max_notif_queue_bytes: 64 * 1024,
            ..StdioLimits::default()
        };
        let in_flight: Mutex<Vec<InFlightEntry>> = Mutex::new(Vec::new());
        let push_waiter = |wire_id: u64, client_id: Value| {
            let (notif_tx, _notif_rx) = notif_channel();
            let (resp_tx, resp_rx) = oneshot::channel();
            in_flight.lock().unwrap().push(
                InFlightEntry::new(
                    wire_id,
                    &client_id,
                    None,
                    false,
                    notif_tx,
                    resp_tx,
                    Weak::new(),
                    &ByteBudget::new(4096),
                )
                .unwrap(),
            );
            resp_rx
        };

        // 1. The 192 KiB pool covers 64 + 128 KiB growth, but not a second 120 KiB AST.
        let rx1 = push_waiter(1, json!("client-long-id-rewrite-0001"));
        let big_str = "A".repeat(120 * 1024);
        let valid_line =
            format!(r#"{{"jsonrpc":"2.0","result":{{"blob":"{big_str}"}},"id":1}}"#) + "\n";
        let (mut w, r) = tokio::io::duplex(256 * 1024);
        w.write_all(valid_line.as_bytes()).await.unwrap();
        drop(w);
        let mut reader = BufReader::new(r);
        let out1 = read_stdout_line(&mut reader, &in_flight, &budget, limits)
            .await
            .unwrap();
        assert!(out1.raw.capacity() > 64 * 1024);
        dispatch_large_response_line(out1, &in_flight);
        let delivered = rx1.await.unwrap();
        match delivered {
            RespDelivery::Ok { json_bytes, lease } => {
                assert_eq!(budget.used(), json_bytes.capacity());
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
        let out2 = read_stdout_line(&mut reader, &in_flight, &budget, limits)
            .await
            .unwrap();
        dispatch_large_response_line(out2, &in_flight);
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
        let err3 = read_stdout_line(&mut reader, &in_flight, &budget, line_cap_limits).await;
        assert!(matches!(
            err3,
            Err(ReadStdoutErr::Hard(HardRejectError::LineTooLarge(_)))
        ));
        assert_eq!(budget.used(), 0);

        // 3b. Line exceeding process ByteBudget (< max_stdout_line_bytes) hard-rejects with BudgetExhausted and resets `raw` + lease.
        let over_budget = vec![b'y'; budget.limit() + 1];
        let (mut w, r) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            let _ = w.write_all(&over_budget).await;
        });
        let mut reader = BufReader::new(r);
        let err3b = read_stdout_line(&mut reader, &in_flight, &budget, limits).await;
        assert!(matches!(
            err3b,
            Err(ReadStdoutErr::Hard(HardRejectError::BudgetExhausted))
        ));
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
        let out4 = read_stdout_line(&mut reader, &in_flight, &budget, limits)
            .await
            .unwrap();
        assert_eq!(out4.len, 0);
        assert_eq!(out4.raw.capacity(), 0);
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
                                initial,
                                "failed growth keeps the existing live buffer charged until drop"
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
    fn notif_queue_charges_spare_capacity_until_the_entry_drops() {
        let make_line = || {
            let mut line = String::with_capacity(128);
            line.push_str("notification");
            line
        };
        let capacity = make_line().capacity();
        let budget = ByteBudget::new(capacity);
        let (tx, rx) = notif_channel();

        let occupied = ByteBudget::try_acquire(&budget, 1).unwrap();
        enqueue_notif(&budget, &tx.queue(), make_line(), None);
        assert_eq!(budget.used(), 1);
        assert!(rx.try_recv().is_err());
        drop(occupied);

        enqueue_notif(&budget, &tx.queue(), make_line(), None);
        assert_eq!(budget.used(), capacity);
        let queued = rx.try_recv().unwrap();
        assert_eq!(
            budget.used(),
            capacity,
            "the dequeued entry still owns its string"
        );
        enqueue_notif(&budget, &tx.queue(), "x".into(), None);
        assert!(rx.try_recv().is_err());
        drop(queued);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn notif_queue_byte_budget_tracks_enqueued_copies_and_reclaims_on_recv_or_drop() {
        let in_flight: Mutex<Vec<InFlightEntry>> = Mutex::new(Vec::new());
        let stdin_tx = Mutex::new(None);
        let alive = AtomicBool::new(true);

        // Register 2 open SSE waiters + 1 closed JSON waiter.
        let (tx1, rx1) = notif_channel();
        let (rtx1, _rrx1) = oneshot::channel();
        let (tx2, rx2) = notif_channel();
        let (rtx2, _rrx2) = oneshot::channel();
        let (tx_closed, rx_closed) = notif_channel();
        drop(rx_closed);
        let (rtx3, _rrx3) = oneshot::channel();

        {
            let mut w = in_flight.lock().unwrap();
            w.push(
                InFlightEntry::new(
                    1,
                    &json!("sse-1"),
                    None,
                    false,
                    tx1,
                    rtx1,
                    Weak::new(),
                    &ByteBudget::new(4096),
                )
                .unwrap(),
            );
            w.push(
                InFlightEntry::new(
                    2,
                    &json!("sse-2"),
                    None,
                    false,
                    tx2,
                    rtx2,
                    Weak::new(),
                    &ByteBudget::new(4096),
                )
                .unwrap(),
            );
            w.push(
                InFlightEntry::new(
                    3,
                    &json!("json-closed"),
                    None,
                    false,
                    tx_closed,
                    rtx3,
                    Weak::new(),
                    &ByteBudget::new(4096),
                )
                .unwrap(),
            );
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

        let notification = make_notif(450, 1);
        let cloned_capacity = json_encoded_len(&notification).unwrap();
        let total_capacity = 2 * cloned_capacity;
        let notif_budget = ByteBudget::new(total_capacity);
        let process_budget = ByteBudget::new(4096);

        // Two exact-capacity encodings fill the budget; the closed waiter costs nothing.
        dispatch_stdout_message(
            &in_flight,
            &stdin_tx,
            &alive,
            &notif_budget,
            &process_budget,
            notification,
        )
        .unwrap();
        assert_eq!(notif_budget.used(), total_capacity);

        // Both open waiters drop the next notification when their shared queue budget is full.
        dispatch_stdout_message(
            &in_flight,
            &stdin_tx,
            &alive,
            &notif_budget,
            &process_budget,
            make_notif(100, 2),
        )
        .unwrap();
        assert_eq!(notif_budget.used(), total_capacity);

        let q1 = rx1.try_recv().unwrap();
        assert_eq!(q1.line.len(), 450);
        assert_eq!(notif_budget.used(), total_capacity);
        drop(q1);
        assert_eq!(notif_budget.used(), cloned_capacity);
        assert!(rx1.try_recv().is_err());

        // Dropping rx2 releases its queued copy.
        drop(rx2);
        assert_eq!(notif_budget.used(), 0);
    }

    #[tokio::test]
    async fn shutdown_waits_for_unregistered_spawn_reservation() {
        let up = Arc::new(
            StdioUpstream::new(StdioUpstreamSettings {
                command: "unused".into(),
                args: Vec::new(),
                env: std::collections::BTreeMap::new(),
                cwd: None,
                max_sessions: 1,
                session_idle_secs: 60,
            })
            .unwrap(),
        );
        let slot = acquire_slot(&up.inner, "g").await.unwrap();
        let stopping = Arc::clone(&up);
        let shutdown = tokio::spawn(async move { stopping.shutdown().await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !up.inner.table.lock().unwrap().shutting_down {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            !shutdown.is_finished(),
            "reserved spawn must finish cleanup before shutdown"
        );
        drop(slot);
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(up.inner.table.lock().unwrap().used_slots(), 0);
    }

    #[cfg(windows)]
    mod windows_spawn_tests {
        use super::*;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::path::Path;
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, ResumeThread, SuspendThread, WaitForSingleObject,
        };

        fn upstream(dir: &Path) -> StdioUpstream {
            StdioUpstream::new(StdioUpstreamSettings {
                command: "python".to_owned(),
                args: vec![
                    "-u".to_owned(),
                    "-c".to_owned(),
                    r#"import json, os, pathlib, subprocess, sys, time
helper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
pathlib.Path("tree.json").write_text(json.dumps([os.getpid(), helper.pid]))
time.sleep(120)
"#
                    .to_owned(),
                ],
                env: std::collections::BTreeMap::new(),
                cwd: Some(dir.to_owned()),
                max_sessions: 1,
                session_idle_secs: 60,
            })
            .unwrap()
        }

        fn process_handle(pid: u32) -> OwnedHandle {
            let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            assert!(
                !raw.is_null(),
                "OpenProcess({pid}): {}",
                io::Error::last_os_error()
            );
            unsafe { OwnedHandle::from_raw_handle(raw) }
        }

        fn wait_tree(dir: &Path) -> [u32; 2] {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Ok(bytes) = std::fs::read(dir.join("tree.json"))
                    && let Ok(pids) = serde_json::from_slice(&bytes)
                {
                    return pids;
                }
                assert!(Instant::now() < deadline, "child must run after resume");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn assert_exited(process: &OwnedHandle) {
            assert_eq!(
                unsafe { WaitForSingleObject(process.as_raw_handle(), 5000) },
                WAIT_OBJECT_0
            );
        }

        fn assert_empty(up: &StdioUpstream) {
            let table = up.inner.table.lock().unwrap();
            assert_eq!(table.used_slots(), 0);
            assert!(table.live_sessions.is_empty());
        }

        #[tokio::test]
        async fn suspended_spawn_joins_job_before_running_and_reaps_tree_and_slot() {
            let dir = tempfile::tempdir().unwrap();
            let up = upstream(dir.path());
            let marker = dir.path().join("tree.json");
            let checks = Arc::new(AtomicUsize::new(0));
            let checked = Arc::clone(&checks);
            *up.inner.spawn_hook.lock().unwrap() = Some(Box::new(move |stage, job, child| {
                // This hook gates the actual StdioSession::spawn path before assignment/resume.
                assert!(!marker.exists());
                let mut in_job = 0;
                assert_ne!(
                    unsafe { IsProcessInJob(child.raw_handle().unwrap(), job.0, &mut in_job) },
                    0
                );
                assert_eq!(in_job != 0, stage == WindowsSpawnStage::BeforeResume);
                with_owned_child_threads(child.id().unwrap(), |thread| {
                    let previous = unsafe { SuspendThread(thread) };
                    if previous == u32::MAX {
                        return Err(io::Error::last_os_error());
                    }
                    let restored = unsafe { ResumeThread(thread) };
                    assert_eq!(restored, previous + 1);
                    assert_eq!(
                        previous, 1,
                        "child must already be suspended at the spawn gate"
                    );
                    Ok(())
                })
                .map_err(|e| e.to_string())?;
                checked.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }));

            let slot = acquire_slot(&up.inner, "g").await.unwrap();
            let (_session, mut guard) = StdioSession::spawn(&up.inner, "g".into(), 0, slot)
                .await
                .unwrap();
            assert_eq!(checks.load(Ordering::Relaxed), 2);
            let pids = wait_tree(dir.path());
            let leader = process_handle(pids[0]);
            let helper = process_handle(pids[1]);
            assert_eq!(up.inner.table.lock().unwrap().reserved_slots, 1);
            guard.terminate_now().await;
            assert_exited(&leader);
            assert_exited(&helper);
            assert_empty(&up);
            let reused = acquire_slot(&up.inner, "next")
                .await
                .expect("reaped slot must be reusable");
            drop(reused);
            up.shutdown().await;
            assert_empty(&up);
        }

        #[tokio::test]
        async fn failed_assignment_or_resume_reaps_child_and_releases_slot() {
            for stage in [
                WindowsSpawnStage::BeforeAssign,
                WindowsSpawnStage::BeforeResume,
            ] {
                let dir = tempfile::tempdir().unwrap();
                let up = upstream(dir.path());
                let child_handle = Arc::new(Mutex::new(None));
                let observed = Arc::clone(&child_handle);
                *up.inner.spawn_hook.lock().unwrap() = Some(Box::new(move |at, _job, child| {
                    if at != stage {
                        return Ok(());
                    }
                    *observed.lock().unwrap() = Some(process_handle(child.id().unwrap()));
                    if stage == WindowsSpawnStage::BeforeAssign {
                        // Exercise the real assignment error, then the production failure cleanup.
                        WindowsJobObject(std::ptr::null_mut()).assign(child)
                    } else {
                        Err("injected ResumeThread failure".to_owned())
                    }
                }));
                let slot = acquire_slot(&up.inner, "g").await.unwrap();
                let result = StdioSession::spawn(&up.inner, "g".into(), 0, slot).await;
                assert!(result.is_err());
                assert_exited(child_handle.lock().unwrap().as_ref().unwrap());
                assert!(!dir.path().join("tree.json").exists());
                assert_empty(&up);
                up.shutdown().await;
            }
        }

        #[tokio::test]
        async fn cancelled_failed_spawn_keeps_slot_and_shutdown_waits_for_reap() {
            let dir = tempfile::tempdir().unwrap();
            let up = Arc::new(upstream(dir.path()));
            let process = Arc::new(Mutex::new(None));
            let observed = Arc::clone(&process);
            *up.inner.spawn_hook.lock().unwrap() = Some(Box::new(move |stage, _job, child| {
                if stage == WindowsSpawnStage::BeforeAssign {
                    *observed.lock().unwrap() = Some(process_handle(child.id().unwrap()));
                    return Err("injected assignment failure".into());
                }
                Ok(())
            }));
            let (entered, waiting) = oneshot::channel();
            let (resume, gate) = oneshot::channel();
            *up.inner.failed_spawn_reap_gate.lock().unwrap() = Some((entered, gate));
            let slot = acquire_slot(&up.inner, "g").await.unwrap();
            let spawning = Arc::clone(&up.inner);
            let caller =
                tokio::spawn(
                    async move { StdioSession::spawn(&spawning, "g".into(), 0, slot).await },
                );
            tokio::time::timeout(Duration::from_secs(5), waiting)
                .await
                .unwrap()
                .unwrap();
            caller.abort();
            let _ = caller.await;
            {
                let table = up.inner.table.lock().unwrap();
                assert_eq!(table.reserved_slots, 0);
                assert_eq!(table.terminating_slots, 1);
                assert_eq!(table.used_slots(), 1);
                assert!(table.live_sessions.is_empty());
            }
            let stopping = Arc::clone(&up);
            let shutdown = tokio::spawn(async move { stopping.shutdown().await });
            tokio::time::timeout(Duration::from_secs(1), async {
                while !up.inner.table.lock().unwrap().shutting_down {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(
                !shutdown.is_finished(),
                "shutdown must await the paused reaper"
            );
            resume.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), shutdown)
                .await
                .unwrap()
                .unwrap();
            assert_exited(process.lock().unwrap().as_ref().unwrap());
            assert_empty(&up);
        }

        #[tokio::test]
        async fn failed_start_after_resume_also_reaps_descendants() {
            let dir = tempfile::tempdir().unwrap();
            let up = upstream(dir.path());
            let marker_dir = dir.path().to_owned();
            let processes = Arc::new(Mutex::new(Vec::new()));
            let observed = Arc::clone(&processes);
            *up.inner.spawn_hook.lock().unwrap() = Some(Box::new(move |stage, _job, child| {
                if stage == WindowsSpawnStage::BeforeResume {
                    resume_windows_child(child)?;
                    let pids = wait_tree(&marker_dir);
                    *observed.lock().unwrap() = pids.into_iter().map(process_handle).collect();
                    return Err("injected failure after partial resume".to_owned());
                }
                Ok(())
            }));
            let slot = acquire_slot(&up.inner, "g").await.unwrap();
            assert!(
                StdioSession::spawn(&up.inner, "g".into(), 0, slot)
                    .await
                    .is_err()
            );
            {
                let handles = processes.lock().unwrap();
                assert_eq!(handles.len(), 2);
                for process in handles.iter() {
                    assert_exited(process);
                }
            }
            assert_empty(&up);
            up.shutdown().await;
        }
    }

    #[tokio::test]
    async fn shutdown_does_not_wait_for_a_retained_ephemeral_response_guard() {
        let up = StdioUpstream::new(StdioUpstreamSettings {
            command: if cfg!(windows) { "python" } else { "python3" }.into(),
            args: vec!["-c".into(), "import time; time.sleep(10)".into()],
            env: std::collections::BTreeMap::new(),
            cwd: None,
            max_sessions: 1,
            session_idle_secs: 60,
        })
        .unwrap();
        let slot = acquire_slot(&up.inner, "g").await.unwrap();
        let (session, guard) = StdioSession::spawn(&up.inner, "g".into(), 0, slot)
            .await
            .unwrap();
        assert_eq!(up.inner.table.lock().unwrap().pending_spawns, 0);
        // A downstream may retain its response body after shutdown has reaped the process.
        let stopped = tokio::time::timeout(Duration::from_secs(3), up.shutdown()).await;
        let child_reaped = session.child.lock().await.is_none();
        drop(guard);
        up.shutdown().await;
        assert!(
            stopped.is_ok(),
            "a retained response guard must not block shutdown"
        );
        assert!(child_reaped);
        let table = up.inner.table.lock().unwrap();
        assert_eq!(table.used_slots(), 0);
        assert!(table.live_sessions.is_empty());
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

    #[tokio::test]
    async fn events_stream_accept_negotiation_and_406_before_dispatch() {
        let accepts = |raw: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(value) = raw {
                headers.insert(header::ACCEPT, value.parse().unwrap());
            }
            client_accepts_sse(&headers)
        };
        assert!(accepts(Some("text/event-stream")));
        assert!(accepts(Some("application/json, text/event-stream; q=0.5")));
        assert!(accepts(Some("text/event-stream; charset=utf-8; q=1.0")));
        assert!(!accepts(None));
        assert!(!accepts(Some("application/json")));
        assert!(!accepts(Some("*/*")));
        assert!(!accepts(Some("text/*")));
        assert!(!accepts(Some("text/event-stream; q=0")));
        assert!(!accepts(Some("text/event-stream; q = 0.000")));
        assert!(!accepts(Some("text/event-stream; Q=0")));
        assert!(!accepts(Some("text/event-stream; q=NaN")));
        assert!(!accepts(Some("text/event-stream; q=inf")));
        assert!(!accepts(Some("text/event-stream; q=infinity")));
        assert!(!accepts(Some("text/event-stream; q=-0.5")));
        assert!(!accepts(Some("text/event-stream; q=invalid")));

        let budget = ByteBudget::new(8192);
        let up = StdioUpstream::with_limits(
            StdioUpstreamSettings {
                command: "nonexistent-should-not-spawn".to_owned(),
                args: Vec::new(),
                env: std::collections::BTreeMap::new(),
                cwd: None,
                max_sessions: 1,
                session_idle_secs: 30,
            },
            Arc::clone(&budget),
            StdioLimits::default(),
        )
        .unwrap();
        let token = VerifiedToken {
            grant_id: "g".to_owned(),
            client_id: "c".to_owned(),
            pool_slot: 0,
            scopes: vec!["mcp".to_owned()],
            resource: "https://mcp.example.com/mcp".to_owned(),
        };
        let payload = json!({
            "jsonrpc": "2.0",
            "id": "sub-1",
            "method": "events/stream",
            "params": {}
        });

        // Sessionless rejects before acquiring a slot or spawning a child.
        for bad_accept in ["application/json", "text/event-stream; q=0"] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, bad_accept.parse().unwrap());
            let reply = up
                .handle_sessionless(
                    &headers,
                    &token,
                    &payload,
                    Some("events/stream"),
                    Some(&payload["id"]),
                )
                .await;
            assert_eq!(reply.status(), StatusCode::NOT_ACCEPTABLE, "{bad_accept}");
            drop(reply);
            let tbl = up.inner.table.lock().unwrap();
            assert_eq!(tbl.used_slots(), 0);
            assert!(tbl.live_sessions.is_empty());
        }

        // Sessionful rejects before registering in-flight or writing stdin.
        let session = request_test_session(&budget);
        let (tx, mut rx) = mpsc::channel(4);
        *session.stdin_tx.lock().unwrap() = Some(tx);
        up.inner
            .table
            .lock()
            .unwrap()
            .sessions
            .insert("sid-1".to_owned(), Arc::clone(&session));
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "text/event-stream; q=0".parse().unwrap());
        let reply = up
            .handle_in_session(
                "sid-1",
                &headers,
                &token,
                &payload,
                Some("events/stream"),
                Some(&payload["id"]),
            )
            .await;
        assert_eq!(reply.status(), StatusCode::NOT_ACCEPTABLE);
        drop(reply);
        assert!(session.in_flight.lock().unwrap().is_empty());
        assert_eq!(session.active_requests.load(Ordering::Acquire), 0);
        assert!(rx.try_recv().is_err());

        up.inner.table.lock().unwrap().sessions.clear();
        up.shutdown().await;
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn events_routing_rewrites_ids_preserves_types_and_isolates_invalid_notices() {
        let budget = ByteBudget::new(64 * 1024);
        let notif_budget = ByteBudget::new(64 * 1024);
        let session = request_test_session(&budget);

        let (w_num, g_num, rx_num, resp_num) = session
            .register_request_opts(&json!(42), None, true, Some("sid".into()))
            .unwrap();
        let (w_str, g_str, rx_str, resp_str) = session
            .register_request_opts(&json!("42"), None, true, Some("sid".into()))
            .unwrap();
        let (w_ord, mut g_ord, rx_ord, _resp_ord) = session
            .register_request_opts(&json!("ord"), None, false, Some("sid".into()))
            .unwrap();

        let dispatch = |msg: Value| {
            dispatch_stdout_message(
                &session.in_flight,
                &session.stdin_tx,
                &session.alive,
                &notif_budget,
                &budget,
                msg,
            )
            .unwrap();
        };

        // All five push notices route only to their matching Events waiter with exact original ID types.
        for method in [
            "notifications/events/active",
            "notifications/events/event",
            "notifications/events/heartbeat",
            "notifications/events/error",
            "notifications/events/terminated",
        ] {
            dispatch(json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": { "_meta": { SUBSCRIPTION_ID_META_KEY: w_num }, "seq": 1 }
            }));
            dispatch(json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": { "_meta": { SUBSCRIPTION_ID_META_KEY: w_str }, "seq": 2 }
            }));
        }

        // Missing, string-typed, unknown, and non-Events-wire-id push notices are ignored.
        dispatch(json!({
            "jsonrpc": "2.0",
            "method": "notifications/events/event",
            "params": { "seq": 99 }
        }));
        dispatch(json!({
            "jsonrpc": "2.0",
            "method": "notifications/events/event",
            "params": { "_meta": { SUBSCRIPTION_ID_META_KEY: w_num.to_string() } }
        }));
        dispatch(json!({
            "jsonrpc": "2.0",
            "method": "notifications/events/event",
            "params": { "_meta": { SUBSCRIPTION_ID_META_KEY: 9999 } }
        }));
        dispatch(json!({
            "jsonrpc": "2.0",
            "method": "notifications/events/event",
            "params": { "_meta": { SUBSCRIPTION_ID_META_KEY: w_ord } }
        }));

        // Ordinary waiter must not have received any Events push notices.
        assert!(rx_ord.try_recv().is_err());

        // notifications/events/list_changed keeps generic broadcast behavior.
        dispatch(json!({
            "jsonrpc": "2.0",
            "method": "notifications/events/list_changed",
            "params": {}
        }));
        let ord_list_changed: Value =
            serde_json::from_str(&rx_ord.try_recv().unwrap().line).unwrap();
        assert_eq!(
            ord_list_changed["method"],
            "notifications/events/list_changed"
        );

        // Valid completion for numeric waiter rewrites both top-level id and subscriptionId.
        dispatch(json!({
            "jsonrpc": "2.0",
            "id": w_num,
            "result": {
                "resultType": "complete",
                "_meta": { SUBSCRIPTION_ID_META_KEY: w_num }
            }
        }));
        let mut body_num = StdioSseStreamBody::new(
            rx_num,
            resp_num,
            g_num,
            Arc::clone(&session),
            Duration::from_secs(30),
            None,
        );
        let mut raw_num = Vec::new();
        while let Some(frame) = body_num.frame().await {
            raw_num.extend_from_slice(&frame.unwrap().into_data().unwrap());
        }
        let frames_num: Vec<Value> = std::str::from_utf8(&raw_num)
            .unwrap()
            .split("\n\n")
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| serde_json::from_str(chunk.strip_prefix("data: ").unwrap()).unwrap())
            .collect();
        assert_eq!(frames_num.len(), 7);
        for frame in &frames_num[..5] {
            assert_eq!(
                frame["params"]["_meta"][SUBSCRIPTION_ID_META_KEY],
                json!(42)
            );
            assert!(frame["params"]["_meta"][SUBSCRIPTION_ID_META_KEY].is_u64());
        }
        assert_eq!(frames_num[5]["method"], "notifications/events/list_changed");
        assert_eq!(frames_num[6]["id"], json!(42));
        assert!(frames_num[6]["id"].is_u64());
        assert_eq!(
            frames_num[6]["result"]["_meta"][SUBSCRIPTION_ID_META_KEY],
            json!(42)
        );
        assert!(frames_num[6]["result"]["_meta"][SUBSCRIPTION_ID_META_KEY].is_u64());

        // JSON-RPC error response for string waiter restores exact string id.
        dispatch(json!({
            "jsonrpc": "2.0",
            "id": w_str,
            "error": { "code": -32000, "message": "upstream failed" }
        }));
        let mut body_str = StdioSseStreamBody::new(
            rx_str,
            resp_str,
            g_str,
            Arc::clone(&session),
            Duration::from_secs(30),
            None,
        );
        let mut raw_str = Vec::new();
        while let Some(frame) = body_str.frame().await {
            raw_str.extend_from_slice(&frame.unwrap().into_data().unwrap());
        }
        let frames_str: Vec<Value> = std::str::from_utf8(&raw_str)
            .unwrap()
            .split("\n\n")
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| serde_json::from_str(chunk.strip_prefix("data: ").unwrap()).unwrap())
            .collect();
        assert_eq!(frames_str.len(), 7);
        for frame in &frames_str[..5] {
            assert_eq!(
                frame["params"]["_meta"][SUBSCRIPTION_ID_META_KEY],
                json!("42")
            );
            assert!(frame["params"]["_meta"][SUBSCRIPTION_ID_META_KEY].is_string());
        }
        assert_eq!(frames_str[6]["id"], json!("42"));
        assert!(frames_str[6]["id"].is_string());
        assert_eq!(frames_str[6]["error"]["message"], "upstream failed");

        // Malformed completions fail the stream without leaking child ID.
        for bad_result in [
            json!({"_meta": { SUBSCRIPTION_ID_META_KEY: 1 }}),
            json!({"resultType": "partial", "_meta": { SUBSCRIPTION_ID_META_KEY: 1 }}),
            json!({"resultType": "complete"}),
            json!({"resultType": "complete", "_meta": { SUBSCRIPTION_ID_META_KEY: 9999 }}),
            json!({"resultType": "complete", "_meta": { SUBSCRIPTION_ID_META_KEY: "1" }}),
        ] {
            let (wid, guard, rx, resp) = session
                .register_request_opts(&json!("bad"), None, true, Some("sid".into()))
                .unwrap();
            let mut result = bad_result;
            if let Some(meta) = result.get_mut("_meta").and_then(Value::as_object_mut)
                && meta.get(SUBSCRIPTION_ID_META_KEY) == Some(&json!(1))
            {
                meta.insert(SUBSCRIPTION_ID_META_KEY.to_owned(), json!(wid));
            }
            dispatch(json!({ "jsonrpc": "2.0", "id": wid, "result": result }));
            let mut body = StdioSseStreamBody::new(
                rx,
                resp,
                guard,
                Arc::clone(&session),
                Duration::from_secs(30),
                None,
            );
            let err = body.frame().await.expect("must yield error").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Other);
        }

        g_ord.disarm();
        drop(rx_ord);
        assert_eq!(session.active_requests.load(Ordering::Acquire), 0);
        assert_eq!(notif_budget.used(), 0);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn events_completion_keeps_subscription_id_copy_leased_until_encoding() {
        for enough_room in [false, true] {
            let budget = ByteBudget::new(4096);
            let notif_budget = ByteBudget::new(4096);
            let session = request_test_session(&budget);
            let client_id = json!("complete-request");
            let (wire_id, mut guard, notifications, mut response) = session
                .register_request_opts(&client_id, None, true, None)
                .unwrap();
            let upstream = json!({
                "jsonrpc": "2.0",
                "id": wire_id,
                "result": {
                    "resultType": "complete",
                    "_meta": { SUBSCRIPTION_ID_META_KEY: wire_id }
                }
            });
            let restored = json!({
                "jsonrpc": "2.0",
                "id": client_id,
                "result": {
                    "resultType": "complete",
                    "_meta": { SUBSCRIPTION_ID_META_KEY: client_id }
                }
            });
            let mut parsed =
                LeasedJson::parse(&serde_json::to_vec(&upstream).unwrap(), &budget).unwrap();
            let encoded_len = json_encoded_len(&restored).unwrap();
            let copy_bytes = json_text_capacity(&client_id);
            let available = encoded_len + copy_bytes - usize::from(!enough_room);
            let retained = budget
                .try_acquire(budget.limit() - budget.used() - available)
                .unwrap();

            dispatch_stdout_message(
                &session.in_flight,
                &session.stdin_tx,
                &session.alive,
                &notif_budget,
                &budget,
                std::mem::take(&mut parsed.value),
            )
            .unwrap();

            if enough_room {
                let RespDelivery::Ok { json_bytes, lease } = response.try_recv().unwrap() else {
                    panic!("complete with enough overlap capacity must succeed");
                };
                assert_eq!(
                    serde_json::from_slice::<Value>(&json_bytes).unwrap(),
                    restored
                );
                assert_eq!(
                    budget.used(),
                    retained.held() + parsed._lease.held() + json_bytes.capacity()
                );
                drop(json_bytes);
                drop(lease);
                guard.mark_completed();
            } else {
                assert_eq!(
                    notifications.take_failure().as_deref(),
                    Some("process active byte budget exceeded"),
                    "encoding cannot reuse the live subscription ID copy's capacity"
                );
                assert!(matches!(
                    response.try_recv(),
                    Err(oneshot::error::TryRecvError::Closed)
                ));
                assert_eq!(budget.used(), retained.held() + parsed._lease.held());
            }
            assert_eq!(session.active_requests.load(Ordering::Acquire), 0);
            assert!(session.in_flight.lock().unwrap().is_empty());
            drop(parsed);
            drop(retained);
            drop(guard);
            assert_eq!(budget.used(), 0);
        }
    }

    #[tokio::test]
    async fn events_oversized_completion_never_bypasses_into_raw_splice() {
        let budget = ByteBudget::new(8 * 1024);
        let limits = StdioLimits {
            max_control_line_bytes: 256,
            max_stdout_line_bytes: 64 * 1024,
            ..StdioLimits::default()
        };
        let session = request_test_session(&budget);

        // Register Events waiter (id-first oversized), Events waiter (id-last oversized), and ordinary sibling.
        let (w_first, g_first, rx_first, resp_first) = session
            .register_request_opts(&json!("ev-first"), None, true, Some("sid".into()))
            .unwrap();
        let (w_last, g_last, rx_last, resp_last) = session
            .register_request_opts(&json!("ev-last"), None, true, Some("sid".into()))
            .unwrap();
        let (w_ord, mut g_ord, _rx_ord, resp_ord) = session
            .register_request_opts(&json!("ord-big"), None, false, Some("sid".into()))
            .unwrap();

        // 1. id-first oversized Events completion > budget (12 KiB > 8 KiB budget) is discarded while scanning.
        let line_first = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{w_first},\"result\":{{\"resultType\":\"complete\",\"_meta\":{{\"{SUBSCRIPTION_ID_META_KEY}\":{w_first}}},\"pad\":\"{}\"}}}}\n",
            "A".repeat(12 * 1024)
        );
        let mut reader = BufReader::new(line_first.as_bytes());
        let outcome = read_stdout_line(&mut reader, &session.in_flight, &budget, limits)
            .await
            .unwrap();
        assert!(outcome.discarded);
        assert!(outcome.len > limits.max_control_line_bytes);
        dispatch_large_response_line(outcome, &session.in_flight);
        let mut body_first = StdioSseStreamBody::new(
            rx_first,
            resp_first,
            g_first,
            Arc::clone(&session),
            Duration::from_secs(30),
            None,
        );
        assert!(body_first.frame().await.unwrap().is_err());

        // 2. id-last oversized Events completion (fits budget, > control limit) is rejected without raw splice.
        let line_last = format!(
            "{{\"jsonrpc\":\"2.0\",\"result\":{{\"resultType\":\"complete\",\"_meta\":{{\"{SUBSCRIPTION_ID_META_KEY}\":{w_last}}},\"pad\":\"{}\"}},\"id\":{w_last}}}\n",
            "B".repeat(1024)
        );
        let mut reader = BufReader::new(line_last.as_bytes());
        let outcome = read_stdout_line(&mut reader, &session.in_flight, &budget, limits)
            .await
            .unwrap();
        assert!(outcome.len > limits.max_control_line_bytes);
        dispatch_large_response_line(outcome, &session.in_flight);
        let mut body_last = StdioSseStreamBody::new(
            rx_last,
            resp_last,
            g_last,
            Arc::clone(&session),
            Duration::from_secs(30),
            None,
        );
        assert!(body_last.frame().await.unwrap().is_err());

        // 3. Ordinary sibling still uses the raw splice path cleanly.
        let line_ord = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{w_ord},\"result\":\"{}\"}}\n",
            "C".repeat(1024)
        );
        let mut reader = BufReader::new(line_ord.as_bytes());
        let outcome = read_stdout_line(&mut reader, &session.in_flight, &budget, limits)
            .await
            .unwrap();
        dispatch_large_response_line(outcome, &session.in_flight);
        g_ord.mark_completed();
        let RespDelivery::Ok { json_bytes, lease } = resp_ord.await.unwrap() else {
            panic!("ordinary sibling must succeed");
        };
        let parsed: Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["id"], "ord-big");
        drop(json_bytes);
        drop(lease);
        drop(body_first);
        drop(body_last);
        assert_eq!(session.active_requests.load(Ordering::Acquire), 0);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn events_delivery_failure_drains_unpolled_body_and_zeros_budgets() {
        let budget = ByteBudget::new(32 * 1024);
        let session = request_test_session(&budget);
        let (tx, mut stdin_rx) = mpsc::channel(4);
        *session.stdin_tx.lock().unwrap() = Some(tx);

        let (w_ev, g_ev, rx_ev, resp_ev) = session
            .register_request_opts(&json!("ev-1"), None, true, Some("sid".into()))
            .unwrap();
        let (w_sib, mut g_sib, rx_sib, _resp_sib) = session
            .register_request_opts(&json!("ev-2"), None, true, Some("sid".into()))
            .unwrap();

        let make_event = |wid: u64, cursor: usize| {
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/events/event",
                "params": {
                    "_meta": { SUBSCRIPTION_ID_META_KEY: wid },
                    "cursor": cursor,
                    "data": "x".repeat(120)
                }
            })
        };
        let sample_len = json_encoded_len(&make_event(w_ev, 1)).unwrap();
        // Fit one queued frame, fail the second queued frame.
        let notif_budget = ByteBudget::new(sample_len + 16);

        let mut body_ev = StdioSseStreamBody::new(
            rx_ev,
            resp_ev,
            g_ev,
            Arc::clone(&session),
            Duration::from_secs(30),
            None,
        );

        // Frame 1 is polled and held by HTTP transport.
        dispatch_stdout_message(
            &session.in_flight,
            &session.stdin_tx,
            &session.alive,
            &notif_budget,
            &budget,
            make_event(w_ev, 1),
        )
        .unwrap();
        let held_by_transport = body_ev.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(notif_budget.used(), 0);
        let transport_bytes = held_by_transport.len();

        // Frame 2 sits queued in gateway while client is slow/unpolled.
        dispatch_stdout_message(
            &session.in_flight,
            &session.stdin_tx,
            &session.alive,
            &notif_budget,
            &budget,
            make_event(w_ev, 2),
        )
        .unwrap();
        assert!(notif_budget.used() > 0);

        // Frame 3 exceeds notif_budget and fails the stream without waiting for another body poll.
        dispatch_stdout_message(
            &session.in_flight,
            &session.stdin_tx,
            &session.alive,
            &notif_budget,
            &budget,
            make_event(w_ev, 3),
        )
        .unwrap();
        assert_eq!(
            notif_budget.used(),
            0,
            "unsent gateway-owned frame 2 must be discarded immediately"
        );
        assert!(
            budget.used() >= transport_bytes,
            "frame 1 handed to transport stays leased"
        );

        // Entry is now in Stopping; later cursor is ignored, and a late final reply settles Stopping.
        assert!(
            session
                .in_flight
                .lock()
                .unwrap()
                .iter()
                .any(|w| w.wire_id == w_ev && matches!(w.state, InFlightState::Stopping(_)))
        );
        dispatch_stdout_message(
            &session.in_flight,
            &session.stdin_tx,
            &session.alive,
            &notif_budget,
            &budget,
            make_event(w_ev, 4),
        )
        .unwrap();
        dispatch_stdout_message(
            &session.in_flight,
            &session.stdin_tx,
            &session.alive,
            &notif_budget,
            &budget,
            json!({
                "jsonrpc": "2.0",
                "id": w_ev,
                "result": { "resultType": "complete", "_meta": { SUBSCRIPTION_ID_META_KEY: w_ev } }
            }),
        )
        .unwrap();
        assert!(
            !session
                .in_flight
                .lock()
                .unwrap()
                .iter()
                .any(|w| w.wire_id == w_ev)
        );

        // Sibling remains live and receives its event.
        dispatch_stdout_message(
            &session.in_flight,
            &session.stdin_tx,
            &session.alive,
            &notif_budget,
            &budget,
            make_event(w_sib, 1),
        )
        .unwrap();
        let sib_frame = rx_sib.try_recv().unwrap();
        drop(sib_frame);

        // Polling the failed body returns a transport error despite the late final reply.
        assert!(body_ev.frame().await.unwrap().is_err());

        // Drain cancel line from stdin queue and clean up sibling + transport frame.
        let cancel_line = stdin_rx.recv().await.unwrap();
        let cancel_json: Value = serde_json::from_slice(&cancel_line.bytes).unwrap();
        assert_eq!(cancel_json["method"], "notifications/cancelled");
        assert_eq!(cancel_json["params"]["requestId"], w_ev);
        drop(cancel_line);

        g_sib.disarm();
        drop(rx_sib);
        drop(body_ev);
        drop(held_by_transport);
        tokio::time::timeout(Duration::from_secs(1), async {
            while session.active_requests.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(notif_budget.used(), 0);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn stopping_entry_counts_toward_cap_and_settles_via_receipt_response_or_retires() {
        // Case A: delayed queue capacity -> flush receipt settles stop, child and sibling stay live.
        {
            let budget = ByteBudget::new(16 * 1024);
            let mut session = request_test_session(&budget);
            let limits = StdioLimits {
                stdin_write_timeout: Duration::from_millis(500),
                stdin_channel_capacity: 1,
                max_in_flight_per_session: 2,
                ..StdioLimits::default()
            };
            Arc::get_mut(&mut session).unwrap().limits = limits;
            let (tx, mut rx) = mpsc::channel(1);
            *session.stdin_tx.lock().unwrap() = Some(tx);

            let (w1, mut g1, _n1, _r1) = session
                .register_request_opts(&json!(1), None, true, Some("sid".into()))
                .unwrap();
            let (_w2, mut g2, _n2, _r2) = session
                .register_request_opts(&json!(2), None, true, Some("sid".into()))
                .unwrap();

            // Fill the 1-slot stdin queue so cancel waits for admission.
            session
                .send_raw_line(StdinLine {
                    bytes: Bytes::from_static(b"{}\n"),
                    flushed: None,
                })
                .unwrap();
            g1.cancel("client disconnected");

            // Stopping entry still counts toward max_in_flight_per_session (2).
            assert!(matches!(
                session.register_request_opts(&json!(3), None, false, Some("sid".into())),
                Err(SendLineErr::Full)
            ));

            // Free queue capacity and acknowledge flush receipt.
            let _filler = rx.recv().await.unwrap();
            let cancel = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            let cancel_json: Value = serde_json::from_slice(&cancel.bytes).unwrap();
            assert_eq!(cancel_json["params"]["requestId"], w1);
            cancel.flushed.unwrap().send(()).unwrap();

            tokio::time::timeout(Duration::from_secs(1), async {
                while session.in_flight.lock().unwrap().len() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(session.alive.load(Ordering::Acquire));
            g2.disarm();
            assert_eq!(session.active_requests.load(Ordering::Acquire), 0);
            assert_eq!(budget.used(), 0);
        }

        // Case B: valid final response arrives while cancel waits on full queue -> no retirement.
        {
            let budget = ByteBudget::new(16 * 1024);
            let mut session = request_test_session(&budget);
            Arc::get_mut(&mut session).unwrap().limits = StdioLimits {
                stdin_write_timeout: Duration::from_millis(80),
                stdin_channel_capacity: 1,
                ..StdioLimits::default()
            };
            let (tx, _rx_blocked) = mpsc::channel(1);
            *session.stdin_tx.lock().unwrap() = Some(tx);
            let (w1, mut g1, _n1, mut r1) = session
                .register_request_opts(&json!(1), None, true, Some("sid".into()))
                .unwrap();
            session
                .send_raw_line(StdinLine {
                    bytes: Bytes::from_static(b"{}\n"),
                    flushed: None,
                })
                .unwrap();
            g1.cancel("client disconnected");

            dispatch_stdout_message(
                &session.in_flight,
                &session.stdin_tx,
                &session.alive,
                &ByteBudget::new(4096),
                &budget,
                json!({
                    "jsonrpc": "2.0",
                    "id": w1,
                    "result": { "resultType": "complete", "_meta": { SUBSCRIPTION_ID_META_KEY: w1 } }
                }),
            )
            .unwrap();
            // Wait past stdin_write_timeout; child must NOT be retired and response must NOT leak.
            tokio::time::sleep(Duration::from_millis(120)).await;
            assert!(session.alive.load(Ordering::Acquire));
            assert!(r1.try_recv().is_err());
            assert!(session.in_flight.lock().unwrap().is_empty());
            assert_eq!(session.active_requests.load(Ordering::Acquire), 0);
            assert_eq!(budget.used(), 0);
        }

        // Case C: permanently stalled writer past deadline retires and reaps the shared session.
        {
            let budget = ByteBudget::new(16 * 1024);
            let limits = StdioLimits {
                stdin_write_timeout: Duration::from_millis(60),
                stdin_channel_capacity: 1,
                ..StdioLimits::default()
            };
            let up = StdioUpstream::with_limits(
                StdioUpstreamSettings {
                    command: "unused".to_owned(),
                    args: Vec::new(),
                    env: std::collections::BTreeMap::new(),
                    cwd: None,
                    max_sessions: 1,
                    session_idle_secs: 30,
                },
                Arc::clone(&budget),
                limits,
            )
            .unwrap();
            let mut session = request_test_session(&budget);
            {
                let s = Arc::get_mut(&mut session).unwrap();
                s.weak_inner = Arc::downgrade(&up.inner);
                s.limits = limits;
            }
            let (tx, _rx_stalled) = mpsc::channel(1);
            *session.stdin_tx.lock().unwrap() = Some(tx);
            {
                let mut tbl = up.inner.table.lock().unwrap();
                tbl.sessions
                    .insert("sid-stalled".to_owned(), Arc::clone(&session));
                tbl.live_sessions.push(Arc::clone(&session));
            }
            let (_w1, mut g1, _n1, _r1) = session
                .register_request_opts(&json!(1), None, true, Some("sid-stalled".into()))
                .unwrap();
            session
                .send_raw_line(StdinLine {
                    bytes: Bytes::from_static(b"{}\n"),
                    flushed: None,
                })
                .unwrap();
            g1.cancel("client disconnected");

            tokio::time::timeout(Duration::from_secs(2), async {
                while session.alive.load(Ordering::Acquire)
                    || up.inner.table.lock().unwrap().used_slots() != 0
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("stalled writer must trigger tracked session retirement at deadline");
            assert!(up.inner.table.lock().unwrap().sessions.is_empty());
            assert!(up.inner.table.lock().unwrap().live_sessions.is_empty());
            assert_eq!(session.active_requests.load(Ordering::Acquire), 0);
            up.shutdown().await;
            assert_eq!(budget.used(), 0);
        }
    }

    #[tokio::test]
    async fn events_stopping_ignores_malformed_and_oversized_completions_and_sessionless_skips_stopping()
     {
        let budget = ByteBudget::new(16 * 1024);
        let notif_budget = ByteBudget::new(4096);
        let limits = StdioLimits {
            max_control_line_bytes: 256,
            max_stdout_line_bytes: 16 * 1024,
            stdin_write_timeout: Duration::from_secs(2),
            stdin_channel_capacity: 1,
            ..StdioLimits::default()
        };
        let mut session = request_test_session(&budget);
        Arc::get_mut(&mut session).unwrap().limits = limits;
        let (tx, mut rx) = mpsc::channel(1);
        *session.stdin_tx.lock().unwrap() = Some(tx);

        // 1. Sessionless request without an attached ephemeral guard removes its slot immediately.
        let (_w_ephem, mut g_ephem, _n_ephem, _r_ephem) = session
            .register_request_opts(&json!("sessless"), None, true, None)
            .unwrap();
        g_ephem.cancel("client disconnected");
        assert!(session.in_flight.lock().unwrap().is_empty());
        assert_eq!(session.active_requests.load(Ordering::Acquire), 0);
        let _ephem_cancel = rx.recv().await.unwrap();

        // 2. Shared session Events entry in Stopping ignores malformed and oversized completions.
        let (w_ev, mut g_ev, _n_ev, _r_ev) = session
            .register_request_opts(&json!("ev-stop"), None, true, Some("sid".into()))
            .unwrap();
        session
            .send_raw_line(StdinLine {
                bytes: Bytes::from_static(b"{}\n"),
                flushed: None,
            })
            .unwrap();
        g_ev.cancel("client disconnected");
        assert!(
            session
                .in_flight
                .lock()
                .unwrap()
                .iter()
                .any(|w| w.wire_id == w_ev && matches!(w.state, InFlightState::Stopping(_)))
        );

        // Malformed completions must not settle the Stopping entry.
        for bad in [
            json!({"jsonrpc":"2.0","id":w_ev,"result":{"resultType":"partial","_meta":{SUBSCRIPTION_ID_META_KEY:w_ev}}}),
            json!({"jsonrpc":"2.0","id":w_ev,"result":{"resultType":"complete","_meta":{SUBSCRIPTION_ID_META_KEY:9999}}}),
            json!({"jsonrpc":"2.0","id":w_ev,"result":{}}),
        ] {
            dispatch_stdout_message(
                &session.in_flight,
                &session.stdin_tx,
                &session.alive,
                &notif_budget,
                &budget,
                bad,
            )
            .unwrap();
            assert_eq!(session.in_flight.lock().unwrap().len(), 1);
        }

        // Oversized Events completion must not settle the Stopping entry either.
        let big_line = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{w_ev},\"result\":{{\"resultType\":\"complete\",\"_meta\":{{\"{SUBSCRIPTION_ID_META_KEY}\":{w_ev}}},\"pad\":\"{}\"}}}}\n",
            "X".repeat(1024)
        );
        let mut reader = BufReader::new(big_line.as_bytes());
        let outcome = read_stdout_line(&mut reader, &session.in_flight, &budget, limits)
            .await
            .unwrap();
        dispatch_large_response_line(outcome, &session.in_flight);
        assert_eq!(session.in_flight.lock().unwrap().len(), 1);

        // A valid JSON-RPC error settles the Stopping entry and releases the slot.
        dispatch_stdout_message(
            &session.in_flight,
            &session.stdin_tx,
            &session.alive,
            &notif_budget,
            &budget,
            json!({"jsonrpc":"2.0","id":w_ev,"error":{"code":-32800,"message":"cancelled"}}),
        )
        .unwrap();
        assert!(session.in_flight.lock().unwrap().is_empty());
        tokio::time::timeout(Duration::from_secs(1), async {
            while session.active_requests.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(budget.used(), 0);
    }
}
