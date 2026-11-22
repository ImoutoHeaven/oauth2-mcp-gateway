mod common;

use bytes::Bytes;
use common::{TestClient, make_client, python_executable, spawn_http1_harness, wait_process_gone};
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use oauth2_mcp_gateway::config::StdioUpstreamSettings;
use oauth2_mcp_gateway::types::{
    ByteBudget, HttpReply, ReplyBody, VerifiedToken, bytes_body, empty_body,
};
use oauth2_mcp_gateway::upstream_stdio::{StdioLimits, StdioUpstream};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

const SUBSCRIPTION_ID_META: &str = "io.modelcontextprotocol/subscriptionId";
const PROTOCOL_VERSION: &str = "2026-07-28";

fn make_token(grant_id: &str) -> VerifiedToken {
    VerifiedToken {
        grant_id: grant_id.to_owned(),
        client_id: "lifecycle-test-client".to_owned(),
        pool_slot: 0,
        scopes: vec!["mcp".to_owned()],
        resource: "https://mcp.example.com/mcp".to_owned(),
    }
}

struct GateState {
    paused: bool,
    released: bool,
    waker: Option<Waker>,
    paused_tx: Option<oneshot::Sender<()>>,
}

struct FrameGate {
    state: Mutex<GateState>,
}

impl FrameGate {
    fn new() -> (Arc<Self>, oneshot::Receiver<()>) {
        let (tx, rx) = oneshot::channel();
        let gate = Arc::new(Self {
            state: Mutex::new(GateState {
                paused: false,
                released: false,
                waker: None,
                paused_tx: Some(tx),
            }),
        });
        (gate, rx)
    }

    fn release(&self) {
        let waker = {
            let mut g = self.state.lock().unwrap();
            g.released = true;
            g.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

// Delivers `pause_after` data frames, then leaves the inner body unpolled until released.
struct GatedBody {
    inner: ReplyBody,
    delivered: usize,
    pause_after: usize,
    gate: Arc<FrameGate>,
}

impl Body for GatedBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.delivered >= self.pause_after {
            let mut g = self.gate.state.lock().unwrap();
            if !g.released {
                g.paused = true;
                g.waker = Some(cx.waker().clone());
                if let Some(tx) = g.paused_tx.take() {
                    let _ = tx.send(());
                }
                return Poll::Pending;
            }
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.is_data() {
                    self.delivered += 1;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }
}

struct CapturedReply {
    status: StatusCode,
    headers: HeaderMap,
    body: ReplyBody,
}

#[derive(Default)]
struct HarnessControls {
    gates: Mutex<HashMap<String, (usize, Arc<FrameGate>)>>,
    captures: Mutex<HashMap<String, oneshot::Sender<CapturedReply>>>,
}

impl HarnessControls {
    fn register_gate(
        &self,
        key: &str,
        pause_after: usize,
    ) -> (Arc<FrameGate>, oneshot::Receiver<()>) {
        let (gate, paused_rx) = FrameGate::new();
        self.gates
            .lock()
            .unwrap()
            .insert(key.to_owned(), (pause_after, Arc::clone(&gate)));
        (gate, paused_rx)
    }

    fn register_capture(&self, key: &str) -> oneshot::Receiver<CapturedReply> {
        let (tx, rx) = oneshot::channel();
        self.captures.lock().unwrap().insert(key.to_owned(), tx);
        rx
    }
}

async fn spawn_controlled_stdio_harness(
    stdio_up: Arc<StdioUpstream>,
    grant_id: &'static str,
) -> (SocketAddr, CancellationToken, Arc<HarnessControls>) {
    let controls = Arc::new(HarnessControls::default());
    let controls_ref = Arc::clone(&controls);
    let (addr, cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&stdio_up);
        let ctrls = Arc::clone(&controls_ref);
        async move {
            let gate_key = req
                .headers()
                .get("x-test-gate")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let capture_key = req
                .headers()
                .get("x-test-capture")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);

            let reply: HttpReply = up.handle_mcp(req, &make_token(grant_id)).await;

            if let Some(key) = capture_key
                && let Some(tx) = ctrls.captures.lock().unwrap().remove(&key)
            {
                let (parts, body) = reply.into_parts();
                let _ = tx.send(CapturedReply {
                    status: parts.status,
                    headers: parts.headers,
                    body,
                });
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(empty_body())
                    .unwrap();
            }

            if let Some(key) = gate_key
                && let Some((pause_after, gate)) = ctrls.gates.lock().unwrap().remove(&key)
            {
                let (parts, body) = reply.into_parts();
                let gated = GatedBody {
                    inner: body,
                    delivered: 0,
                    pause_after,
                    gate,
                };
                return Response::from_parts(parts, gated.boxed());
            }

            reply
        }
    })
    .await;
    (addr, cancel, controls)
}

fn write_lifecycle_fixture(dir: &Path) -> PathBuf {
    let path = dir.join("events_lifecycle_fixture.py");
    let script = r#"import json
import os
import sys
import threading
import time

stdout_lock = threading.Lock()
state_lock = threading.Lock()

history = [
    {"cursor": "cur-1", "seq": 1, "payload": "evt-1"},
    {"cursor": "cur-2", "seq": 2, "payload": "evt-2"},
    {"cursor": "cur-3", "seq": 3, "payload": "evt-3"},
    {"cursor": "cur-4", "seq": 4, "payload": "evt-4"},
    {"cursor": "cur-5", "seq": 5, "payload": "evt-5"},
]

cancelled_ids = []
active_streams = {}
late_on_cancel = {}
stop_flag = threading.Event()
flag_dir = os.environ.get("TEST_FLAG_DIR", "")


def emit(obj):
    raw = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
    with stdout_lock:
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()


def emit_event_notice(kind, wire_id, params):
    p = dict(params)
    meta = dict(p.get("_meta", {}))
    meta["io.modelcontextprotocol/subscriptionId"] = wire_id
    p["_meta"] = meta
    emit({
        "jsonrpc": "2.0",
        "method": f"notifications/events/{kind}",
        "params": p,
    })


def emit_complete(wire_id, extra=None):
    res = {
        "resultType": "complete",
        "_meta": {"io.modelcontextprotocol/subscriptionId": wire_id},
    }
    if extra:
        res.update(extra)
    emit({"jsonrpc": "2.0", "id": wire_id, "result": res})


def watch_flags():
    final_sent = False
    while not stop_flag.is_set():
        if flag_dir and not final_sent:
            fp = os.path.join(flag_dir, "send_final.flag")
            if os.path.exists(fp):
                try:
                    with open(fp, "r", encoding="utf-8") as f:
                        target_tag = f.read().strip()
                except OSError:
                    target_tag = ""
                with state_lock:
                    wid = active_streams.get(target_tag)
                if wid is not None:
                    final_sent = True
                    emit_complete(wid, {"settled_via_flag": True})
        time.sleep(0.01)


if flag_dir:
    t = threading.Thread(target=watch_flags, daemon=True)
    t.start()


def pause_stdin_until_flag(flag_name):
    if not flag_dir or not flag_name:
        return
    target = os.path.join(flag_dir, flag_name)
    while not stop_flag.is_set() and not os.path.exists(target):
        time.sleep(0.01)


for raw_line in sys.stdin.buffer:
    line = raw_line.decode("utf-8", errors="replace").strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue

    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        emit({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "serverInfo": {"name": "events-lifecycle-fixture", "version": "1.0"},
            },
        })
        continue

    if method == "notifications/initialized" or method == "notifications/pad":
        continue

    if method == "notifications/cancelled":
        cid = params.get("requestId")
        with state_lock:
            cancelled_ids.append(cid)
            emit_late = late_on_cancel.pop(cid, False)
        if emit_late:
            emit_event_notice("event", cid, {"cursor": "late-cur", "data": "late-event"})
            emit_event_notice("heartbeat", cid, {"ts": 999999})
            emit_complete(cid, {"late": True})
        continue

    if method == "events/poll":
        cursor = params.get("cursor")
        idx = 0
        if cursor is not None:
            for i, item in enumerate(history):
                if item["cursor"] == cursor:
                    idx = i + 1
                    break
        emit({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "events": history[idx:],
                "nextCursor": history[-1]["cursor"],
            },
        })
        continue

    if method == "events/stream":
        tag = params.get("tag", "")
        with state_lock:
            if tag:
                active_streams[tag] = req_id
            if params.get("emit_late_on_cancel"):
                late_on_cancel[req_id] = True

        emit_event_notice("active", req_id, {
            "pid": os.getpid(),
            "wireId": req_id,
            "tag": tag,
        })

        mode = params.get("mode", "hold")
        if mode == "first_then_hold":
            emit_event_notice("event", req_id, history[0])
        elif mode == "replay":
            cursor = params.get("cursor")
            idx = 0
            if cursor is not None:
                for i, item in enumerate(history):
                    if item["cursor"] == cursor:
                        idx = i + 1
                        break
            for item in history[idx:]:
                emit_event_notice("event", req_id, item)
            emit_complete(req_id, {"replayed": True})
        elif mode == "single_sized_then_complete":
            pad_len = int(params.get("pad_bytes", 128))
            emit_event_notice("event", req_id, {"cursor": "sized-1", "pad": "x" * pad_len})
            emit_complete(req_id, {"sized": True})
        elif mode == "overflow_after_flag":
            gate_flag = params.get("gate_flag", "go_overflow.flag")
            count = int(params.get("count", 8))
            pad_len = int(params.get("pad_bytes", 320))
            def _bg_overflow(wid=req_id, gflag=gate_flag, cnt=count, plen=pad_len):
                if flag_dir and gflag:
                    target = os.path.join(flag_dir, gflag)
                    while not stop_flag.is_set() and not os.path.exists(target):
                        time.sleep(0.01)
                for i in range(cnt):
                    emit_event_notice("event", wid, {"cursor": f"ov-{i}", "pad": "a" * plen})
                emit_event_notice("heartbeat", wid, {"ts": 12345})
            threading.Thread(target=_bg_overflow, daemon=True).start()
        elif mode == "pause_stdin_after_active":
            pause_stdin_until_flag(params.get("resume_flag", "never_exists.flag"))
        continue

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}

        if name == "ping":
            emit({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"ok": True, "pid": os.getpid(), "tag": args.get("tag", "")},
            })
            continue

        if name == "get_cancels":
            with state_lock:
                cids = list(cancelled_ids)
            emit({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"cancelled": cids, "pid": os.getpid()},
            })
            continue

        if name == "push_overflow":
            tag = args["tag"]
            with state_lock:
                wid = active_streams.get(tag)
            if wid is not None:
                start_idx = int(args.get("history_start", 1))
                pad_len = int(args.get("pad_bytes", 350))
                if args.get("use_history", False):
                    for item in history[start_idx:]:
                        ev = dict(item)
                        ev["pad"] = "p" * pad_len
                        emit_event_notice("event", wid, ev)
                else:
                    count = int(args.get("count", 8))
                    for i in range(count):
                        emit_event_notice("event", wid, {"cursor": f"burst-{i}", "pad": "b" * pad_len})
                if args.get("send_heartbeat", True):
                    emit_event_notice("heartbeat", wid, {"ts": 4242})
                if args.get("send_late_complete", False):
                    emit_complete(wid, {"raced": True})
            emit({"jsonrpc": "2.0", "id": req_id, "result": {"pushed": wid is not None}})
            continue

        if name == "push_stream_event_and_complete":
            tag = args["tag"]
            with state_lock:
                wid = active_streams.get(tag)
            if wid is not None:
                emit_event_notice("event", wid, {"cursor": args.get("cursor", "sib-1"), "ok": True})
                if args.get("complete", True):
                    emit_complete(wid, {"sibling_done": True})
            emit({"jsonrpc": "2.0", "id": req_id, "result": {"sent": wid is not None}})
            continue

        if name == "complete_stream":
            tag = args["tag"]
            with state_lock:
                wid = active_streams.get(tag)
            if wid is not None:
                emit_complete(wid, {"completed": True})
            emit({"jsonrpc": "2.0", "id": req_id, "result": {"completed": wid is not None}})
            continue

        if name == "pause_stdin":
            resume_flag = args.get("resume_flag", "resume_stdin.flag")
            emit({"jsonrpc": "2.0", "id": req_id, "result": {"paused": True, "pid": os.getpid()}})
            pause_stdin_until_flag(resume_flag)
            continue

        if name == "ordinary_notif_flood":
            count = int(args.get("count", 40))
            pad_len = int(args.get("pad_bytes", 400))
            gate_flag = args.get("burst_flag")
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {
                    "seq": 0,
                    "data": "first",
                    "_meta": {"relatedRequestId": req_id},
                },
            })
            def _bg_flood(wid=req_id, cnt=count, plen=pad_len, gflag=gate_flag):
                if gflag and flag_dir:
                    target = os.path.join(flag_dir, gflag)
                    while not stop_flag.is_set() and not os.path.exists(target):
                        time.sleep(0.01)
                for i in range(1, cnt + 1):
                    emit({
                        "jsonrpc": "2.0",
                        "method": "notifications/message",
                        "params": {
                            "seq": i,
                            "pad": "m" * plen,
                            "_meta": {"relatedRequestId": wid},
                        },
                    })
                emit({
                    "jsonrpc": "2.0",
                    "id": wid,
                    "result": {"flood_done": True, "sent": cnt + 1},
                })
            threading.Thread(target=_bg_flood, daemon=True).start()
            continue

        emit({"jsonrpc": "2.0", "id": req_id, "result": {"unknown_tool": name}})

stop_flag.set()
"#;
    std::fs::write(&path, script).expect("write lifecycle fixture");
    path
}

fn make_stdio_upstream(
    script: &Path,
    flag_dir: &Path,
    max_sessions: usize,
    budget: Arc<ByteBudget>,
    limits: StdioLimits,
) -> Arc<StdioUpstream> {
    let mut env = BTreeMap::new();
    env.insert(
        "TEST_FLAG_DIR".to_owned(),
        flag_dir.to_str().unwrap().to_owned(),
    );
    Arc::new(
        StdioUpstream::with_limits(
            StdioUpstreamSettings {
                command: python_executable().to_owned(),
                args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                env,
                cwd: Some(flag_dir.to_path_buf()),
                max_sessions,
                session_idle_secs: 30,
            },
            budget,
            limits,
        )
        .expect("create StdioUpstream"),
    )
}

async fn init_session(client: &TestClient, gw_addr: SocketAddr) -> String {
    let resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .expect("initialize request");
    assert_eq!(resp.status(), StatusCode::OK);
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .expect("mcp-session-id header")
        .to_str()
        .unwrap()
        .to_owned();
    let _ = resp.into_body().collect().await.unwrap();
    sid
}

async fn post_json(
    client: &TestClient,
    gw_addr: SocketAddr,
    sid: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{gw_addr}/mcp"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json");
    if let Some(sid) = sid {
        req = req.header("mcp-session-id", sid);
    } else {
        req = req.header("mcp-protocol-version", PROTOCOL_VERSION);
    }
    let resp = client
        .request(req.body(bytes_body(body.to_string())).unwrap())
        .await
        .expect("post_json request");
    let status = resp.status();
    let raw = resp.into_body().collect().await.unwrap().to_bytes();
    let val = if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&raw).expect("valid JSON response")
    };
    (status, val)
}

async fn open_sse_stream(
    client: &TestClient,
    gw_addr: SocketAddr,
    sid: Option<&str>,
    body: Value,
    extra_headers: &[(&str, &str)],
) -> Response<Incoming> {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{gw_addr}/mcp"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "text/event-stream");
    if let Some(sid) = sid {
        req = req.header("mcp-session-id", sid);
    } else {
        req = req.header("mcp-protocol-version", PROTOCOL_VERSION);
    }
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    client
        .request(req.body(bytes_body(body.to_string())).unwrap())
        .await
        .expect("open_sse_stream request")
}

struct SseReader {
    body: Incoming,
    buf: String,
}

impl SseReader {
    fn new(body: Incoming) -> Self {
        Self {
            body,
            buf: String::new(),
        }
    }

    async fn next_json(&mut self) -> Result<Option<Value>, hyper::Error> {
        loop {
            if let Some(pos) = self.buf.find("\n\n") {
                let block = self.buf[..pos].to_owned();
                self.buf.drain(..pos + 2);
                let data: Vec<&str> = block
                    .lines()
                    .filter_map(|l| l.strip_prefix("data: "))
                    .collect();
                if data.is_empty() {
                    continue;
                }
                let val: Value =
                    serde_json::from_str(&data.join("\n")).expect("valid SSE JSON frame");
                return Ok(Some(val));
            }
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(chunk) = frame.into_data() {
                        self.buf.push_str(&String::from_utf8_lossy(&chunk));
                    }
                }
                Some(Err(err)) => return Err(err),
                None => {
                    if self.buf.trim().is_empty() {
                        return Ok(None);
                    }
                    let block = std::mem::take(&mut self.buf);
                    let data: Vec<&str> = block
                        .lines()
                        .filter_map(|l| l.strip_prefix("data: "))
                        .collect();
                    if data.is_empty() {
                        return Ok(None);
                    }
                    let val: Value =
                        serde_json::from_str(&data.join("\n")).expect("valid trailing JSON");
                    return Ok(Some(val));
                }
            }
        }
    }

    async fn collect_all(mut self) -> Result<Vec<Value>, hyper::Error> {
        let mut out = Vec::new();
        while let Some(v) = self.next_json().await? {
            out.push(v);
        }
        Ok(out)
    }
}

async fn wait_budget_zero(budget: &ByteBudget) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if budget.used() == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "byte budget did not return to 0, still used={}",
            budget.used()
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

async fn wait_budget_positive(budget: &ByteBudget) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if budget.used() > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "byte budget never became positive while frames were queued"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn fill_stdin_until_full(client: &TestClient, gw_addr: SocketAddr, sid: &str) {
    let pad = "z".repeat(32 * 1024);
    let payload = json!({
        "jsonrpc": "2.0",
        "method": "notifications/pad",
        "params": { "data": pad }
    })
    .to_string();
    for _ in 0..128 {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json")
                    .body(bytes_body(payload.clone()))
                    .unwrap(),
            )
            .await
            .expect("pad notification request");
        if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
            let body: Value =
                serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert!(
                body["error"]["message"]
                    .as_str()
                    .unwrap_or("")
                    .contains("upstream stdin queue is full"),
                "expected full stdin queue 503, got {body}"
            );
            return;
        }
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let _ = resp.into_body().collect().await.unwrap();
    }
    panic!("stdin queue never filled after 128 x 32 KiB notifications");
}

async fn wait_for_cancel_id(
    client: &TestClient,
    gw_addr: SocketAddr,
    sid: &str,
    expected_wire_id: u64,
) -> Vec<u64> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let (status, val) = post_json(
            client,
            gw_addr,
            Some(sid),
            json!({
                "jsonrpc": "2.0",
                "id": "poll-cancels",
                "method": "tools/call",
                "params": { "name": "get_cancels", "arguments": {} }
            }),
        )
        .await;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for cancel of wire_id={expected_wire_id}, last status={status} body={val}"
            );
            tokio::time::sleep(Duration::from_millis(15)).await;
            continue;
        }
        assert_eq!(status, StatusCode::OK, "unexpected response: {val}");
        let ids: Vec<u64> = val["result"]["cancelled"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_u64)
            .collect();
        if ids.contains(&expected_wire_id) {
            return ids;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for cancel of wire_id={expected_wire_id}, last status={status} body={val}"
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

#[tokio::test]
async fn events_notif_queue_backpressure_isolates_sibling_and_replays_cursor() {
    let tmp = TempDir::new().unwrap();
    let script = write_lifecycle_fixture(tmp.path());
    let budget = ByteBudget::new(64 * 1024);
    let limits = StdioLimits {
        max_notif_queue_bytes: 1024,
        max_in_flight_per_session: 3,
        ..StdioLimits::default()
    };
    let stdio_up = make_stdio_upstream(&script, tmp.path(), 2, Arc::clone(&budget), limits);
    let (gw_addr, gw_cancel, controls) =
        spawn_controlled_stdio_harness(Arc::clone(&stdio_up), "grant-ac2-notif").await;
    let client = make_client();
    let sid = init_session(&client, gw_addr).await;

    // Pause slow stream after 2 frames (`active` + `cur-1`).
    let (slow_gate, slow_paused_rx) = controls.register_gate("slow-1", 2);
    let slow_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "slow-ev-1",
            "method": "events/stream",
            "params": { "tag": "slow", "mode": "first_then_hold" }
        }),
        &[("x-test-gate", "slow-1")],
    )
    .await;
    assert_eq!(slow_resp.status(), StatusCode::OK);
    let mut slow_reader = SseReader::new(slow_resp.into_body());

    let active_frame = tokio::time::timeout(Duration::from_secs(3), slow_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(active_frame["method"], "notifications/events/active");
    assert_eq!(
        active_frame["params"]["_meta"][SUBSCRIPTION_ID_META],
        "slow-ev-1"
    );
    let slow_wire_id = active_frame["params"]["wireId"].as_u64().unwrap();

    let first_event = tokio::time::timeout(Duration::from_secs(3), slow_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first_event["method"], "notifications/events/event");
    assert_eq!(first_event["params"]["cursor"], "cur-1");
    let last_cursor = first_event["params"]["cursor"].as_str().unwrap().to_owned();

    tokio::time::timeout(Duration::from_secs(3), slow_paused_rx)
        .await
        .expect("slow gate paused")
        .unwrap();

    // Open a sibling Events stream on the same child.
    let sib_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": 9001,
            "method": "events/stream",
            "params": { "tag": "sibling", "mode": "hold" }
        }),
        &[],
    )
    .await;
    assert_eq!(sib_resp.status(), StatusCode::OK);
    let mut sib_reader = SseReader::new(sib_resp.into_body());
    let sib_active = tokio::time::timeout(Duration::from_secs(3), sib_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(sib_active["method"], "notifications/events/active");
    assert_eq!(sib_active["params"]["_meta"][SUBSCRIPTION_ID_META], 9001);

    // Push remaining history events (> 1024 B total) + heartbeat to the paused stream.
    let (push_status, push_val) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "push-ov",
            "method": "tools/call",
            "params": {
                "name": "push_overflow",
                "arguments": {
                    "tag": "slow",
                    "use_history": true,
                    "history_start": 1,
                    "pad_bytes": 380,
                    "send_heartbeat": true
                }
            }
        }),
    )
    .await;
    assert_eq!(push_status, StatusCode::OK);
    assert_eq!(push_val["result"]["pushed"], true);

    // Release the slow gate and verify the stream terminates visibly with a transport error.
    slow_gate.release();
    let next = tokio::time::timeout(Duration::from_secs(3), slow_reader.next_json())
        .await
        .expect("slow stream must terminate promptly");
    assert!(
        next.is_err(),
        "failed events/stream must end with a transport error without leaking cur-2+ or heartbeat, got {next:?}"
    );
    drop(slow_reader);

    // Sibling Events stream and ordinary calls remain healthy on the same child.
    let cancels = wait_for_cancel_id(&client, gw_addr, &sid, slow_wire_id).await;
    assert_eq!(
        cancels.iter().filter(|&&id| id == slow_wire_id).count(),
        1,
        "expected exactly one cancel for failed stream, got {cancels:?}"
    );

    let (sib_push_status, _) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "sib-finish",
            "method": "tools/call",
            "params": {
                "name": "push_stream_event_and_complete",
                "arguments": { "tag": "sibling", "cursor": "sib-ok", "complete": true }
            }
        }),
    )
    .await;
    assert_eq!(sib_push_status, StatusCode::OK);
    let sib_frames = tokio::time::timeout(Duration::from_secs(3), sib_reader.collect_all())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sib_frames.len(), 2);
    assert_eq!(sib_frames[0]["method"], "notifications/events/event");
    assert_eq!(sib_frames[0]["params"]["cursor"], "sib-ok");
    assert_eq!(sib_frames[1]["id"], 9001);
    assert_eq!(sib_frames[1]["result"]["resultType"], "complete");

    // Process budget returns to 0 after cleanup.
    wait_budget_zero(&budget).await;

    // Verify request slots (all 3) and notification queue budget returned to baseline.
    let mut slot_streams = Vec::new();
    for i in 0..3 {
        let r = open_sse_stream(
            &client,
            gw_addr,
            Some(&sid),
            json!({
                "jsonrpc": "2.0",
                "id": format!("slot-check-{i}"),
                "method": "events/stream",
                "params": { "tag": format!("slot-{i}"), "mode": "hold" }
            }),
            &[],
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "slot {i} must be available after cleanup"
        );
        let mut reader = SseReader::new(r.into_body());
        let act = tokio::time::timeout(Duration::from_secs(3), reader.next_json())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(act["method"], "notifications/events/active");
        slot_streams.push(reader);
    }
    drop(slot_streams);
    wait_budget_zero(&budget).await;

    // A frame close to max_notif_queue_bytes (1024 B) succeeds, proving notif_budget returned to 0.
    let sized_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "sized-check",
            "method": "events/stream",
            "params": { "tag": "sized", "mode": "single_sized_then_complete", "pad_bytes": 600 }
        }),
        &[],
    )
    .await;
    assert_eq!(sized_resp.status(), StatusCode::OK);
    let sized_frames = tokio::time::timeout(
        Duration::from_secs(3),
        SseReader::new(sized_resp.into_body()).collect_all(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(sized_frames.len(), 3);
    assert_eq!(sized_frames[1]["params"]["cursor"], "sized-1");
    assert_eq!(sized_frames[2]["result"]["resultType"], "complete");

    // Cursor replay via events/stream from last confirmed cursor (`cur-1`) delivers cur-2..cur-5 with no gaps.
    let replay_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "replay-stream",
            "method": "events/stream",
            "params": { "tag": "replay", "mode": "replay", "cursor": last_cursor }
        }),
        &[],
    )
    .await;
    assert_eq!(replay_resp.status(), StatusCode::OK);
    let replay_frames = tokio::time::timeout(
        Duration::from_secs(3),
        SseReader::new(replay_resp.into_body()).collect_all(),
    )
    .await
    .unwrap()
    .unwrap();
    let replayed_cursors: Vec<&str> = replay_frames
        .iter()
        .filter(|f| f["method"] == "notifications/events/event")
        .filter_map(|f| f["params"]["cursor"].as_str())
        .collect();
    assert_eq!(replayed_cursors, vec!["cur-2", "cur-3", "cur-4", "cur-5"]);
    assert_eq!(
        replay_frames.last().unwrap()["result"]["resultType"],
        "complete"
    );

    // Cursor replay via events/poll from `cur-1` also returns the same stable history.
    let (poll_status, poll_val) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "replay-poll",
            "method": "events/poll",
            "params": { "cursor": "cur-1" }
        }),
    )
    .await;
    assert_eq!(poll_status, StatusCode::OK);
    let polled_cursors: Vec<&str> = poll_val["result"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["cursor"].as_str())
        .collect();
    assert_eq!(polled_cursors, vec!["cur-2", "cur-3", "cur-4", "cur-5"]);

    wait_budget_zero(&budget).await;
    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn events_process_byte_budget_failure_isolates_sibling_and_returns_to_baseline() {
    let tmp = TempDir::new().unwrap();
    let script = write_lifecycle_fixture(tmp.path());
    // Large notif queue budget so process ByteBudget fails during Events ID rewrite/encoding
    // while small stdout lines still parse without triggering a child-wide hard reject.
    let budget = ByteBudget::new(8 * 1024);
    let limits = StdioLimits {
        max_notif_queue_bytes: 64 * 1024,
        max_in_flight_per_session: 4,
        ..StdioLimits::default()
    };
    let stdio_up = make_stdio_upstream(&script, tmp.path(), 2, Arc::clone(&budget), limits);
    let (gw_addr, gw_cancel, controls) =
        spawn_controlled_stdio_harness(Arc::clone(&stdio_up), "grant-ac2-proc").await;
    let client = make_client();
    let sid = init_session(&client, gw_addr).await;

    let long_client_id = format!("proc-slow-{}", "k".repeat(1400));
    let (slow_gate, slow_paused_rx) = controls.register_gate("proc-slow", 1);
    let slow_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": long_client_id,
            "method": "events/stream",
            "params": { "tag": "proc-slow", "mode": "hold" }
        }),
        &[("x-test-gate", "proc-slow")],
    )
    .await;
    assert_eq!(slow_resp.status(), StatusCode::OK);
    let mut slow_reader = SseReader::new(slow_resp.into_body());
    let active = tokio::time::timeout(Duration::from_secs(3), slow_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(active["method"], "notifications/events/active");

    tokio::time::timeout(Duration::from_secs(3), slow_paused_rx)
        .await
        .expect("proc-slow paused")
        .unwrap();

    // Open a sibling Events stream on the same child.
    let sib_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "proc-sib",
            "method": "events/stream",
            "params": { "tag": "proc-sib", "mode": "hold" }
        }),
        &[],
    )
    .await;
    assert_eq!(sib_resp.status(), StatusCode::OK);
    let mut sib_reader = SseReader::new(sib_resp.into_body());
    let sib_active = tokio::time::timeout(Duration::from_secs(3), sib_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(sib_active["method"], "notifications/events/active");

    // Push compact stdout events whose rewritten SSE frames (carrying the 1400 B client ID)
    // exceed the 6 KiB process ByteBudget during encode_notification.
    let (push_status, _) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "proc-push",
            "method": "tools/call",
            "params": {
                "name": "push_overflow",
                "arguments": {
                    "tag": "proc-slow",
                    "count": 6,
                    "pad_bytes": 16,
                    "send_heartbeat": true
                }
            }
        }),
    )
    .await;
    assert_eq!(push_status, StatusCode::OK);

    slow_gate.release();
    let next = tokio::time::timeout(Duration::from_secs(3), slow_reader.next_json())
        .await
        .expect("proc-slow must terminate");
    assert!(
        next.is_err(),
        "process budget failure must terminate stream with transport error, got {next:?}"
    );
    drop(slow_reader);

    // Sibling stream and ordinary request still work on the same child.
    let (sib_status, _) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "proc-sib-done",
            "method": "tools/call",
            "params": {
                "name": "push_stream_event_and_complete",
                "arguments": { "tag": "proc-sib", "cursor": "proc-sib-1", "complete": true }
            }
        }),
    )
    .await;
    assert_eq!(sib_status, StatusCode::OK);
    let sib_frames = tokio::time::timeout(Duration::from_secs(3), sib_reader.collect_all())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sib_frames.len(), 2);
    assert_eq!(sib_frames[0]["params"]["cursor"], "proc-sib-1");
    assert_eq!(sib_frames[1]["result"]["resultType"], "complete");

    wait_budget_zero(&budget).await;
    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn events_unpolled_failed_sse_body_discards_frames_and_returns_budgets() {
    let tmp = TempDir::new().unwrap();
    let script = write_lifecycle_fixture(tmp.path());
    let budget = ByteBudget::new(64 * 1024);
    let limits = StdioLimits {
        max_notif_queue_bytes: 1024,
        max_in_flight_per_session: 2,
        ..StdioLimits::default()
    };
    let stdio_up = make_stdio_upstream(&script, tmp.path(), 2, Arc::clone(&budget), limits);
    let (gw_addr, gw_cancel, controls) =
        spawn_controlled_stdio_harness(Arc::clone(&stdio_up), "grant-ac2-unpolled").await;
    let client = make_client();
    let sid = init_session(&client, gw_addr).await;

    // Capture the raw ReplyBody so it is NEVER polled while frames queue and overflow.
    let cap_rx = controls.register_capture("unpolled-1");
    let trigger = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "unpolled-ev",
            "method": "events/stream",
            "params": { "tag": "unpolled", "mode": "first_then_hold" }
        }),
        &[("x-test-capture", "unpolled-1")],
    )
    .await;
    assert_eq!(trigger.status(), StatusCode::OK);
    let _ = trigger.into_body().collect().await.unwrap();

    let mut captured = tokio::time::timeout(Duration::from_secs(3), cap_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(captured.status, StatusCode::OK);
    assert_eq!(
        captured
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );

    // Confirm `active` + `cur-1` are queued and charging the byte budget while body is unpolled.
    wait_budget_positive(&budget).await;

    // Trigger overflow on the unpolled stream.
    let (push_status, _) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "unpolled-push",
            "method": "tools/call",
            "params": {
                "name": "push_overflow",
                "arguments": { "tag": "unpolled", "count": 6, "pad_bytes": 380 }
            }
        }),
    )
    .await;
    assert_eq!(push_status, StatusCode::OK);

    // WITHOUT polling or dropping `captured.body`, unsent frames must be discarded and budget -> 0.
    wait_budget_zero(&budget).await;

    // Verify all 2 request slots are back to baseline while `captured.body` is STILL unpolled.
    let mut holders = Vec::new();
    for i in 0..2 {
        let r = open_sse_stream(
            &client,
            gw_addr,
            Some(&sid),
            json!({
                "jsonrpc": "2.0",
                "id": format!("reuse-slot-{i}"),
                "method": "events/stream",
                "params": { "tag": format!("reuse-{i}"), "mode": "hold" }
            }),
            &[],
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let mut reader = SseReader::new(r.into_body());
        let act = tokio::time::timeout(Duration::from_secs(3), reader.next_json())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(act["method"], "notifications/events/active");
        holders.push(reader);
    }
    drop(holders);
    wait_budget_zero(&budget).await;

    // Now poll the unpolled body once: it must immediately report Err (no queued frames escape).
    let first_poll = tokio::time::timeout(Duration::from_secs(2), captured.body.frame())
        .await
        .expect("unpolled failed body must resolve immediately");
    assert!(
        matches!(first_poll, Some(Err(_))),
        "expected immediate transport error on unpolled failed body, got {first_poll:?}"
    );
    drop(captured);

    wait_budget_zero(&budget).await;
    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn events_final_reply_racing_with_delivery_failure_does_not_override_error() {
    let tmp = TempDir::new().unwrap();
    let script = write_lifecycle_fixture(tmp.path());
    let budget = ByteBudget::new(64 * 1024);
    let limits = StdioLimits {
        max_notif_queue_bytes: 1024,
        max_in_flight_per_session: 3,
        ..StdioLimits::default()
    };
    let stdio_up = make_stdio_upstream(&script, tmp.path(), 2, Arc::clone(&budget), limits);
    let (gw_addr, gw_cancel, controls) =
        spawn_controlled_stdio_harness(Arc::clone(&stdio_up), "grant-ac2-race").await;
    let client = make_client();
    let sid = init_session(&client, gw_addr).await;

    let cap_rx = controls.register_capture("race-1");
    let trigger = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "race-ev",
            "method": "events/stream",
            "params": { "tag": "race", "mode": "first_then_hold" }
        }),
        &[("x-test-capture", "race-1")],
    )
    .await;
    assert_eq!(trigger.status(), StatusCode::OK);
    let _ = trigger.into_body().collect().await.unwrap();
    let mut captured = tokio::time::timeout(Duration::from_secs(3), cap_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(captured.status, StatusCode::OK);

    wait_budget_positive(&budget).await;

    // Emit overflow frames AND immediately emit a valid `resultType: "complete"` final reply
    // on stdout before the SSE body is polled.
    let (push_status, _) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "race-push",
            "method": "tools/call",
            "params": {
                "name": "push_overflow",
                "arguments": {
                    "tag": "race",
                    "count": 6,
                    "pad_bytes": 380,
                    "send_heartbeat": true,
                    "send_late_complete": true
                }
            }
        }),
    )
    .await;
    assert_eq!(push_status, StatusCode::OK);

    // FIFO barrier: receiving ping confirms stdout reader already processed the late complete reply.
    let (ping_status, ping_val) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "race-ping",
            "method": "tools/call",
            "params": { "name": "ping", "arguments": { "tag": "barrier" } }
        }),
    )
    .await;
    assert_eq!(ping_status, StatusCode::OK);
    assert_eq!(ping_val["result"]["ok"], true);

    // Polling the failed body must still yield Err; the late final reply cannot overwrite failure.
    let polled = tokio::time::timeout(Duration::from_secs(2), captured.body.frame())
        .await
        .expect("failed body resolves immediately");
    assert!(
        matches!(polled, Some(Err(_))),
        "late final reply must not override already-signaled failure, got {polled:?}"
    );
    drop(captured);

    wait_budget_zero(&budget).await;
    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn events_close_sends_single_cancel_and_blocks_late_output() {
    let tmp = TempDir::new().unwrap();
    let script = write_lifecycle_fixture(tmp.path());
    let budget = ByteBudget::new(64 * 1024);
    let stdio_up = make_stdio_upstream(
        &script,
        tmp.path(),
        2,
        Arc::clone(&budget),
        StdioLimits::default(),
    );
    let (gw_addr, gw_cancel, _controls) =
        spawn_controlled_stdio_harness(Arc::clone(&stdio_up), "grant-ac3-close").await;
    let client = make_client();
    let sid = init_session(&client, gw_addr).await;

    let stream_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "close-ev-1",
            "method": "events/stream",
            "params": {
                "tag": "close-me",
                "mode": "hold",
                "emit_late_on_cancel": true
            }
        }),
        &[],
    )
    .await;
    assert_eq!(stream_resp.status(), StatusCode::OK);
    let mut reader = SseReader::new(stream_resp.into_body());
    let active = tokio::time::timeout(Duration::from_secs(3), reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(active["method"], "notifications/events/active");
    let wire_id = active["params"]["wireId"].as_u64().unwrap();

    // Closing the streaming POST must emit exactly one notifications/cancelled for wire_id.
    drop(reader);

    let cancels = wait_for_cancel_id(&client, gw_addr, &sid, wire_id).await;
    assert_eq!(
        cancels.iter().filter(|&&id| id == wire_id).count(),
        1,
        "expected exactly one notifications/cancelled for wire_id={wire_id}, got {cancels:?}"
    );

    // A later request reusing the same downstream ID must not receive any late output from the cancelled stream.
    let later_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "close-ev-1",
            "method": "events/stream",
            "params": { "tag": "later", "mode": "single_sized_then_complete", "pad_bytes": 16 }
        }),
        &[],
    )
    .await;
    assert_eq!(later_resp.status(), StatusCode::OK);
    let frames = tokio::time::timeout(
        Duration::from_secs(3),
        SseReader::new(later_resp.into_body()).collect_all(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        frames.len(),
        3,
        "unexpected frames on later stream: {frames:?}"
    );
    assert_eq!(frames[0]["method"], "notifications/events/active");
    assert_eq!(frames[1]["params"]["cursor"], "sized-1");
    assert_eq!(frames[2]["result"]["resultType"], "complete");
    assert!(
        frames
            .iter()
            .all(|f| f["params"]["cursor"] != "late-cur" && f["result"]["late"] != true),
        "late output from cancelled request leaked into later stream: {frames:?}"
    );

    // Ordinary follow-up call also stays clean.
    let (ping_status, ping_val) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "after-close-ping",
            "method": "tools/call",
            "params": { "name": "ping", "arguments": { "tag": "clean" } }
        }),
    )
    .await;
    assert_eq!(ping_status, StatusCode::OK);
    assert_eq!(ping_val["result"]["tag"], "clean");

    wait_budget_zero(&budget).await;
    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn events_full_stdin_queue_delayed_capacity_and_stopping_cap() {
    let tmp = TempDir::new().unwrap();
    let script = write_lifecycle_fixture(tmp.path());
    let budget = ByteBudget::new(512 * 1024);
    let limits = StdioLimits {
        stdin_channel_capacity: 1,
        stdin_write_timeout: Duration::from_secs(5),
        max_in_flight_per_session: 2,
        ..StdioLimits::default()
    };
    let stdio_up = make_stdio_upstream(&script, tmp.path(), 2, Arc::clone(&budget), limits);
    let (gw_addr, gw_cancel, _controls) =
        spawn_controlled_stdio_harness(Arc::clone(&stdio_up), "grant-ac3-delay").await;
    let client = make_client();
    let sid = init_session(&client, gw_addr).await;

    // Open two concurrent streams filling max_in_flight_per_session = 2.
    let s1_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "stop-s1",
            "method": "events/stream",
            "params": { "tag": "s1", "mode": "hold" }
        }),
        &[],
    )
    .await;
    assert_eq!(s1_resp.status(), StatusCode::OK);
    let mut s1_reader = SseReader::new(s1_resp.into_body());
    let s1_active = tokio::time::timeout(Duration::from_secs(3), s1_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let s1_wire_id = s1_active["params"]["wireId"].as_u64().unwrap();

    // Pause stdin before opening s2? No: open s2 after pausing? Wait: pause_stdin is a tools/call
    // that occupies a slot briefly, so run pause_stdin first while only s1 is open, then?
    // Even simpler: open s2 first, then pause_stdin? If max_in_flight_per_session == 2, we can't
    // run pause_stdin while both s1 and s2 are open! Instead:
    // 1. Open s1 (slot 1).
    // 2. Call `pause_stdin` (slot 2 -> returns immediately, frees slot 2, then Python stops reading stdin).
    // Wait: once Python stops reading stdin, we can still open s2 BEFORE filling the OS pipe!
    // Because the OS pipe has 64 KiB free, opening s2 writes ~120 bytes into the OS pipe (succeeds)
    // and registers slot 2! We don't even need s2's `active` before filling the pipe—s2 is already
    // registered in `in_flight` (slot 2)!
    let (pause_status, pause_val) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "pause-1",
            "method": "tools/call",
            "params": { "name": "pause_stdin", "arguments": { "resume_flag": "resume_delay.flag" } }
        }),
    )
    .await;
    assert_eq!(pause_status, StatusCode::OK);
    let child_pid = pause_val["result"]["pid"].as_u64().unwrap();

    // Register sibling stream s2 (slot 2 of 2) while stdin pipe still has room.
    let s2_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "stop-s2",
            "method": "events/stream",
            "params": { "tag": "s2", "mode": "hold" }
        }),
        &[],
    )
    .await;
    assert_eq!(s2_resp.status(), StatusCode::OK);
    let mut s2_reader = SseReader::new(s2_resp.into_body());

    // Fill OS pipe + stdin_channel_capacity (1) so s1's cancel must wait for queue capacity.
    fill_stdin_until_full(&client, gw_addr, &sid).await;

    // Close s1 -> enters Stopping state while cancel waits on the full stdin queue.
    drop(s1_reader);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Stopping entry MUST still count toward max_in_flight_per_session (2: s1 Stopping + s2 Live).
    let (cap_status, cap_val) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "over-cap",
            "method": "tools/call",
            "params": { "name": "ping", "arguments": {} }
        }),
    )
    .await;
    assert_eq!(cap_status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        cap_val["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("too many concurrent requests in session"),
        "Stopping entry must count toward max_in_flight_per_session, got {cap_val}"
    );

    // Resume fixture stdin reading so the queued cancel flushes and settles s1's Stopping slot.
    std::fs::write(tmp.path().join("resume_delay.flag"), "go").unwrap();

    // Sibling s2 was buffered in stdin and now becomes active on the same child.
    let s2_active = tokio::time::timeout(Duration::from_secs(3), s2_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(s2_active["method"], "notifications/events/active");
    assert_eq!(s2_active["params"]["pid"].as_u64(), Some(child_pid));

    // Wait for s1's cancel to flush and confirm exactly one cancel for s1_wire_id and slot release.
    let cancels = wait_for_cancel_id(&client, gw_addr, &sid, s1_wire_id).await;
    assert_eq!(
        cancels.iter().filter(|&&id| id == s1_wire_id).count(),
        1,
        "expected exactly one flushed cancel for s1, got {cancels:?}"
    );

    // Complete sibling s2 cleanly on the same child.
    let (sib_done, _) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "s2-done",
            "method": "tools/call",
            "params": {
                "name": "push_stream_event_and_complete",
                "arguments": { "tag": "s2", "cursor": "s2-ok", "complete": true }
            }
        }),
    )
    .await;
    assert_eq!(sib_done, StatusCode::OK);
    let s2_frames = tokio::time::timeout(Duration::from_secs(3), s2_reader.collect_all())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s2_frames.len(), 2);
    assert_eq!(s2_frames[0]["params"]["cursor"], "s2-ok");
    assert_eq!(s2_frames[1]["result"]["resultType"], "complete");

    wait_budget_zero(&budget).await;
    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn events_full_stdin_queue_final_reply_settles_without_retiring_child() {
    let tmp = TempDir::new().unwrap();
    let script = write_lifecycle_fixture(tmp.path());
    let budget = ByteBudget::new(512 * 1024);
    let limits = StdioLimits {
        stdin_channel_capacity: 1,
        stdin_write_timeout: Duration::from_millis(250),
        max_in_flight_per_session: 2,
        ..StdioLimits::default()
    };
    let stdio_up = make_stdio_upstream(&script, tmp.path(), 2, Arc::clone(&budget), limits);
    let (gw_addr, gw_cancel, _controls) =
        spawn_controlled_stdio_harness(Arc::clone(&stdio_up), "grant-ac3-final").await;
    let client = make_client();
    let sid = init_session(&client, gw_addr).await;

    let s1_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "final-s1",
            "method": "events/stream",
            "params": { "tag": "settle-me", "mode": "hold" }
        }),
        &[],
    )
    .await;
    assert_eq!(s1_resp.status(), StatusCode::OK);
    let mut s1_reader = SseReader::new(s1_resp.into_body());
    let s1_active = tokio::time::timeout(Duration::from_secs(3), s1_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let child_pid = s1_active["params"]["pid"].as_u64().unwrap();

    // Pause fixture stdin and fill stdin queue until full.
    let (pause_status, _) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "pause-final",
            "method": "tools/call",
            "params": { "name": "pause_stdin", "arguments": { "resume_flag": "resume_final.flag" } }
        }),
    )
    .await;
    assert_eq!(pause_status, StatusCode::OK);
    fill_stdin_until_full(&client, gw_addr, &sid).await;

    // Close s1 so cancel waits on the full stdin queue.
    drop(s1_reader);
    tokio::time::sleep(Duration::from_millis(40)).await;

    // Signal fixture to emit a valid terminal `complete` response while stdin is still blocked.
    std::fs::write(tmp.path().join("send_final.flag"), "settle-me").unwrap();

    // Wait well past stdin_write_timeout (250ms) to confirm the child is NOT retired.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Resume stdin and wait for the fixture to drain padded notifications before pinging.
    std::fs::write(tmp.path().join("resume_final.flag"), "go").unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let ping_val = loop {
        let (ping_status, val) = post_json(
            &client,
            gw_addr,
            Some(&sid),
            json!({
                "jsonrpc": "2.0",
                "id": "after-settle-ping",
                "method": "tools/call",
                "params": { "name": "ping", "arguments": { "tag": "still-same-child" } }
            }),
        )
        .await;
        if ping_status == StatusCode::OK {
            break val;
        }
        assert_eq!(
            ping_status,
            StatusCode::SERVICE_UNAVAILABLE,
            "expected only transient full-stdin 503 while draining, got {ping_status} {val}"
        );
        assert!(
            val["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("upstream stdin queue is full"),
            "session must stay alive while draining stdin, got {val}"
        );
        assert!(
            Instant::now() < deadline,
            "stdin never drained after resume"
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
    };
    assert_eq!(ping_val["result"]["ok"], true);
    assert_eq!(
        ping_val["result"]["pid"].as_u64(),
        Some(child_pid),
        "valid final reply must settle Stopping without retiring the child"
    );
    assert!(
        ping_val["result"].get("settled_via_flag").is_none(),
        "settled final reply must not leak to subsequent requests"
    );

    wait_budget_zero(&budget).await;
    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn events_stalled_stdin_writer_retires_and_reaps_child_at_deadline() {
    let tmp = TempDir::new().unwrap();
    let script = write_lifecycle_fixture(tmp.path());
    let budget = ByteBudget::new(512 * 1024);
    let limits = StdioLimits {
        stdin_channel_capacity: 1,
        stdin_write_timeout: Duration::from_millis(200),
        max_in_flight_per_session: 2,
        ..StdioLimits::default()
    };
    let stdio_up = make_stdio_upstream(&script, tmp.path(), 1, Arc::clone(&budget), limits);
    let (gw_addr, gw_cancel, _controls) =
        spawn_controlled_stdio_harness(Arc::clone(&stdio_up), "grant-ac3-retire").await;
    let client = make_client();
    let sid = init_session(&client, gw_addr).await;

    let s1_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "stall-s1",
            "method": "events/stream",
            "params": { "tag": "stall", "mode": "hold" }
        }),
        &[],
    )
    .await;
    assert_eq!(s1_resp.status(), StatusCode::OK);
    let mut s1_reader = SseReader::new(s1_resp.into_body());
    let s1_active = tokio::time::timeout(Duration::from_secs(3), s1_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let child_pid = s1_active["params"]["pid"].as_u64().unwrap() as u32;

    // Permanently stall stdin (never create `never_resume.flag`) and fill the stdin queue.
    let (pause_status, _) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "pause-forever",
            "method": "tools/call",
            "params": { "name": "pause_stdin", "arguments": { "resume_flag": "never_resume.flag" } }
        }),
    )
    .await;
    assert_eq!(pause_status, StatusCode::OK);
    fill_stdin_until_full(&client, gw_addr, &sid).await;

    // Close s1 with no final reply: at stdin_write_timeout (200ms) the gateway must retire and reap the child.
    drop(s1_reader);

    assert!(
        wait_process_gone(child_pid).await,
        "stalled child pid {child_pid} was not reaped after stdin_write_timeout"
    );

    // Retired session is gone (404), and max_sessions=1 slot is returned for a fresh session.
    let (old_status, _) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "old-sid-ping",
            "method": "tools/call",
            "params": { "name": "ping", "arguments": {} }
        }),
    )
    .await;
    assert_eq!(old_status, StatusCode::NOT_FOUND);

    let sid2 = init_session(&client, gw_addr).await;
    let (ping_status, ping_val) = post_json(
        &client,
        gw_addr,
        Some(&sid2),
        json!({
            "jsonrpc": "2.0",
            "id": "new-sid-ping",
            "method": "tools/call",
            "params": { "name": "ping", "arguments": {} }
        }),
    )
    .await;
    assert_eq!(ping_status, StatusCode::OK);
    assert_ne!(
        ping_val["result"]["pid"].as_u64().unwrap() as u32,
        child_pid
    );

    wait_budget_zero(&budget).await;
    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn events_sessionless_ephemeral_reap_and_slot_return_under_small_child_limit() {
    let tmp = TempDir::new().unwrap();
    let script = write_lifecycle_fixture(tmp.path());
    let budget = ByteBudget::new(64 * 1024);
    let limits = StdioLimits {
        max_notif_queue_bytes: 1024,
        stdin_write_timeout: Duration::from_secs(5),
        ..StdioLimits::default()
    };
    let stdio_up = make_stdio_upstream(&script, tmp.path(), 1, Arc::clone(&budget), limits);
    let (gw_addr, gw_cancel, controls) =
        spawn_controlled_stdio_harness(Arc::clone(&stdio_up), "grant-ac3-ephem").await;
    let client = make_client();

    // Part A: Ephemeral disconnect reaps child immediately (even if stdin is blocked) and returns slot.
    let resp1 = open_sse_stream(
        &client,
        gw_addr,
        None,
        json!({
            "jsonrpc": "2.0",
            "id": "ephem-1",
            "method": "events/stream",
            "params": {
                "tag": "ephem-1",
                "mode": "pause_stdin_after_active",
                "resume_flag": "ephem_never.flag"
            }
        }),
        &[],
    )
    .await;
    assert_eq!(resp1.status(), StatusCode::OK);
    let mut reader1 = SseReader::new(resp1.into_body());
    let active1 = tokio::time::timeout(Duration::from_secs(3), reader1.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(active1["method"], "notifications/events/active");
    let pid1 = active1["params"]["pid"].as_u64().unwrap() as u32;

    // While child slot 1/1 is occupied, another sessionless request is rejected with 503.
    let (busy_status, _) = post_json(
        &client,
        gw_addr,
        None,
        json!({
            "jsonrpc": "2.0",
            "id": "ephem-busy",
            "method": "tools/call",
            "params": { "name": "ping", "arguments": {} }
        }),
    )
    .await;
    assert_eq!(busy_status, StatusCode::SERVICE_UNAVAILABLE);

    // Drop the sessionless stream -> temporary child reaps promptly without waiting 5s on stdin.
    let drop_start = Instant::now();
    drop(reader1);
    assert!(
        wait_process_gone(pid1).await,
        "ephemeral child pid {pid1} was not reaped after disconnect"
    );
    assert!(
        drop_start.elapsed() < Duration::from_secs(3),
        "ephemeral reap waited too long: {:?}",
        drop_start.elapsed()
    );

    // Part B: Ephemeral delivery failure also reaps the temporary child and returns the slot.
    let (gate2, paused2_rx) = controls.register_gate("ephem-fail", 1);
    let resp2 = open_sse_stream(
        &client,
        gw_addr,
        None,
        json!({
            "jsonrpc": "2.0",
            "id": "ephem-2",
            "method": "events/stream",
            "params": {
                "tag": "ephem-2",
                "mode": "overflow_after_flag",
                "gate_flag": "ephem_ov.flag",
                "count": 8,
                "pad_bytes": 380
            }
        }),
        &[("x-test-gate", "ephem-fail")],
    )
    .await;
    assert_eq!(resp2.status(), StatusCode::OK);
    let mut reader2 = SseReader::new(resp2.into_body());
    let active2 = tokio::time::timeout(Duration::from_secs(3), reader2.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let pid2 = active2["params"]["pid"].as_u64().unwrap() as u32;

    tokio::time::timeout(Duration::from_secs(3), paused2_rx)
        .await
        .expect("ephem-fail gate paused")
        .unwrap();

    // Trigger overflow on the paused sessionless stream.
    std::fs::write(tmp.path().join("ephem_ov.flag"), "go").unwrap();
    assert!(
        wait_process_gone(pid2).await,
        "ephemeral child pid {pid2} was not reaped after delivery failure"
    );

    gate2.release();
    let err2 = tokio::time::timeout(Duration::from_secs(3), reader2.next_json())
        .await
        .unwrap();
    assert!(
        err2.is_err(),
        "failed sessionless stream must end with transport error, got {err2:?}"
    );
    drop(reader2);

    // Slot is returned: a fresh sessionless call succeeds with 200 OK.
    let (ok_status, ok_val) = post_json(
        &client,
        gw_addr,
        None,
        json!({
            "jsonrpc": "2.0",
            "id": "ephem-3",
            "method": "tools/call",
            "params": { "name": "ping", "arguments": { "tag": "slot-returned" } }
        }),
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK);
    assert_eq!(ok_val["result"]["tag"], "slot-returned");

    wait_budget_zero(&budget).await;
    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn ordinary_notification_backpressure_keeps_sibling_events_and_requests_alive() {
    let tmp = TempDir::new().unwrap();
    let script = write_lifecycle_fixture(tmp.path());
    let budget = ByteBudget::new(64 * 1024);
    let limits = StdioLimits {
        max_notif_queue_bytes: 2048,
        max_in_flight_per_session: 4,
        ..StdioLimits::default()
    };
    let stdio_up = make_stdio_upstream(&script, tmp.path(), 2, Arc::clone(&budget), limits);
    let (gw_addr, gw_cancel, controls) =
        spawn_controlled_stdio_harness(Arc::clone(&stdio_up), "grant-ac3-ordinary").await;
    let client = make_client();
    let sid = init_session(&client, gw_addr).await;

    // Sibling Events stream on the same child.
    let sib_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "ord-sib-ev",
            "method": "events/stream",
            "params": { "tag": "ord-sib", "mode": "hold" }
        }),
        &[],
    )
    .await;
    assert_eq!(sib_resp.status(), StatusCode::OK);
    let mut sib_reader = SseReader::new(sib_resp.into_body());
    let sib_active = tokio::time::timeout(Duration::from_secs(3), sib_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(sib_active["method"], "notifications/events/active");

    // Ordinary SSE tools/call paused after its first notification while flooded with 40 x 400 B notices.
    let (ord_gate, ord_paused_rx) = controls.register_gate("ord-flood", 1);
    let ord_resp = open_sse_stream(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "ord-call-1",
            "method": "tools/call",
            "params": {
                "name": "ordinary_notif_flood",
                "arguments": {
                    "count": 40,
                    "pad_bytes": 400,
                    "burst_flag": "ord_burst.flag"
                }
            }
        }),
        &[("x-test-gate", "ord-flood")],
    )
    .await;
    assert_eq!(ord_resp.status(), StatusCode::OK);
    let mut ord_reader = SseReader::new(ord_resp.into_body());
    let first_notif = tokio::time::timeout(Duration::from_secs(3), ord_reader.next_json())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first_notif["method"], "notifications/message");
    assert_eq!(first_notif["params"]["seq"], 0);

    tokio::time::timeout(Duration::from_secs(3), ord_paused_rx)
        .await
        .expect("ord-flood gate paused")
        .unwrap();

    // Release the flood burst while ord_reader is paused.
    std::fs::write(tmp.path().join("ord_burst.flag"), "go").unwrap();

    // Confirm another ordinary call on the same child succeeds while the flood runs/finishes.
    let (ping_status, ping_val) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "ord-ping",
            "method": "tools/call",
            "params": { "name": "ping", "arguments": { "tag": "sibling-ok" } }
        }),
    )
    .await;
    assert_eq!(ping_status, StatusCode::OK);
    assert_eq!(ping_val["result"]["tag"], "sibling-ok");

    // Release the ordinary SSE body: excess notifications were dropped, but final response arrives intact.
    ord_gate.release();
    let ord_frames = tokio::time::timeout(Duration::from_secs(3), ord_reader.collect_all())
        .await
        .unwrap()
        .unwrap();
    let notif_count = ord_frames
        .iter()
        .filter(|f| f["method"] == "notifications/message")
        .count();
    assert!(
        notif_count < 40,
        "ordinary notification backpressure should drop excess frames, got {notif_count}"
    );
    let last_ord = ord_frames.last().expect("final response present");
    assert_eq!(last_ord["id"], "ord-call-1");
    assert_eq!(last_ord["result"]["flood_done"], true);

    // Sibling Events stream is still alive and receives its event + completion cleanly.
    let (sib_done, _) = post_json(
        &client,
        gw_addr,
        Some(&sid),
        json!({
            "jsonrpc": "2.0",
            "id": "ord-sib-complete",
            "method": "tools/call",
            "params": {
                "name": "push_stream_event_and_complete",
                "arguments": { "tag": "ord-sib", "cursor": "ord-sib-1", "complete": true }
            }
        }),
    )
    .await;
    assert_eq!(sib_done, StatusCode::OK);
    let sib_frames = tokio::time::timeout(Duration::from_secs(3), sib_reader.collect_all())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sib_frames.len(), 2);
    assert_eq!(sib_frames[0]["params"]["cursor"], "ord-sib-1");
    assert_eq!(sib_frames[1]["result"]["resultType"], "complete");

    wait_budget_zero(&budget).await;
    stdio_up.shutdown().await;
    gw_cancel.cancel();
}
