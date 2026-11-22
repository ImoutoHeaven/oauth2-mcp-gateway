mod common;

use common::{make_client, python_executable, spawn_http1_harness, wait_process_gone};
use http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use oauth2_mcp_gateway::config::StdioUpstreamSettings;
use oauth2_mcp_gateway::types::{ByteBudget, VerifiedToken, bytes_body};
use oauth2_mcp_gateway::upstream_stdio::{StdioLimits, StdioUpstream};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const SUBSCRIPTION_ID_KEY: &str = "io.modelcontextprotocol/subscriptionId";
const SESSIONLESS_PROTOCOL_VERSION: &str = "2026-07-28";

fn make_token(grant_id: &str) -> VerifiedToken {
    VerifiedToken {
        grant_id: grant_id.to_owned(),
        client_id: "events-proto-client".to_owned(),
        pool_slot: 0,
        scopes: vec!["mcp".to_owned()],
        resource: "https://mcp.example.com/mcp".to_owned(),
    }
}

fn write_events_fixture_script(dir: &Path) -> PathBuf {
    let script_path = dir.join("mock_events_stdio.py");
    let script = r##"import json
import os
import sys
import threading

state_dir = os.environ["MOCK_STATE_DIR"]
pid = os.getpid()

with open(os.path.join(state_dir, f"spawn_{pid}.json"), "w", encoding="utf-8") as sf:
    json.dump({"pid": pid}, sf)

write_lock = threading.Lock()
state_lock = threading.Lock()
gates = {}
subscriptions = {}


def get_gate(name):
    with state_lock:
        ev = gates.get(name)
        if ev is None:
            ev = threading.Event()
            gates[name] = ev
        return ev


def emit(obj):
    line = json.dumps(obj, separators=(",", ":"))
    with write_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def sub_meta(wire_id, extra=None):
    meta = {"io.modelcontextprotocol/subscriptionId": wire_id}
    if extra:
        meta.update(extra)
    return meta


def emit_active(wire_id, tag):
    emit({
        "jsonrpc": "2.0",
        "method": "notifications/events/active",
        "params": {
            "subscription": tag,
            "cursor": f"{tag}-c0",
            "_meta": sub_meta(wire_id, {"pid": pid, "phase": "active"}),
        },
    })


def emit_tail_and_complete(wire_id, tag):
    emit({
        "jsonrpc": "2.0",
        "method": "notifications/events/event",
        "params": {
            "cursor": f"{tag}-c1",
            "event": {"tag": tag, "seq": 1},
            "_meta": sub_meta(wire_id, {"pid": pid}),
        },
    })
    emit({
        "jsonrpc": "2.0",
        "method": "notifications/events/heartbeat",
        "params": {
            "cursor": f"{tag}-c1",
            "_meta": sub_meta(wire_id, {"pid": pid, "seq": 2}),
        },
    })
    emit({
        "jsonrpc": "2.0",
        "method": "notifications/events/error",
        "params": {
            "code": "transient_gap",
            "message": "recoverable notice",
            "recoverable": True,
            "_meta": sub_meta(wire_id, {"pid": pid, "seq": 3}),
        },
    })
    emit({
        "jsonrpc": "2.0",
        "method": "notifications/events/terminated",
        "params": {
            "reason": "completed",
            "cursor": f"{tag}-c2",
            "_meta": sub_meta(wire_id, {"pid": pid, "seq": 4}),
        },
    })
    emit({
        "jsonrpc": "2.0",
        "id": wire_id,
        "result": {
            "resultType": "complete",
            "nextCursor": f"{tag}-c2",
            "_meta": sub_meta(wire_id, {"pid": pid, "tag": tag}),
        },
    })


for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    with open(os.path.join(state_dir, f"log_{pid}.jsonl"), "a", encoding="utf-8") as lf:
        lf.write(json.dumps(msg, separators=(",", ":")) + "\n")

    method = msg.get("method")
    req_id = msg.get("id")

    if method == "notifications/cancelled":
        with open(os.path.join(state_dir, f"cancelled_{pid}.jsonl"), "a", encoding="utf-8") as cf:
            cf.write(json.dumps(msg, separators=(",", ":")) + "\n")
        continue

    if req_id is None:
        continue

    if method == "initialize":
        emit({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-11-25"),
                "capabilities": {"events": {}},
                "serverInfo": {"name": "mock-events-stdio", "version": "1.0.0"},
                "_meta": {"pid": pid},
            },
        })
        continue

    if method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})

        if name == "slot_probe":
            emit({"jsonrpc": "2.0", "id": req_id, "result": {"ok": True, "pid": pid}})
        elif name == "release_gate":
            gate_name = args["gate"]
            get_gate(gate_name).set()
            emit({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"released": gate_name, "pid": pid},
            })
        elif name == "interleave_and_finish":
            tags = args["tags"]
            with state_lock:
                pairs = [(t, subscriptions[t]) for t in tags]

            def run_interleaved(entries):
                for t, wid in entries:
                    emit({
                        "jsonrpc": "2.0",
                        "method": "notifications/events/event",
                        "params": {
                            "cursor": f"{t}-c1",
                            "event": {"tag": t, "seq": 1},
                            "_meta": sub_meta(wid, {"pid": pid}),
                        },
                    })
                for t, wid in entries:
                    emit({
                        "jsonrpc": "2.0",
                        "method": "notifications/events/heartbeat",
                        "params": {
                            "cursor": f"{t}-c1",
                            "_meta": sub_meta(wid, {"pid": pid, "seq": 2}),
                        },
                    })
                for t, wid in entries:
                    emit({
                        "jsonrpc": "2.0",
                        "method": "notifications/events/error",
                        "params": {
                            "code": "transient_gap",
                            "message": "recoverable notice",
                            "recoverable": True,
                            "_meta": sub_meta(wid, {"pid": pid, "seq": 3}),
                        },
                    })
                for t, wid in entries:
                    emit({
                        "jsonrpc": "2.0",
                        "method": "notifications/events/terminated",
                        "params": {
                            "reason": "completed",
                            "cursor": f"{t}-c2",
                            "_meta": sub_meta(wid, {"pid": pid, "seq": 4}),
                        },
                    })
                for t, wid in entries:
                    emit({
                        "jsonrpc": "2.0",
                        "id": wid,
                        "result": {
                            "resultType": "complete",
                            "nextCursor": f"{t}-c2",
                            "_meta": sub_meta(wid, {"pid": pid, "tag": t}),
                        },
                    })

            threading.Thread(target=run_interleaved, args=(pairs,), daemon=True).start()
            emit({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"interleaved": tags, "pid": pid},
            })
        elif name == "sse_waiter":
            ptok = params.get("_meta", {}).get("progressToken", "waiter-ptok")
            wait_gate = args["wait_gate"]
            tag = args.get("tag", "ord")

            def run_waiter(rid, tok, gname, t):
                emit({
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {"progressToken": tok, "progress": 1, "total": 2},
                })
                get_gate(gname).wait(timeout=10.0)
                emit({"jsonrpc": "2.0", "id": rid, "result": {"ok": True, "tag": t, "pid": pid}})

            threading.Thread(target=run_waiter, args=(req_id, ptok, wait_gate, tag), daemon=True).start()
        elif name == "emit_noise_and_list_changed":
            target_tag = args["target_tag"]
            finish_gate = args["finish_gate"]
            with state_lock:
                target_wid = subscriptions[target_tag]
            # Missing _meta
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/events/event",
                "params": {"cursor": "noise-no-meta", "event": {"noise": 1}},
            })
            # Missing subscriptionId
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/events/event",
                "params": {"cursor": "noise-missing-id", "event": {"noise": 2}, "_meta": {}},
            })
            # Unknown numeric subscriptionId
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/events/event",
                "params": {
                    "cursor": "noise-unknown-id",
                    "event": {"noise": 3},
                    "_meta": {"io.modelcontextprotocol/subscriptionId": 999999},
                },
            })
            # Wrong-kind string subscriptionId matching wire_id lexically
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/events/event",
                "params": {
                    "cursor": "noise-string-id",
                    "event": {"noise": 4},
                    "_meta": {"io.modelcontextprotocol/subscriptionId": str(target_wid)},
                },
            })
            # Wrong-kind boolean subscriptionId
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/events/event",
                "params": {
                    "cursor": "noise-bool-id",
                    "event": {"noise": 5},
                    "_meta": {"io.modelcontextprotocol/subscriptionId": True},
                },
            })
            # Generic list_changed notification must keep existing broadcast routing
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/events/list_changed",
                "params": {"reason": "catalog-updated"},
            })
            # Valid follow-up event for the real subscription
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/events/event",
                "params": {
                    "cursor": "after-noise",
                    "event": {"clean": True},
                    "_meta": sub_meta(target_wid, {"pid": pid}),
                },
            })
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/events/terminated",
                "params": {
                    "reason": "done",
                    "cursor": "after-noise",
                    "_meta": sub_meta(target_wid, {"pid": pid}),
                },
            })
            emit({
                "jsonrpc": "2.0",
                "id": target_wid,
                "result": {
                    "resultType": "complete",
                    "nextCursor": "after-noise",
                    "_meta": sub_meta(target_wid, {"pid": pid}),
                },
            })
            get_gate(finish_gate).set()
            emit({"jsonrpc": "2.0", "id": req_id, "result": {"emitted": True}})
        continue

    if method == "events/stream":
        params = msg.get("params", {})
        mode = params.get("mode", "immediate_full")
        tag = params.get("tag", "sub")

        if mode == "rpc_error":
            emit({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32001,
                    "message": "stream rejected by upstream",
                    "data": {"tag": tag, "pid": pid},
                },
            })
        elif mode == "immediate_full":
            emit_active(req_id, tag)
            emit_tail_and_complete(req_id, tag)
        elif mode == "register_only":
            with state_lock:
                subscriptions[tag] = req_id
            emit_active(req_id, tag)
        elif mode == "gated_full":
            wait_gate = params["wait_gate"]
            emit_active(req_id, tag)

            def run_gated(wid, t, gname):
                get_gate(gname).wait(timeout=10.0)
                emit_tail_and_complete(wid, t)

            threading.Thread(target=run_gated, args=(req_id, tag, wait_gate), daemon=True).start()
        elif mode == "malformed":
            variant = params["variant"]
            wait_gate = params["wait_gate"]
            emit_active(req_id, tag)

            def run_malformed(wid, v, gname):
                get_gate(gname).wait(timeout=10.0)
                if v == "missing_result_type":
                    result = {"_meta": sub_meta(wid)}
                elif v == "wrong_result_type":
                    result = {"resultType": "partial", "_meta": sub_meta(wid)}
                elif v == "missing_sub_id":
                    result = {"resultType": "complete"}
                elif v == "wrong_sub_id_value":
                    result = {"resultType": "complete", "_meta": sub_meta(999999)}
                elif v == "wrong_sub_id_type":
                    result = {"resultType": "complete", "_meta": sub_meta(str(wid))}
                elif v == "oversized":
                    result = {
                        "resultType": "complete",
                        "pad": "x" * 4096,
                        "_meta": sub_meta(wid),
                    }
                else:
                    raise ValueError(f"unknown variant {v}")
                emit({"jsonrpc": "2.0", "id": wid, "result": result})

            threading.Thread(target=run_malformed, args=(req_id, variant, wait_gate), daemon=True).start()
        elif mode == "terminated_no_reply":
            emit_active(req_id, tag)
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/events/event",
                "params": {
                    "cursor": f"{tag}-c1",
                    "event": {"tag": tag, "seq": 1},
                    "_meta": sub_meta(req_id, {"pid": pid}),
                },
            })
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/events/terminated",
                "params": {
                    "reason": "upstream_done_no_reply",
                    "cursor": f"{tag}-c1",
                    "_meta": sub_meta(req_id, {"pid": pid}),
                },
            })
"##;
    std::fs::write(&script_path, script).expect("write mock events fixture");
    script_path
}

fn build_upstream(
    script: &Path,
    state_dir: &Path,
    max_sessions: usize,
    limits: StdioLimits,
) -> Arc<StdioUpstream> {
    let mut env = BTreeMap::new();
    env.insert(
        "MOCK_STATE_DIR".to_owned(),
        state_dir.to_str().expect("utf-8 state dir").to_owned(),
    );
    let settings = StdioUpstreamSettings {
        command: python_executable().to_owned(),
        args: vec![
            "-u".to_owned(),
            script.to_str().expect("utf-8 script").to_owned(),
        ],
        env,
        cwd: Some(state_dir.to_path_buf()),
        max_sessions,
        session_idle_secs: 30,
    };
    Arc::new(
        StdioUpstream::with_limits(settings, ByteBudget::global(), limits)
            .expect("create stdio upstream"),
    )
}

async fn spawn_stdio_server(
    upstream: Arc<StdioUpstream>,
    grant_id: &'static str,
) -> (SocketAddr, tokio_util::sync::CancellationToken) {
    spawn_http1_harness(move |req| {
        let up = Arc::clone(&upstream);
        async move { up.handle_mcp(req, &make_token(grant_id)).await }
    })
    .await
}

fn post_mcp_req(
    addr: SocketAddr,
    sid: Option<&str>,
    protocol_version: Option<&str>,
    accept: &str,
    payload: &Value,
) -> Request<oauth2_mcp_gateway::types::ReplyBody> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/mcp"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, accept);
    if let Some(sid) = sid {
        builder = builder.header("mcp-session-id", sid);
    }
    if let Some(ver) = protocol_version {
        builder = builder.header("mcp-protocol-version", ver);
    }
    builder
        .body(bytes_body(payload.to_string()))
        .expect("build POST /mcp request")
}

async fn init_session(client: &common::TestClient, addr: SocketAddr) -> (String, u32) {
    let resp = client
        .request(post_mcp_req(
            addr,
            None,
            None,
            "application/json",
            &json!({
                "jsonrpc": "2.0",
                "id": "init-1",
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25"}
            }),
        ))
        .await
        .expect("initialize request");
    assert_eq!(resp.status(), StatusCode::OK);
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .expect("mcp-session-id header")
        .to_str()
        .expect("ascii sid")
        .to_owned();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect initialize body")
        .to_bytes();
    let parsed: Value = serde_json::from_slice(&body).expect("parse initialize json");
    let pid = parsed["result"]["_meta"]["pid"]
        .as_u64()
        .expect("child pid") as u32;
    (sid, pid)
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

    async fn next_event(&mut self) -> Result<Option<Value>, String> {
        loop {
            if let Some(idx) = self.buf.find("\n\n") {
                let block = self.buf[..idx].to_owned();
                self.buf.drain(..idx + 2);
                if block.trim().is_empty() {
                    continue;
                }
                let mut data_lines = Vec::new();
                for line in block.lines() {
                    if let Some(rest) = line.strip_prefix("data:") {
                        data_lines.push(rest.trim_start());
                    }
                }
                if data_lines.is_empty() {
                    continue;
                }
                let joined = data_lines.join("\n");
                let parsed: Value = serde_json::from_str(&joined)
                    .map_err(|e| format!("invalid SSE JSON {joined:?}: {e}"))?;
                return Ok(Some(parsed));
            }
            match tokio::time::timeout(Duration::from_secs(5), self.body.frame()).await {
                Err(_) => return Err("timed out waiting for SSE frame".to_owned()),
                Ok(None) => return Ok(None),
                Ok(Some(Err(e))) => return Err(format!("transport error: {e}")),
                Ok(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        self.buf.push_str(&String::from_utf8_lossy(&data));
                    }
                }
            }
        }
    }

    async fn collect_all(&mut self) -> Result<Vec<Value>, String> {
        let mut out = Vec::new();
        while let Some(ev) = self.next_event().await? {
            out.push(ev);
        }
        Ok(out)
    }
}

fn assert_exact_id(actual: &Value, expected: &Value, context: &str) {
    assert_eq!(actual, expected, "{context}: id mismatch");
    assert_eq!(
        actual.is_number(),
        expected.is_number(),
        "{context}: numeric vs string id kind changed"
    );
    assert_eq!(
        actual.is_string(),
        expected.is_string(),
        "{context}: string vs numeric id kind changed"
    );
}

fn assert_five_notices_and_complete(frames: &[Value], expected_id: &Value, expected_tag: &str) {
    assert_eq!(
        frames.len(),
        6,
        "expected 5 push notices + 1 complete response, got {frames:#?}"
    );
    let expected_methods = [
        "notifications/events/active",
        "notifications/events/event",
        "notifications/events/heartbeat",
        "notifications/events/error",
        "notifications/events/terminated",
    ];
    for (idx, method) in expected_methods.iter().enumerate() {
        let frame = &frames[idx];
        assert_eq!(frame["method"], *method, "frame {idx} method mismatch");
        assert!(frame.get("id").is_none(), "notification must not have id");
        assert_exact_id(
            &frame["params"]["_meta"][SUBSCRIPTION_ID_KEY],
            expected_id,
            &format!("notice {method}"),
        );
    }
    assert_eq!(frames[0]["params"]["subscription"], expected_tag);
    assert_eq!(frames[1]["params"]["event"]["tag"], expected_tag);
    assert_eq!(frames[1]["params"]["event"]["seq"], 1);
    assert_eq!(frames[2]["params"]["_meta"]["seq"], 2);
    assert_eq!(frames[3]["params"]["recoverable"], true);
    assert_eq!(frames[4]["params"]["reason"], "completed");

    let terminal = &frames[5];
    assert_exact_id(&terminal["id"], expected_id, "terminal top-level id");
    assert_eq!(terminal["result"]["resultType"], "complete");
    assert_eq!(terminal["result"]["_meta"]["tag"], expected_tag);
    assert_exact_id(
        &terminal["result"]["_meta"][SUBSCRIPTION_ID_KEY],
        expected_id,
        "terminal subscriptionId",
    );
}

#[tokio::test]
async fn stdio_events_sessionful_interleaved_streams_id_types_and_all_five_notices() {
    let tmp = TempDir::new().unwrap();
    let script = write_events_fixture_script(tmp.path());
    let upstream = build_upstream(&script, tmp.path(), 2, StdioLimits::default());
    let (addr, stop) = spawn_stdio_server(Arc::clone(&upstream), "grant-interleave").await;
    let client = make_client();
    let (sid, shared_pid) = init_session(&client, addr).await;

    // Concurrent integer 42 and string "42" on the same shared child test exact type preservation.
    let id_num = json!(42);
    let id_str = json!("42");
    let id_ord = json!("sub-alpha");

    let resp_num = client
        .request(post_mcp_req(
            addr,
            Some(&sid),
            None,
            "text/event-stream, application/json",
            &json!({
                "jsonrpc": "2.0",
                "id": id_num,
                "method": "events/stream",
                "params": {"mode": "register_only", "tag": "alpha"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp_num.status(), StatusCode::OK);
    let mut sse_num = SseReader::new(resp_num.into_body());
    let active_num = sse_num.next_event().await.unwrap().expect("active for 42");
    assert_eq!(active_num["method"], "notifications/events/active");
    assert_exact_id(
        &active_num["params"]["_meta"][SUBSCRIPTION_ID_KEY],
        &id_num,
        "immediate active for numeric 42",
    );
    assert_eq!(active_num["params"]["_meta"]["pid"], shared_pid);

    let resp_str = client
        .request(post_mcp_req(
            addr,
            Some(&sid),
            None,
            "text/event-stream",
            &json!({
                "jsonrpc": "2.0",
                "id": id_str,
                "method": "events/stream",
                "params": {"mode": "register_only", "tag": "beta"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp_str.status(), StatusCode::OK);
    let mut sse_str = SseReader::new(resp_str.into_body());
    let active_str = sse_str
        .next_event()
        .await
        .unwrap()
        .expect("active for \"42\"");
    assert_eq!(active_str["method"], "notifications/events/active");
    assert_exact_id(
        &active_str["params"]["_meta"][SUBSCRIPTION_ID_KEY],
        &id_str,
        "immediate active for string \"42\"",
    );
    assert_eq!(active_str["params"]["_meta"]["pid"], shared_pid);

    // Ordinary RPC interleaved on the same shared child while both subscriptions stay active.
    let ord_resp = client
        .request(post_mcp_req(
            addr,
            Some(&sid),
            None,
            "application/json",
            &json!({
                "jsonrpc": "2.0",
                "id": id_ord,
                "method": "tools/call",
                "params": {
                    "name": "interleave_and_finish",
                    "arguments": {"tags": ["alpha", "beta"]}
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(ord_resp.status(), StatusCode::OK);
    let ord_bytes = ord_resp.into_body().collect().await.unwrap().to_bytes();
    let ord_json: Value = serde_json::from_slice(&ord_bytes).unwrap();
    assert_exact_id(&ord_json["id"], &id_ord, "ordinary interleaved call");
    assert_eq!(ord_json["result"]["pid"], shared_pid);

    let (rest_num, rest_str) = tokio::join!(sse_num.collect_all(), sse_str.collect_all());
    let mut all_num = vec![active_num];
    all_num.extend(rest_num.expect("numeric stream completes cleanly"));
    let mut all_str = vec![active_str];
    all_str.extend(rest_str.expect("string stream completes cleanly"));

    assert_five_notices_and_complete(&all_num, &id_num, "alpha");
    assert_five_notices_and_complete(&all_str, &id_str, "beta");

    stop.cancel();
    upstream.shutdown().await;
}

#[tokio::test]
async fn stdio_events_ignores_bad_subscription_id_and_preserves_list_changed() {
    let tmp = TempDir::new().unwrap();
    let script = write_events_fixture_script(tmp.path());
    let upstream = build_upstream(&script, tmp.path(), 2, StdioLimits::default());
    let (addr, stop) = spawn_stdio_server(Arc::clone(&upstream), "grant-noise").await;
    let client = make_client();
    let (sid, _) = init_session(&client, addr).await;

    let sub_id = json!("sub-alpha");
    let sub_resp = client
        .request(post_mcp_req(
            addr,
            Some(&sid),
            None,
            "text/event-stream",
            &json!({
                "jsonrpc": "2.0",
                "id": sub_id,
                "method": "events/stream",
                "params": {"mode": "register_only", "tag": "watched"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(sub_resp.status(), StatusCode::OK);
    let mut sub_sse = SseReader::new(sub_resp.into_body());
    let sub_active = sub_sse.next_event().await.unwrap().expect("active");
    assert_eq!(sub_active["method"], "notifications/events/active");

    let ord_resp = client
        .request(post_mcp_req(
            addr,
            Some(&sid),
            None,
            "text/event-stream",
            &json!({
                "jsonrpc": "2.0",
                "id": 77,
                "method": "tools/call",
                "params": {
                    "name": "sse_waiter",
                    "arguments": {"wait_gate": "noise_done", "tag": "ord-waiter"},
                    "_meta": {"progressToken": "ord-ptok"}
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(ord_resp.status(), StatusCode::OK);
    let mut ord_sse = SseReader::new(ord_resp.into_body());
    let ord_progress = ord_sse
        .next_event()
        .await
        .unwrap()
        .expect("initial progress");
    assert_eq!(ord_progress["method"], "notifications/progress");

    let trigger_resp = client
        .request(post_mcp_req(
            addr,
            Some(&sid),
            None,
            "application/json",
            &json!({
                "jsonrpc": "2.0",
                "id": "trigger-noise",
                "method": "tools/call",
                "params": {
                    "name": "emit_noise_and_list_changed",
                    "arguments": {"target_tag": "watched", "finish_gate": "noise_done"}
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(trigger_resp.status(), StatusCode::OK);
    let _ = trigger_resp.into_body().collect().await.unwrap();

    let (sub_rest, ord_rest) = tokio::join!(sub_sse.collect_all(), ord_sse.collect_all());
    let sub_frames = sub_rest.expect("events stream completes");
    let ord_frames = ord_rest.expect("ordinary sse completes");

    // Bad-id push notifications must never reach either waiter.
    for frame in sub_frames.iter().chain(ord_frames.iter()) {
        if frame.get("method").and_then(Value::as_str) == Some("notifications/events/event") {
            assert_eq!(
                frame["params"]["cursor"], "after-noise",
                "unexpected invalid push notice delivered: {frame:?}"
            );
        }
    }
    assert!(
        !ord_frames
            .iter()
            .any(|f| f.get("method").and_then(Value::as_str) == Some("notifications/events/event")),
        "ordinary waiter must never receive events push notices: {ord_frames:#?}"
    );
    assert!(
        ord_frames.iter().any(|f| {
            f.get("method").and_then(Value::as_str) == Some("notifications/events/list_changed")
                && f["params"]["reason"] == "catalog-updated"
        }),
        "notifications/events/list_changed must still reach ordinary SSE waiter: {ord_frames:#?}"
    );
    assert_eq!(ord_frames.last().unwrap()["id"], json!(77));

    assert!(
        sub_frames.iter().any(|f| {
            f.get("method").and_then(Value::as_str) == Some("notifications/events/event")
                && f["params"]["cursor"] == "after-noise"
        }),
        "valid follow-up event missing: {sub_frames:#?}"
    );
    let sub_terminal = sub_frames.last().unwrap();
    assert_exact_id(&sub_terminal["id"], &sub_id, "watched terminal id");
    assert_eq!(sub_terminal["result"]["resultType"], "complete");

    stop.cancel();
    upstream.shutdown().await;
}

#[tokio::test]
async fn stdio_events_upstream_rpc_error_restores_original_id() {
    let tmp = TempDir::new().unwrap();
    let script = write_events_fixture_script(tmp.path());
    let upstream = build_upstream(&script, tmp.path(), 2, StdioLimits::default());
    let (addr, stop) = spawn_stdio_server(Arc::clone(&upstream), "grant-rpc-err").await;
    let client = make_client();
    let (sid, _) = init_session(&client, addr).await;

    for (req_id, tag) in [(json!(42), "err-num"), (json!("sub-alpha"), "err-str")] {
        let resp = client
            .request(post_mcp_req(
                addr,
                Some(&sid),
                None,
                "text/event-stream",
                &json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "events/stream",
                    "params": {"mode": "rpc_error", "tag": tag}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let mut sse = SseReader::new(resp.into_body());
        let frames = sse.collect_all().await.expect("rpc error closes cleanly");
        assert_eq!(frames.len(), 1, "expected single JSON-RPC error frame");
        assert_exact_id(&frames[0]["id"], &req_id, "rpc error top-level id");
        assert_eq!(frames[0]["error"]["code"], -32001);
        assert_eq!(frames[0]["error"]["message"], "stream rejected by upstream");
        assert_eq!(frames[0]["error"]["data"]["tag"], tag);
    }

    stop.cancel();
    upstream.shutdown().await;
}

#[tokio::test]
async fn stdio_events_malformed_and_oversized_completions_fail_stream_and_spare_siblings() {
    let tmp = TempDir::new().unwrap();
    let script = write_events_fixture_script(tmp.path());
    let limits = StdioLimits {
        max_control_line_bytes: 2048,
        ..StdioLimits::default()
    };
    let upstream = build_upstream(&script, tmp.path(), 2, limits);
    let (addr, stop) = spawn_stdio_server(Arc::clone(&upstream), "grant-malformed").await;
    let client = make_client();
    let (sid, shared_pid) = init_session(&client, addr).await;

    let variants = [
        "missing_result_type",
        "wrong_result_type",
        "missing_sub_id",
        "wrong_sub_id_value",
        "wrong_sub_id_type",
        "oversized",
    ];

    for (idx, variant) in variants.iter().enumerate() {
        let gate = format!("malformed_gate_{idx}");
        let bad_id = json!(format!("bad-{variant}"));
        let sib_id = json!(1000 + idx as u64);

        let bad_resp = client
            .request(post_mcp_req(
                addr,
                Some(&sid),
                None,
                "text/event-stream",
                &json!({
                    "jsonrpc": "2.0",
                    "id": bad_id,
                    "method": "events/stream",
                    "params": {
                        "mode": "malformed",
                        "variant": variant,
                        "tag": format!("bad-{idx}"),
                        "wait_gate": gate
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(bad_resp.status(), StatusCode::OK);
        let mut bad_sse = SseReader::new(bad_resp.into_body());
        let bad_active = bad_sse
            .next_event()
            .await
            .unwrap()
            .expect("active before malformed completion");
        assert_eq!(bad_active["method"], "notifications/events/active");
        assert_exact_id(
            &bad_active["params"]["_meta"][SUBSCRIPTION_ID_KEY],
            &bad_id,
            variant,
        );

        let sib_resp = client
            .request(post_mcp_req(
                addr,
                Some(&sid),
                None,
                "text/event-stream",
                &json!({
                    "jsonrpc": "2.0",
                    "id": sib_id,
                    "method": "events/stream",
                    "params": {
                        "mode": "gated_full",
                        "tag": format!("sib-{idx}"),
                        "wait_gate": gate
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(sib_resp.status(), StatusCode::OK);
        let mut sib_sse = SseReader::new(sib_resp.into_body());
        let sib_active = sib_sse.next_event().await.unwrap().expect("sibling active");
        assert_eq!(sib_active["method"], "notifications/events/active");

        let rel_resp = client
            .request(post_mcp_req(
                addr,
                Some(&sid),
                None,
                "application/json",
                &json!({
                    "jsonrpc": "2.0",
                    "id": format!("rel-{idx}"),
                    "method": "tools/call",
                    "params": {"name": "release_gate", "arguments": {"gate": gate}}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(rel_resp.status(), StatusCode::OK);
        let rel_json: Value =
            serde_json::from_slice(&rel_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(rel_json["result"]["pid"], shared_pid);

        let (bad_next, sib_rest) = tokio::join!(bad_sse.next_event(), sib_sse.collect_all());
        let Err(bad_err) = bad_next else {
            panic!(
                "variant {variant} must fail stream with transport error without passing through any frame, got {bad_next:?}"
            );
        };
        assert!(
            bad_err.starts_with("transport error:"),
            "variant {variant} must fail with transport error, not timeout or parse error: {bad_err}"
        );

        let mut sib_all = vec![sib_active];
        sib_all.extend(
            sib_rest.unwrap_or_else(|e| panic!("sibling stream must survive {variant}, got {e}")),
        );
        assert_five_notices_and_complete(&sib_all, &sib_id, &format!("sib-{idx}"));
    }

    stop.cancel();
    upstream.shutdown().await;
}

#[tokio::test]
async fn stdio_events_sessionless_concurrent_same_id_streams_are_independent() {
    let tmp = TempDir::new().unwrap();
    let script = write_events_fixture_script(tmp.path());
    let upstream = build_upstream(&script, tmp.path(), 4, StdioLimits::default());
    let (addr, stop) = spawn_stdio_server(Arc::clone(&upstream), "grant-sessionless").await;
    let client = make_client();

    let shared_str_id = json!("sub-alpha");
    let req_a = client.request(post_mcp_req(
        addr,
        None,
        Some(SESSIONLESS_PROTOCOL_VERSION),
        "text/event-stream",
        &json!({
            "jsonrpc": "2.0",
            "id": shared_str_id,
            "method": "events/stream",
            "params": {"mode": "immediate_full", "tag": "ephemeral-a"}
        }),
    ));
    let req_b = client.request(post_mcp_req(
        addr,
        None,
        Some(SESSIONLESS_PROTOCOL_VERSION),
        "text/event-stream, application/json",
        &json!({
            "jsonrpc": "2.0",
            "id": shared_str_id,
            "method": "events/stream",
            "params": {"mode": "immediate_full", "tag": "ephemeral-b"}
        }),
    ));
    let (resp_a, resp_b) = tokio::join!(req_a, req_b);
    let resp_a = resp_a.unwrap();
    let resp_b = resp_b.unwrap();
    assert_eq!(resp_a.status(), StatusCode::OK);
    assert_eq!(resp_b.status(), StatusCode::OK);
    assert!(resp_a.headers().get("mcp-session-id").is_none());
    assert!(resp_b.headers().get("mcp-session-id").is_none());

    let mut sse_a = SseReader::new(resp_a.into_body());
    let mut sse_b = SseReader::new(resp_b.into_body());
    let (frames_a, frames_b) = tokio::join!(sse_a.collect_all(), sse_b.collect_all());
    let frames_a = frames_a.expect("sessionless stream a");
    let frames_b = frames_b.expect("sessionless stream b");

    assert_five_notices_and_complete(&frames_a, &shared_str_id, "ephemeral-a");
    assert_five_notices_and_complete(&frames_b, &shared_str_id, "ephemeral-b");

    let pid_a = frames_a[0]["params"]["_meta"]["pid"].as_u64().unwrap() as u32;
    let pid_b = frames_b[0]["params"]["_meta"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(
        pid_a, pid_b,
        "concurrent sessionless calls must use separate children"
    );
    assert!(
        wait_process_gone(pid_a).await,
        "ephemeral child a not reaped"
    );
    assert!(
        wait_process_gone(pid_b).await,
        "ephemeral child b not reaped"
    );

    // Numeric ID on sessionless also preserves integer type.
    let num_id = json!(42);
    let resp_num = client
        .request(post_mcp_req(
            addr,
            None,
            Some(SESSIONLESS_PROTOCOL_VERSION),
            "text/event-stream",
            &json!({
                "jsonrpc": "2.0",
                "id": num_id,
                "method": "events/stream",
                "params": {"mode": "immediate_full", "tag": "ephemeral-num"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp_num.status(), StatusCode::OK);
    let mut sse_num = SseReader::new(resp_num.into_body());
    let frames_num = sse_num.collect_all().await.expect("sessionless numeric");
    assert_five_notices_and_complete(&frames_num, &num_id, "ephemeral-num");
    let pid_num = frames_num[0]["params"]["_meta"]["pid"].as_u64().unwrap() as u32;
    assert!(
        wait_process_gone(pid_num).await,
        "ephemeral numeric child not reaped"
    );

    stop.cancel();
    upstream.shutdown().await;
}

#[tokio::test]
async fn stdio_events_accept_406_before_dispatch_on_sessionful_and_sessionless() {
    let bad_accepts = [
        "application/json",
        "*/*",
        "text/event-stream; q=0, application/json",
    ];

    // Sessionful: must reject before registering or writing to child stdin.
    let tmp_sf = TempDir::new().unwrap();
    let script_sf = write_events_fixture_script(tmp_sf.path());
    let up_sf = build_upstream(&script_sf, tmp_sf.path(), 2, StdioLimits::default());
    let (addr_sf, stop_sf) = spawn_stdio_server(Arc::clone(&up_sf), "grant-406-sf").await;
    let client = make_client();
    let (sid, sf_pid) = init_session(&client, addr_sf).await;

    for (idx, accept) in bad_accepts.iter().enumerate() {
        let req_id = json!(format!("sf-406-{idx}"));
        let resp = client
            .request(post_mcp_req(
                addr_sf,
                Some(&sid),
                None,
                accept,
                &json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "events/stream",
                    "params": {"mode": "immediate_full", "tag": "must-not-send"}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_ACCEPTABLE,
            "sessionful Accept={accept:?} must return 406"
        );
        let body: Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_exact_id(&body["id"], &req_id, "sessionful 406 id");
    }

    // Confirm child stdin is responsive and never saw any events/stream request.
    let probe = client
        .request(post_mcp_req(
            addr_sf,
            Some(&sid),
            None,
            "application/json",
            &json!({
                "jsonrpc": "2.0",
                "id": "probe-after-406",
                "method": "tools/call",
                "params": {"name": "slot_probe"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(probe.status(), StatusCode::OK);
    let _ = probe.into_body().collect().await.unwrap();

    let log_text = std::fs::read_to_string(tmp_sf.path().join(format!("log_{sf_pid}.jsonl")))
        .expect("read child stdin log");
    assert!(
        !log_text.contains("\"events/stream\""),
        "rejected events/stream must never reach child stdin: {log_text}"
    );

    stop_sf.cancel();
    up_sf.shutdown().await;

    // Sessionless: must reject before spawning any ephemeral child.
    let tmp_sl = TempDir::new().unwrap();
    let script_sl = write_events_fixture_script(tmp_sl.path());
    let up_sl = build_upstream(&script_sl, tmp_sl.path(), 2, StdioLimits::default());
    let (addr_sl, stop_sl) = spawn_stdio_server(Arc::clone(&up_sl), "grant-406-sl").await;

    for (idx, accept) in bad_accepts.iter().enumerate() {
        let req_id = json!(idx as u64 + 10);
        let resp = client
            .request(post_mcp_req(
                addr_sl,
                None,
                Some(SESSIONLESS_PROTOCOL_VERSION),
                accept,
                &json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "events/stream",
                    "params": {"mode": "immediate_full", "tag": "must-not-spawn"}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_ACCEPTABLE,
            "sessionless Accept={accept:?} must return 406"
        );
        let body: Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_exact_id(&body["id"], &req_id, "sessionless 406 id");
    }

    let spawned_markers: Vec<_> = std::fs::read_dir(tmp_sl.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("spawn_"))
        })
        .collect();
    assert!(
        spawned_markers.is_empty(),
        "sessionless 406 must not spawn any child, found {spawned_markers:?}"
    );

    stop_sl.cancel();
    up_sl.shutdown().await;
}

#[tokio::test]
async fn stdio_events_terminated_then_disconnect_without_final_reply_releases_slot() {
    // Shared sessionful child with 1 in-flight slot verifies slot release after disconnect.
    let tmp = TempDir::new().unwrap();
    let script = write_events_fixture_script(tmp.path());
    let limits = StdioLimits {
        max_in_flight_per_session: 1,
        ..StdioLimits::default()
    };
    let upstream = build_upstream(&script, tmp.path(), 1, limits);
    let (addr, stop) = spawn_stdio_server(Arc::clone(&upstream), "grant-term-drop").await;
    let client = make_client();
    let (sid, sf_pid) = init_session(&client, addr).await;

    let sub_id = json!("term-only-1");
    let resp = client
        .request(post_mcp_req(
            addr,
            Some(&sid),
            None,
            "text/event-stream",
            &json!({
                "jsonrpc": "2.0",
                "id": sub_id,
                "method": "events/stream",
                "params": {"mode": "terminated_no_reply", "tag": "term-only"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut sse = SseReader::new(resp.into_body());

    let f_active = sse.next_event().await.unwrap().expect("active");
    let f_event = sse.next_event().await.unwrap().expect("event");
    let f_term = sse.next_event().await.unwrap().expect("terminated");
    assert_eq!(f_active["method"], "notifications/events/active");
    assert_eq!(f_event["method"], "notifications/events/event");
    assert_eq!(f_term["method"], "notifications/events/terminated");
    assert_eq!(f_term["params"]["reason"], "upstream_done_no_reply");
    assert_exact_id(
        &f_term["params"]["_meta"][SUBSCRIPTION_ID_KEY],
        &sub_id,
        "terminated subscriptionId",
    );

    // No final reply may be fabricated before the client disconnects.
    assert!(
        tokio::time::timeout(Duration::from_millis(120), sse.next_event())
            .await
            .is_err(),
        "gateway must not fabricate a final response after terminated"
    );

    // Disconnect immediately after terminated.
    drop(sse);

    // Wait for cancellation to settle and release the single in-flight slot.
    let cancel_file = tmp.path().join(format!("cancelled_{sf_pid}.jsonl"));
    let deadline = Instant::now() + Duration::from_secs(3);
    while !cancel_file.exists() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        cancel_file.exists(),
        "shared child should receive notifications/cancelled after client disconnect"
    );

    let probe_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let probe = client
            .request(post_mcp_req(
                addr,
                Some(&sid),
                None,
                "application/json",
                &json!({
                    "jsonrpc": "2.0",
                    "id": "after-term-drop",
                    "method": "tools/call",
                    "params": {"name": "slot_probe"}
                }),
            ))
            .await
            .unwrap();
        if probe.status() == StatusCode::OK {
            let body: Value =
                serde_json::from_slice(&probe.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(body["result"]["ok"], true);
            break;
        }
        assert!(
            Instant::now() < probe_deadline,
            "in-flight slot did not release after terminated disconnect (status {})",
            probe.status()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    stop.cancel();
    upstream.shutdown().await;

    // Sessionless with 1 session slot: terminated + disconnect reaps child and frees slot.
    let tmp_sl = TempDir::new().unwrap();
    let script_sl = write_events_fixture_script(tmp_sl.path());
    let up_sl = build_upstream(&script_sl, tmp_sl.path(), 1, StdioLimits::default());
    let (addr_sl, stop_sl) = spawn_stdio_server(Arc::clone(&up_sl), "grant-term-drop-sl").await;

    let sl_resp = client
        .request(post_mcp_req(
            addr_sl,
            None,
            Some(SESSIONLESS_PROTOCOL_VERSION),
            "text/event-stream",
            &json!({
                "jsonrpc": "2.0",
                "id": 99,
                "method": "events/stream",
                "params": {"mode": "terminated_no_reply", "tag": "term-sl"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(sl_resp.status(), StatusCode::OK);
    let mut sl_sse = SseReader::new(sl_resp.into_body());
    let sl_active = sl_sse.next_event().await.unwrap().expect("sl active");
    let sl_pid = sl_active["params"]["_meta"]["pid"].as_u64().unwrap() as u32;
    let _ = sl_sse.next_event().await.unwrap().expect("sl event");
    let sl_term = sl_sse.next_event().await.unwrap().expect("sl terminated");
    assert_eq!(sl_term["method"], "notifications/events/terminated");
    drop(sl_sse);

    assert!(
        wait_process_gone(sl_pid).await,
        "ephemeral child must be reaped after terminated disconnect"
    );

    let followup = client
        .request(post_mcp_req(
            addr_sl,
            None,
            Some(SESSIONLESS_PROTOCOL_VERSION),
            "application/json",
            &json!({
                "jsonrpc": "2.0",
                "id": "sl-after-term",
                "method": "tools/call",
                "params": {"name": "slot_probe"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(followup.status(), StatusCode::OK);
    let _ = followup.into_body().collect().await.unwrap();

    stop_sl.cancel();
    up_sl.shutdown().await;
}
