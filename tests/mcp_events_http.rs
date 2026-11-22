mod common;

use bytes::Bytes;
use common::{TestClient, channel_body, make_client, spawn_gateway, spawn_http1_harness};
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use oauth2_mcp_gateway::config::GatewayConfig;
use oauth2_mcp_gateway::crypto::{PasswordVerifier, sha256_b64};
use oauth2_mcp_gateway::types::{ReplyBody, bytes_body, empty_body};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use url::Url;

const OWNER_PASSWORD: &str = "events-http-test-password-42";
const PUBLIC_URL: &str = "https://mcp.example.com";
const PROTOCOL_VERSION: &str = "2025-11-25";
const SESSION_ID: &str = "http-events-session-1";
const UPSTREAM_BEARER: &str = "upstream-events-pool-secret";

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: Method,
    headers: BTreeMap<String, String>,
    body: Value,
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}

fn extract_hidden_input(html: &str, field_name: &str) -> String {
    let marker = format!("name=\"{field_name}\" value=\"");
    let start = html.find(&marker).expect("hidden input present") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("closing quote");
    rest[..end].to_owned()
}

fn extract_cookie_pair(headers: &HeaderMap) -> String {
    headers
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header")
        .to_str()
        .expect("ASCII Set-Cookie")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned()
}

async fn send_http(
    client: &TestClient,
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: ReplyBody,
) -> (StatusCode, HeaderMap, Bytes) {
    let mut builder = Request::builder().method(method).uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let resp = client
        .request(builder.body(body).expect("build request"))
        .await
        .expect("execute request");
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    (status, resp_headers, bytes)
}

async fn authorize_access_token(client: &TestClient, gw_addr: SocketAddr) -> String {
    let redirect_uri = "http://127.0.0.1:43210/callback";
    let (reg_status, _, reg_body) = send_http(
        client,
        Method::POST,
        &format!("http://{gw_addr}/oauth/register"),
        &[("content-type", "application/json")],
        bytes_body(
            json!({
                "client_name": "events-http-client",
                "redirect_uris": [redirect_uri],
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(reg_status, StatusCode::CREATED);
    let client_id = serde_json::from_slice::<Value>(&reg_body).unwrap()["client_id"]
        .as_str()
        .expect("client_id")
        .to_owned();

    let verifier = "events-http-pkce-verifier-0123456789abcdef0123456789";
    let challenge = sha256_b64(verifier);
    let auth_query = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("state", "events-state"),
    ]);

    let (get_status, get_headers, get_body) = send_http(
        client,
        Method::GET,
        &format!("http://{gw_addr}/oauth/authorize?{auth_query}"),
        &[],
        empty_body(),
    )
    .await;
    assert_eq!(get_status, StatusCode::OK);

    let cookie_pair = extract_cookie_pair(&get_headers);
    let html = std::str::from_utf8(&get_body).expect("UTF-8 authorize HTML");
    let ar_id = extract_hidden_input(html, "ar_id");
    let csrf_token = extract_hidden_input(html, "csrf_token");

    let post_form = form_encode(&[
        ("ar_id", &ar_id),
        ("csrf_token", &csrf_token),
        ("password", OWNER_PASSWORD),
    ]);
    let (post_status, post_headers, _) = send_http(
        client,
        Method::POST,
        &format!("http://{gw_addr}/oauth/authorize"),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie_pair),
            ("origin", PUBLIC_URL),
        ],
        bytes_body(post_form),
    )
    .await;
    assert_eq!(post_status, StatusCode::SEE_OTHER);

    let location = post_headers
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .expect("ASCII Location");
    let params: BTreeMap<String, String> = Url::parse(location)
        .expect("valid redirect URL")
        .query_pairs()
        .into_owned()
        .collect();
    let code = params.get("code").expect("authorization code");

    let token_form = form_encode(&[
        ("grant_type", "authorization_code"),
        ("client_id", &client_id),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
    ]);
    let (tok_status, _, tok_body) = send_http(
        client,
        Method::POST,
        &format!("http://{gw_addr}/oauth/token"),
        &[("content-type", "application/x-www-form-urlencoded")],
        bytes_body(token_form),
    )
    .await;
    assert_eq!(tok_status, StatusCode::OK);
    serde_json::from_slice::<Value>(&tok_body).unwrap()["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned()
}

fn build_events_stream_frames(req_id: &Value) -> Vec<(Option<&'static str>, Value)> {
    let sub_meta = |extra: Value| {
        let mut obj = extra.as_object().cloned().unwrap_or_default();
        obj.insert(
            "io.modelcontextprotocol/subscriptionId".to_owned(),
            req_id.clone(),
        );
        Value::Object(obj)
    };

    vec![
        (
            Some("ev-active-1"),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/events/active",
                "params": {
                    "subscription": "tasks",
                    "cursor": "cur-0",
                    "_meta": sub_meta(json!({ "phase": "active" }))
                }
            }),
        ),
        (
            Some("ev-data-2"),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/events/event",
                "params": {
                    "cursor": "cur-1",
                    "event": { "kind": "task.done", "exitCode": 0 },
                    "_meta": sub_meta(json!({ "source": "upstream-http" }))
                }
            }),
        ),
        (
            Some("ev-hb-3"),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/events/heartbeat",
                "params": {
                    "cursor": "cur-1",
                    "_meta": sub_meta(json!({ "intervalSec": 15 }))
                }
            }),
        ),
        (
            Some("ev-err-4"),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/events/error",
                "params": {
                    "code": "transient_gap",
                    "message": "recoverable upstream notice",
                    "recoverable": true,
                    "_meta": sub_meta(json!({ "cursor": "cur-1" }))
                }
            }),
        ),
        (
            Some("ev-term-5"),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/events/terminated",
                "params": {
                    "reason": "completed",
                    "cursor": "cur-2",
                    "_meta": sub_meta(json!({ "terminal": true }))
                }
            }),
        ),
        (
            Some("ev-complete-6"),
            json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resultType": "complete",
                    "nextCursor": "cur-2",
                    "_meta": sub_meta(json!({ "upstreamTag": "untouched" }))
                }
            }),
        ),
    ]
}

fn parse_sse_blocks(raw: &str) -> Vec<(Option<String>, Value)> {
    raw.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            let mut id = None;
            let mut data_lines = Vec::new();
            for line in block.lines() {
                if let Some(rest) = line.strip_prefix("id:") {
                    id = Some(rest.trim().to_owned());
                } else if let Some(rest) = line.strip_prefix("data:") {
                    data_lines.push(rest.trim_start());
                }
            }
            let data = data_lines.join("\n");
            let parsed: Value = serde_json::from_str(&data)
                .unwrap_or_else(|e| panic!("invalid JSON in SSE block {block:?}: {e}"));
            (id, parsed)
        })
        .collect()
}

#[tokio::test]
async fn http_upstream_events_list_poll_and_sse_stream_passthrough() {
    let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_up = Arc::clone(&captured);

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let captured_ref = Arc::clone(&captured_up);
        async move {
            let method = req.method().clone();
            let headers: BTreeMap<String, String> = req
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
                .collect();
            let raw_body = req
                .into_body()
                .collect()
                .await
                .expect("collect upstream body")
                .to_bytes();
            let body: Value = serde_json::from_slice(&raw_body).unwrap_or(Value::Null);
            captured_ref.lock().unwrap().push(CapturedRequest {
                method,
                headers,
                body: body.clone(),
            });

            let rpc_method = body.get("method").and_then(Value::as_str).unwrap_or("");
            let rpc_id = body.get("id").cloned().unwrap_or(Value::Null);

            match rpc_method {
                "initialize" => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("mcp-session-id", SESSION_ID)
                    .header("mcp-protocol-version", PROTOCOL_VERSION)
                    .body(bytes_body(
                        json!({
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "result": {
                                "protocolVersion": PROTOCOL_VERSION,
                                "capabilities": { "events": {} },
                                "serverInfo": { "name": "mock-http-events", "version": "1.0.0" }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
                "events/list" => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("mcp-session-id", SESSION_ID)
                    .header("mcp-protocol-version", PROTOCOL_VERSION)
                    .header("x-upstream-route", "events-list")
                    .body(bytes_body(
                        json!({
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "result": {
                                "streams": [{ "name": "tasks", "supportsPush": true }],
                                "_meta": { "cursorVersion": 1 }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
                "events/poll" => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("mcp-session-id", SESSION_ID)
                    .header("mcp-protocol-version", PROTOCOL_VERSION)
                    .header("x-upstream-route", "events-poll")
                    .body(bytes_body(
                        json!({
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "result": {
                                "events": [{ "cursor": "cur-1", "payload": { "ok": true } }],
                                "nextCursor": "cur-1",
                                "_meta": { "source": "poll" }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
                "events/stream" => {
                    let frames = build_events_stream_frames(&rpc_id);
                    let (tx, body) = channel_body(16);
                    tokio::spawn(async move {
                        let priming: &[&[u8]] = &[
                            b": priming comment\n\n",
                            b"retry: 2500\r\n\r\n",
                            b"id: prime-0\n\n",
                        ];
                        for chunk in priming {
                            if tx
                                .send(Ok(Frame::data(Bytes::from_static(chunk))))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        for (ev_id, payload) in frames {
                            let mut wire = String::new();
                            if let Some(id) = ev_id {
                                wire.push_str("id: ");
                                wire.push_str(id);
                                wire.push('\n');
                            }
                            wire.push_str("data: ");
                            wire.push_str(&payload.to_string());
                            wire.push_str("\n\n");
                            if tx.send(Ok(Frame::data(Bytes::from(wire)))).await.is_err() {
                                return;
                            }
                        }
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
                        .header(header::CACHE_CONTROL, "no-cache")
                        .header("mcp-session-id", SESSION_ID)
                        .header("mcp-protocol-version", PROTOCOL_VERSION)
                        .header("x-upstream-route", "events-stream")
                        .body(body)
                        .unwrap()
                }
                _ => Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(empty_body())
                    .unwrap(),
            }
        }
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let owner_hash = PasswordVerifier::from_plaintext_with_iterations(OWNER_PASSWORD, 10_000)
        .expect("pbkdf2 hash")
        .encode();
    let cfg_json = format!(
        r#"{{
          "listen": "127.0.0.1:0",
          "public_url": "{PUBLIC_URL}",
          "state_path": "state.json",
          "oauth": {{ "owner_password_hash": "{owner_hash}" }},
          "upstream": {{
            "transport": "http",
            "url": "http://{up_addr}/mcp",
            "bearer_tokens": ["{UPSTREAM_BEARER}"],
            "request_timeout_secs": 30
          }}
        }}"#
    );
    let cfg = Arc::new(GatewayConfig::from_json_str(&cfg_json, tmp.path()).unwrap());
    let (gw_addr, gw_shutdown, gw_task) = spawn_gateway(cfg).await;

    let client = make_client();
    let access_token = authorize_access_token(&client, gw_addr).await;
    let bearer = format!("Bearer {access_token}");
    let mcp_url = format!("http://{gw_addr}/mcp");

    let (init_status, init_headers, init_body) = send_http(
        &client,
        Method::POST,
        &mcp_url,
        &[
            ("authorization", &bearer),
            ("content-type", "application/json"),
            ("accept", "application/json"),
            ("mcp-protocol-version", PROTOCOL_VERSION),
        ],
        bytes_body(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": PROTOCOL_VERSION }
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(init_status, StatusCode::OK);
    assert_eq!(
        init_headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok()),
        Some(SESSION_ID)
    );
    let init_json: Value = serde_json::from_slice(&init_body).unwrap();
    assert_eq!(init_json["id"], json!(1));

    let (list_status, list_headers, list_body) = send_http(
        &client,
        Method::POST,
        &mcp_url,
        &[
            ("authorization", &bearer),
            ("content-type", "application/json"),
            ("accept", "application/json"),
            ("mcp-protocol-version", PROTOCOL_VERSION),
            ("mcp-session-id", SESSION_ID),
        ],
        bytes_body(
            json!({
                "jsonrpc": "2.0",
                "id": "list-req-1",
                "method": "events/list",
                "params": {}
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(
        list_headers
            .get("mcp-protocol-version")
            .and_then(|v| v.to_str().ok()),
        Some(PROTOCOL_VERSION)
    );
    assert_eq!(
        list_headers
            .get("x-upstream-route")
            .and_then(|v| v.to_str().ok()),
        Some("events-list")
    );
    let list_json: Value = serde_json::from_slice(&list_body).unwrap();
    assert_eq!(list_json["id"], json!("list-req-1"));
    assert_eq!(list_json["result"]["streams"][0]["name"], json!("tasks"));

    let (poll_status, poll_headers, poll_body) = send_http(
        &client,
        Method::POST,
        &mcp_url,
        &[
            ("authorization", &bearer),
            ("content-type", "application/json"),
            ("accept", "application/json"),
            ("mcp-protocol-version", PROTOCOL_VERSION),
            ("mcp-session-id", SESSION_ID),
            ("last-event-id", "cur-0"),
        ],
        bytes_body(
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "events/poll",
                "params": { "cursor": "cur-0" }
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(poll_status, StatusCode::OK);
    assert_eq!(
        poll_headers
            .get("x-upstream-route")
            .and_then(|v| v.to_str().ok()),
        Some("events-poll")
    );
    let poll_json: Value = serde_json::from_slice(&poll_body).unwrap();
    assert_eq!(poll_json["id"], json!(7));
    assert_eq!(poll_json["result"]["nextCursor"], json!("cur-1"));

    for (req_id, last_event_id) in [(json!(42), "cur-0"), (json!("sub-str-7"), "cur-1")] {
        let req_payload = json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "events/stream",
            "params": { "subscription": "tasks", "cursor": last_event_id }
        });
        let req = Request::builder()
            .method(Method::POST)
            .uri(&mcp_url)
            .header(header::AUTHORIZATION, &bearer)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "text/event-stream, application/json")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .header("mcp-session-id", SESSION_ID)
            .header("last-event-id", last_event_id)
            .body(bytes_body(req_payload.to_string()))
            .unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(5), client.request(req))
            .await
            .expect("events/stream response timeout")
            .expect("events/stream HTTP request");

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream; charset=utf-8")
        );
        assert_eq!(
            resp.headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok()),
            Some(SESSION_ID)
        );
        assert_eq!(
            resp.headers()
                .get("mcp-protocol-version")
                .and_then(|v| v.to_str().ok()),
            Some(PROTOCOL_VERSION)
        );
        assert_eq!(
            resp.headers()
                .get("x-upstream-route")
                .and_then(|v| v.to_str().ok()),
            Some("events-stream")
        );
        assert_eq!(
            resp.headers()
                .get("x-accel-buffering")
                .and_then(|v| v.to_str().ok()),
            Some("no")
        );
        assert!(resp.headers().get(header::CONTENT_LENGTH).is_none());

        let sse_bytes = tokio::time::timeout(Duration::from_secs(5), resp.into_body().collect())
            .await
            .expect("SSE body collect timeout")
            .expect("SSE body collect")
            .to_bytes();
        let sse_text = String::from_utf8(sse_bytes.to_vec()).expect("UTF-8 SSE stream");

        assert!(!sse_text.contains("priming comment"));
        assert!(!sse_text.contains("retry: 2500"));
        assert!(!sse_text.contains("prime-0"));
        assert!(
            sse_text.starts_with("id: ev-active-1\ndata: "),
            "expected priming blocks stripped before first data frame, got: {sse_text:?}"
        );

        let received = parse_sse_blocks(&sse_text);
        let expected = build_events_stream_frames(&req_id);
        assert_eq!(received.len(), expected.len());

        for ((got_id, got_json), (want_id, want_json)) in received.iter().zip(expected.iter()) {
            assert_eq!(got_id.as_deref(), *want_id);
            assert_eq!(got_json, want_json);
        }

        for (_, frame) in &received[..5] {
            let sub_id = &frame["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"];
            assert_eq!(sub_id, &req_id);
            assert_eq!(sub_id.is_u64(), req_id.is_u64());
            assert_eq!(sub_id.is_string(), req_id.is_string());
        }
        let final_frame = &received[5].1;
        assert_eq!(final_frame["id"], req_id);
        assert_eq!(final_frame["id"].is_u64(), req_id.is_u64());
        assert_eq!(final_frame["id"].is_string(), req_id.is_string());
        assert_eq!(final_frame["result"]["resultType"], json!("complete"));
        assert_eq!(
            final_frame["result"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
            req_id
        );
    }

    let seen = captured.lock().unwrap().clone();
    assert_eq!(seen.len(), 5);
    for req in &seen {
        assert_eq!(req.method, Method::POST);
        assert_eq!(
            req.headers.get("authorization").map(String::as_str),
            Some(&format!("Bearer {UPSTREAM_BEARER}")[..])
        );
        assert_eq!(
            req.headers.get("mcp-protocol-version").map(String::as_str),
            Some(PROTOCOL_VERSION)
        );
    }

    assert_eq!(
        seen[1].headers.get("mcp-session-id").map(String::as_str),
        Some(SESSION_ID)
    );
    assert_eq!(seen[1].body["id"], json!("list-req-1"));

    assert_eq!(
        seen[2].headers.get("last-event-id").map(String::as_str),
        Some("cur-0")
    );
    assert_eq!(seen[2].body["id"], json!(7));

    assert_eq!(
        seen[3].headers.get("accept").map(String::as_str),
        Some("text/event-stream, application/json")
    );
    assert_eq!(
        seen[3].headers.get("mcp-session-id").map(String::as_str),
        Some(SESSION_ID)
    );
    assert_eq!(
        seen[3].headers.get("last-event-id").map(String::as_str),
        Some("cur-0")
    );
    assert_eq!(seen[3].body["id"], json!(42));

    assert_eq!(
        seen[4].headers.get("accept").map(String::as_str),
        Some("text/event-stream, application/json")
    );
    assert_eq!(
        seen[4].headers.get("mcp-session-id").map(String::as_str),
        Some(SESSION_ID)
    );
    assert_eq!(
        seen[4].headers.get("last-event-id").map(String::as_str),
        Some("cur-1")
    );
    assert_eq!(seen[4].body["id"], json!("sub-str-7"));

    gw_shutdown.cancel();
    gw_task.await.unwrap().unwrap();
    up_cancel.cancel();
}
