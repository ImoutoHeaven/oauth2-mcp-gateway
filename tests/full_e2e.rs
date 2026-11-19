mod common;

use bytes::Bytes;
use common::{
    TestClient, channel_body, make_client, process_exists, python_executable, spawn_gateway,
    spawn_http1_harness, wait_process_gone,
};
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use oauth2_mcp_gateway::config::GatewayConfig;
use oauth2_mcp_gateway::crypto::{PBKDF2_ITERATIONS, PasswordVerifier, sha256_b64};
use oauth2_mcp_gateway::types::{ReplyBody, bytes_body, empty_body};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Barrier;
use url::Url;

const OWNER_PASSWORD: &str = "e2e-owner-correct-horse-staple-42";
const PUBLIC_URL: &str = "https://mcp.example.com";

fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}

fn pkce_pair(seed: &str) -> (String, String) {
    let verifier = format!("e2e-pkce-verifier-{seed:0<40}");
    let challenge = sha256_b64(&verifier);
    (verifier, challenge)
}

fn extract_hidden_input(html: &str, field_name: &str) -> String {
    let marker = format!("name=\"{field_name}\" value=\"");
    let start = html.find(&marker).expect("hidden input field present") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("closing quote on hidden input");
    rest[..end].to_owned()
}

fn extract_cookie_pair(headers: &HeaderMap) -> String {
    let raw = headers
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header present")
        .to_str()
        .expect("ASCII Set-Cookie");
    raw.split(';').next().expect("cookie key=value").to_owned()
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
        .expect("execute HTTP request");
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

fn parse_json(bytes: &Bytes) -> Value {
    serde_json::from_slice(bytes).expect("valid JSON payload")
}

async fn register_and_authorize_grant(
    client: &TestClient,
    gw_addr: SocketAddr,
    client_name: &str,
    redirect_uri: &str,
    seed: &str,
) -> (String, String, String) {
    let (reg_status, _, reg_body) = send_http(
        client,
        Method::POST,
        &format!("http://{gw_addr}/oauth/register"),
        &[("content-type", "application/json")],
        bytes_body(
            json!({
                "client_name": client_name,
                "redirect_uris": [redirect_uri],
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(reg_status, StatusCode::CREATED);
    let client_id = parse_json(&reg_body)["client_id"]
        .as_str()
        .expect("client_id")
        .to_owned();

    let (verifier, challenge) = pkce_pair(seed);
    let state = format!("state-{seed}");
    let auth_query = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("state", &state),
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
    let html = std::str::from_utf8(&get_body).expect("authorize HTML is UTF-8");
    let ar_id = extract_hidden_input(html, "ar_id");
    let csrf_token = extract_hidden_input(html, "csrf_token");
    assert!(
        cookie_pair.contains(&format!("mcp_ar_{ar_id}=")),
        "expected mcp_ar_<ar_id> cookie, got {cookie_pair:?}"
    );

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
        .expect("Location header on 303")
        .to_str()
        .expect("ASCII Location");
    let parsed_loc = Url::parse(location).expect("valid redirect URI");
    let params: BTreeMap<String, String> = parsed_loc.query_pairs().into_owned().collect();
    assert_eq!(params.get("iss").map(String::as_str), Some(PUBLIC_URL));
    assert_eq!(
        params.get("state").map(String::as_str),
        Some(state.as_str())
    );
    let code = params.get("code").expect("authorization code").to_owned();

    let token_form = form_encode(&[
        ("grant_type", "authorization_code"),
        ("client_id", &client_id),
        ("code", &code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", &verifier),
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
    let tok_json = parse_json(&tok_body);
    let access_token = tok_json["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let refresh_token = tok_json["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned();
    (client_id, access_token, refresh_token)
}

fn fast_owner_hash() -> String {
    PasswordVerifier::from_plaintext_with_iterations(OWNER_PASSWORD, 10_000)
        .expect("pbkdf2 hash")
        .encode()
}

fn write_stdio_e2e_script(dir: &Path) -> PathBuf {
    let script_path = dir.join("e2e_stdio_mcp.py");
    let script = r#"import json, os, subprocess, sys, time

pid = os.getpid()
pgid = pid if sys.platform == "win32" else os.getpgrp()
bg_code = (
    "import time; time.sleep(120)"
    if sys.platform == "win32"
    else "import signal, time; signal.signal(signal.SIGHUP, signal.SIG_IGN); time.sleep(120)"
)
bg = subprocess.Popen(
    [sys.executable, "-c", bg_code],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

def emit(payload):
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    method = msg.get("method")
    req_id = msg.get("id")
    if req_id is None:
        continue
    if method == "initialize":
        emit({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "e2e-stdio", "version": "0.1.0"},
                "_meta": {"pid": pid, "pgid": pgid, "grandchild_pid": bg.pid},
            },
        })
    elif method == "tools/call":
        ptok = msg.get("params", {}).get("_meta", {}).get("progressToken", "pt-0")
        emit({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": ptok, "progress": 50, "total": 100},
        })
        time.sleep(0.02)
        emit({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": "stdio-ok"}],
                "structuredContent": {"pid": pid},
            },
        })
"#;
    std::fs::write(&script_path, script).expect("write stdio python script");
    script_path
}

type SeenAuth = (Option<String>, String);

#[tokio::test]
async fn e2e_http_oauth_flow_bearer_pool_sse_stripping_and_passthrough() {
    let seen_up_auth: Arc<Mutex<Vec<SeenAuth>>> = Arc::new(Mutex::new(Vec::new()));
    let artifact_store: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

    let seen_ref = Arc::clone(&seen_up_auth);
    let artifact_ref = Arc::clone(&artifact_store);

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let seen = Arc::clone(&seen_ref);
        let store = Arc::clone(&artifact_ref);
        async move {
            let path = req.uri().path().to_owned();
            let auth = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let proto = req
                .headers()
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();

            if path == "/mcp" {
                let req_bytes = req
                    .into_body()
                    .collect()
                    .await
                    .expect("read upstream /mcp body")
                    .to_bytes();
                let rpc: Value = serde_json::from_slice(&req_bytes).unwrap_or_else(|_| json!({}));
                let id = rpc.get("id").cloned().unwrap_or(json!(1));
                let auth_echo = auth.clone().unwrap_or_default();
                seen.lock().unwrap().push((auth, proto));

                let (tx, body) = channel_body(8);
                tokio::spawn(async move {
                    let leading: &[&[u8]] = &[b"retry: 1500\r\n\r\n", b": keepalive\n\n"];
                    for frame in leading {
                        if tx.send(Ok(Frame::data(Bytes::from_static(frame)))).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    let ev1 = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"step\":1}}\n\n";
                    if tx.send(Ok(Frame::data(Bytes::from(ev1)))).await.is_err() {
                        return;
                    }
                    let _ = tx
                        .send(Ok(Frame::data(Bytes::from_static(b": keepalive-after\n\n"))))
                        .await;
                    let ev2 = format!(
                        "data: {}\n\n",
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {"upstream_auth": auth_echo}
                        })
                    );
                    let _ = tx.send(Ok(Frame::data(Bytes::from(ev2)))).await;
                });

                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
                    .body(body)
                    .unwrap();
            }

            if path == "/t/artifact-1" {
                assert_eq!(
                    auth, None,
                    "passthrough route must not receive Authorization header"
                );
                match *req.method() {
                    Method::PUT => {
                        let mut buf = Vec::new();
                        let mut incoming = req.into_body();
                        while let Some(frame) = incoming.frame().await {
                            let chunk = frame.expect("put frame").into_data().expect("data frame");
                            buf.extend_from_slice(&chunk);
                        }
                        *store.lock().unwrap() = buf;
                        return Response::builder()
                            .status(StatusCode::CREATED)
                            .body(empty_body())
                            .unwrap();
                    }
                    Method::GET => {
                        let data = store.lock().unwrap().clone();
                        let (tx, body) = channel_body(4);
                        tokio::spawn(async move {
                            for chunk in data.chunks(32 * 1024) {
                                if tx
                                    .send(Ok(Frame::data(Bytes::copy_from_slice(chunk))))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        });
                        return Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/octet-stream")
                            .body(body)
                            .unwrap();
                    }
                    _ => {}
                }
            }

            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(empty_body())
                .unwrap()
        }
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let cfg_json = json!({
        "listen": "127.0.0.1:0",
        "public_url": PUBLIC_URL,
        "state_path": tmp.path().join("state.json").to_string_lossy(),
        "oauth": {
            "owner_password_hash": fast_owner_hash(),
            "scopes": ["mcp"],
        },
        "upstream": {
            "transport": "http",
            "url": format!("http://{up_addr}/mcp"),
            "bearer_tokens": ["pool-static-alpha", "pool-static-beta"],
            "passthrough_prefixes": ["/t/"],
        }
    });
    let cfg = Arc::new(GatewayConfig::from_json_str(&cfg_json.to_string(), tmp.path()).unwrap());
    let (gw_addr, gw_shutdown, gw_handle) = spawn_gateway(cfg).await;
    let client = make_client();

    let (unauth_status, unauth_headers, _) = send_http(
        &client,
        Method::GET,
        &format!("http://{gw_addr}/mcp"),
        &[],
        empty_body(),
    )
    .await;
    assert_eq!(unauth_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauth_headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some(
            "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp\""
        )
    );

    let (prm_status, prm_headers, prm_body) = send_http(
        &client,
        Method::GET,
        &format!("http://{gw_addr}/.well-known/oauth-protected-resource/mcp"),
        &[],
        empty_body(),
    )
    .await;
    assert_eq!(prm_status, StatusCode::OK);
    assert_eq!(
        prm_headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
    let prm = parse_json(&prm_body);
    assert_eq!(prm["resource"], "https://mcp.example.com/mcp");
    assert_eq!(prm["authorization_servers"], json!([PUBLIC_URL]));

    let (asm_status, _, asm_body) = send_http(
        &client,
        Method::GET,
        &format!("http://{gw_addr}/.well-known/oauth-authorization-server"),
        &[],
        empty_body(),
    )
    .await;
    assert_eq!(asm_status, StatusCode::OK);
    let asm = parse_json(&asm_body);
    assert_eq!(asm["issuer"], PUBLIC_URL);
    assert_eq!(
        asm["authorization_endpoint"],
        "https://mcp.example.com/oauth/authorize"
    );
    assert_eq!(asm["token_endpoint"], "https://mcp.example.com/oauth/token");
    assert_eq!(
        asm["registration_endpoint"],
        "https://mcp.example.com/oauth/register"
    );
    assert_eq!(
        asm["revocation_endpoint"],
        "https://mcp.example.com/oauth/revoke"
    );
    assert_eq!(asm["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(asm["authorization_response_iss_parameter_supported"], true);

    let (_, access_1, _) = register_and_authorize_grant(
        &client,
        gw_addr,
        "E2E Client One",
        "http://127.0.0.1:29101/callback",
        "client-one",
    )
    .await;
    let (_, access_2, _) = register_and_authorize_grant(
        &client,
        gw_addr,
        "E2E Client Two",
        "http://127.0.0.1:29102/callback",
        "client-two",
    )
    .await;
    assert_ne!(access_1, access_2);

    for (idx, (token, expected_up_bearer)) in [
        (&access_1, "Bearer pool-static-alpha"),
        (&access_2, "Bearer pool-static-beta"),
    ]
    .into_iter()
    .enumerate()
    {
        let (mcp_status, mcp_headers, mcp_body) = send_http(
            &client,
            Method::POST,
            &format!("http://{gw_addr}/mcp"),
            &[
                ("authorization", &format!("Bearer {token}")),
                ("accept", "application/json, text/event-stream"),
                ("content-type", "application/json"),
            ],
            bytes_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": idx + 1,
                    "method": "tools/call",
                    "params": {"name": "echo"}
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(mcp_status, StatusCode::OK);
        assert_eq!(
            mcp_headers
                .get("x-accel-buffering")
                .and_then(|v| v.to_str().ok()),
            Some("no")
        );
        let sse_text = std::str::from_utf8(&mcp_body).expect("UTF-8 SSE stream");
        assert!(
            sse_text.starts_with("data: "),
            "leading retry:/comment SSE frames must be stripped, got: {sse_text:?}"
        );
        assert!(!sse_text.contains("retry: 1500"));
        assert!(!sse_text.contains(": keepalive\n\n"));

        let data_events: Vec<Value> = sse_text
            .split("\n\n")
            .filter_map(|blk| blk.strip_prefix("data: "))
            .map(|line| serde_json::from_str(line).expect("valid SSE JSON data"))
            .collect();
        assert_eq!(data_events.len(), 2);
        assert_eq!(data_events[0]["method"], "notifications/progress");
        assert_eq!(
            data_events[1]["result"]["upstream_auth"],
            expected_up_bearer
        );
    }

    {
        let recorded = seen_up_auth.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            recorded[0],
            (
                Some("Bearer pool-static-alpha".to_owned()),
                "https".to_owned()
            )
        );
        assert_eq!(
            recorded[1],
            (
                Some("Bearer pool-static-beta".to_owned()),
                "https".to_owned()
            )
        );
    }

    let total_size = 512 * 1024;
    let mut expected_artifact = vec![0u8; total_size];
    for (i, byte) in expected_artifact.iter_mut().enumerate() {
        *byte = ((i * 73 + 19) & 0xff) as u8;
    }

    let (put_tx, put_body) = channel_body(4);
    let payload_to_send = expected_artifact.clone();
    tokio::spawn(async move {
        for chunk in payload_to_send.chunks(32 * 1024) {
            put_tx
                .send(Ok(Frame::data(Bytes::copy_from_slice(chunk))))
                .await
                .expect("stream PUT chunk");
        }
    });

    let (put_status, _, _) = send_http(
        &client,
        Method::PUT,
        &format!("http://{gw_addr}/t/artifact-1"),
        &[("content-type", "application/octet-stream")],
        put_body,
    )
    .await;
    assert_eq!(put_status, StatusCode::CREATED);

    let get_resp = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{gw_addr}/t/artifact-1"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .expect("GET /t/artifact-1");
    assert_eq!(get_resp.status(), StatusCode::OK);
    let mut downloaded = Vec::with_capacity(total_size);
    let mut get_stream = get_resp.into_body();
    while let Some(frame) = get_stream.frame().await {
        let chunk = frame
            .expect("GET stream frame")
            .into_data()
            .expect("GET data");
        downloaded.extend_from_slice(&chunk);
    }
    assert_eq!(downloaded, expected_artifact);

    gw_shutdown.cancel();
    gw_handle.await.unwrap().unwrap();
    up_cancel.cancel();
}

#[tokio::test]
async fn e2e_ten_way_concurrent_refresh_rotation_and_replay_breach() {
    let (up_addr, up_cancel) = spawn_http1_harness(|_req: Request<Incoming>| async move {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(bytes_body(
                r#"{"jsonrpc":"2.0","id":1,"result":{"pong":true}}"#,
            ))
            .unwrap()
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let cfg_json = json!({
        "listen": "127.0.0.1:0",
        "public_url": PUBLIC_URL,
        "state_path": tmp.path().join("state.json").to_string_lossy(),
        "oauth": {
            "owner_password_hash": fast_owner_hash(),
            "scopes": ["mcp"],
            "refresh_grace_secs": 2,
            "refresh_reuse_policy": "revoke",
        },
        "upstream": {
            "transport": "http",
            "url": format!("http://{up_addr}/mcp"),
            "bearer_tokens": ["pool-tok"],
        }
    });
    let cfg = Arc::new(GatewayConfig::from_json_str(&cfg_json.to_string(), tmp.path()).unwrap());
    let (gw_addr, gw_shutdown, gw_handle) = spawn_gateway(cfg).await;

    let setup_client = make_client();
    let (client_id, a0, r0) = register_and_authorize_grant(
        &setup_client,
        gw_addr,
        "Concurrent Refresh Client",
        "http://127.0.0.1:29200/cb",
        "refresh-0",
    )
    .await;

    let (a0_mcp_st, _, _) = send_http(
        &setup_client,
        Method::POST,
        &format!("http://{gw_addr}/mcp"),
        &[
            ("authorization", &format!("Bearer {a0}")),
            ("content-type", "application/json"),
        ],
        bytes_body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
    )
    .await;
    assert_eq!(a0_mcp_st, StatusCode::OK);

    let barrier = Arc::new(Barrier::new(10));
    let mut tasks = Vec::with_capacity(10);
    for _ in 0..10 {
        let bar = Arc::clone(&barrier);
        let cid = client_id.clone();
        let rt = r0.clone();
        tasks.push(tokio::spawn(async move {
            let http_client = make_client();
            let form = form_encode(&[
                ("grant_type", "refresh_token"),
                ("client_id", &cid),
                ("refresh_token", &rt),
            ]);
            bar.wait().await;
            send_http(
                &http_client,
                Method::POST,
                &format!("http://{gw_addr}/oauth/token"),
                &[("content-type", "application/x-www-form-urlencoded")],
                bytes_body(form),
            )
            .await
        }));
    }

    let mut issued_pairs = Vec::with_capacity(10);
    for task in tasks {
        let (st, _, body) = task.await.expect("refresh task join");
        assert_eq!(st, StatusCode::OK);
        let val = parse_json(&body);
        issued_pairs.push((
            val["access_token"].as_str().unwrap().to_owned(),
            val["refresh_token"].as_str().unwrap().to_owned(),
        ));
    }

    let (ref a1, ref r1) = issued_pairs[0];
    assert_ne!(a1, &a0);
    assert_ne!(r1, &r0);
    for (at, rt) in &issued_pairs[1..] {
        assert_eq!(at, a1, "all 10 concurrent TCP refreshes must return A1");
        assert_eq!(rt, r1, "all 10 concurrent TCP refreshes must return R1");
    }

    let (a1_ok_st, _, _) = send_http(
        &setup_client,
        Method::POST,
        &format!("http://{gw_addr}/mcp"),
        &[
            ("authorization", &format!("Bearer {a1}")),
            ("content-type", "application/json"),
        ],
        bytes_body(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#),
    )
    .await;
    assert_eq!(a1_ok_st, StatusCode::OK);

    // Sleep past 2s integer unix_now() window with margin for 2-vCPU CI scheduling.
    tokio::time::sleep(Duration::from_millis(3500)).await;

    let (replay_st, _, replay_body) = send_http(
        &setup_client,
        Method::POST,
        &format!("http://{gw_addr}/oauth/token"),
        &[("content-type", "application/x-www-form-urlencoded")],
        bytes_body(form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &r0),
        ])),
    )
    .await;
    assert_eq!(replay_st, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&replay_body)["error"], "invalid_grant");

    let (a1_revoked_st, _, _) = send_http(
        &setup_client,
        Method::POST,
        &format!("http://{gw_addr}/mcp"),
        &[
            ("authorization", &format!("Bearer {a1}")),
            ("content-type", "application/json"),
        ],
        bytes_body(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#),
    )
    .await;
    assert_eq!(a1_revoked_st, StatusCode::UNAUTHORIZED);

    gw_shutdown.cancel();
    gw_handle.await.unwrap().unwrap();
    up_cancel.cancel();
}

#[tokio::test]
async fn e2e_stdio_grant_isolation_revocation_process_reap_and_cli_smoke() {
    let tmp = TempDir::new().unwrap();
    let script_path = write_stdio_e2e_script(tmp.path());
    let cfg_path = tmp.path().join("stdio_gateway.json");
    let cfg_json = json!({
        "listen": "127.0.0.1:0",
        "public_url": PUBLIC_URL,
        "state_path": tmp.path().join("state.json").to_string_lossy(),
        "oauth": {
            "owner_password_hash": fast_owner_hash(),
            "scopes": ["mcp"],
        },
        "upstream": {
            "transport": "stdio",
            "command": python_executable(),
            "args": ["-u", script_path.to_string_lossy()],
            "max_sessions": 8,
            "session_idle_secs": 120,
        }
    });
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg_json).unwrap()).unwrap();

    let cfg = Arc::new(GatewayConfig::from_file(&cfg_path).expect("load stdio config"));
    let (gw_addr, gw_shutdown, gw_handle) = spawn_gateway(cfg).await;
    let client = make_client();

    let (client_1, token_1, _) = register_and_authorize_grant(
        &client,
        gw_addr,
        "Stdio Grant One",
        "http://127.0.0.1:29301/cb",
        "stdio-g1",
    )
    .await;
    let (_, token_2, _) = register_and_authorize_grant(
        &client,
        gw_addr,
        "Stdio Grant Two",
        "http://127.0.0.1:29302/cb",
        "stdio-g2",
    )
    .await;

    let (init_st, init_headers, init_body) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/mcp"),
        &[
            ("authorization", &format!("Bearer {token_1}")),
            ("content-type", "application/json"),
        ],
        bytes_body(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "e2e-client", "version": "1.0"}
                }
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(init_st, StatusCode::OK);
    let sid_1 = init_headers
        .get("mcp-session-id")
        .expect("Mcp-Session-Id header")
        .to_str()
        .unwrap()
        .to_owned();
    let init_val = parse_json(&init_body);
    let pid_1 = init_val["result"]["_meta"]["pid"].as_u64().unwrap() as u32;
    let pgid_1 = init_val["result"]["_meta"]["pgid"].as_u64().unwrap() as u32;
    let grandchild_1 = init_val["result"]["_meta"]["grandchild_pid"]
        .as_u64()
        .unwrap() as u32;
    assert_eq!(pid_1, pgid_1);
    assert!(process_exists(pid_1));
    assert!(process_exists(grandchild_1));

    let (notif_st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/mcp"),
        &[
            ("authorization", &format!("Bearer {token_1}")),
            ("mcp-session-id", &sid_1),
            ("content-type", "application/json"),
        ],
        bytes_body(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
    )
    .await;
    assert_eq!(notif_st, StatusCode::ACCEPTED);

    let (call_st, call_headers, call_body) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/mcp"),
        &[
            ("authorization", &format!("Bearer {token_1}")),
            ("mcp-session-id", &sid_1),
            ("accept", "application/json, text/event-stream"),
            ("content-type", "application/json"),
        ],
        bytes_body(
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "demo",
                    "_meta": {"progressToken": "pt-e2e"}
                }
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(call_st, StatusCode::OK);
    assert_eq!(
        call_headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    let sse_str = std::str::from_utf8(&call_body).unwrap();
    let sse_events: Vec<Value> = sse_str
        .split("\n\n")
        .filter(|b| !b.is_empty())
        .map(|b| serde_json::from_str(b.strip_prefix("data: ").expect("SSE data prefix")).unwrap())
        .collect();
    assert_eq!(sse_events.len(), 2);
    assert_eq!(sse_events[0]["method"], "notifications/progress");
    assert_eq!(sse_events[0]["params"]["progressToken"], "pt-e2e");
    assert_eq!(sse_events[1]["id"], 2);
    assert_eq!(sse_events[1]["result"]["structuredContent"]["pid"], pid_1);

    let (hijack_post_st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/mcp"),
        &[
            ("authorization", &format!("Bearer {token_2}")),
            ("mcp-session-id", &sid_1),
            ("content-type", "application/json"),
        ],
        bytes_body(r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"demo"}}"#),
    )
    .await;
    assert_eq!(hijack_post_st, StatusCode::NOT_FOUND);

    let (hijack_del_st, _, _) = send_http(
        &client,
        Method::DELETE,
        &format!("http://{gw_addr}/mcp"),
        &[
            ("authorization", &format!("Bearer {token_2}")),
            ("mcp-session-id", &sid_1),
        ],
        empty_body(),
    )
    .await;
    assert_eq!(hijack_del_st, StatusCode::NOT_FOUND);
    assert!(
        process_exists(pid_1),
        "Grant 1 child must remain alive after Grant 2 404 attempts"
    );

    let (rev_st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/oauth/revoke"),
        &[("content-type", "application/x-www-form-urlencoded")],
        bytes_body(form_encode(&[
            ("client_id", &client_1),
            ("token", &token_1),
        ])),
    )
    .await;
    assert_eq!(rev_st, StatusCode::OK);

    let (after_rev_st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/mcp"),
        &[
            ("authorization", &format!("Bearer {token_1}")),
            ("mcp-session-id", &sid_1),
            ("content-type", "application/json"),
        ],
        bytes_body(r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"demo"}}"#),
    )
    .await;
    assert_eq!(after_rev_st, StatusCode::UNAUTHORIZED);
    assert!(
        wait_process_gone(pid_1).await,
        "revoking Grant 1 must immediately terminate its stdio session leader"
    );
    assert!(
        wait_process_gone(grandchild_1).await,
        "revoking Grant 1 must immediately reap its background grandchild"
    );

    gw_shutdown.cancel();
    gw_handle.await.unwrap().unwrap();

    let bin = env!("CARGO_BIN_EXE_oauth2-mcp-gateway");
    let mut child = Command::new(bin)
        .arg("hash-password")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hash-password");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"cli-smoke-secret-password\n")
        .expect("write password to stdin");
    let hash_out = child.wait_with_output().expect("wait hash-password");
    assert!(hash_out.status.success());
    let encoded_hash = std::str::from_utf8(&hash_out.stdout).unwrap().trim();
    assert!(
        encoded_hash.starts_with(&format!("pbkdf2-sha256${PBKDF2_ITERATIONS}$")),
        "unexpected hash output: {encoded_hash:?}"
    );
    let parsed_verifier = PasswordVerifier::parse_encoded(encoded_hash).expect("parse CLI hash");
    assert!(parsed_verifier.verify("cli-smoke-secret-password"));

    let check_tmp = Command::new(bin)
        .args(["check", "--config"])
        .arg(&cfg_path)
        .output()
        .expect("run check on temp stdio config");
    assert!(check_tmp.status.success());

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let ex_http_path = manifest_dir.join("examples/gateway-http.json");
    let ex_stdio_path = manifest_dir.join("examples/gateway-stdio.json");

    let ex_http_raw = std::fs::read_to_string(&ex_http_path).expect("read gateway-http.json");
    assert!(ex_http_raw.contains("\"${OWNER_PASSWORD_HASH}\""));
    assert!(ex_http_raw.contains("\"${UPSTREAM_BEARER_TOKEN_1}\""));

    let ex_stdio_raw = std::fs::read_to_string(&ex_stdio_path).expect("read gateway-stdio.json");
    assert!(ex_stdio_raw.contains("\"${OWNER_PASSWORD_HASH}\""));

    let check_ex_http = Command::new(bin)
        .args(["check", "--config"])
        .arg(&ex_http_path)
        .env("OWNER_PASSWORD_HASH", encoded_hash)
        .env("UPSTREAM_BEARER_TOKEN_1", "tok-slot-1")
        .env("UPSTREAM_BEARER_TOKEN_2", "tok-slot-2")
        .output()
        .expect("validate examples/gateway-http.json");
    assert!(
        check_ex_http.status.success(),
        "examples/gateway-http.json failed check: {}",
        String::from_utf8_lossy(&check_ex_http.stderr)
    );

    let check_ex_stdio = Command::new(bin)
        .args(["check", "--config"])
        .arg(&ex_stdio_path)
        .env("OWNER_PASSWORD_HASH", encoded_hash)
        .env("MCP_UPSTREAM_API_KEY", "stdio-api-key")
        .output()
        .expect("validate examples/gateway-stdio.json");
    assert!(
        check_ex_stdio.status.success(),
        "examples/gateway-stdio.json failed check: {}",
        String::from_utf8_lossy(&check_ex_stdio.stderr)
    );

    let check_missing_env = Command::new(bin)
        .args(["check", "--config"])
        .arg(&ex_http_path)
        .env_remove("OWNER_PASSWORD_HASH")
        .env_remove("UPSTREAM_BEARER_TOKEN_1")
        .output()
        .expect("check missing env fails");
    assert!(!check_missing_env.status.success());
}

#[tokio::test]
async fn e2e_custom_resource_path_host_rebinding_discovery_cors_and_http_revocation() {
    let deleted_up = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
    let deleted_ref = Arc::clone(&deleted_up);

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let deleted = Arc::clone(&deleted_ref);
        async move {
            let path = req.uri().path().to_owned();
            let method = req.method().clone();
            let sid = req
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let auth = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let _ = req.into_body().collect().await;

            if path == "/t/item" {
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(bytes_body("item-ok"))
                    .unwrap();
            }

            if path == "/upstream-mcp" {
                if method == Method::DELETE {
                    if let Some(s) = sid {
                        deleted.lock().unwrap().push((s, auth));
                    }
                    return Response::builder()
                        .status(StatusCode::OK)
                        .body(empty_body())
                        .unwrap();
                }
                if method == Method::GET {
                    let (tx, body) = channel_body(4);
                    tokio::spawn(async move {
                        let _ = tx
                            .send(Ok(Frame::data(Bytes::from_static(
                                b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n",
                            ))))
                            .await;
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    });
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(body)
                        .unwrap();
                }
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        "mcp-session-id",
                        sid.unwrap_or_else(|| "custom-http-sid-1".to_owned()),
                    )
                    .body(bytes_body(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#))
                    .unwrap();
            }

            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(empty_body())
                .unwrap()
        }
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let cfg_json = json!({
        "listen": "127.0.0.1:0",
        "public_url": PUBLIC_URL,
        "resource_path": "/bridge/mcp",
        "state_path": tmp.path().join("state.json").to_string_lossy(),
        "oauth": {
            "owner_password_hash": fast_owner_hash(),
            "scopes": ["mcp"],
        },
        "upstream": {
            "transport": "http",
            "url": format!("http://{up_addr}/upstream-mcp"),
            "bearer_tokens": ["pool-alpha", "pool-beta"],
            "passthrough_prefixes": ["/t/"],
        }
    });
    let cfg = Arc::new(GatewayConfig::from_json_str(&cfg_json.to_string(), tmp.path()).unwrap());
    let (gw_addr, gw_shutdown, gw_handle) = spawn_gateway(cfg).await;
    let client = make_client();

    let (head_st, _, head_body) = send_http(
        &client,
        Method::HEAD,
        &format!("http://{gw_addr}/healthz"),
        &[],
        empty_body(),
    )
    .await;
    assert_eq!(head_st, StatusCode::OK);
    assert!(head_body.is_empty());

    for raw_bad_host in [
        "GET /healthz HTTP/1.1\r\nHost: evil.example\r\n\r\n",
        "GET /healthz HTTP/1.1\r\nHost: evil.rebind:8080\r\n\r\n",
        "GET /healthz HTTP/1.1\r\nHost: mcp.example.com:8443\r\n\r\n",
        "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: mcp.example.com\r\n\r\n",
    ] {
        let mut sock = TcpStream::connect(gw_addr).await.unwrap();
        sock.write_all(raw_bad_host.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        sock.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.starts_with("HTTP/1.1 400 "),
            "expected 400 for {raw_bad_host:?}, got {text:?}"
        );
    }

    for good_host in [
        "MCP.EXAMPLE.COM",
        "mcp.example.com:443",
        "localhost:8080",
        "[::1]:8080",
    ] {
        let mut sock = TcpStream::connect(gw_addr).await.unwrap();
        let req =
            format!("HEAD /healthz HTTP/1.1\r\nHost: {good_host}\r\nConnection: close\r\n\r\n");
        sock.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        sock.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.starts_with("HTTP/1.1 200 "),
            "expected 200 for Host: {good_host}, got {text:?}"
        );
    }

    for disc_path in [
        "/.well-known/oauth-protected-resource/bridge/mcp",
        "/.well-known/oauth-authorization-server",
    ] {
        let (opt_st, opt_hdrs, _) = send_http(
            &client,
            Method::OPTIONS,
            &format!("http://{gw_addr}{disc_path}"),
            &[
                ("origin", "http://localhost:6274"),
                ("access-control-request-method", "GET"),
                ("access-control-request-headers", "mcp-protocol-version"),
            ],
            empty_body(),
        )
        .await;
        assert_eq!(opt_st, StatusCode::NO_CONTENT);
        assert_eq!(
            opt_hdrs
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );

        let (get_st, get_hdrs, _) = send_http(
            &client,
            Method::GET,
            &format!("http://{gw_addr}{disc_path}"),
            &[("origin", "http://localhost:6274")],
            empty_body(),
        )
        .await;
        assert_eq!(get_st, StatusCode::OK);
        assert_eq!(
            get_hdrs
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
    }

    for (method, path) in [
        (Method::POST, "/bridge/mcp"),
        (Method::POST, "/oauth/authorize"),
        (Method::POST, "/oauth/token"),
        (Method::GET, "/t/item"),
    ] {
        for bad_origin in ["https://evil.example", "null"] {
            let (st, _, _) = send_http(
                &client,
                method.clone(),
                &format!("http://{gw_addr}{path}"),
                &[("origin", bad_origin)],
                empty_body(),
            )
            .await;
            assert_eq!(st, StatusCode::FORBIDDEN);
        }
    }

    let (upper_pt_st, _, _) = send_http(
        &client,
        Method::GET,
        &format!("http://{gw_addr}/t/item"),
        &[("origin", "HTTPS://MCP.EXAMPLE.COM")],
        empty_body(),
    )
    .await;
    assert_eq!(upper_pt_st, StatusCode::OK);

    let (old_mcp_st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/mcp"),
        &[],
        empty_body(),
    )
    .await;
    assert_eq!(old_mcp_st, StatusCode::NOT_FOUND);

    let (unauth_custom_st, unauth_custom_hdrs, _) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/bridge/mcp"),
        &[("origin", "HTTPS://MCP.EXAMPLE.COM")],
        empty_body(),
    )
    .await;
    assert_eq!(unauth_custom_st, StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauth_custom_hdrs
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some(
            "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/bridge/mcp\""
        )
    );

    let (client_1, token_1, _) = register_and_authorize_grant(
        &client,
        gw_addr,
        "Custom Path One",
        "http://127.0.0.1:29401/cb",
        "custom-1",
    )
    .await;
    let (_, token_2, _) = register_and_authorize_grant(
        &client,
        gw_addr,
        "Custom Path Two",
        "http://127.0.0.1:29402/cb",
        "custom-2",
    )
    .await;

    let (init_st, init_hdrs, _) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/bridge/mcp"),
        &[
            ("authorization", &format!("Bearer {token_1}")),
            ("content-type", "application/json"),
        ],
        bytes_body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#),
    )
    .await;
    assert_eq!(init_st, StatusCode::OK);
    let sid = init_hdrs
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(sid, "custom-http-sid-1");

    let (hijack_st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/bridge/mcp"),
        &[
            ("authorization", &format!("Bearer {token_2}")),
            ("mcp-session-id", &sid),
            ("content-type", "application/json"),
        ],
        bytes_body(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#),
    )
    .await;
    assert_eq!(hijack_st, StatusCode::NOT_FOUND);

    let sse_resp = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{gw_addr}/bridge/mcp"))
                .header(header::AUTHORIZATION, format!("Bearer {token_1}"))
                .header("mcp-session-id", &sid)
                .header(header::ACCEPT, "text/event-stream")
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut sse_body = sse_resp.into_body();
    let first = tokio::time::timeout(Duration::from_secs(3), sse_body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&first.into_data().unwrap()).contains("notifications/message"));

    let sse_wait = tokio::spawn(async move {
        while let Some(res) = sse_body.frame().await {
            if res.is_err() {
                break;
            }
        }
    });

    let (rev_st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("http://{gw_addr}/oauth/revoke"),
        &[("content-type", "application/x-www-form-urlencoded")],
        bytes_body(form_encode(&[
            ("client_id", &client_1),
            ("token", &token_1),
        ])),
    )
    .await;
    assert_eq!(rev_st, StatusCode::OK);

    tokio::time::timeout(Duration::from_secs(3), sse_wait)
        .await
        .expect("OAuth revoke must abort active HttpUpstream SSE stream")
        .unwrap();

    for _ in 0..50 {
        if !deleted_up.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        deleted_up.lock().unwrap().clone(),
        vec![(
            "custom-http-sid-1".to_owned(),
            Some("Bearer pool-alpha".to_owned())
        )]
    );

    gw_shutdown.cancel();
    gw_handle.await.unwrap().unwrap();
    up_cancel.cancel();
}
