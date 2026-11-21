mod common;

use bytes::Bytes;
use common::{
    channel_body, make_client, process_exists, python_executable, spawn_gateway,
    spawn_http1_harness, wait_process_gone,
};
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use oauth2_mcp_gateway::config::{
    GatewayConfig, HttpUpstreamSettings, StdioUpstreamSettings, UpstreamSettings,
};
use oauth2_mcp_gateway::crypto::PasswordVerifier;
use oauth2_mcp_gateway::types::{ByteBudget, VerifiedToken, bytes_body, empty_body};
use oauth2_mcp_gateway::upstream_http::{HttpLimits, HttpUpstream};
use oauth2_mcp_gateway::upstream_stdio::{StdioLimits, StdioUpstream};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use url::Url;

fn make_token(grant_id: &str, pool_slot: usize) -> VerifiedToken {
    VerifiedToken {
        grant_id: grant_id.to_owned(),
        client_id: "test-client".to_owned(),
        pool_slot,
        scopes: vec!["mcp".to_owned()],
        resource: "https://mcp.example.com/mcp".to_owned(),
    }
}

#[tokio::test]
async fn http_bearer_pool_rotation_and_empty_pool_stripping() {
    type SeenRecord = (
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
    );
    let seen: Arc<Mutex<Vec<SeenRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_up = Arc::clone(&seen);

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let seen_ref = Arc::clone(&seen_up);
        async move {
            let auth = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let host = req
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let proto = req
                .headers()
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let hop_leak = req
                .headers()
                .get("x-hop-secret")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let query = req.uri().query().map(str::to_owned);
            let _ = req.into_body().collect().await;
            seen_ref
                .lock()
                .unwrap()
                .push((auth, host, proto, hop_leak, query));
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                ))
                .unwrap()
        }
    })
    .await;

    let settings = HttpUpstreamSettings {
        url: Url::parse(&format!("http://{up_addr}/v1/mcp")).unwrap(),
        origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
        public_is_https: true,
        bearer_tokens: vec![
            "pool-secret-0".to_owned(),
            "pool-secret-1".to_owned(),
            "pool-secret-2".to_owned(),
        ],
        passthrough_prefixes: vec!["/t/".to_owned()],
        request_timeout_secs: 30,
    };
    let http_up = Arc::new(HttpUpstream::new(settings).unwrap());
    let up_bridge = Arc::clone(&http_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&up_bridge);
        async move {
            let slot: usize = req
                .headers()
                .get("x-test-slot")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let tok = make_token("grant-1", slot);
            up.handle_mcp(req, &tok).await
        }
    })
    .await;

    let client = make_client();
    for (slot, expected) in [
        (0usize, "Bearer pool-secret-0"),
        (1, "Bearer pool-secret-1"),
        (2, "Bearer pool-secret-2"),
        (5, "Bearer pool-secret-2"),
    ] {
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{gw_addr}/mcp?cursor=slot-{slot}"))
            .header(
                header::AUTHORIZATION,
                "Bearer client-oauth-token-never-leak",
            )
            .header(header::CONNECTION, "keep-alive, x-hop-secret")
            .header("x-hop-secret", "should-be-stripped")
            .header("x-test-slot", slot.to_string())
            .header(header::CONTENT_TYPE, "application/json")
            .body(bytes_body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-accel-buffering")
                .and_then(|v| v.to_str().ok()),
            Some("no")
        );
        let _ = resp.into_body().collect().await.unwrap();
        let last = seen.lock().unwrap().pop().unwrap();
        assert_eq!(last.0.as_deref(), Some(expected));
        assert_eq!(last.1, up_addr.to_string());
        assert_eq!(last.2, "https");
        assert_eq!(last.3, None);
        assert_eq!(last.4.as_deref(), Some(&format!("cursor=slot-{slot}")[..]));
    }

    let bad_method_req = Request::builder()
        .method(Method::PUT)
        .uri(format!("http://{gw_addr}/mcp"))
        .body(empty_body())
        .unwrap();
    let bad_resp = client.request(bad_method_req).await.unwrap();
    assert_eq!(bad_resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    let empty_pool_settings = HttpUpstreamSettings {
        url: Url::parse(&format!("http://{up_addr}/v1/mcp")).unwrap(),
        origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
        public_is_https: false,
        bearer_tokens: Vec::new(),
        passthrough_prefixes: Vec::new(),
        request_timeout_secs: 30,
    };
    let empty_up = Arc::new(HttpUpstream::new(empty_pool_settings).unwrap());
    let (gw2_addr, gw2_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&empty_up);
        async move { up.handle_mcp(req, &make_token("grant-2", 3)).await }
    })
    .await;

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{gw2_addr}/mcp"))
        .header(header::AUTHORIZATION, "Bearer inbound-oauth-token")
        .body(empty_body())
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let last = seen.lock().unwrap().pop().unwrap();
    assert_eq!(last.0, None);
    assert_eq!(last.2, "http");

    gw_cancel.cancel();
    gw2_cancel.cancel();
    up_cancel.cancel();
}

#[tokio::test]
async fn http_sse_strips_leading_priming_frames_and_streams_realtime() {
    let (release_second_tx, release_second_rx) = oneshot::channel::<()>();
    let release_holder = Arc::new(Mutex::new(Some(release_second_rx)));

    let (up_addr, up_cancel) = spawn_http1_harness(move |_req: Request<Incoming>| {
        let rx_opt = release_holder.lock().unwrap().take();
        async move {
            let (tx, body) = channel_body(8);
            tokio::spawn(async move {
                let chunks: &[&[u8]] = &[
                    b": leading comment\n\n",
                    b"retry: 2500\r\n",
                    b"\r\nid: prime-0\n\n",
                    b"id: ev-1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"step\":1}}\n\n",
                ];
                for chunk in chunks {
                    if tx.send(Ok(Frame::data(Bytes::from_static(chunk)))).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                if let Some(rx) = rx_opt {
                    let _ = rx.await;
                }
                let tail = b": keepalive-after-data\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"done\":true}}\n\n";
                let _ = tx.send(Ok(Frame::data(Bytes::from_static(tail)))).await;
            });

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
                .body(body)
                .unwrap()
        }
    })
    .await;

    let settings = HttpUpstreamSettings {
        url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
        origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
        public_is_https: true,
        bearer_tokens: vec!["tok".to_owned()],
        passthrough_prefixes: Vec::new(),
        request_timeout_secs: 30,
    };
    let http_up = Arc::new(HttpUpstream::new(settings).unwrap());
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&http_up);
        async move { up.handle_mcp(req, &make_token("g1", 0)).await }
    })
    .await;

    let client = make_client();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{gw_addr}/mcp"))
        .header(header::ACCEPT, "text/event-stream")
        .body(bytes_body(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#,
        ))
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok()),
        Some("no")
    );

    let mut body = resp.into_body();
    let mut first_part = Vec::new();
    while !first_part.windows(2).any(|w| w == b"\n\n") {
        let frame = tokio::time::timeout(Duration::from_secs(3), body.frame())
            .await
            .expect("first SSE event must stream before upstream closes")
            .expect("stream yielded EOF early")
            .unwrap();
        if let Ok(data) = frame.into_data() {
            first_part.extend_from_slice(&data);
        }
    }

    let first_str = String::from_utf8(first_part.clone()).unwrap();
    assert!(
        first_str.starts_with("id: ev-1\ndata: "),
        "leading priming blocks were not stripped: {first_str:?}"
    );
    assert!(!first_str.contains("leading comment"));
    assert!(!first_str.contains("retry: 2500"));
    assert!(!first_str.contains("prime-0"));

    let _ = release_second_tx.send(());
    let mut full = first_part;
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            full.extend_from_slice(&data);
        }
    }
    let full_str = String::from_utf8(full).unwrap();
    assert!(full_str.contains(": keepalive-after-data\n\n"));
    assert!(full_str.contains(r#"data: {"jsonrpc":"2.0","id":1,"result":{"done":true}}"#));

    gw_cancel.cancel();
    up_cancel.cancel();
}

#[tokio::test]
async fn http_passthrough_large_streaming_put_get_and_traversal_blocking() {
    type StoredDigest = (usize, String, Option<String>);
    let stored_digest: Arc<Mutex<Option<StoredDigest>>> = Arc::new(Mutex::new(None));
    let stored_ref = Arc::clone(&stored_digest);
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let hits_ref = Arc::clone(&upstream_hits);

    let total_bytes: usize = 4 * 1024 * 1024;

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let digest_slot = Arc::clone(&stored_ref);
        let hits = Arc::clone(&hits_ref);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            let auth = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);

            match *req.method() {
                Method::PUT => {
                    let mut hasher = Sha256::new();
                    let mut count = 0usize;
                    let mut body = req.into_body();
                    while let Some(frame) = body.frame().await {
                        let chunk = frame.unwrap().into_data().unwrap();
                        count += chunk.len();
                        hasher.update(&chunk);
                    }
                    let hex: String = hasher
                        .finalize()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    *digest_slot.lock().unwrap() = Some((count, hex.clone(), auth));
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .header("x-sha256", hex)
                        .body(empty_body())
                        .unwrap()
                }
                Method::HEAD => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, total_bytes.to_string())
                    .body(empty_body())
                    .unwrap(),
                Method::GET => {
                    let range_hdr = req
                        .headers()
                        .get(header::RANGE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let (tx, body) = channel_body(4);
                    tokio::spawn(async move {
                        let chunk_size = 64 * 1024;
                        for idx in 0..(total_bytes / chunk_size) {
                            let mut buf = vec![0u8; chunk_size];
                            for (j, b) in buf.iter_mut().enumerate() {
                                *b = ((idx * 31 + j * 17) & 0xff) as u8;
                            }
                            if tx.send(Ok(Frame::data(Bytes::from(buf)))).await.is_err() {
                                break;
                            }
                        }
                    });
                    Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .header("x-echo-range", range_hdr)
                        .body(body)
                        .unwrap()
                }
                _ => Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(empty_body())
                    .unwrap(),
            }
        }
    })
    .await;

    let tmp = TempDir::new().unwrap();
    let hash = PasswordVerifier::from_plaintext_with_iterations("pw12345", 10_000)
        .unwrap()
        .encode();
    let cfg_json = format!(
        r#"{{
          "listen": "127.0.0.1:0",
          "public_url": "https://mcp.example.com",
          "state_path": "state.json",
          "oauth": {{ "owner_password_hash": "{hash}" }},
          "upstream": {{
            "transport": "http",
            "url": "http://{up_addr}/mcp",
            "bearer_tokens": ["secret-tok"],
            "passthrough_prefixes": ["/t/"]
          }}
        }}"#
    );
    let cfg = Arc::new(GatewayConfig::from_json_str(&cfg_json, tmp.path()).unwrap());
    let UpstreamSettings::Http(ref http_settings) = cfg.upstream else {
        panic!("expected http settings");
    };
    let direct_http = HttpUpstream::new(http_settings.clone()).unwrap();

    for bad_path in [
        "/t/../mcp",
        "/t/..",
        "/t/.",
        "/t/%2e%2e/mcp",
        "/t/%2E%2e/secret",
        "/t/.%2e/secret",
        "/t/%2e/secret",
        "/t/%252e%252e/mcp",
        "/t/%25%32%65%25%32%65/mcp",
        "/t/a%255cb",
        "/t/..;/mcp",
        "/t/.;/mcp",
        "/t/%2e%2e;v=1/mcp",
        "/t/%252e%252e;v=1/mcp",
        "/t/%25252525252525252541",
        "/t/bad%2gpath",
        "/t/foo%2f..%2f..%2fmcp",
        "/t/foo%2F..%2Fsecret",
        "/t/foo%5cbar",
        "/t/foo\\bar",
        "/t/foo%00bar",
        "/T/upload-01",
    ] {
        assert!(
            !direct_http.matches_passthrough(bad_path),
            "unsafe or mismatched path must not match passthrough: {bad_path}"
        );
    }
    assert!(direct_http.matches_passthrough("/t/upload-01"));

    let (gw_addr, gw_shutdown, gw_task) = spawn_gateway(cfg).await;

    for raw_target in [
        "/t/../mcp",
        "/t/%2e%2e/mcp",
        "/t/%2E./mcp",
        "/t/%252e%252e/mcp",
        "/t/%25%32%65%25%32%65/mcp",
        "/t/a%255cb",
        "/t/..;/mcp",
        "/t/a%2f..%2f..%2fmcp",
        "/t/a%5cb",
        "/t/a%00b",
        "/T/upload-01",
    ] {
        let mut sock = TcpStream::connect(gw_addr).await.unwrap();
        let req_bytes =
            format!("GET {raw_target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        sock.write_all(req_bytes.as_bytes()).await.unwrap();
        let mut resp_buf = Vec::new();
        sock.read_to_end(&mut resp_buf).await.unwrap();
        let head = String::from_utf8_lossy(&resp_buf);
        assert!(
            head.starts_with("HTTP/1.1 404 ") || head.starts_with("HTTP/1.1 400 "),
            "expected rejection for {raw_target}, got {head:?}"
        );
    }
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "traversal attempts must never reach upstream"
    );

    let client = make_client();
    let (tx, put_body) = channel_body(4);
    let expected_hash_task = tokio::spawn(async move {
        let mut hasher = Sha256::new();
        let chunk_size = 64 * 1024;
        for idx in 0..(total_bytes / chunk_size) {
            let mut buf = vec![0u8; chunk_size];
            for (j, b) in buf.iter_mut().enumerate() {
                *b = ((idx * 31 + j * 17) & 0xff) as u8;
            }
            hasher.update(&buf);
            tx.send(Ok(Frame::data(Bytes::from(buf)))).await.unwrap();
        }
        let hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        hex
    });

    let put_req = Request::builder()
        .method(Method::PUT)
        .uri(format!("http://{gw_addr}/t/blob-large?offset=0"))
        .header(header::AUTHORIZATION, "Bearer should-strip-on-passthrough")
        .body(put_body)
        .unwrap();
    let put_resp = client.request(put_req).await.unwrap();
    assert_eq!(put_resp.status(), StatusCode::CREATED);
    let expected_hex = expected_hash_task.await.unwrap();
    let (seen_len, seen_hex, seen_auth) = stored_digest.lock().unwrap().clone().unwrap();
    assert_eq!(seen_len, total_bytes);
    assert_eq!(seen_hex, expected_hex);
    assert_eq!(seen_auth, None);

    let head_req = Request::builder()
        .method(Method::HEAD)
        .uri(format!("http://{gw_addr}/t/blob-large"))
        .body(empty_body())
        .unwrap();
    let head_resp = client.request(head_req).await.unwrap();
    assert_eq!(head_resp.status(), StatusCode::OK);

    let get_req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{gw_addr}/t/blob-large"))
        .header(header::RANGE, "bytes=0-4194303")
        .body(empty_body())
        .unwrap();
    let get_resp = client.request(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        get_resp
            .headers()
            .get("x-echo-range")
            .and_then(|v| v.to_str().ok()),
        Some("bytes=0-4194303")
    );
    let mut get_hasher = Sha256::new();
    let mut recv_len = 0usize;
    let mut get_body = get_resp.into_body();
    while let Some(frame) = get_body.frame().await {
        let chunk = frame.unwrap().into_data().unwrap();
        recv_len += chunk.len();
        get_hasher.update(&chunk);
    }
    let get_hex: String = get_hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(recv_len, total_bytes);
    assert_eq!(get_hex, expected_hex);

    let post_passthrough = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{gw_addr}/t/blob-large"))
        .body(bytes_body("nope"))
        .unwrap();
    let post_resp = client.request(post_passthrough).await.unwrap();
    assert_eq!(post_resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    gw_shutdown.cancel();
    gw_task.await.unwrap().unwrap();
    up_cancel.cancel();
}

#[tokio::test]
async fn http_mcp_rejects_oversized_payload_with_413() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let hits_ref = Arc::clone(&upstream_hits);

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let hits = Arc::clone(&hits_ref);
        async move {
            let _ = req.into_body().collect().await;
            hits.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .status(StatusCode::OK)
                .body(bytes_body("{}"))
                .unwrap()
        }
    })
    .await;

    let settings = HttpUpstreamSettings {
        url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
        origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
        public_is_https: true,
        bearer_tokens: vec!["tok".to_owned()],
        passthrough_prefixes: Vec::new(),
        request_timeout_secs: 30,
    };
    let http_up = Arc::new(HttpUpstream::new(settings).unwrap());
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&http_up);
        async move { up.handle_mcp(req, &make_token("g1", 0)).await }
    })
    .await;

    let mut sock = TcpStream::connect(gw_addr).await.unwrap();
    let oversized = 16 * 1024 * 1024 + 1;
    let raw_head = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {oversized}\r\n\r\n"
    );
    sock.write_all(raw_head.as_bytes()).await.unwrap();
    let mut resp_bytes = Vec::new();
    sock.read_to_end(&mut resp_bytes).await.unwrap();
    let resp_head = String::from_utf8_lossy(&resp_bytes);
    assert!(
        resp_head.starts_with("HTTP/1.1 413 "),
        "expected 413 for Content-Length > 16 MiB, got {resp_head:?}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    let client = make_client();
    let (tx, chunked_body) = channel_body(4);
    let (done_tx, done_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let block = Bytes::from(vec![b'a'; 1024 * 1024]);
        for _ in 0..16 {
            if tx.send(Ok(Frame::data(block.clone()))).await.is_err() {
                return;
            }
        }
        // Hold sender open until client reads 413 so Winsock does not reset early.
        if tx
            .send(Ok(Frame::data(Bytes::from_static(b"x"))))
            .await
            .is_ok()
        {
            let _ = done_rx.await;
        }
    });
    let chunked_req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{gw_addr}/mcp"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(chunked_body)
        .unwrap();
    let chunked_resp = client.request(chunked_req).await.unwrap();
    let _ = done_tx.send(());
    assert_eq!(chunked_resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    gw_cancel.cancel();
    up_cancel.cancel();
}

#[tokio::test]
async fn http_tls_native_roots_loads_cleanly() {
    let settings = HttpUpstreamSettings {
        url: Url::parse("https://mcp.example.com/mcp").unwrap(),
        origin_base: Url::parse("https://mcp.example.com").unwrap(),
        public_is_https: true,
        bearer_tokens: vec!["tls-pool-tok".to_owned()],
        passthrough_prefixes: vec!["/t/".to_owned()],
        request_timeout_secs: 30,
    };
    let upstream = HttpUpstream::new(settings).expect("native OS TLS roots must load");
    upstream.shutdown().await;
}

#[tokio::test]
async fn http_session_grant_isolation_terminate_grant_sse_abort_and_upstream_delete() {
    let deleted_sessions = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
    let deleted_ref = Arc::clone(&deleted_sessions);
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let hits_ref = Arc::clone(&upstream_hits);

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let deleted = Arc::clone(&deleted_ref);
        let hits = Arc::clone(&hits_ref);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
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

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    "mcp-session-id",
                    sid.unwrap_or_else(|| "http-sess-1".to_owned()),
                )
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                ))
                .unwrap()
        }
    })
    .await;

    let settings = HttpUpstreamSettings {
        url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
        origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
        public_is_https: true,
        bearer_tokens: vec!["pool-tok-a".to_owned(), "pool-tok-b".to_owned()],
        passthrough_prefixes: Vec::new(),
        request_timeout_secs: 30,
    };
    let http_up = Arc::new(HttpUpstream::new(settings).unwrap());
    let up_bridge = Arc::clone(&http_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&up_bridge);
        async move {
            let grant = req
                .headers()
                .get("x-test-grant")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("grant-a")
                .to_owned();
            let slot = if grant == "grant-a" { 0 } else { 1 };
            up.handle_mcp(req, &make_token(&grant, slot)).await
        }
    })
    .await;

    let client = make_client();

    let init_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-a")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let sid = init_resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(sid, "http-sess-1");
    let _ = init_resp.into_body().collect().await.unwrap();
    let hits_after_init = upstream_hits.load(Ordering::SeqCst);

    for bad_req in [
        Request::builder()
            .method(Method::POST)
            .uri(format!("http://{gw_addr}/mcp"))
            .header("x-test-grant", "grant-a")
            .header("mcp-session-id", "s1")
            .header("mcp-session-id", "s2")
            .body(bytes_body("{}"))
            .unwrap(),
        Request::builder()
            .method(Method::POST)
            .uri(format!("http://{gw_addr}/mcp"))
            .header("x-test-grant", "grant-a")
            .header("mcp-session-id", "   ")
            .body(bytes_body("{}"))
            .unwrap(),
        Request::builder()
            .method(Method::POST)
            .uri(format!("http://{gw_addr}/mcp"))
            .header("x-test-grant", "grant-a")
            .header("mcp-session-id", "bad space")
            .body(bytes_body("{}"))
            .unwrap(),
    ] {
        let resp = client.request(bad_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    for method in [Method::POST, Method::GET, Method::DELETE] {
        let hijack = client
            .request(
                Request::builder()
                    .method(method)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("x-test-grant", "grant-b")
                    .header("mcp-session-id", &sid)
                    .body(empty_body())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(hijack.status(), StatusCode::NOT_FOUND);
    }
    assert_eq!(upstream_hits.load(Ordering::SeqCst), hits_after_init);

    let sse_resp = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-a")
                .header("mcp-session-id", &sid)
                .header(header::ACCEPT, "text/event-stream")
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut sse_body = sse_resp.into_body();
    let first_frame = tokio::time::timeout(Duration::from_secs(3), sse_body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let first_bytes = first_frame.into_data().unwrap();
    assert!(String::from_utf8_lossy(&first_bytes).contains("notifications/message"));

    let reader_task = tokio::spawn(async move {
        while let Some(res) = sse_body.frame().await {
            if res.is_err() {
                break;
            }
        }
    });

    http_up.terminate_grant("grant-a").await;

    tokio::time::timeout(Duration::from_secs(2), reader_task)
        .await
        .expect("terminate_grant must abort active HTTP SSE stream")
        .unwrap();

    let deleted = deleted_sessions.lock().unwrap().clone();
    assert_eq!(
        deleted,
        vec![(
            "http-sess-1".to_owned(),
            Some("Bearer pool-tok-a".to_owned())
        )]
    );

    gw_cancel.cancel();
    up_cancel.cancel();
}

#[tokio::test]
async fn http_header_hardening_non_ascii_connection_and_upstream_401_masking() {
    let seen_headers: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_ref = Arc::clone(&seen_headers);

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let seen = Arc::clone(&seen_ref);
        async move {
            let mut recorded = Vec::new();
            for (k, v) in req.headers() {
                recorded.push((k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()));
            }
            *seen.lock().unwrap() = recorded;
            let force_401 = req.uri().query() == Some("auth_fail=1");
            let _ = req.into_body().collect().await;

            if force_401 {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(
                        header::WWW_AUTHENTICATE,
                        "Bearer realm=\"upstream-internal\"",
                    )
                    .header(header::SET_COOKIE, "up=1")
                    .body(bytes_body("upstream secret error"))
                    .unwrap();
            }

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::WWW_AUTHENTICATE, "Bearer realm=\"stray\"")
                .body(bytes_body(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#))
                .unwrap()
        }
    })
    .await;

    let settings = HttpUpstreamSettings {
        url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
        origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
        public_is_https: true,
        bearer_tokens: vec!["tok".to_owned()],
        passthrough_prefixes: Vec::new(),
        request_timeout_secs: 30,
    };
    let http_up = Arc::new(HttpUpstream::new(settings).unwrap());
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&http_up);
        async move { up.handle_mcp(req, &make_token("grant-hdr", 0)).await }
    })
    .await;

    let client = make_client();
    let non_ascii_conn =
        HeaderValue::from_bytes(b"bad-\xff-tok, x-hop-secret, content-type, content-length, host")
            .unwrap();
    let payload = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{gw_addr}/mcp"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-hop-secret", "must-strip")
        .header(header::ORIGIN, "https://mcp.example.com")
        .header("x-user-id", "spoof")
        .header("x-user-name", "spoof")
        .header("x-forwarded-user", "spoof")
        .header("x-remote-user", "spoof")
        .header("x-forwarded-port", "443")
        .header("x-forwarded-prefix", "/admin")
        .header("x-original-url", "/admin")
        .header("x-rewrite-url", "/admin")
        .header("cf-connecting-ip", "1.1.1.1")
        .header("true-client-ip", "1.1.1.1")
        .body(bytes_body(payload))
        .unwrap();
    req.headers_mut().insert(header::CONNECTION, non_ascii_conn);

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_none());
    let _ = resp.into_body().collect().await.unwrap();

    {
        let recorded = seen_headers.lock().unwrap();
        for stripped in [
            "x-hop-secret",
            "origin",
            "x-user-id",
            "x-user-name",
            "x-forwarded-user",
            "x-remote-user",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "x-original-url",
            "x-rewrite-url",
            "cf-connecting-ip",
            "true-client-ip",
        ] {
            assert!(
                !recorded.iter().any(|(k, _)| k == stripped),
                "header {stripped} must be stripped"
            );
        }
        assert!(
            recorded
                .iter()
                .any(|(k, v)| k == "content-type" && v == "application/json")
        );
        assert!(
            recorded
                .iter()
                .any(|(k, v)| k == "content-length" && v == &payload.len().to_string())
        );
        assert!(
            recorded
                .iter()
                .any(|(k, v)| k == "host" && v == &up_addr.to_string())
        );
    }

    let fail_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp?auth_fail=1"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fail_resp.status(), StatusCode::BAD_GATEWAY);
    assert!(fail_resp.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert!(fail_resp.headers().get(header::SET_COOKIE).is_none());
    assert!(
        fail_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );

    gw_cancel.cancel();
    up_cancel.cancel();
}

fn write_mock_mcp_python_script(dir: &Path) -> std::path::PathBuf {
    let script_path = dir.join("mock_mcp_server.py");
    let script = r##"import json, os, subprocess, sys, threading, time

state_dir = os.environ["MOCK_STATE_DIR"]
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
with open(os.path.join(state_dir, f"pids_{pid}.json"), "w", encoding="utf-8") as f:
    json.dump({"pid": pid, "pgid": pgid, "grandchild_pid": bg.pid}, f)

write_lock = threading.Lock()
cancel_events = {}
server_req_waiters = {}
counter = 0

def emit(obj):
    line = json.dumps(obj, separators=(",", ":"))
    with write_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

def emit_raw(line):
    with write_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

def run_slow(req_id, ptok, ev):
    emit({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": ptok,
            "progress": 10,
            "total": 100,
            "_meta": {"pid": pid, "grandchild_pid": bg.pid},
        },
    })
    if ev.wait(timeout=10.0):
        return
    emit({"jsonrpc": "2.0", "id": req_id, "result": {"completed": True}})

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    method = msg.get("method")
    req_id = msg.get("id")

    with open(os.path.join(state_dir, f"log_{pid}.jsonl"), "a", encoding="utf-8") as lf:
        lf.write(json.dumps(msg, separators=(",", ":")) + "\n")

    if method is None and req_id in server_req_waiters:
        q_ev, box = server_req_waiters.pop(req_id)
        box.append(msg)
        q_ev.set()
        continue

    if method == "notifications/cancelled":
        target = msg.get("params", {}).get("requestId")
        with open(os.path.join(state_dir, "cancelled.jsonl"), "a", encoding="utf-8") as cf:
            cf.write(json.dumps(msg, separators=(",", ":")) + "\n")
        ev = cancel_events.get(str(target))
        if ev is not None:
            ev.set()
        continue

    if req_id is None:
        continue

    if method == "initialize":
        client_name = msg.get("params", {}).get("clientInfo", {}).get("name", "")
        if client_name == "fail-init-error":
            emit({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "init rejected", "data": {"pid": pid, "grandchild_pid": bg.pid}},
            })
            continue
        if client_name == "fail-init-malformed":
            emit({"jsonrpc": "2.0", "id": req_id})
            continue
        emit({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "mock-stdio", "version": "1.0.0"},
                "instructions": "Keep exact multiline\ninstructions & symbols: <>[]{}",
                "_meta": {"pid": pid, "pgid": pgid, "grandchild_pid": bg.pid},
            },
        })
    elif method == "tools/list":
        emit({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "complex_tool",
                        "description": "Validates lossless schema forwarding",
                        "inputSchema": {
                            "$schema": "https://json-schema.org/draft/2020-12/schema",
                            "type": "object",
                            "$defs": {
                                "Coordinate": {
                                    "type": "object",
                                    "properties": {
                                        "lat": {"type": "number", "minimum": -90, "maximum": 90},
                                        "lon": {"type": "number", "minimum": -180, "maximum": 180},
                                    },
                                    "required": ["lat", "lon"],
                                    "additionalProperties": False,
                                }
                            },
                            "properties": {
                                "target": {
                                    "anyOf": [
                                        {"$ref": "#/$defs/Coordinate"},
                                        {"type": "string", "pattern": "^[a-z0-9_-]+$"},
                                    ]
                                },
                                "tags": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
                            },
                            "required": ["target"],
                            "additionalProperties": False,
                        },
                        "outputSchema": {
                            "type": "object",
                            "properties": {"count": {"type": "integer"}, "pid": {"type": "integer"}},
                            "required": ["count", "pid"],
                        },
                        "_meta": {"x-custom-vendor": {"nested": [1, True, None, "ok"]}},
                    }
                ]
            },
        })
    elif method == "tools/call":
        name = msg.get("params", {}).get("name")
        ptok = msg.get("params", {}).get("_meta", {}).get("progressToken", "tok-default")
        if name == "bump":
            counter += 1
            emit({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"count={counter}"}],
                    "structuredContent": {"count": counter, "pid": pid},
                    "_meta": {"preserved": True},
                },
            })
        elif name == "dump_env":
            emit({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"env": dict(os.environ)},
            })
        elif name == "progress_demo":
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {"progressToken": ptok, "progress": 25, "total": 100},
            })
            time.sleep(0.04)
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {"progressToken": ptok, "progress": 75, "total": 100},
            })
            time.sleep(0.04)
            emit({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": "finished"}],
                    "structuredContent": {"pid": pid, "status": "complete"},
                },
            })
        elif name == "hang_until_cancel":
            ev = threading.Event()
            cancel_events[str(req_id)] = ev
            threading.Thread(target=run_slow, args=(req_id, ptok, ev), daemon=True).start()
        elif name == "hang_forever":
            with open(os.path.join(state_dir, "hung_pid.json"), "w", encoding="utf-8") as hf:
                json.dump({"pid": pid, "grandchild_pid": bg.pid}, hf)
        elif name == "concurrent_clean":
            tag = msg.get("params", {}).get("arguments", {}).get("tag", "default")
            def run_clean(rid, tok, t):
                emit({
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {"progressToken": tok, "progress": 10, "total": 100, "message": t},
                })
                time.sleep(0.12)
                emit({
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {"progressToken": tok, "progress": 90, "total": 100, "message": t},
                })
                emit({
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {"ok": True, "tag": t},
                })
            threading.Thread(target=run_clean, args=(req_id, ptok, tag), daemon=True).start()
        elif name == "late_progress_emitter":
            emit({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"done_fast": True},
            })
            def emit_late(tok):
                time.sleep(0.03)
                emit({
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {"progressToken": tok, "progress": 99, "total": 100},
                })
                emit({
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {"progressToken": "unknown-token", "progress": 50, "total": 100},
                })
            threading.Thread(target=emit_late, args=(ptok,), daemon=True).start()
        elif name == "crash_after_progress":
            emit({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {"progressToken": ptok, "progress": 33, "total": 100},
            })
            time.sleep(0.01)
            os._exit(1)
        elif name == "delayed_echo":
            args = msg.get("params", {}).get("arguments", {})
            delay_ms = args.get("delay_ms", 0)
            tag = args.get("tag", "")
            def run_delayed(rid, ms, t):
                time.sleep(ms / 1000.0)
                emit({"jsonrpc": "2.0", "id": rid, "result": {"tag": t, "pid": pid}})
            threading.Thread(target=run_delayed, args=(req_id, delay_ms, tag), daemon=True).start()
        elif name == "ask_client_requests":
            def run_ask(rid):
                ev_ping = threading.Event()
                box_ping = []
                server_req_waiters["srv-ping-1"] = (ev_ping, box_ping)
                emit({"jsonrpc": "2.0", "id": "srv-ping-1", "method": "ping"})
                ev_ping.wait(timeout=3.0)

                ev_roots = threading.Event()
                box_roots = []
                server_req_waiters["srv-roots-1"] = (ev_roots, box_roots)
                emit({"jsonrpc": "2.0", "id": "srv-roots-1", "method": "roots/list", "params": {}})
                ev_roots.wait(timeout=3.0)

                emit({
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "ping_reply": box_ping[0] if box_ping else None,
                        "roots_reply": box_roots[0] if box_roots else None,
                    },
                })
            threading.Thread(target=run_ask, args=(req_id,), daemon=True).start()
        elif name == "emit_cr_json":
            emit_raw('{"jsonrpc":"2.0",\r"method":"notifications/message",\r"params":{"note":"has-cr"}}')
            emit_raw(f'{{"jsonrpc":"2.0",\r"id":{json.dumps(req_id)},\r"result":{{"cr_clean":true}}}}')
"##;
    std::fs::write(&script_path, script).unwrap();
    script_path
}

fn build_stdio_upstream(
    script_path: &Path,
    state_dir: &Path,
    max_sessions: usize,
) -> Arc<StdioUpstream> {
    let mut env = BTreeMap::new();
    env.insert(
        "MOCK_STATE_DIR".to_owned(),
        state_dir.to_str().unwrap().to_owned(),
    );
    let settings = StdioUpstreamSettings {
        command: python_executable().to_owned(),
        args: vec!["-u".to_owned(), script_path.to_str().unwrap().to_owned()],
        env,
        cwd: Some(state_dir.to_path_buf()),
        max_sessions,
        session_idle_secs: 60,
    };
    Arc::new(StdioUpstream::new(settings).unwrap())
}

#[tokio::test]
async fn stdio_late_cancellation_does_not_cancel_an_unrelated_wire_id() {
    let tmp = TempDir::new().unwrap();
    let script = write_mock_mcp_python_script(tmp.path());
    let upstream = build_stdio_upstream(&script, tmp.path(), 1);
    let bridge = Arc::clone(&upstream);
    let (addr, stop) = spawn_http1_harness(move |req| {
        let bridge = Arc::clone(&bridge);
        async move { bridge.handle_mcp(req, &make_token("cancel", 0)).await }
    })
    .await;
    let client = make_client();
    let post = |sid: Option<&str>, accept: &str, payload: Value| {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{addr}/mcp"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, accept);
        if let Some(sid) = sid {
            req = req.header("mcp-session-id", sid);
        }
        client.request(req.body(bytes_body(payload.to_string())).unwrap())
    };

    let init = post(
        None,
        "application/json",
        json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{}}),
    )
    .await
    .unwrap();
    assert_eq!(init.status(), StatusCode::OK);
    let sid = init.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let _ = init.into_body().collect().await.unwrap();

    let finished = post(
        Some(&sid),
        "application/json",
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bump"}}),
    )
    .await
    .unwrap();
    let _ = finished.into_body().collect().await.unwrap();

    let active = post(
        Some(&sid),
        "text/event-stream",
        json!({"jsonrpc":"2.0","id":"next","method":"tools/call","params":{"name":"hang_until_cancel","_meta":{"progressToken":"next-progress"}}}),
    )
    .await
    .unwrap();
    let mut body = active.into_body();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut received = Vec::new();
        while !String::from_utf8_lossy(&received).contains("notifications/progress") {
            received.extend_from_slice(&body.frame().await.unwrap().unwrap().into_data().unwrap());
        }
    })
    .await
    .unwrap();

    for (request_id, expected_cancellations) in [(json!(3), 0), (json!("next"), 1)] {
        let cancelled = post(
            Some(&sid),
            "application/json",
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":request_id}}),
        )
        .await
        .unwrap();
        assert_eq!(cancelled.status(), StatusCode::ACCEPTED);
        let _ = cancelled.into_body().collect().await.unwrap();

        // This reply confirms the child processed every earlier stdin message.
        let barrier = post(
            Some(&sid),
            "application/json",
            json!({"jsonrpc":"2.0","id":"barrier","method":"tools/call","params":{"name":"bump"}}),
        )
        .await
        .unwrap();
        let _ = barrier.into_body().collect().await.unwrap();
        let cancellations =
            std::fs::read_to_string(tmp.path().join("cancelled.jsonl")).unwrap_or_default();
        let messages: Vec<Value> = cancellations
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(messages.len(), expected_cancellations);
        if let Some(message) = messages.first() {
            assert_eq!(message["params"]["requestId"], 3);
        }
    }
    drop(body);
    upstream.shutdown().await;
    stop.cancel();
}

#[tokio::test]
async fn stdio_isolation_grant_binding_schema_progress_cancel_delete_and_sessionless() {
    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let stdio_up = build_stdio_upstream(&script_path, tmp.path(), 2);
    let bridge_ref = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge_ref);
        async move {
            let grant = req
                .headers()
                .get("x-test-grant")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("grant-a")
                .to_owned();
            up.handle_mcp(req, &make_token(&grant, 0)).await
        }
    })
    .await;

    let client = make_client();

    let get_resp = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{gw_addr}/mcp"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    let init_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"}
        }
    });

    let resp_a = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-a")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(serde_json::to_vec(&init_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_a.status(), StatusCode::OK);
    let sid_a = resp_a
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        resp_a
            .headers()
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok()),
        Some("no")
    );
    let init_json_a: Value =
        serde_json::from_slice(&resp_a.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        init_json_a["result"]["instructions"],
        "Keep exact multiline\ninstructions & symbols: <>[]{}"
    );
    let pid_a = init_json_a["result"]["_meta"]["pid"].as_u64().unwrap() as u32;
    let pgid_a = init_json_a["result"]["_meta"]["pgid"].as_u64().unwrap() as u32;
    let grandchild_a = init_json_a["result"]["_meta"]["grandchild_pid"]
        .as_u64()
        .unwrap() as u32;
    assert_eq!(pid_a, pgid_a, "child must lead its own process group");
    assert!(process_exists(pid_a));
    assert!(process_exists(grandchild_a));

    let resp_b = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-b")
                .header(header::ACCEPT, "text/event-stream")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(serde_json::to_vec(&init_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_b.status(), StatusCode::OK);
    let sid_b = resp_b
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_ne!(sid_a, sid_b);
    let sse_init_b = String::from_utf8(
        resp_b
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(sse_init_b.starts_with("data: {"));
    let init_json_b: Value =
        serde_json::from_str(sse_init_b.trim().strip_prefix("data: ").unwrap()).unwrap();
    let pid_b = init_json_b["result"]["_meta"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(pid_a, pid_b);

    let resp_full = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-c")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(serde_json::to_vec(&init_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_full.status(), StatusCode::SERVICE_UNAVAILABLE);

    let note_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-a")
                .header("mcp-session-id", &sid_a)
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(note_resp.status(), StatusCode::ACCEPTED);

    let tools_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-a")
                .header("mcp-session-id", &sid_a)
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tools_resp.status(), StatusCode::OK);
    let tools_val: Value =
        serde_json::from_slice(&tools_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    let tool = &tools_val["result"]["tools"][0];
    assert_eq!(
        tool["inputSchema"]["$defs"]["Coordinate"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        tool["inputSchema"]["properties"]["target"]["anyOf"][0]["$ref"],
        json!("#/$defs/Coordinate")
    );
    assert_eq!(tool["outputSchema"]["required"], json!(["count", "pid"]));
    assert_eq!(
        tool["_meta"]["x-custom-vendor"]["nested"],
        json!([1, true, null, "ok"])
    );

    let hijack_post = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-b")
                .header("mcp-session-id", &sid_a)
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bump"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hijack_post.status(), StatusCode::NOT_FOUND);

    let hijack_del = client
        .request(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-b")
                .header("mcp-session-id", &sid_a)
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hijack_del.status(), StatusCode::NOT_FOUND);
    assert!(
        process_exists(pid_a),
        "cross-grant DELETE must not kill owner session"
    );

    let bump_a = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-a")
                .header("mcp-session-id", &sid_a)
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bump"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bump_a_val: Value =
        serde_json::from_slice(&bump_a.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(bump_a_val["result"]["structuredContent"]["count"], 1);
    assert_eq!(bump_a_val["result"]["structuredContent"]["pid"], pid_a);

    let bump_b = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-b")
                .header("mcp-session-id", &sid_b)
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bump"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bump_b_val: Value =
        serde_json::from_slice(&bump_b.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(bump_b_val["result"]["structuredContent"]["count"], 1);
    assert_eq!(bump_b_val["result"]["structuredContent"]["pid"], pid_b);

    let prog_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-a")
                .header("mcp-session-id", &sid_a)
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"progress_demo","_meta":{"progressToken":"pt-99"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prog_resp.status(), StatusCode::OK);
    assert_eq!(
        prog_resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    let mut sse_raw = Vec::new();
    let mut prog_body = prog_resp.into_body();
    while let Some(frame) = prog_body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            sse_raw.extend_from_slice(&data);
        }
    }
    let sse_text = String::from_utf8(sse_raw).unwrap();
    let blocks: Vec<&str> = sse_text.split("\n\n").filter(|b| !b.is_empty()).collect();
    assert_eq!(
        blocks.len(),
        3,
        "expected 2 progress events + 1 final response: {sse_text:?}"
    );
    for b in &blocks {
        assert!(b.starts_with("data: "), "unexpected priming block: {b:?}");
    }
    let ev0: Value = serde_json::from_str(blocks[0].strip_prefix("data: ").unwrap()).unwrap();
    let ev1: Value = serde_json::from_str(blocks[1].strip_prefix("data: ").unwrap()).unwrap();
    let ev2: Value = serde_json::from_str(blocks[2].strip_prefix("data: ").unwrap()).unwrap();
    assert_eq!(ev0["method"], "notifications/progress");
    assert_eq!(ev0["params"]["progressToken"], "pt-99");
    assert_eq!(ev0["params"]["progress"], 25);
    assert_eq!(ev1["params"]["progressToken"], "pt-99");
    assert_eq!(ev1["params"]["progress"], 75);
    assert_eq!(ev2["id"], 5);
    assert_eq!(ev2["result"]["structuredContent"]["status"], "complete");

    {
        let mut raw_conn = TcpStream::connect(gw_addr).await.unwrap();
        let body_str = r#"{"jsonrpc":"2.0","id":"req-cancel-42","method":"tools/call","params":{"name":"hang_until_cancel","_meta":{"progressToken":"pt-cancel"}}}"#;
        let http_req = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nx-test-grant: grant-a\r\nmcp-session-id: {sid_a}\r\nAccept: text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body_str}",
            body_str.len()
        );
        raw_conn.write_all(http_req.as_bytes()).await.unwrap();

        let mut buf = [0u8; 2048];
        let mut received = String::new();
        while !received.contains("notifications/progress") {
            let n = tokio::time::timeout(Duration::from_secs(3), raw_conn.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert!(n > 0);
            received.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        drop(raw_conn);
    }

    let cancel_file = tmp.path().join("cancelled.jsonl");
    let mut cancelled_msg: Option<Value> = None;
    for _ in 0..50 {
        if let Ok(text) = std::fs::read_to_string(&cancel_file)
            && let Some(first_line) = text.lines().next()
        {
            cancelled_msg = Some(serde_json::from_str(first_line).unwrap());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let cancelled =
        cancelled_msg.expect("child must receive notifications/cancelled on disconnect");
    assert_eq!(cancelled["method"], "notifications/cancelled");
    assert!(
        cancelled["params"]["requestId"].is_u64(),
        "cancelled requestId must be internal wire_id: {cancelled}"
    );
    assert_eq!(cancelled["params"]["reason"], "client disconnected");

    let del_a = client
        .request(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-a")
                .header("mcp-session-id", &sid_a)
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_a.status(), StatusCode::OK);
    assert!(
        wait_process_gone(pid_a).await,
        "session child must be reaped"
    );
    assert!(
        wait_process_gone(grandchild_a).await,
        "background grandchild in process group must be killed"
    );

    let sessionless_meta_req = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {
            "name": "bump",
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28"
            }
        }
    });
    let sl_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-ephemeral")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    serde_json::to_vec(&sessionless_meta_req).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sl_resp.status(), StatusCode::OK);
    assert!(
        sl_resp.headers().get("mcp-session-id").is_none(),
        "sessionless response must not emit Mcp-Session-Id"
    );
    let sl_val: Value =
        serde_json::from_slice(&sl_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let sl_pid = sl_val["result"]["structuredContent"]["pid"]
        .as_u64()
        .unwrap() as u32;
    assert_eq!(sl_val["result"]["structuredContent"]["count"], 1);
    assert!(
        wait_process_gone(sl_pid).await,
        "ephemeral child must be reaped before returning sessionless response"
    );

    let pid_meta: Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(format!("pids_{sl_pid}.json"))).unwrap(),
    )
    .unwrap();
    let sl_grandchild = pid_meta["grandchild_pid"].as_u64().unwrap() as u32;
    assert!(wait_process_gone(sl_grandchild).await);

    let sl_hdr_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-ephemeral")
                .header("MCP-Protocol-Version", "2026-07-28")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":"bump"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sl_hdr_resp.status(), StatusCode::OK);
    assert!(sl_hdr_resp.headers().get("mcp-session-id").is_none());

    stdio_up.shutdown().await;
    assert!(wait_process_gone(pid_b).await);

    gw_cancel.cancel();
}

#[tokio::test]
async fn server_routing_order_healthz_unauth_mcp_404_and_shutdown() {
    let tmp = TempDir::new().unwrap();
    let hash = PasswordVerifier::from_plaintext_with_iterations("secret123", 10_000)
        .unwrap()
        .encode();
    let py = python_executable();
    let cfg_json = format!(
        r#"{{
          "listen": "127.0.0.1:0",
          "public_url": "https://mcp.example.com",
          "state_path": "state.json",
          "oauth": {{ "owner_password_hash": "{hash}" }},
          "upstream": {{
            "transport": "stdio",
            "command": "{py}",
            "args": ["-c", "import sys; sys.exit(0)"]
          }}
        }}"#
    );
    let cfg = Arc::new(GatewayConfig::from_json_str(&cfg_json, tmp.path()).unwrap());
    let (addr, shutdown, server_task) = spawn_gateway(cfg).await;
    let client = make_client();

    let health = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/healthz"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    let health_json: Value =
        serde_json::from_slice(&health.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(health_json, json!({"ok": true}));

    let head_health = client
        .request(
            Request::builder()
                .method(Method::HEAD)
                .uri(format!("http://{addr}/healthz"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head_health.status(), StatusCode::OK);
    assert!(
        head_health
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );

    let oauth_meta = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "http://{addr}/.well-known/oauth-authorization-server"
                ))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oauth_meta.status(), StatusCode::OK);
    assert_eq!(
        oauth_meta
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );

    let mut unauth_sock = TcpStream::connect(addr).await.unwrap();
    unauth_sock
        .write_all(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 99999999\r\n\r\n")
        .await
        .unwrap();
    let mut unauth_buf = Vec::new();
    unauth_sock.read_to_end(&mut unauth_buf).await.unwrap();
    let unauth_text = String::from_utf8_lossy(&unauth_buf);
    assert!(unauth_text.starts_with("HTTP/1.1 401 "));
    assert!(
        unauth_text
            .to_ascii_lowercase()
            .contains("www-authenticate: bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp\"")
    );

    let mut evil_host_sock = TcpStream::connect(addr).await.unwrap();
    evil_host_sock
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: evil.example\r\n\r\n")
        .await
        .unwrap();
    let mut evil_buf = Vec::new();
    evil_host_sock.read_to_end(&mut evil_buf).await.unwrap();
    let evil_text = String::from_utf8_lossy(&evil_buf);
    assert!(evil_text.starts_with("HTTP/1.1 400 "));
    assert!(evil_text.to_ascii_lowercase().contains("connection: close"));

    let not_found = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/no-such-route"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        not_found
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok()),
        Some("close")
    );
    assert!(
        not_found
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );

    shutdown.cancel();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn stdio_idle_session_eviction_reclaims_slot_and_process_group() {
    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let mut env = BTreeMap::new();
    env.insert(
        "MOCK_STATE_DIR".to_owned(),
        tmp.path().to_str().unwrap().to_owned(),
    );
    let settings = StdioUpstreamSettings {
        command: python_executable().to_owned(),
        args: vec!["-u".to_owned(), script_path.to_str().unwrap().to_owned()],
        env,
        cwd: Some(tmp.path().to_path_buf()),
        max_sessions: 1,
        session_idle_secs: 1,
    };
    let stdio_up = Arc::new(StdioUpstream::new(settings).unwrap());
    let bridge = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge);
        async move { up.handle_mcp(req, &make_token("grant-idle", 0)).await }
    })
    .await;

    let client = make_client();
    let init_body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "idle-test", "version": "0.1"}
        }
    }))
    .unwrap();

    let first = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(init_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_val: Value =
        serde_json::from_slice(&first.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let pid1 = first_val["result"]["_meta"]["pid"].as_u64().unwrap() as u32;
    let grand1 = first_val["result"]["_meta"]["grandchild_pid"]
        .as_u64()
        .unwrap() as u32;
    assert!(process_exists(pid1));
    assert!(process_exists(grand1));

    tokio::time::sleep(Duration::from_millis(1600)).await;

    let second = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(init_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_val: Value =
        serde_json::from_slice(&second.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let pid2 = second_val["result"]["_meta"]["pid"].as_u64().unwrap() as u32;
    assert_ne!(pid1, pid2);
    assert!(wait_process_gone(pid1).await);
    assert!(wait_process_gone(grand1).await);

    stdio_up.shutdown().await;
    assert!(wait_process_gone(pid2).await);
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_sessionless_timeout_returns_504_and_releases_slot() {
    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let mut env = BTreeMap::new();
    env.insert(
        "MOCK_STATE_DIR".to_owned(),
        tmp.path().to_str().unwrap().to_owned(),
    );
    let settings = StdioUpstreamSettings {
        command: python_executable().to_owned(),
        args: vec!["-u".to_owned(), script_path.to_str().unwrap().to_owned()],
        env,
        cwd: Some(tmp.path().to_path_buf()),
        max_sessions: 1,
        session_idle_secs: 1,
    };
    let stdio_up = Arc::new(StdioUpstream::new(settings).unwrap());
    let bridge = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge);
        async move { up.handle_mcp(req, &make_token("grant-sl-timeout", 0)).await }
    })
    .await;

    let client = make_client();
    let hung_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("MCP-Protocol-Version", "2026-07-28")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":701,"method":"tools/call","params":{"name":"hang_forever"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hung_resp.status(), StatusCode::GATEWAY_TIMEOUT);
    let err_json: Value =
        serde_json::from_slice(&hung_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(err_json["id"], 701);
    assert!(err_json["error"].is_object());

    let hung_meta: Value =
        serde_json::from_str(&std::fs::read_to_string(tmp.path().join("hung_pid.json")).unwrap())
            .unwrap();
    let hung_pid = hung_meta["pid"].as_u64().unwrap() as u32;
    let hung_grandchild = hung_meta["grandchild_pid"].as_u64().unwrap() as u32;
    assert!(wait_process_gone(hung_pid).await);
    assert!(wait_process_gone(hung_grandchild).await);

    let next_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("MCP-Protocol-Version", "2026-07-28")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":702,"method":"tools/call","params":{"name":"bump"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(next_resp.status(), StatusCode::OK);

    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_late_progress_notification_does_not_leak_to_concurrent_request() {
    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let stdio_up = build_stdio_upstream(&script_path, tmp.path(), 2);
    let bridge = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge);
        async move { up.handle_mcp(req, &make_token("grant-concurrent", 0)).await }
    })
    .await;

    let client = make_client();
    let init_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"0.1"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let sid = init_resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let _ = init_resp.into_body().collect().await.unwrap();

    let clean_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &sid)
                .header(header::ACCEPT, "text/event-stream")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":"req-clean","method":"tools/call","params":{"name":"concurrent_clean","_meta":{"progressToken":"pt-clean"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(clean_resp.status(), StatusCode::OK);
    let mut clean_body = clean_resp.into_body();

    let mut collected = Vec::new();
    while !String::from_utf8_lossy(&collected).contains("\"progress\":10") {
        let frame = clean_body.frame().await.unwrap().unwrap();
        if let Ok(data) = frame.into_data() {
            collected.extend_from_slice(&data);
        }
    }

    let fast_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &sid)
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":"req-fast","method":"tools/call","params":{"name":"late_progress_emitter","_meta":{"progressToken":"pt-stale"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fast_resp.status(), StatusCode::OK);
    let fast_val: Value =
        serde_json::from_slice(&fast_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(fast_val["result"]["done_fast"], true);

    while let Some(frame) = clean_body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            collected.extend_from_slice(&data);
        }
    }

    let sse_text = String::from_utf8(collected).unwrap();
    assert!(
        !sse_text.contains("pt-stale"),
        "late progress leaked: {sse_text:?}"
    );
    assert!(
        !sse_text.contains("unknown-token"),
        "unmatched progress leaked: {sse_text:?}"
    );

    let events: Vec<Value> = sse_text
        .split("\n\n")
        .filter(|b| !b.is_empty())
        .map(|b| serde_json::from_str(b.strip_prefix("data: ").unwrap()).unwrap())
        .collect();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["params"]["progressToken"], "pt-clean");
    assert_eq!(events[0]["params"]["progress"], 10);
    assert_eq!(events[1]["params"]["progressToken"], "pt-clean");
    assert_eq!(events[1]["params"]["progress"], 90);
    assert_eq!(events[2]["id"], "req-clean");
    assert_eq!(events[2]["result"]["ok"], true);

    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_sse_abrupt_exit_and_concurrent_delete_close_stream_cleanly() {
    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let stdio_up = build_stdio_upstream(&script_path, tmp.path(), 4);
    let bridge = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge);
        async move { up.handle_mcp(req, &make_token("grant-crash", 0)).await }
    })
    .await;

    let client = make_client();
    let init_payload = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"crash-test","version":"0.1"}}}"#;

    let init1 = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(init_payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(init1.status(), StatusCode::OK);
    let sid1 = init1
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let init1_val: Value =
        serde_json::from_slice(&init1.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let grand1 = init1_val["result"]["_meta"]["grandchild_pid"]
        .as_u64()
        .unwrap() as u32;

    let crash_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &sid1)
                .header(header::ACCEPT, "text/event-stream")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":"req-crash","method":"tools/call","params":{"name":"crash_after_progress","_meta":{"progressToken":"pt-crash"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(crash_resp.status(), StatusCode::OK);
    let mut crash_body = crash_resp.into_body();
    let mut crash_bytes = Vec::new();
    while let Some(frame_res) = crash_body.frame().await {
        if let Ok(frame) = frame_res
            && let Ok(data) = frame.into_data()
        {
            crash_bytes.extend_from_slice(&data);
        }
    }
    let crash_text = String::from_utf8(crash_bytes).unwrap();
    assert!(crash_text.contains("\"progress\":33"));
    assert!(!crash_text.contains("\"id\":\"req-crash\""));

    assert!(wait_process_gone(grand1).await);

    for round in 0..8 {
        let init_r = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(init_payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(init_r.status(), StatusCode::OK);
        let sid_r = init_r
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let _ = init_r.into_body().collect().await.unwrap();

        let sse_client = client.clone();
        let sid_sse = sid_r.clone();
        let sse_task = tokio::spawn(async move {
            let resp = sse_client
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("mcp-session-id", &sid_sse)
                        .header(header::ACCEPT, "text/event-stream")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            r#"{"jsonrpc":"2.0","id":"req-race","method":"tools/call","params":{"name":"hang_until_cancel","_meta":{"progressToken":"pt-race"}}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let mut body = resp.into_body();
            while let Some(frame_res) = body.frame().await {
                if frame_res.is_err() {
                    break;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis((round % 4) * 5)).await;

        let del_resp = client
            .request(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &sid_r)
                    .body(empty_body())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_resp.status(), StatusCode::OK);

        tokio::time::timeout(Duration::from_secs(3), sse_task)
            .await
            .expect("SSE stream must terminate when session is deleted")
            .expect("SSE task must not panic");
    }

    let verify_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("MCP-Protocol-Version", "2026-07-28")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":888,"method":"tools/call","params":{"name":"bump"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), StatusCode::OK);

    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_concurrent_duplicate_jsonrpc_id_preserves_session_and_routes_both_responses() {
    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let stdio_up = build_stdio_upstream(&script_path, tmp.path(), 2);
    let bridge = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge);
        async move { up.handle_mcp(req, &make_token("grant-dup-id", 0)).await }
    })
    .await;

    let client = make_client();
    let init_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"dup-id","version":"0.1"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let sid = init_resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let init_val: Value =
        serde_json::from_slice(&init_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let child_pid = init_val["result"]["_meta"]["pid"].as_u64().unwrap() as u32;

    let c1 = client.clone();
    let s1 = sid.clone();
    let slow_task = tokio::spawn(async move {
        let resp = c1
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &s1)
                    .header(header::ACCEPT, "application/json")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"delayed_echo","arguments":{"delay_ms":150,"tag":"slow"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        serde_json::from_slice::<Value>(&resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let c2 = client.clone();
    let s2 = sid.clone();
    let fast_task = tokio::spawn(async move {
        let resp = c2
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &s2)
                    .header(header::ACCEPT, "application/json")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"delayed_echo","arguments":{"delay_ms":20,"tag":"fast"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        serde_json::from_slice::<Value>(&resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap()
    });

    let (slow_val, fast_val) = tokio::join!(slow_task, fast_task);
    let slow_val = slow_val.unwrap();
    let fast_val = fast_val.unwrap();
    assert_eq!(slow_val["id"], 42);
    assert_eq!(slow_val["result"]["tag"], "slow");
    assert_eq!(fast_val["id"], 42);
    assert_eq!(fast_val["result"]["tag"], "fast");
    assert!(process_exists(child_pid), "child must remain alive");

    let follow_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &sid)
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"bump"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(follow_resp.status(), StatusCode::OK);
    let follow_val: Value =
        serde_json::from_slice(&follow_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(follow_val["result"]["structuredContent"]["pid"], child_pid);

    stdio_up.shutdown().await;
    assert!(wait_process_gone(child_pid).await);
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_old_protocol_version_without_session_id_returns_400() {
    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let stdio_up = build_stdio_upstream(&script_path, tmp.path(), 2);
    let bridge = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge);
        async move { up.handle_mcp(req, &make_token("grant-old-ver", 0)).await }
    })
    .await;

    let client = make_client();
    let resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("MCP-Protocol-Version", "2025-06-18")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"bump"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"]["message"], "missing Mcp-Session-Id header");

    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn http_strips_cookie_set_cookie_and_forwarded_headers() {
    let seen_headers: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_ref = Arc::clone(&seen_headers);

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let seen = Arc::clone(&seen_ref);
        async move {
            let mut recorded = Vec::new();
            for (k, v) in req.headers() {
                recorded.push((k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()));
            }
            *seen.lock().unwrap() = recorded;
            let _ = req.into_body().collect().await;
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::SET_COOKIE, "upstream_sid=secret; HttpOnly")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                ))
                .unwrap()
        }
    })
    .await;

    let settings = HttpUpstreamSettings {
        url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
        origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
        public_is_https: true,
        bearer_tokens: vec!["tok".to_owned()],
        passthrough_prefixes: Vec::new(),
        request_timeout_secs: 30,
    };
    let http_up = Arc::new(HttpUpstream::new(settings).unwrap());
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&http_up);
        async move { up.handle_mcp(req, &make_token("grant-cookie", 0)).await }
    })
    .await;

    let client = make_client();
    let resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::COOKIE, "session=client-secret")
                .header("x-forwarded-for", "1.2.3.4")
                .header("x-forwarded-host", "evil.example")
                .header("x-real-ip", "5.6.7.8")
                .header("forwarded", "for=1.2.3.4;proto=http")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "Set-Cookie from upstream must be stripped"
    );

    let recorded = seen_headers.lock().unwrap();
    for forbidden in [
        "cookie",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-real-ip",
        "forwarded",
    ] {
        assert!(
            !recorded.iter().any(|(k, _)| k == forbidden),
            "request header {forbidden} must not be forwarded upstream"
        );
    }

    gw_cancel.cancel();
    up_cancel.cancel();
}

#[tokio::test]
async fn server_origin_validation_blocks_cross_site_requests() {
    let tmp = TempDir::new().unwrap();
    let hash = PasswordVerifier::from_plaintext_with_iterations("secret123", 10_000)
        .unwrap()
        .encode();
    let py = python_executable();
    let cfg_json = format!(
        r#"{{
          "listen": "127.0.0.1:0",
          "public_url": "https://mcp.example.com",
          "state_path": "state.json",
          "oauth": {{ "owner_password_hash": "{hash}" }},
          "upstream": {{
            "transport": "stdio",
            "command": "{py}",
            "args": ["-c", "import sys; sys.exit(0)"]
          }}
        }}"#
    );
    let cfg = Arc::new(GatewayConfig::from_json_str(&cfg_json, tmp.path()).unwrap());
    let (addr, shutdown, server_task) = spawn_gateway(cfg).await;

    let client = make_client();

    for path in ["/mcp", "/oauth/register", "/oauth/token"] {
        for bad_origin in ["https://evil.example", "null"] {
            let evil_resp = client
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{addr}{path}"))
                        .header(header::ORIGIN, bad_origin)
                        .body(empty_body())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                evil_resp.status(),
                StatusCode::FORBIDDEN,
                "Origin {bad_origin:?} on {path} must return 403"
            );
        }
    }

    for valid_origin in ["https://mcp.example.com", "HTTPS://MCP.EXAMPLE.COM:443"] {
        let same_origin_mcp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{addr}/mcp"))
                    .header(header::ORIGIN, valid_origin)
                    .body(empty_body())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(same_origin_mcp.status(), StatusCode::UNAUTHORIZED);
    }

    let no_origin_mcp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{addr}/mcp"))
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_origin_mcp.status(), StatusCode::UNAUTHORIZED);

    shutdown.cancel();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn stdio_terminate_grant_kills_only_matching_grant_sessions() {
    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let stdio_up = build_stdio_upstream(&script_path, tmp.path(), 4);
    let bridge = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge);
        async move {
            let grant = req
                .headers()
                .get("x-test-grant")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("grant-a")
                .to_owned();
            up.handle_mcp(req, &make_token(&grant, 0)).await
        }
    })
    .await;

    let client = make_client();
    let init_payload = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"term-grant","version":"0.1"}}}"#;

    let spawn_for = |grant: &'static str| {
        let client = client.clone();
        async move {
            let resp = client
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("x-test-grant", grant)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(init_payload))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let sid = resp
                .headers()
                .get("mcp-session-id")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let val: Value =
                serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            let pid = val["result"]["_meta"]["pid"].as_u64().unwrap() as u32;
            let grand = val["result"]["_meta"]["grandchild_pid"].as_u64().unwrap() as u32;
            (sid, pid, grand)
        }
    };

    let (sid_a, pid_a, grand_a) = spawn_for("grant-a").await;
    let (_sid_b, pid_b, grand_b) = spawn_for("grant-b").await;

    assert!(process_exists(pid_a));
    assert!(process_exists(grand_a));
    assert!(process_exists(pid_b));
    assert!(process_exists(grand_b));

    stdio_up.terminate_grant("grant-a").await;

    assert!(wait_process_gone(pid_a).await);
    assert!(wait_process_gone(grand_a).await);
    assert!(
        process_exists(pid_b),
        "other grant session must remain alive"
    );
    assert!(process_exists(grand_b));

    let stale_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-a")
                .header("mcp-session-id", &sid_a)
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bump"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_resp.status(), StatusCode::NOT_FOUND);

    stdio_up.shutdown().await;
    assert!(wait_process_gone(pid_b).await);
    assert!(wait_process_gone(grand_b).await);
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_env_sanitization_blocks_host_secrets_and_applies_overrides() {
    if std::env::var("GW_ENV_SANITIZE_SUBTEST").as_deref() != Ok("1") {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "stdio_env_sanitization_blocks_host_secrets_and_applies_overrides",
                "--nocapture",
            ])
            .env("GW_ENV_SANITIZE_SUBTEST", "1")
            .env("SECRET_HOST_ENV", "host-secret-must-not-leak")
            .env("OWNER_PASSWORD", "owner-password-must-not-leak")
            .env("UPSTREAM_BEARER_TOKEN_1", "bearer-must-not-leak")
            .output()
            .expect("run env sanitization subprocess");
        assert!(
            out.status.success(),
            "env sanitization subprocess failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let mut env = BTreeMap::new();
    env.insert(
        "MOCK_STATE_DIR".to_owned(),
        tmp.path().to_str().unwrap().to_owned(),
    );
    env.insert(
        "CONFIGURED_API_KEY".to_owned(),
        "allowed-explicit-val".to_owned(),
    );
    let settings = StdioUpstreamSettings {
        command: python_executable().to_owned(),
        args: vec!["-u".to_owned(), script_path.to_str().unwrap().to_owned()],
        env,
        cwd: Some(tmp.path().to_path_buf()),
        max_sessions: 2,
        session_idle_secs: 60,
    };
    let stdio_up = Arc::new(StdioUpstream::new(settings).unwrap());
    let bridge = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge);
        async move { up.handle_mcp(req, &make_token("grant-env", 0)).await }
    })
    .await;

    let client = make_client();
    let resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("MCP-Protocol-Version", "2026-07-28")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dump_env"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let val: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let child_env = val["result"]["env"].as_object().unwrap();

    let has_ci_key = |needle: &str| child_env.keys().any(|k| k.eq_ignore_ascii_case(needle));
    assert!(!has_ci_key("SECRET_HOST_ENV"));
    assert!(!has_ci_key("OWNER_PASSWORD"));
    assert!(!has_ci_key("UPSTREAM_BEARER_TOKEN_1"));
    assert!(!has_ci_key("GW_ENV_SANITIZE_SUBTEST"));
    assert_eq!(
        child_env.get("CONFIGURED_API_KEY").and_then(Value::as_str),
        Some("allowed-explicit-val")
    );
    assert!(has_ci_key("PATH"));

    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_revoke_grant_mid_sessionless_sse_kills_ephemeral_process_tree() {
    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let stdio_up = build_stdio_upstream(&script_path, tmp.path(), 1);
    let bridge = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge);
        async move { up.handle_mcp(req, &make_token("grant-sl-revoke", 0)).await }
    })
    .await;

    let client = make_client();
    let sse_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("MCP-Protocol-Version", "2026-07-28")
                .header(header::ACCEPT, "text/event-stream")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"hang_until_cancel","_meta":{"progressToken":"pt-sl"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut body = sse_resp.into_body();

    let mut first_chunk = Vec::new();
    while !first_chunk.windows(2).any(|w| w == b"\n\n") {
        let frame = tokio::time::timeout(Duration::from_secs(3), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Ok(data) = frame.into_data() {
            first_chunk.extend_from_slice(&data);
        }
    }
    let first_text = String::from_utf8(first_chunk).unwrap();
    let ev: Value =
        serde_json::from_str(first_text.trim().strip_prefix("data: ").unwrap()).unwrap();
    let pid = ev["params"]["_meta"]["pid"].as_u64().unwrap() as u32;
    let grandchild = ev["params"]["_meta"]["grandchild_pid"].as_u64().unwrap() as u32;
    assert!(process_exists(pid));
    assert!(process_exists(grandchild));

    let drain_task = tokio::spawn(async move {
        while let Some(res) = body.frame().await {
            if res.is_err() {
                break;
            }
        }
    });

    stdio_up.terminate_grant("grant-sl-revoke").await;

    assert!(
        !process_exists(pid),
        "ephemeral leader must be dead on revoke return"
    );
    assert!(wait_process_gone(grandchild).await);
    tokio::time::timeout(Duration::from_secs(2), drain_task)
        .await
        .expect("sessionless SSE stream must close on grant revocation")
        .unwrap();

    let next_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("MCP-Protocol-Version", "2026-07-28")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":78,"method":"tools/call","params":{"name":"bump"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(next_resp.status(), StatusCode::OK);

    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_jsonrpc_hardening_failed_init_null_id_server_requests_progress_rewrite_and_cr_framing()
 {
    let tmp = TempDir::new().unwrap();
    let script_path = write_mock_mcp_python_script(tmp.path());
    let stdio_up = build_stdio_upstream(&script_path, tmp.path(), 1);
    let bridge = Arc::clone(&stdio_up);

    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&bridge);
        async move { up.handle_mcp(req, &make_token("grant-rpc", 0)).await }
    })
    .await;

    let client = make_client();

    let fail_init_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fail-init-error","version":"0.1"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(fail_init_resp.headers().get("mcp-session-id").is_none());
    let fail_init_val: Value = serde_json::from_slice(
        &fail_init_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let fail_pid = fail_init_val["error"]["data"]["pid"].as_u64().unwrap() as u32;
    let fail_grand = fail_init_val["error"]["data"]["grandchild_pid"]
        .as_u64()
        .unwrap() as u32;
    assert!(wait_process_gone(fail_pid).await);
    assert!(wait_process_gone(fail_grand).await);

    let malformed_init_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fail-init-malformed","version":"0.1"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed_init_resp.status(), StatusCode::BAD_GATEWAY);
    assert!(
        malformed_init_resp
            .headers()
            .get("mcp-session-id")
            .is_none()
    );

    let ok_init_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ok","version":"0.1"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_init_resp.status(), StatusCode::OK);
    let sid = ok_init_resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let _ = ok_init_resp.into_body().collect().await.unwrap();

    let second_init = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &sid)
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_init.status(), StatusCode::BAD_REQUEST);
    let second_init_val: Value =
        serde_json::from_slice(&second_init.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(second_init_val["error"]["code"], -32600);

    for bad_rpc in [
        r#"{"jsonrpc":"2.0","id":null,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":[1],"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":true,"method":"tools/list"}"#,
        r#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#,
    ] {
        let bad_resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(bad_rpc))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
        let bad_val: Value =
            serde_json::from_slice(&bad_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(bad_val["error"]["code"], -32600);
    }

    let srv_req_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &sid)
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"ask_client_requests"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(srv_req_resp.status(), StatusCode::OK);
    let srv_req_val: Value =
        serde_json::from_slice(&srv_req_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(srv_req_val["result"]["ping_reply"]["result"], json!({}));
    assert_eq!(
        srv_req_val["result"]["roots_reply"]["error"]["code"],
        -32601
    );

    let run_shared_pt = |tag: &'static str, req_id: i64| {
        let c = client.clone();
        let s = sid.clone();
        async move {
            let resp = c
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("mcp-session-id", &s)
                        .header(header::ACCEPT, "text/event-stream")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            json!({
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "method": "tools/call",
                                "params": {
                                    "name": "concurrent_clean",
                                    "arguments": {"tag": tag},
                                    "_meta": {"progressToken": "shared-pt"}
                                }
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let raw = resp.into_body().collect().await.unwrap().to_bytes();
            let text = String::from_utf8(raw.to_vec()).unwrap();
            let events: Vec<Value> = text
                .split("\n\n")
                .filter(|b| !b.is_empty())
                .map(|b| serde_json::from_str(b.strip_prefix("data: ").unwrap()).unwrap())
                .collect();
            events
        }
    };

    let (evs_a, evs_b) = tokio::join!(run_shared_pt("alpha", 21), run_shared_pt("beta", 22));
    assert_eq!(evs_a.len(), 3);
    assert_eq!(evs_b.len(), 3);
    for ev in &evs_a[..2] {
        assert_eq!(ev["params"]["progressToken"], "shared-pt");
        assert_eq!(ev["params"]["message"], "alpha");
    }
    assert_eq!(evs_a[2]["result"]["tag"], "alpha");
    for ev in &evs_b[..2] {
        assert_eq!(ev["params"]["progressToken"], "shared-pt");
        assert_eq!(ev["params"]["message"], "beta");
    }
    assert_eq!(evs_b[2]["result"]["tag"], "beta");

    let cr_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &sid)
                .header(header::ACCEPT, "text/event-stream")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"emit_cr_json"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cr_resp.status(), StatusCode::OK);
    let cr_bytes = cr_resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        !cr_bytes.contains(&b'\r'),
        "SSE output must not contain bare CR bytes"
    );
    let cr_text = String::from_utf8(cr_bytes.to_vec()).unwrap();
    let cr_events: Vec<Value> = cr_text
        .split("\n\n")
        .filter(|b| !b.is_empty())
        .map(|b| serde_json::from_str(b.strip_prefix("data: ").unwrap()).unwrap())
        .collect();
    assert_eq!(cr_events.len(), 2);
    assert_eq!(cr_events[0]["params"]["note"], "has-cr");
    assert_eq!(cr_events[1]["id"], 30);
    assert_eq!(cr_events[1]["result"]["cr_clean"], true);

    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn http_per_grant_session_cap_evicts_lru_sends_delete_and_returns_404_on_reuse() {
    let deleted = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
    let del_log = Arc::clone(&deleted);
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_log = Arc::clone(&hit_count);
    let next_sid = Arc::new(AtomicUsize::new(1));
    let sid_gen = Arc::clone(&next_sid);

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let del_log = Arc::clone(&del_log);
        let hit_log = Arc::clone(&hit_log);
        let sid_gen = Arc::clone(&sid_gen);
        async move {
            let method = req.method().clone();
            let auth = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let req_sid = req
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let _ = req.into_body().collect().await;

            if method == Method::DELETE {
                if let Some(sid) = req_sid {
                    del_log.lock().unwrap().push((sid, auth));
                }
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(empty_body())
                    .unwrap();
            }

            hit_log.fetch_add(1, Ordering::SeqCst);
            let sid = req_sid.unwrap_or_else(|| {
                let n = sid_gen.fetch_add(1, Ordering::SeqCst);
                format!("sess-{n}")
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header("mcp-session-id", sid)
                .body(bytes_body(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#))
                .unwrap()
        }
    })
    .await;

    let up = Arc::new(
        HttpUpstream::new(HttpUpstreamSettings {
            url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
            origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
            public_is_https: false,
            bearer_tokens: vec!["pool-tok-0".to_owned()],
            passthrough_prefixes: vec![],
            request_timeout_secs: 10,
        })
        .unwrap(),
    );
    let up_srv = Arc::clone(&up);
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up_srv = Arc::clone(&up_srv);
        async move {
            let tok = VerifiedToken {
                grant_id: "grant-lru".to_owned(),
                client_id: "client-lru".to_owned(),
                pool_slot: 0,
                scopes: vec!["mcp".to_owned()],
                resource: "http://127.0.0.1/mcp".to_owned(),
            };
            up_srv.handle_mcp(req, &tok).await
        }
    })
    .await;

    let client = make_client();
    let mut sids = Vec::new();
    for i in 0..33 {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(format!(
                        r#"{{"jsonrpc":"2.0","id":{i},"method":"initialize","params":{{}}}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let sid = resp
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let _ = resp.into_body().collect().await.unwrap();
        sids.push(sid);
    }

    let mut got_delete = false;
    for _ in 0..40 {
        if deleted
            .lock()
            .unwrap()
            .iter()
            .any(|(s, auth)| s == &sids[0] && auth.as_deref() == Some("Bearer pool-tok-0"))
        {
            got_delete = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        got_delete,
        "evicted oldest session {} must receive upstream DELETE with pool bearer token",
        sids[0]
    );

    let hits_before = hit_count.load(Ordering::SeqCst);
    let stale_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("mcp-session-id", &sids[0])
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":99,"method":"tools/list","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(hit_count.load(Ordering::SeqCst), hits_before);

    let live_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("mcp-session-id", sids.last().unwrap())
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":100,"method":"tools/list","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(live_resp.status(), StatusCode::OK);

    up.shutdown().await;
    gw_cancel.cancel();
    up_cancel.cancel();
}

#[tokio::test]
async fn http_large_json_and_sse_priming_passthrough_and_slow_receiver_budget_backpressure() {
    let payload_len = 18 * 1024 * 1024usize; // > 16 MiB inbound cap
    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| async move {
        let mode = req
            .headers()
            .get("x-test-mode")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("json")
            .to_owned();
        let _ = req.into_body().collect().await;

        if mode == "json_18m" {
            let (tx, body) = channel_body(8);
            tokio::spawn(async move {
                let _ = tx
                    .send(Ok(Frame::data(Bytes::from_static(
                        br#"{"jsonrpc":"2.0","id":1,"result":{"blob":""#,
                    ))))
                    .await;
                let chunk = Bytes::from(vec![b'J'; 256 * 1024]);
                let mut rem = payload_len;
                while rem > 0 {
                    let n = rem.min(chunk.len());
                    if tx.send(Ok(Frame::data(chunk.slice(..n)))).await.is_err() {
                        return;
                    }
                    rem -= n;
                }
                let _ = tx
                    .send(Ok(Frame::data(Bytes::from_static(br#""}}"#))))
                    .await;
            });
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap();
        }

        if mode == "sse_big_priming_and_18m" {
            let (tx, body) = channel_body(8);
            tokio::spawn(async move {
                // Single 1.5 MiB priming chunk (> 1 MiB cap) followed by 18 MiB SSE data event.
                let mut prime = vec![b':'];
                prime.extend(std::iter::repeat_n(b'P', 1536 * 1024));
                prime.extend_from_slice(
                    b"\nid: big-ev\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"blob\":\"",
                );
                if tx.send(Ok(Frame::data(Bytes::from(prime)))).await.is_err() {
                    return;
                }
                let chunk = Bytes::from(vec![b'S'; 256 * 1024]);
                let mut rem = payload_len;
                while rem > 0 {
                    let n = rem.min(chunk.len());
                    if tx.send(Ok(Frame::data(chunk.slice(..n)))).await.is_err() {
                        return;
                    }
                    rem -= n;
                }
                let _ = tx
                    .send(Ok(Frame::data(Bytes::from_static(br#""}}"#))))
                    .await;
                let _ = tx.send(Ok(Frame::data(Bytes::from_static(b"\n\n")))).await;
            });
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(body)
                .unwrap();
        }

        if mode == "sse_hold_priming" {
            let (tx, body) = channel_body(4);
            tokio::spawn(async move {
                let mut prime = vec![b':'];
                prime.extend(std::iter::repeat_n(b'H', 3499));
                let _ = tx.send(Ok(Frame::data(Bytes::from(prime)))).await;
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(tx);
            });
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(body)
                .unwrap();
        }

        if mode == "sse_over_budget" {
            let (tx, body) = channel_body(4);
            tokio::spawn(async move {
                let mut prime = vec![b':'];
                prime.extend(std::iter::repeat_n(b'O', 1023));
                let _ = tx.send(Ok(Frame::data(Bytes::from(prime)))).await;
                let _ = tx
                    .send(Ok(Frame::data(Bytes::from_static(
                        b"\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{}}\n\n",
                    ))))
                    .await;
            });
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(body)
                .unwrap();
        }

        if mode == "sse_direct_data" {
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(bytes_body(
                    "data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"fast\":true}}\n\n",
                ))
                .unwrap();
        }

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(bytes_body(
                r#"{"jsonrpc":"2.0","id":6,"result":{"ctrl":true}}"#,
            ))
            .unwrap()
    })
    .await;

    let budget = ByteBudget::new(4096);
    let up = Arc::new(
        HttpUpstream::with_limits(
            HttpUpstreamSettings {
                url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
                origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
                public_is_https: false,
                bearer_tokens: Vec::new(),
                passthrough_prefixes: Vec::new(),
                request_timeout_secs: 30,
            },
            Arc::clone(&budget),
            HttpLimits {
                max_priming_buffer_bytes: 8192,
                ..HttpLimits::default()
            },
        )
        .unwrap(),
    );
    let up_srv = Arc::clone(&up);
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up_srv = Arc::clone(&up_srv);
        async move {
            up_srv
                .handle_mcp(req, &make_token("grant-http-big", 0))
                .await
        }
    })
    .await;

    let client = make_client();

    // 1. Stream 18 MiB application/json response through HttpUpstream.
    let resp_json = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-mode", "json_18m")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_json.status(), StatusCode::OK);
    let mut json_total = 0usize;
    let mut j_body = resp_json.into_body();
    while let Some(frame) = j_body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            json_total += data.len();
        }
    }
    assert_eq!(
        json_total,
        payload_len + br#"{"jsonrpc":"2.0","id":1,"result":{"blob":""#.len() + br#""}}"#.len()
    );
    assert_eq!(budget.used(), 0);

    // 2. Stream 18 MiB text/event-stream with 1.5 MiB single-chunk priming preamble (even with 4 KiB budget, stops at 8 KiB cap? Wait: cap=8192 > budget=4096 would hit budget if >4096; test default cap with default budget too!).
    let default_up = Arc::new(
        HttpUpstream::new(HttpUpstreamSettings {
            url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
            origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
            public_is_https: false,
            bearer_tokens: Vec::new(),
            passthrough_prefixes: Vec::new(),
            request_timeout_secs: 30,
        })
        .unwrap(),
    );
    let def_srv = Arc::clone(&default_up);
    let (gw_def_addr, gw_def_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let def_srv = Arc::clone(&def_srv);
        async move {
            def_srv
                .handle_mcp(req, &make_token("grant-http-def", 0))
                .await
        }
    })
    .await;

    let resp_sse = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_def_addr}/mcp"))
                .header("x-test-mode", "sse_big_priming_and_18m")
                .header(header::ACCEPT, "text/event-stream")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_sse.status(), StatusCode::OK);
    let mut sse_total = 0usize;
    let mut s_body = resp_sse.into_body();
    while let Some(frame) = s_body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            sse_total += data.len();
        }
    }
    assert!(sse_total > payload_len + 1536 * 1024);

    // 3. Slow/stalled priming stream holds 3500 bytes in `budget` (limit 4096); second 1024-byte priming stream fails non-blockingly while control paths succeed.
    let gw_hold_uri = format!("http://{gw_addr}/mcp");
    let hold_client = client.clone();
    let hold_task = tokio::spawn(async move {
        let resp = hold_client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(gw_hold_uri)
                    .header("x-test-mode", "sse_hold_priming")
                    .header(header::ACCEPT, "text/event-stream")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut body = resp.into_body();
        let _ = body.frame().await;
    });

    wait_until(|| budget.used() == 3500).await;

    // Over-budget priming stream fails fast without blocking.
    let over_outcome = tokio::time::timeout(Duration::from_secs(2), async {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("x-test-mode", "sse_over_budget")
                    .header(header::ACCEPT, "text/event-stream")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .map_err(|e| e.to_string())?;
        resp.into_body().collect().await.map_err(|e| e.to_string())
    })
    .await
    .expect("over-budget priming stream must not block");
    assert!(
        over_outcome.is_err(),
        "over-budget SSE priming stream must abort with error"
    );
    assert_eq!(budget.used(), 3500);

    // Control paths (JSON response & direct `data:` SSE without priming buffer) still succeed!
    let ctrl_json = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-mode", "ctrl_json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(r#"{"jsonrpc":"2.0","id":6,"method":"ping"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ctrl_json.status(), StatusCode::OK);
    let ctrl_val: Value =
        serde_json::from_slice(&ctrl_json.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(ctrl_val["result"]["ctrl"], true);

    let direct_sse = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-mode", "sse_direct_data")
                .header(header::ACCEPT, "text/event-stream")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":5,"method":"tools/call"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(direct_sse.status(), StatusCode::OK);
    let direct_bytes = direct_sse.into_body().collect().await.unwrap().to_bytes();
    assert!(
        std::str::from_utf8(&direct_bytes)
            .unwrap()
            .contains("\"fast\":true")
    );

    // Cancelling the stalled receiver releases the priming lease.
    hold_task.abort();
    let _ = hold_task.await;
    up.terminate_grant("grant-http-big").await;
    wait_until(|| budget.used() == 0).await;

    default_up.shutdown().await;
    up.shutdown().await;
    gw_def_cancel.cancel();
    gw_cancel.cancel();
    up_cancel.cancel();
}

fn write_multimodal_stdio_mock_script(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("multimodal_stdio_mock.py");
    let script = r##"import json, os, sys, threading, time

pid = os.getpid()
out_lock = threading.Lock()
gate_events = {}
burst_flushed_events = {}
waiter_cond = threading.Condition()
gate_waiter_counts = {}
spew_after_init = int(os.environ.get("MOCK_SPEW_AFTER_INIT_BYTES", "0"))

def write_raw(data: bytes):
    with out_lock:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

def build_tail_id_line(req_id, target_bytes: int) -> bytes:
    prefix = b'{"jsonrpc":"2.0","result":{"content":[{"type":"image","mimeType":"image/png","data":"'
    suffix = (
        b'"}],"_meta":{"explicit_null":null,"nested":{"method":"GET","arr":[{"method":1}]}}},"id":'
        + json.dumps(req_id, separators=(",", ":")).encode("utf-8")
        + b"}\n"
    )
    pad_len = target_bytes - len(prefix) - len(suffix)
    assert pad_len >= 0, f"target_bytes {target_bytes} too small"
    return prefix + (b"A" * pad_len) + suffix

for raw_line in sys.stdin.buffer:
    line = raw_line.decode("utf-8").strip()
    if not line:
        continue
    msg = json.loads(line)
    method = msg.get("method")
    req_id = msg.get("id")

    if method == "initialize":
        resp = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": {"name": "mm-mock", "version": "0.1"},
                "_meta": {"pid": pid},
            },
        }
        out = (json.dumps(resp, separators=(",", ":")) + "\n").encode("utf-8")
        if spew_after_init > 0:
            out += b'{"jsonrpc":"2.0","unsolicited":"' + (b"U" * spew_after_init) + b'"}\n'
        write_raw(out)
        continue

    if method == "notifications/cancelled":
        flag_dir = os.environ.get("MOCK_CANCEL_DIR")
        if flag_dir:
            cid = msg.get("params", {}).get("requestId")
            with open(os.path.join(flag_dir, f"cancelled_{cid}.flag"), "w", encoding="utf-8") as cf:
                cf.write("1")
        continue

    if method == "notifications/spew_unsolicited_large":
        nbytes = int(msg.get("params", {}).get("bytes", 600))
        write_raw(b'{"jsonrpc":"2.0","unsolicited":"' + (b"U" * nbytes) + b'"}\n')
        continue

    if method == "notifications/gate_open":
        p = msg.get("params", {})
        gate = p.get("gate", "default")
        wait_b = p.get("wait_burst", False)
        def do_open(g, wb):
            if wb:
                bev = burst_flushed_events.setdefault(g, threading.Event())
                bev.wait(timeout=10.0)
            ev = gate_events.setdefault(g, threading.Event())
            ev.set()
        threading.Thread(target=do_open, args=(gate, wait_b), daemon=True).start()
        continue

    if method != "tools/call":
        continue

    params = msg.get("params", {})
    name = params.get("name")
    args = params.get("arguments", {})
    ptok = params.get("_meta", {}).get("progressToken")

    if name == "small_echo":
        resp = {"jsonrpc": "2.0", "id": req_id, "result": {"ok": True, "pid": pid, "tag": args.get("tag", "")}}
        write_raw((json.dumps(resp, separators=(",", ":")) + "\n").encode("utf-8"))
    elif name == "exact_tail_id":
        target = int(args["target_bytes"])
        write_raw(build_tail_id_line(req_id, target))
    elif name == "wait_gate":
        gate = args.get("gate", "default")
        ev = gate_events.setdefault(gate, threading.Event())
        with waiter_cond:
            gate_waiter_counts[gate] = gate_waiter_counts.get(gate, 0) + 1
            waiter_cond.notify_all()
        def wait_and_reply(rid, g_ev):
            g_ev.wait(timeout=10.0)
            r = {"jsonrpc": "2.0", "id": rid, "result": {"should_never_arrive": True}}
            write_raw((json.dumps(r, separators=(",", ":")) + "\n").encode("utf-8"))
        threading.Thread(target=wait_and_reply, args=(req_id, ev), daemon=True).start()
    elif name == "trigger_midline_method_then_valid":
        def run_trig_method(rid, a):
            w_gate = a.get("wait_for_gate")
            w_cnt = int(a.get("expected_waiters", 0))
            if w_gate and w_cnt > 0:
                with waiter_cond:
                    waiter_cond.wait_for(lambda: gate_waiter_counts.get(w_gate, 0) >= w_cnt, timeout=10.0)
            other_ids = a.get("other_wire_ids", [])
            bad_notif = (
                b'{"jsonrpc":"2.0","method":"notifications/message","params":{"pad":"'
                + (b"M" * int(a["pad_len"]))
                + b'"}}\n'
            )
            follow = b"".join(
                (json.dumps({"jsonrpc": "2.0", "id": oid, "result": {"should_never_arrive": True}}, separators=(",", ":")) + "\n").encode("utf-8")
                for oid in ([rid] + other_ids)
            )
            write_raw(bad_notif + follow)
        threading.Thread(target=run_trig_method, args=(req_id, dict(args)), daemon=True).start()
    elif name == "trigger_oversized_line_then_valid":
        def run_trig_line(rid, a):
            w_gate = a.get("wait_for_gate")
            w_cnt = int(a.get("expected_waiters", 0))
            if w_gate and w_cnt > 0:
                with waiter_cond:
                    waiter_cond.wait_for(lambda: gate_waiter_counts.get(w_gate, 0) >= w_cnt, timeout=10.0)
            ready_file = a.get("ready_file")
            release_file = a.get("release_file")
            if ready_file:
                with open(ready_file, "w", encoding="utf-8") as ready:
                    ready.write("ready")
            if release_file:
                deadline = time.monotonic() + 10.0
                while not os.path.exists(release_file) and time.monotonic() < deadline:
                    time.sleep(0.01)
            target = int(a["target_bytes"])
            bad_line = build_tail_id_line(rid, target)
            follow = (json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"should_never_arrive": True}}, separators=(",", ":")) + "\n").encode("utf-8")
            write_raw(bad_line + follow)
        threading.Thread(target=run_trig_line, args=(req_id, dict(args)), daemon=True).start()
    elif name == "complete_line_discards_then_valid":
        for nlen in args.get("pass_notif_lens", []):
            pre = b'{"jsonrpc":"2.0","method":"notifications/message","params":{"p":"'
            suf = b'"}}\n'
            write_raw(pre + (b"p" * (int(nlen) - len(pre) - len(suf))) + suf)
        tail_m_total = int(args["tail_method_bytes"])
        pre_m = b'{"jsonrpc":"2.0","params":{"pad":"'
        suf_m = b'"},"method":"notifications/message"}\n'
        pad_m = tail_m_total - len(pre_m) - len(suf_m)
        write_raw(pre_m + (b"T" * pad_m) + suf_m)
        write_raw(build_tail_id_line(999999, int(args["unmatched_bytes"])))
        write_raw(build_tail_id_line(req_id, int(args["valid_bytes"])))
    elif name == "gated_two_half_line":
        half1 = int(args["half1_bytes"])
        gate = args.get("gate", "half_gate")
        ev = gate_events.setdefault(gate, threading.Event())
        def run_halves(rid, h1, g_ev):
            prefix = b'{"jsonrpc":"2.0","result":{"blob":"'
            write_raw(prefix + (b"H" * (h1 - len(prefix))))
            g_ev.wait(timeout=10.0)
            suffix = b'"},"id":' + json.dumps(rid, separators=(",", ":")).encode("utf-8") + b"}\n"
            write_raw((b"H" * 1024) + suffix)
        threading.Thread(target=run_halves, args=(req_id, half1, ev), daemon=True).start()
    elif name == "notif_budget_burst":
        notif_len = int(args["notif_bytes"])
        count = int(args["count"])
        gate = args.get("gate", "burst")
        ev = gate_events.setdefault(gate, threading.Event())
        bev = burst_flushed_events.setdefault(gate, threading.Event())
        def run_burst(rid, tok, nlen, cnt, g_ev, b_ev):
            for idx in range(cnt):
                if tok is not None:
                    pre = ('{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":' + json.dumps(tok, separators=(",", ":")) + ',"i":' + str(idx) + ',"p":"').encode("utf-8")
                    suf = b'"}}'
                else:
                    pre = ('{"jsonrpc":"2.0","method":"notifications/message","params":{"i":' + str(idx) + ',"p":"').encode("utf-8")
                    suf = b'"}}'
                body = pre + (b"N" * (nlen - len(pre) - len(suf))) + suf + b"\n"
                write_raw(body)
            b_ev.set()
            g_ev.wait(timeout=10.0)
            if args.get("post_gate_notif", False):
                pre = ('{"jsonrpc":"2.0","method":"notifications/message","params":{"after":true,"p":"').encode("utf-8")
                suf = b'"}}'
                body = pre + (b"A" * (nlen - len(pre) - len(suf))) + suf + b"\n"
                write_raw(body)
            r = {"jsonrpc": "2.0", "id": rid, "result": {"burst_done": True}}
            write_raw((json.dumps(r, separators=(",", ":")) + "\n").encode("utf-8"))
        threading.Thread(target=run_burst, args=(req_id, ptok, notif_len, count, ev, bev), daemon=True).start()
"##;
    std::fs::write(&path, script).unwrap();
    path
}

async fn wait_until<F: Fn() -> bool>(cond: F) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition did not settle within 5s"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn stdio_large_tail_id_boundaries_and_multimodal_18mib_passthrough() {
    let tmp = TempDir::new().unwrap();
    let script = write_multimodal_stdio_mock_script(tmp.path());

    let n_max = 4096usize;
    let budget = ByteBudget::new(64 * 1024);
    let stdio_small = Arc::new(
        StdioUpstream::with_limits(
            StdioUpstreamSettings {
                command: python_executable().to_owned(),
                args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                env: BTreeMap::new(),
                cwd: Some(tmp.path().to_path_buf()),
                max_sessions: 8,
                session_idle_secs: 30,
            },
            Arc::clone(&budget),
            StdioLimits {
                max_stdout_line_bytes: n_max,
                max_control_line_bytes: 512,
                max_notif_queue_bytes: 16 * 1024,
                ..StdioLimits::default()
            },
        )
        .unwrap(),
    );
    let up_ref = Arc::clone(&stdio_small);
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&up_ref);
        async move { up.handle_mcp(req, &make_token("grant-mm", 0)).await }
    })
    .await;

    let client = make_client();
    let init_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let sid = init_resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let _ = init_resp.into_body().collect().await.unwrap();

    // Exact N - 1 (4095) and N (4096) with "id" at tail pass over both JSON and SSE, preserving result subtree.
    for (target, accept_hdr, client_id) in [
        (n_max - 1, "application/json", "tail-json-n-minus-1"),
        (n_max, "application/json", "tail-json-n"),
        (n_max, "text/event-stream", "tail-sse-n"),
    ] {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &sid)
                    .header(header::ACCEPT, accept_hdr)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        json!({
                            "jsonrpc": "2.0",
                            "id": client_id,
                            "method": "tools/call",
                            "params": {
                                "name": "exact_tail_id",
                                "arguments": {"target_bytes": target}
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = resp.into_body().collect().await.unwrap().to_bytes();
        let val: Value = if accept_hdr == "text/event-stream" {
            let s = std::str::from_utf8(&raw).unwrap();
            let line = s.trim().strip_prefix("data: ").unwrap();
            serde_json::from_str(line).unwrap()
        } else {
            serde_json::from_slice(&raw).unwrap()
        };
        assert_eq!(val["id"], client_id);
        assert_eq!(val["result"]["content"][0]["type"], "image");
        assert!(val["result"]["_meta"]["explicit_null"].is_null());
        assert_eq!(val["result"]["_meta"]["nested"]["method"], "GET");
        assert_eq!(val["result"]["_meta"]["nested"]["arr"][0]["method"], 1);
        assert_eq!(budget.used(), 0);
    }

    // Exact N + 1 (4097) is hard-rejected and terminates the session.
    let n_plus_1 = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &sid)
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": "tail-over",
                        "method": "tools/call",
                        "params": {
                            "name": "exact_tail_id",
                            "arguments": {"target_bytes": n_max + 1}
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(n_plus_1.status(), StatusCode::BAD_GATEWAY);
    let err_val: Value =
        serde_json::from_slice(&n_plus_1.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(err_val["id"], "tail-over");
    assert!(
        err_val["error"]["message"]
            .as_str()
            .unwrap()
            .contains("4096 byte limit")
    );
    assert_eq!(budget.used(), 0);

    // Part B: Real 18 MiB (> 16 MiB inbound cap) tool response passes through default StdioUpstream, while > 16 MiB inbound POST returns 413.
    let stdio_default = Arc::new(
        StdioUpstream::new(StdioUpstreamSettings {
            command: python_executable().to_owned(),
            args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
            env: BTreeMap::new(),
            cwd: Some(tmp.path().to_path_buf()),
            max_sessions: 4,
            session_idle_secs: 60,
        })
        .unwrap(),
    );
    let def_ref = Arc::clone(&stdio_default);
    let (gw2_addr, gw2_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&def_ref);
        async move { up.handle_mcp(req, &make_token("grant-18m", 0)).await }
    })
    .await;

    let inbound_too_big = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw2_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH, (16 * 1024 * 1024 + 1).to_string())
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inbound_too_big.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let big_target = 18 * 1024 * 1024usize;
    let big_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw2_addr}/mcp"))
                .header("MCP-Protocol-Version", "2026-07-28")
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": "mm-18mib",
                        "method": "tools/call",
                        "params": {
                            "name": "exact_tail_id",
                            "arguments": {"target_bytes": big_target}
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(big_resp.status(), StatusCode::OK);
    let big_bytes = big_resp.into_body().collect().await.unwrap().to_bytes();
    assert!(big_bytes.len() > 17 * 1024 * 1024);
    let big_val: Value = serde_json::from_slice(&big_bytes).unwrap();
    assert_eq!(big_val["id"], "mm-18mib");
    assert_eq!(big_val["result"]["content"][0]["mimeType"], "image/png");

    stdio_default.shutdown().await;
    stdio_small.shutdown().await;
    gw2_cancel.cancel();
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_midline_hard_reject_terminates_session_and_notifies_json_and_sse_waiters() {
    let tmp = TempDir::new().unwrap();
    let script = write_multimodal_stdio_mock_script(tmp.path());

    for scenario in ["midline_method", "oversized_line", "budget_exhausted"] {
        let budget = ByteBudget::new(16 * 1024);
        let ready_file = tmp.path().join("response_ready");
        let release_file = tmp.path().join("response_release");

        let stdio_up = Arc::new(
            StdioUpstream::with_limits(
                StdioUpstreamSettings {
                    command: python_executable().to_owned(),
                    args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                    env: BTreeMap::new(),
                    cwd: Some(tmp.path().to_path_buf()),
                    max_sessions: 4,
                    session_idle_secs: 30,
                },
                Arc::clone(&budget),
                StdioLimits {
                    max_stdout_line_bytes: 2048,
                    max_control_line_bytes: 256,
                    max_notif_queue_bytes: 8192,
                    ..StdioLimits::default()
                },
            )
            .unwrap(),
        );
        let up_ref = Arc::clone(&stdio_up);
        let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
            let up = Arc::clone(&up_ref);
            async move { up.handle_mcp(req, &make_token("grant-hard", 0)).await }
        })
        .await;

        let client = make_client();
        let init_resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(init_resp.status(), StatusCode::OK);
        let sid = init_resp
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let init_val: Value =
            serde_json::from_slice(&init_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let child_pid = init_val["result"]["_meta"]["pid"].as_u64().unwrap() as u32;

        // Spawn one SSE waiter and one JSON waiter waiting on a gate before triggering the mid-line reject.
        let c_sse = client.clone();
        let sid_sse = sid.clone();
        let sse_waiter = tokio::spawn(async move {
            let resp = c_sse
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("mcp-session-id", &sid_sse)
                        .header(header::ACCEPT, "text/event-stream")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            r#"{"jsonrpc":"2.0","id":"sse-waiter","method":"tools/call","params":{"name":"wait_gate","arguments":{"gate":"g1"}}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let raw = resp.into_body().collect().await.unwrap().to_bytes();
            String::from_utf8(raw.to_vec()).unwrap()
        });

        let c_json = client.clone();
        let sid_json = sid.clone();
        let json_waiter = tokio::spawn(async move {
            let resp = c_json
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("mcp-session-id", &sid_json)
                        .header(header::ACCEPT, "application/json")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            r#"{"jsonrpc":"2.0","id":"json-waiter","method":"tools/call","params":{"name":"wait_gate","arguments":{"gate":"g1"}}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let val: Value =
                serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            (status, val)
        });

        let trigger_body = match scenario {
            "midline_method" => json!({
                "jsonrpc": "2.0",
                "id": "trigger-call",
                "method": "tools/call",
                "params": {
                    "name": "trigger_midline_method_then_valid",
                    "arguments": {
                        "pad_len": 400,
                        "other_wire_ids": [2, 3],
                        "wait_for_gate": "g1",
                        "expected_waiters": 2
                    }
                }
            }),
            "oversized_line" => json!({
                "jsonrpc": "2.0",
                "id": "trigger-call",
                "method": "tools/call",
                "params": {
                    "name": "trigger_oversized_line_then_valid",
                    "arguments": {
                        "target_bytes": 2400,
                        "wait_for_gate": "g1",
                        "expected_waiters": 2
                    }
                }
            }),
            _ => json!({
                "jsonrpc": "2.0",
                "id": "trigger-call",
                "method": "tools/call",
                "params": {
                    "name": "trigger_oversized_line_then_valid",
                    "arguments": {
                        "target_bytes": 1536,
                        "wait_for_gate": "g1",
                        "expected_waiters": 2,
                        "ready_file": ready_file,
                        "release_file": release_file
                    }
                }
            }),
        };

        let trig_request = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{gw_addr}/mcp"))
            .header("mcp-session-id", &sid)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .body(bytes_body(trigger_body.to_string()))
            .unwrap();
        let trig_client = client.clone();
        let trigger = tokio::spawn(async move { trig_client.request(trig_request).await.unwrap() });
        let held_lease = if scenario == "budget_exhausted" {
            // Admit all ordinary requests and their correlated error buffers first.
            // The child then waits while this test leaves only a small output allowance.
            wait_until(|| ready_file.exists()).await;
            let held = budget
                .try_acquire(budget.limit() - budget.used() - 64)
                .unwrap();
            std::fs::write(&release_file, b"release").unwrap();
            Some(held)
        } else {
            None
        };
        let trig_resp = trigger.await.unwrap();
        let trig_status = trig_resp.status();
        let trig_val: Value =
            serde_json::from_slice(&trig_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();

        let sse_text = tokio::time::timeout(Duration::from_secs(5), sse_waiter)
            .await
            .expect("SSE waiter must not hang")
            .unwrap();
        let (json_status, json_val) = tokio::time::timeout(Duration::from_secs(5), json_waiter)
            .await
            .expect("JSON waiter must not hang")
            .unwrap();

        let expected_substr = match scenario {
            "midline_method" => {
                assert_eq!(trig_status, StatusCode::BAD_GATEWAY);
                assert_eq!(json_status, StatusCode::BAD_GATEWAY);
                "256 byte limit"
            }
            "oversized_line" => {
                assert_eq!(trig_status, StatusCode::BAD_GATEWAY);
                assert_eq!(json_status, StatusCode::BAD_GATEWAY);
                "2048 byte limit"
            }
            _ => {
                assert_eq!(trig_status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(json_status, StatusCode::SERVICE_UNAVAILABLE);
                "byte budget"
            }
        };

        assert_eq!(trig_val["id"], "trigger-call");
        assert!(
            trig_val["error"]["message"]
                .as_str()
                .unwrap()
                .contains(expected_substr),
            "scenario={scenario}, trig_val={trig_val}"
        );

        assert_eq!(json_val["id"], "json-waiter");
        assert!(
            json_val["error"]["message"]
                .as_str()
                .unwrap()
                .contains(expected_substr),
            "scenario={scenario}, json_val={json_val}"
        );
        assert!(json_val.get("result").is_none());

        assert!(
            !sse_text.contains("should_never_arrive"),
            "residual bytes after hard reject must never be parsed: {sse_text}"
        );
        let sse_line = sse_text
            .trim()
            .strip_prefix("data: ")
            .expect("SSE waiter must receive explicit JSON-RPC error event, not bare EOF");
        let sse_val: Value = serde_json::from_str(sse_line).unwrap();
        assert_eq!(sse_val["id"], "sse-waiter");
        assert!(
            sse_val["error"]["message"]
                .as_str()
                .unwrap()
                .contains(expected_substr),
            "scenario={scenario}, sse_val={sse_val}"
        );

        assert!(wait_process_gone(child_pid).await);
        drop(held_lease);
        assert_eq!(budget.used(), 0);

        let after_resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"small_echo"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(after_resp.status(), StatusCode::NOT_FOUND);

        assert_eq!(budget.used(), 0);
        stdio_up.shutdown().await;
        gw_cancel.cancel();
    }
}

#[tokio::test]
async fn stdio_complete_line_discard_notif_byte_budget_and_slow_receiver_backpressure() {
    let tmp = TempDir::new().unwrap();
    let script = write_multimodal_stdio_mock_script(tmp.path());

    // Part A: Complete-line discard (> N_ctrl tail "method" and unmatched "id") preserves session.
    {
        let budget = ByteBudget::new(64 * 1024);
        let stdio_up = Arc::new(
            StdioUpstream::with_limits(
                StdioUpstreamSettings {
                    command: python_executable().to_owned(),
                    args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                    env: BTreeMap::new(),
                    cwd: Some(tmp.path().to_path_buf()),
                    max_sessions: 4,
                    session_idle_secs: 30,
                },
                Arc::clone(&budget),
                StdioLimits {
                    max_stdout_line_bytes: 2048,
                    max_control_line_bytes: 256,
                    max_notif_queue_bytes: 8192,
                    ..StdioLimits::default()
                },
            )
            .unwrap(),
        );
        let up_ref = Arc::clone(&stdio_up);
        let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
            let up = Arc::clone(&up_ref);
            async move { up.handle_mcp(req, &make_token("grant-discard", 0)).await }
        })
        .await;

        let client = make_client();
        let init_resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let sid = init_resp
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let _ = init_resp.into_body().collect().await.unwrap();

        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &sid)
                    .header(header::ACCEPT, "text/event-stream")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        json!({
                            "jsonrpc": "2.0",
                            "id": "keep-alive-1",
                            "method": "tools/call",
                            "params": {
                                "name": "complete_line_discards_then_valid",
                                "arguments": {
                                    "pass_notif_lens": [255, 256],
                                    "tail_method_bytes": 450,
                                    "unmatched_bytes": 700,
                                    "valid_bytes": 900
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(raw.to_vec()).unwrap();
        let events: Vec<Value> = text
            .split("\n\n")
            .filter(|b| !b.is_empty())
            .map(|b| serde_json::from_str(b.strip_prefix("data: ").unwrap()).unwrap())
            .collect();
        // Exactly 2 valid notifications (255 B and 256 B) + 1 final response; 450 B tail-method & 700 B unmatched-id were discarded!
        assert_eq!(events.len(), 3, "unexpected events: {events:?}");
        assert_eq!(events[0]["method"], "notifications/message");
        assert_eq!(events[1]["method"], "notifications/message");
        assert_eq!(events[2]["id"], "keep-alive-1");
        assert_eq!(budget.used(), 0);

        // Session is still alive for subsequent calls!
        let follow = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":"after-discard","method":"tools/call","params":{"name":"small_echo","arguments":{"tag":"still-alive"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(follow.status(), StatusCode::OK);
        let follow_val: Value =
            serde_json::from_slice(&follow.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(follow_val["result"]["tag"], "still-alive");

        stdio_up.shutdown().await;
        gw_cancel.cancel();
    }

    // Part B: Per-session notification queue byte budget under slow SSE receiver (6.4 MiB flood capped at 4 KiB budget without losing final response).
    {
        let budget = ByteBudget::new(64 * 1024);
        let stdio_up = Arc::new(
            StdioUpstream::with_limits(
                StdioUpstreamSettings {
                    command: python_executable().to_owned(),
                    args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                    env: BTreeMap::new(),
                    cwd: Some(tmp.path().to_path_buf()),
                    max_sessions: 4,
                    session_idle_secs: 30,
                },
                Arc::clone(&budget),
                StdioLimits {
                    max_stdout_line_bytes: 8192,
                    max_control_line_bytes: 1024,
                    max_notif_queue_bytes: 4096,
                    ..StdioLimits::default()
                },
            )
            .unwrap(),
        );
        let up_ref = Arc::clone(&stdio_up);
        let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
            let up = Arc::clone(&up_ref);
            async move { up.handle_mcp(req, &make_token("grant-nbudget", 0)).await }
        })
        .await;

        let client = make_client();
        let init_resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let sid = init_resp
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let _ = init_resp.into_body().collect().await.unwrap();

        let mut sse_tcp = TcpStream::connect(gw_addr).await.unwrap();
        let burst_req = json!({
            "jsonrpc": "2.0",
            "id": "sw-flood",
            "method": "tools/call",
            "params": {
                "name": "notif_budget_burst",
                "arguments": {
                    "notif_bytes": 800,
                    "count": 8000,
                    "gate": "nb",
                    "post_gate_notif": false
                }
            }
        })
        .to_string();
        let raw_sse_http = format!(
            "POST /mcp HTTP/1.1\r\nHost: {gw_addr}\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\nmcp-session-id: {sid}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{burst_req}",
            burst_req.len()
        );
        sse_tcp.write_all(raw_sse_http.as_bytes()).await.unwrap();

        let gate_resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","method":"notifications/gate_open","params":{"gate":"nb","wait_burst":true}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(gate_resp.status(), StatusCode::ACCEPTED);

        let mut flooded_out = Vec::new();
        sse_tcp.read_to_end(&mut flooded_out).await.unwrap();
        let flooded_str = String::from_utf8(flooded_out).unwrap();
        assert!(
            flooded_str.len() < 6_400_000,
            "notification flood must drop excess events once TCP window + 4 KiB notif budget fill, got {} bytes",
            flooded_str.len()
        );
        assert!(
            flooded_str.contains("\"burst_done\":true"),
            "final RPC response must still arrive intact after notification budget overflow"
        );

        stdio_up.shutdown().await;
        gw_cancel.cancel();
    }

    // Part C: Slow receiver lease backpressure on StdioUpstream without starving control paths.
    {
        let cancel_dir = tmp.path().join("cancel_flags");
        std::fs::create_dir_all(&cancel_dir).unwrap();
        let mut slow_env = BTreeMap::new();
        slow_env.insert(
            "MOCK_CANCEL_DIR".to_owned(),
            cancel_dir.to_str().unwrap().to_owned(),
        );
        let budget = ByteBudget::new(8 * 1024 * 1024);
        let stdio_up = Arc::new(
            StdioUpstream::with_limits(
                StdioUpstreamSettings {
                    command: python_executable().to_owned(),
                    args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                    env: slow_env,
                    cwd: Some(tmp.path().to_path_buf()),
                    max_sessions: 8,
                    session_idle_secs: 30,
                },
                Arc::clone(&budget),
                StdioLimits {
                    max_stdout_line_bytes: 7 * 1024 * 1024,
                    max_control_line_bytes: 2048,
                    max_notif_queue_bytes: 16 * 1024,
                    ..StdioLimits::default()
                },
            )
            .unwrap(),
        );
        let up_ref = Arc::clone(&stdio_up);
        let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
            let up = Arc::clone(&up_ref);
            async move { up.handle_mcp(req, &make_token("grant-slow-real", 0)).await }
        })
        .await;

        let client = make_client();
        let mut sids = Vec::new();
        for _ in 0..2 {
            let r = client
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let sid = r
                .headers()
                .get("mcp-session-id")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let _ = r.into_body().collect().await.unwrap();
            sids.push(sid);
        }

        let mut tcp = TcpStream::connect(gw_addr).await.unwrap();
        let req_json = json!({
            "jsonrpc": "2.0",
            "id": "slow-a",
            "method": "tools/call",
            "params": {
                "name": "exact_tail_id",
                "arguments": {"target_bytes": 6 * 1024 * 1024}
            }
        })
        .to_string();
        let raw_http = format!(
            "POST /mcp HTTP/1.1\r\nHost: {gw_addr}\r\nContent-Type: application/json\r\nAccept: application/json\r\nmcp-session-id: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{req_json}",
            sids[0],
            req_json.len()
        );
        tcp.write_all(raw_http.as_bytes()).await.unwrap();

        let mut head_buf = [0u8; 1024];
        let n_read = tcp.read(&mut head_buf).await.unwrap();
        assert!(
            std::str::from_utf8(&head_buf[..n_read])
                .unwrap_or("")
                .starts_with("HTTP/1.1 200")
        );

        // Lease transferred from `raw` to `LeasedReplyBody` without double-counting (used <= 8 MiB),
        // and stays held (~6 MiB) while Slow Receiver A stalls reading TCP!
        assert!(
            budget.used() >= 5 * 1024 * 1024,
            "slow receiver must keep response lease active, got used={}",
            budget.used()
        );

        // Caller B on Session 2 requesting 4 MiB (6 MiB + 4 MiB > 8 MiB) fails non-blockingly with 503!
        let over_resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &sids[1])
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        json!({
                            "jsonrpc": "2.0",
                            "id": "caller-b-over",
                            "method": "tools/call",
                            "params": {
                                "name": "exact_tail_id",
                                "arguments": {"target_bytes": 4 * 1024 * 1024}
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(over_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let over_val: Value =
            serde_json::from_slice(&over_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert!(
            over_val["error"]["message"]
                .as_str()
                .unwrap()
                .contains("byte budget")
        );

        // Control path (new initialize + small <= 2 KiB tool call) is NOT starved while budget is held!
        let ctrl_init = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ctrl_init.status(), StatusCode::OK);
        let ctrl_sid = ctrl_init
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let _ = ctrl_init.into_body().collect().await.unwrap();

        let ctrl_call = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &ctrl_sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":"ctrl-ok","method":"tools/call","params":{"name":"small_echo","arguments":{"tag":"unstarved"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ctrl_call.status(), StatusCode::OK);

        // Drain Slow Receiver A completely -> lease returns to 0!
        let mut rest = Vec::new();
        tcp.read_to_end(&mut rest).await.unwrap();
        drop(tcp);
        wait_until(|| budget.used() == 0).await;

        // Subsequent 6 MiB call on `ctrl_sid` now succeeds!
        let recovered = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &ctrl_sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        json!({
                            "jsonrpc": "2.0",
                            "id": "after-drain",
                            "method": "tools/call",
                            "params": {
                                "name": "exact_tail_id",
                                "arguments": {"target_bytes": 6 * 1024 * 1024}
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
        let _ = recovered.into_body().collect().await.unwrap();
        assert_eq!(budget.used(), 0);

        // Verify mid-stream TCP disconnect + mid-line request cancellation hold lease until memory actually frees.
        let mut tcp_abort = TcpStream::connect(gw_addr).await.unwrap();
        tcp_abort.write_all(raw_http.as_bytes()).await.unwrap();
        let n_abort = tcp_abort.read(&mut head_buf).await.unwrap();
        assert!(
            std::str::from_utf8(&head_buf[..n_abort])
                .unwrap_or("")
                .starts_with("HTTP/1.1 200")
        );
        assert!(budget.used() >= 5 * 1024 * 1024);
        drop(tcp_abort);
        wait_until(|| budget.used() == 0).await;

        let cancel_client = client.clone();
        let cancel_sid = ctrl_sid.clone();
        let cancel_task = tokio::spawn(async move {
            let _ = cancel_client
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("mcp-session-id", &cancel_sid)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            json!({
                                "jsonrpc": "2.0",
                                "id": "cancel-mid-line",
                                "method": "tools/call",
                                "params": {
                                    "name": "gated_two_half_line",
                                    "arguments": {
                                        "half1_bytes": 32 * 1024,
                                        "gate": "cancel_half"
                                    }
                                }
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await;
        });

        // The raw allocation and this active request's metadata are both charged.
        // After cancellation below, only the exact 32 KiB reader allocation remains.
        wait_until(|| budget.used() > 32 * 1024).await;

        // Cancel caller and wait deterministically until child receives `notifications/cancelled` (wire_id = 4 on ctrl_sid: 1=init, 2=ctrl-ok, 3=after-drain, 4=cancel-mid-line).
        cancel_task.abort();
        let _ = cancel_task.await;
        wait_until(|| {
            std::fs::read_dir(&cancel_dir)
                .unwrap()
                .filter_map(Result::ok)
                .any(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.starts_with("cancelled_"))
                })
        })
        .await;
        assert_eq!(
            budget.used(),
            32 * 1024,
            "cancelled caller must NOT release lease while background reader still buffers `raw`"
        );

        let open_half = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &ctrl_sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","method":"notifications/gate_open","params":{"gate":"cancel_half"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(open_half.status(), StatusCode::ACCEPTED);
        wait_until(|| budget.used() == 0).await;

        let still_ok = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &ctrl_sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":"post-cancel-ok","method":"tools/call","params":{"name":"small_echo","arguments":{"tag":"alive"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(still_ok.status(), StatusCode::OK);

        stdio_up.shutdown().await;
        gw_cancel.cancel();
    }
}

#[tokio::test]
async fn stdio_unsolicited_large_output_sessionless_hard_rejects() {
    let tmp = TempDir::new().unwrap();
    let script = write_multimodal_stdio_mock_script(tmp.path());

    // 1. UnexpectedLargeOutput (> max_control_line_bytes with NO active in-flight request) kills stateful session.
    {
        let budget = ByteBudget::new(64 * 1024);
        let stdio_up = Arc::new(
            StdioUpstream::with_limits(
                StdioUpstreamSettings {
                    command: python_executable().to_owned(),
                    args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                    env: BTreeMap::new(),
                    cwd: Some(tmp.path().to_path_buf()),
                    max_sessions: 2,
                    session_idle_secs: 30,
                },
                Arc::clone(&budget),
                StdioLimits {
                    max_stdout_line_bytes: 4096,
                    max_control_line_bytes: 256,
                    max_notif_queue_bytes: 4096,
                    ..StdioLimits::default()
                },
            )
            .unwrap(),
        );
        let up_ref = Arc::clone(&stdio_up);
        let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
            let up = Arc::clone(&up_ref);
            async move { up.handle_mcp(req, &make_token("grant-unsol", 0)).await }
        })
        .await;

        let client = make_client();
        let init_resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let sid = init_resp
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let init_val: Value =
            serde_json::from_slice(&init_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let child_pid = init_val["result"]["_meta"]["pid"].as_u64().unwrap() as u32;

        // Trigger > 256 B stdout output via notification so `in_flight` has 0 active requests.
        let notif_resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","method":"notifications/spew_unsolicited_large","params":{"bytes":600}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(notif_resp.status(), StatusCode::ACCEPTED);

        assert!(wait_process_gone(child_pid).await);
        assert_eq!(budget.used(), 0);

        let dead_resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"small_echo"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dead_resp.status(), StatusCode::NOT_FOUND);

        // 2. Sessionless (`MCP-Protocol-Version: 2026-07-28`) propagates explicit hard-reject reasons to both JSON and SSE callers and reclaims slots.
        for accept_hdr in ["application/json", "text/event-stream"] {
            let sl_over = client
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("MCP-Protocol-Version", "2026-07-28")
                        .header(header::ACCEPT, accept_hdr)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            json!({
                                "jsonrpc": "2.0",
                                "id": "sl-over",
                                "method": "tools/call",
                                "params": {
                                    "name": "trigger_oversized_line_then_valid",
                                    "arguments": {"target_bytes": 5000}
                                }
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();

            if accept_hdr == "application/json" {
                assert_eq!(sl_over.status(), StatusCode::BAD_GATEWAY);
                let val: Value = serde_json::from_slice(
                    &sl_over.into_body().collect().await.unwrap().to_bytes(),
                )
                .unwrap();
                assert_eq!(val["id"], "sl-over");
                assert!(
                    val["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains("4096 byte limit")
                );
            } else {
                assert_eq!(sl_over.status(), StatusCode::OK);
                let raw = sl_over.into_body().collect().await.unwrap().to_bytes();
                let s = std::str::from_utf8(&raw).unwrap();
                assert!(!s.contains("should_never_arrive"));
                let val: Value =
                    serde_json::from_str(s.trim().strip_prefix("data: ").unwrap()).unwrap();
                assert_eq!(val["id"], "sl-over");
                assert!(
                    val["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains("4096 byte limit")
                );
            }
            assert_eq!(budget.used(), 0);
        }

        // Clean sessionless call still succeeds (proving slots were reclaimed).
        let sl_ok = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("MCP-Protocol-Version", "2026-07-28")
                    .header(header::ACCEPT, "application/json")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":"sl-clean","method":"tools/call","params":{"name":"small_echo","arguments":{"tag":"ok"}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sl_ok.status(), StatusCode::OK);

        stdio_up.shutdown().await;
        gw_cancel.cancel();
    }

    // 3. Sessionless dead-session mapping when child spews > max_control_line_bytes right after `initialize` (`UnexpectedLargeOutput` preserved through `register_request` / `send_request_line`).
    {
        let mut spew_env = BTreeMap::new();
        spew_env.insert("MOCK_SPEW_AFTER_INIT_BYTES".to_owned(), "600".to_owned());
        let budget = ByteBudget::new(64 * 1024);
        let stdio_up = Arc::new(
            StdioUpstream::with_limits(
                StdioUpstreamSettings {
                    command: python_executable().to_owned(),
                    args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                    env: spew_env,
                    cwd: Some(tmp.path().to_path_buf()),
                    max_sessions: 2,
                    session_idle_secs: 30,
                },
                Arc::clone(&budget),
                StdioLimits {
                    max_stdout_line_bytes: 4096,
                    max_control_line_bytes: 256,
                    max_notif_queue_bytes: 4096,
                    ..StdioLimits::default()
                },
            )
            .unwrap(),
        );
        let up_ref = Arc::clone(&stdio_up);
        let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
            let up = Arc::clone(&up_ref);
            async move { up.handle_mcp(req, &make_token("grant-spew", 0)).await }
        })
        .await;

        let client = make_client();
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("MCP-Protocol-Version", "2026-07-28")
                    .header(header::ACCEPT, "application/json")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":"sl-spew","method":"tools/call","params":{"name":"small_echo"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Must report 502 (never misclassified as 503 "too many concurrent requests in session").
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let val: Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(val["id"], "sl-spew");
        let err_msg = val["error"]["message"].as_str().unwrap();
        assert!(
            !err_msg.contains("too many concurrent"),
            "dead session must not be misreported as concurrency limit: {err_msg}"
        );

        stdio_up.shutdown().await;
        gw_cancel.cancel();
    }
}

#[tokio::test]
async fn stdio_request_and_rewrite_buffers_share_the_process_budget() {
    let tmp = TempDir::new().unwrap();
    let script = write_multimodal_stdio_mock_script(tmp.path());

    let response_len = 40_000usize;
    // Ingress values, retained IDs, and the correlated error workspace share this pool.
    // The unit test isolates the exact 40,000/40,001-byte rewrite allowance.
    let budget = ByteBudget::new(response_len + 4096);
    let stdio_up = Arc::new(
        StdioUpstream::with_limits(
            StdioUpstreamSettings {
                command: python_executable().to_owned(),
                args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                env: BTreeMap::new(),
                cwd: Some(tmp.path().to_path_buf()),
                max_sessions: 4,
                session_idle_secs: 30,
            },
            Arc::clone(&budget),
            StdioLimits {
                max_stdout_line_bytes: 60_000,
                max_control_line_bytes: 512,
                max_notif_queue_bytes: 4096,
                ..StdioLimits::default()
            },
        )
        .unwrap(),
    );
    let up_ref = Arc::clone(&stdio_up);
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&up_ref);
        async move { up.handle_mcp(req, &make_token("grant-tight", 0)).await }
    })
    .await;

    let client = make_client();
    let init_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let sid = init_resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let _ = init_resp.into_body().collect().await.unwrap();

    // wire_id = 2 ("2" = 1 B) -> client_id = "long-client-id-expanded-by-30b" (serialized JSON = 32 B).
    // Line 39,970 B (39,969 B without '\n') - 1 + 32 = 40,000 B.
    let long_cid = "long-client-id-expanded-by-30b";
    assert_eq!(serde_json::to_vec(&json!(long_cid)).unwrap().len(), 32);

    let exact_fit = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &sid)
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": long_cid,
                        "method": "tools/call",
                        "params": {
                            "name": "exact_tail_id",
                            "arguments": {"target_bytes": 39_970}
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exact_fit.status(), StatusCode::OK);
    let exact_bytes = exact_fit.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(exact_bytes.len(), response_len);
    let exact_val: Value = serde_json::from_slice(&exact_bytes).unwrap();
    assert_eq!(exact_val["id"], long_cid);
    assert!(exact_val["result"]["_meta"]["explicit_null"].is_null());
    assert_eq!(budget.used(), 0);

    // Both adjacent response lengths fit together with the ordinary request metadata.
    let plus_one = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &sid)
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": long_cid,
                        "method": "tools/call",
                        "params": {
                            "name": "exact_tail_id",
                            "arguments": {"target_bytes": 39_971}
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(plus_one.status(), StatusCode::OK);
    let plus_bytes = plus_one.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(plus_bytes.len(), response_len + 1);
    let plus_val: Value = serde_json::from_slice(&plus_bytes).unwrap();
    assert_eq!(plus_val["id"], long_cid);
    assert!(plus_val["result"]["_meta"]["explicit_null"].is_null());
    assert_eq!(budget.used(), 0);

    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_pressure_lru_ignores_stdout_noise_and_disconnect_cancel() {
    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("noisy_stdio_mock.py");
    std::fs::write(
        &script,
        r#"import json, os, sys, threading, time

write_lock = threading.Lock()
stop_flag = False

def write_line(obj):
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    with write_lock:
        try:
            sys.stdout.write(line)
            sys.stdout.flush()
        except Exception:
            pass

def spam_notifications():
    i = 0
    while not stop_flag:
        time.sleep(0.015)
        if stop_flag:
            break
        i += 1
        write_line({"jsonrpc": "2.0", "method": "notifications/message", "params": {"tick": i}})

def hold_until_file(req_id, args):
    ready_path = args["ready_path"]
    release_path = args["release_path"]
    with open(ready_path, "w") as f:
        f.write("ready")
    while not os.path.exists(release_path):
        time.sleep(0.005)
    write_line({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "done"}]}})

t = threading.Thread(target=spam_notifications, daemon=True)
t.start()

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        write_line({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "serverInfo": {"name": "noisy-mock", "version": "1.0", "pid": os.getpid()},
            },
        })
    elif method == "notifications/cancelled":
        cancel_marker = os.environ.get("CANCEL_MARKER_DIR")
        if cancel_marker:
            with open(os.path.join(cancel_marker, f"cancel_{os.getpid()}"), "w") as f:
                f.write("1")
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "ping_fast":
            write_line({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "pong"}]}})
        elif name == "hold_until_file":
            threading.Thread(target=hold_until_file, args=(req_id, args), daemon=True).start()

stop_flag = True
"#,
    )
    .unwrap();

    let cancel_dir = tmp.path().join("cancels");
    std::fs::create_dir_all(&cancel_dir).unwrap();
    let mut env = BTreeMap::new();
    env.insert(
        "CANCEL_MARKER_DIR".to_owned(),
        cancel_dir.to_str().unwrap().to_owned(),
    );

    let stdio_up = Arc::new(
        StdioUpstream::with_limits(
            StdioUpstreamSettings {
                command: python_executable().to_owned(),
                args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                env,
                cwd: Some(tmp.path().to_path_buf()),
                max_sessions: 3,
                session_idle_secs: 30,
            },
            ByteBudget::new(16 * 1024 * 1024),
            StdioLimits {
                pressure_idle: Duration::from_millis(80),
                ..StdioLimits::default()
            },
        )
        .unwrap(),
    );
    let up_ref = Arc::clone(&stdio_up);
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&up_ref);
        async move { up.handle_mcp(req, &make_token("grant-a", 0)).await }
    })
    .await;

    let client = make_client();
    let init_one = |id: u64| {
        let client = client.clone();
        async move {
            let resp = client
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{}})
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let sid = resp
                .headers()
                .get("mcp-session-id")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let body: Value =
                serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            let pid = body["result"]["serverInfo"]["pid"].as_u64().unwrap() as u32;
            (sid, pid)
        }
    };
    let ping_one = |sid: String| {
        let client = client.clone();
        async move {
            client
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("mcp-session-id", sid)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"ping_fast","arguments":{}}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };

    let (sid1, _pid1) = init_one(1).await;
    let (sid2, pid2) = init_one(2).await;
    let (sid3, pid3) = init_one(3).await;

    // Refresh sid1 via real client call so client LRU order becomes sid2 (oldest) < sid3 < sid1.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let p1 = ping_one(sid1.clone()).await;
    assert_eq!(p1.status(), StatusCode::OK);
    let _ = p1.into_body().collect().await.unwrap();

    // Let >= 80 ms pass while all 3 children continuously emit stdout notifications every 15 ms.
    tokio::time::sleep(Duration::from_millis(105)).await;

    // 4th initialize must evict sid2 (exact client LRU) despite sid2's stdout noise.
    let (sid4, _pid4) = init_one(4).await;
    assert!(wait_process_gone(pid2).await);

    let r2 = ping_one(sid2.clone()).await;
    assert_eq!(r2.status(), StatusCode::NOT_FOUND);
    let _ = r2.into_body().collect().await.unwrap();

    for alive_sid in [&sid1, &sid3, &sid4] {
        let r = ping_one((*alive_sid).clone()).await;
        assert_eq!(r.status(), StatusCode::OK);
        let _ = r.into_body().collect().await.unwrap();
    }

    // Verify client disconnect (RequestGuard::cancel) does NOT refresh last_client_active_ms:
    // Start a hold call on sid3, let >= 95 ms pass after sid3's start touch, then abort TCP.
    let ready3 = tmp.path().join("ready3");
    let release3 = tmp.path().join("release3");
    let raw_body = json!({
        "jsonrpc": "2.0",
        "id": 77,
        "method": "tools/call",
        "params": {
            "name": "hold_until_file",
            "arguments": {
                "ready_path": ready3.to_str().unwrap(),
                "release_path": release3.to_str().unwrap(),
            }
        }
    })
    .to_string();
    let mut raw_conn = TcpStream::connect(gw_addr).await.unwrap();
    let http_req = format!(
        "POST /mcp HTTP/1.1\r\nHost: {gw_addr}\r\nMcp-Session-Id: {sid3}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{raw_body}",
        raw_body.len()
    );
    raw_conn.write_all(http_req.as_bytes()).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !ready3.exists() {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    tokio::time::sleep(Duration::from_millis(95)).await;
    // Refresh sid1 and sid4 right now (< 80 ms old) and drop sid3's TCP socket.
    for fresh_sid in [&sid1, &sid4] {
        let r = ping_one((*fresh_sid).clone()).await;
        assert_eq!(r.status(), StatusCode::OK);
        let _ = r.into_body().collect().await.unwrap();
    }
    drop(raw_conn);

    let cancel_marker = cancel_dir.join(format!("cancel_{pid3}"));
    let cancel_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !cancel_marker.exists() {
        assert!(tokio::time::Instant::now() < cancel_deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    std::fs::write(&release3, "go").unwrap();

    // Immediately (well under 80 ms after disconnect!) initialize sid5: sid3 must be evicted.
    let (_sid5, _pid5) = init_one(5).await;
    assert!(wait_process_gone(pid3).await);
    let r3 = ping_one(sid3).await;
    assert_eq!(r3.status(), StatusCode::NOT_FOUND);
    let _ = r3.into_body().collect().await.unwrap();

    stdio_up.shutdown().await;
    gw_cancel.cancel();
}

#[tokio::test]
async fn stdio_pressure_admission_protects_recent_cross_grant_inflight_and_handshakes() {
    let tmp = TempDir::new().unwrap();
    let script = tmp.path().join("protected_stdio_mock.py");
    std::fs::write(
        &script,
        r#"import json, os, sys, time

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        hold_dir = os.environ.get("HOLD_INIT_READY_DIR")
        release_init = os.environ.get("HOLD_INIT_RELEASE_FILE")
        if hold_dir and release_init:
            with open(os.path.join(hold_dir, f"init_{os.getpid()}"), "w") as f:
                f.write("1")
            while not os.path.exists(release_init):
                time.sleep(0.005)
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "serverInfo": {"name": "prot-mock", "version": "1.0"},
            },
        }) + "\n")
        sys.stdout.flush()
    elif method == "tools/call":
        args = params.get("arguments") or {}
        if params.get("name") == "hold":
            with open(args["ready"], "w") as f:
                f.write("1")
            while not os.path.exists(args["release"]):
                time.sleep(0.005)
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }) + "\n")
        sys.stdout.flush()
"#,
    )
    .unwrap();

    // Part A: recent (< pressure_idle), cross-grant, active_requests > 0, and re-initialize guard.
    {
        let stdio_up = Arc::new(
            StdioUpstream::with_limits(
                StdioUpstreamSettings {
                    command: python_executable().to_owned(),
                    args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                    env: BTreeMap::new(),
                    cwd: Some(tmp.path().to_path_buf()),
                    max_sessions: 2,
                    session_idle_secs: 30,
                },
                ByteBudget::new(8 * 1024 * 1024),
                StdioLimits {
                    pressure_idle: Duration::from_millis(120),
                    ..StdioLimits::default()
                },
            )
            .unwrap(),
        );
        let up_ref = Arc::clone(&stdio_up);
        let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
            let up = Arc::clone(&up_ref);
            async move {
                let grant = req
                    .headers()
                    .get("x-test-grant")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("grant-a")
                    .to_owned();
                up.handle_mcp(req, &make_token(&grant, 0)).await
            }
        })
        .await;

        let client = make_client();
        let send_init = |grant: &str, id: u64| {
            let client = client.clone();
            let grant = grant.to_owned();
            async move {
                client
                    .request(
                        Request::builder()
                            .method(Method::POST)
                            .uri(format!("http://{gw_addr}/mcp"))
                            .header("x-test-grant", grant)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(bytes_body(
                                json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{}})
                                    .to_string(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            }
        };

        let r1 = send_init("grant-a", 1).await;
        assert_eq!(r1.status(), StatusCode::OK);
        let sid1 = r1
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let _ = r1.into_body().collect().await.unwrap();

        let r2 = send_init("grant-a", 2).await;
        assert_eq!(r2.status(), StatusCode::OK);
        let sid2 = r2
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let _ = r2.into_body().collect().await.unwrap();

        // 1. Recent (< 120 ms) same-grant sessions must NOT be evicted -> 503.
        let r_recent = send_init("grant-a", 3).await;
        assert_eq!(r_recent.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = r_recent.into_body().collect().await.unwrap();

        // 2. Duplicate initialize on an established session returns 400 without corrupting active_requests.
        let dup_init = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("x-test-grant", "grant-a")
                    .header("mcp-session-id", &sid1)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":99,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dup_init.status(), StatusCode::BAD_REQUEST);
        let _ = dup_init.into_body().collect().await.unwrap();

        // 3. After >= 120 ms, a DIFFERENT grant ("grant-b") still gets 503 and cannot evict grant-a's sessions.
        tokio::time::sleep(Duration::from_millis(145)).await;
        let r_other_grant = send_init("grant-b", 4).await;
        assert_eq!(r_other_grant.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = r_other_grant.into_body().collect().await.unwrap();

        // 4. Start long calls on both sid1 and sid2; even after >= 120 ms, active_requests > 0 protects both -> 503.
        let ready1 = tmp.path().join("hold_r1");
        let rel1 = tmp.path().join("hold_rel1");
        let ready2 = tmp.path().join("hold_r2");
        let rel2 = tmp.path().join("hold_rel2");

        let spawn_hold = |sid: String, ready: std::path::PathBuf, rel: std::path::PathBuf| {
            let client = client.clone();
            tokio::spawn(async move {
                let resp = client
                    .request(
                        Request::builder()
                            .method(Method::POST)
                            .uri(format!("http://{gw_addr}/mcp"))
                            .header("x-test-grant", "grant-a")
                            .header("mcp-session-id", sid)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(bytes_body(
                                json!({
                                    "jsonrpc": "2.0",
                                    "id": 10,
                                    "method": "tools/call",
                                    "params": {
                                        "name": "hold",
                                        "arguments": {
                                            "ready": ready.to_str().unwrap(),
                                            "release": rel.to_str().unwrap(),
                                        }
                                    }
                                })
                                .to_string(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                let _ = resp.into_body().collect().await.unwrap();
            })
        };

        let h1 = spawn_hold(sid1.clone(), ready1.clone(), rel1.clone());
        let h2 = spawn_hold(sid2.clone(), ready2.clone(), rel2.clone());
        let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while !ready1.exists() || !ready2.exists() {
            assert!(tokio::time::Instant::now() < wait_deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        tokio::time::sleep(Duration::from_millis(145)).await;
        let r_busy = send_init("grant-a", 5).await;
        assert_eq!(r_busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = r_busy.into_body().collect().await.unwrap();

        std::fs::write(&rel1, "1").unwrap();
        std::fs::write(&rel2, "1").unwrap();
        h1.await.unwrap();
        h2.await.unwrap();

        stdio_up.shutdown().await;
        gw_cancel.cancel();
    }

    // Part B: in-handshake initialize sessions (reserved_slots) are naturally immune to pressure eviction.
    {
        let init_ready_dir = tmp.path().join("init_ready");
        std::fs::create_dir_all(&init_ready_dir).unwrap();
        let init_release = tmp.path().join("init_release");
        let mut env = BTreeMap::new();
        env.insert(
            "HOLD_INIT_READY_DIR".to_owned(),
            init_ready_dir.to_str().unwrap().to_owned(),
        );
        env.insert(
            "HOLD_INIT_RELEASE_FILE".to_owned(),
            init_release.to_str().unwrap().to_owned(),
        );

        let stdio_up = Arc::new(
            StdioUpstream::with_limits(
                StdioUpstreamSettings {
                    command: python_executable().to_owned(),
                    args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                    env,
                    cwd: Some(tmp.path().to_path_buf()),
                    max_sessions: 2,
                    session_idle_secs: 30,
                },
                ByteBudget::new(8 * 1024 * 1024),
                StdioLimits {
                    pressure_idle: Duration::from_millis(60),
                    ..StdioLimits::default()
                },
            )
            .unwrap(),
        );
        let up_ref = Arc::clone(&stdio_up);
        let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
            let up = Arc::clone(&up_ref);
            async move { up.handle_mcp(req, &make_token("grant-a", 0)).await }
        })
        .await;

        let client = make_client();
        let spawn_init = |id: u64| {
            let client = client.clone();
            tokio::spawn(async move {
                client
                    .request(
                        Request::builder()
                            .method(Method::POST)
                            .uri(format!("http://{gw_addr}/mcp"))
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(bytes_body(
                                json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{}})
                                    .to_string(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            })
        };

        let i1 = spawn_init(1);
        let i2 = spawn_init(2);
        let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while std::fs::read_dir(&init_ready_dir).unwrap().count() < 2 {
            assert!(tokio::time::Instant::now() < wait_deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        tokio::time::sleep(Duration::from_millis(85)).await;
        let i3 = spawn_init(3).await.unwrap();
        assert_eq!(i3.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = i3.into_body().collect().await.unwrap();

        std::fs::write(&init_release, "1").unwrap();
        let r1 = i1.await.unwrap();
        let r2 = i2.await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        assert_eq!(r2.status(), StatusCode::OK);
        let _ = r1.into_body().collect().await.unwrap();
        let _ = r2.into_body().collect().await.unwrap();

        stdio_up.shutdown().await;
        gw_cancel.cancel();
    }
}

#[tokio::test]
async fn stdio_concurrent_reap_and_burst_enforces_hard_max_sessions_cap() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("active_pids");
    std::fs::create_dir_all(&active_dir).unwrap();
    let peak_file = tmp.path().join("child_watermark.txt");
    std::fs::write(&peak_file, "0 0").unwrap();
    let pids_file = tmp.path().join("spawned_pids.txt");
    std::fs::write(&pids_file, "").unwrap();
    let lock_dir = tmp.path().join("watermark_lock");

    let script = tmp.path().join("slow_reap_stdio_mock.py");
    std::fs::write(
        &script,
        r#"import json, os, sys, time

if os.name == "nt":
    import msvcrt
else:
    import fcntl

active_dir = os.environ["ACTIVE_DIR"]
peak_file = os.environ["PEAK_FILE"]
pids_file = os.environ["PIDS_FILE"]
lock_dir = os.environ["LOCK_DIR"]
_HELD_LOCK_FILE = None

def acquire_spin_lock():
    while True:
        try:
            os.mkdir(lock_dir)
            return
        except FileExistsError:
            time.sleep(0.001)

def lock_nonblocking(f):
    if os.name == "nt":
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

def unlock_file(f):
    if os.name == "nt":
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

def scan_live_and_update_peak(own_name):
    live = 0
    for name in os.listdir(active_dir):
        if name == own_name:
            live += 1
            continue
        p = os.path.join(active_dir, name)
        try:
            f = open(p, "r+b")
        except OSError:
            continue
        try:
            lock_nonblocking(f)
        except OSError:
            live += 1
            f.close()
            continue
        try:
            unlock_file(f)
        except OSError:
            pass
        f.close()
        try:
            os.remove(p)
        except OSError:
            pass
    with open(peak_file, "r") as pf:
        _old_cur, old_peak = pf.read().strip().split()
    peak = max(int(old_peak), live)
    with open(peak_file, "w") as pf:
        pf.write(f"{live} {peak}")
    return live, peak

if len(sys.argv) > 1 and sys.argv[1] == "--probe":
    acquire_spin_lock()
    try:
        cur, peak = scan_live_and_update_peak(None)
    finally:
        os.rmdir(lock_dir)
    sys.stdout.write(f"{cur} {peak}\n")
    sys.exit(0)

acquire_spin_lock()
try:
    own_name = f"{os.getpid()}_{time.time_ns()}.lock"
    own_path = os.path.join(active_dir, own_name)
    _HELD_LOCK_FILE = open(own_path, "w+b")
    _HELD_LOCK_FILE.write(b"1")
    _HELD_LOCK_FILE.flush()
    lock_nonblocking(_HELD_LOCK_FILE)
    with open(pids_file, "a") as pf:
        pf.write(f"{os.getpid()}\n")
    scan_live_and_update_peak(own_name)
finally:
    os.rmdir(lock_dir)

need_force_kill = False
for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        ready_marker = params.get("readyMarker")
        if ready_marker:
            need_force_kill = True
            with open(ready_marker, "w") as f:
                f.write("1")
            # Block past STDIN_GRACE_WAIT so Unix SIGTERM or Windows JobObject/TerminateProcess reaps this child.
            time.sleep(5.0)
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "serverInfo": {"name": "slow-reap", "version": "1.0"},
            },
        }) + "\n")
        sys.stdout.flush()
    elif method == "tools/call":
        args = params.get("arguments") or {}
        ready_marker = args.get("readyMarker")
        if ready_marker:
            need_force_kill = True
            with open(ready_marker, "w") as f:
                f.write("1")
            time.sleep(5.0)
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }) + "\n")
        sys.stdout.flush()

if need_force_kill:
    time.sleep(5.0)
else:
    # Stay alive for 140 ms inside STDIN_GRACE_WAIT so async reaping overlaps with concurrent reconnects.
    time.sleep(0.14)
"#,
    )
    .unwrap();

    let probe_watermark =
        |a_dir: &Path, pk_file: &Path, p_file: &Path, lk_dir: &Path| -> (usize, usize) {
            let out = std::process::Command::new(python_executable())
                .args(["-u", script.to_str().unwrap(), "--probe"])
                .env("ACTIVE_DIR", a_dir)
                .env("PEAK_FILE", pk_file)
                .env("PIDS_FILE", p_file)
                .env("LOCK_DIR", lk_dir)
                .output()
                .unwrap();
            assert!(out.status.success());
            let nums: Vec<usize> = String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .map(|v| v.parse().unwrap())
                .collect();
            (nums[0], nums[1])
        };

    let mut env = BTreeMap::new();
    env.insert(
        "ACTIVE_DIR".to_owned(),
        active_dir.to_str().unwrap().to_owned(),
    );
    env.insert(
        "PEAK_FILE".to_owned(),
        peak_file.to_str().unwrap().to_owned(),
    );
    env.insert(
        "PIDS_FILE".to_owned(),
        pids_file.to_str().unwrap().to_owned(),
    );
    env.insert("LOCK_DIR".to_owned(), lock_dir.to_str().unwrap().to_owned());

    let max_cap = 4usize;
    let stdio_up = Arc::new(
        StdioUpstream::with_limits(
            StdioUpstreamSettings {
                command: python_executable().to_owned(),
                args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                env,
                cwd: Some(tmp.path().to_path_buf()),
                max_sessions: max_cap,
                session_idle_secs: 30,
            },
            ByteBudget::new(16 * 1024 * 1024),
            StdioLimits {
                pressure_idle: Duration::from_millis(60),
                ..StdioLimits::default()
            },
        )
        .unwrap(),
    );
    let up_ref = Arc::clone(&stdio_up);
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&up_ref);
        async move {
            let grant = req
                .headers()
                .get("x-test-grant")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("grant-burst")
                .to_owned();
            up.handle_mcp(req, &make_token(&grant, 0)).await
        }
    })
    .await;

    let client = make_client();
    let mut initial_sids = Vec::new();
    for i in 0..max_cap {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        json!({"jsonrpc":"2.0","id":i + 1,"method":"initialize","params":{}})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        initial_sids.push(
            resp.headers()
                .get("mcp-session-id")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned(),
        );
        let _ = resp.into_body().collect().await.unwrap();
    }

    // Age all 4 initial sessions past pressure_idle (60 ms), then fire 8 concurrent initializes.
    tokio::time::sleep(Duration::from_millis(85)).await;
    let mut burst = tokio::task::JoinSet::new();
    for i in 0..8usize {
        let c = client.clone();
        burst.spawn(async move {
            let resp = c
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            json!({"jsonrpc":"2.0","id":100 + i,"method":"initialize","params":{}})
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let sid = resp
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let _ = resp.into_body().collect().await.unwrap();
            (status, sid)
        });
    }

    let mut new_sids = Vec::new();
    let mut rejected = 0usize;
    while let Some(res) = burst.join_next().await {
        let (status, sid) = res.unwrap();
        if status == StatusCode::OK {
            new_sids.push(sid.unwrap());
        } else {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            rejected += 1;
        }
    }
    assert_eq!(
        new_sids.len(),
        max_cap,
        "each of the 4 idle victims must be claimed once without slot stealing"
    );
    assert_eq!(rejected, 4);

    // Every initial victim must now return 404.
    for old_sid in &initial_sids {
        let r = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", old_sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let _ = r.into_body().collect().await.unwrap();
    }

    // Refresh the 3 kept sessions (< 60 ms), start DELETE on new_sids[0] (140 ms reap), and fire 2 concurrent initializes.
    for keep_sid in &new_sids[1..] {
        let r = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", keep_sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x","arguments":{}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let _ = r.into_body().collect().await.unwrap();
    }

    let c_del = client.clone();
    let del_sid = new_sids[0].clone();
    let del_task = tokio::spawn(async move {
        let resp = c_del
            .request(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", del_sid)
                    .body(empty_body())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await.unwrap();
    });

    // Wait until DELETE has removed del_sid from tbl.sessions (404) while its 140 ms reap is still in terminating_slots.
    let del_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let probe = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", &new_sids[0])
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x","arguments":{}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let st = probe.status();
        let _ = probe.into_body().collect().await.unwrap();
        if st == StatusCode::NOT_FOUND {
            break;
        }
        assert!(tokio::time::Instant::now() < del_deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut race_inits = tokio::task::JoinSet::new();
    for k in 0..2usize {
        let c = client.clone();
        race_inits.spawn(async move {
            let resp = c
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("x-test-grant", "grant-other")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            json!({"jsonrpc":"2.0","id":300 + k,"method":"initialize","params":{}})
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let st = resp.status();
            let _ = resp.into_body().collect().await.unwrap();
            st
        });
    }
    let mut del_ok = 0usize;
    let mut del_503 = 0usize;
    while let Some(res) = race_inits.join_next().await {
        match res.unwrap() {
            StatusCode::OK => del_ok += 1,
            StatusCode::SERVICE_UNAVAILABLE => del_503 += 1,
            other => panic!("unexpected status: {other}"),
        }
    }
    del_task.await.unwrap();
    assert_eq!(del_ok, 1);
    assert_eq!(del_503, 1);

    let (cur_live, peak_live) = probe_watermark(&active_dir, &peak_file, &pids_file, &lock_dir);
    assert_eq!(cur_live, max_cap);
    assert!(
        peak_live <= max_cap,
        "peak simultaneous live child count {peak_live} exceeded max_sessions {max_cap}"
    );

    // Free 1 slot (leaving 3 live sessions in "grant-burst"/"grant-other"), then test mid-flight TCP disconnect
    // during BOTH slow-exit initialize AND slow-exit sessionless non-SSE calls, followed by immediate reconnect bursts!
    let free_one = client
        .request(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", &new_sids[1])
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(free_one.status(), StatusCode::OK);
    let _ = free_one.into_body().collect().await.unwrap();

    // Case A: Mid-initialize TCP disconnect on a child that ignores stdin EOF (requires SIGTERM after STDIN_GRACE_WAIT).
    let init_disc_marker = tmp.path().join("init_disc_ready");
    let init_disc_body = json!({
        "jsonrpc": "2.0",
        "id": 501,
        "method": "initialize",
        "params": { "readyMarker": init_disc_marker.to_str().unwrap() }
    })
    .to_string();
    let mut raw_init_conn = TcpStream::connect(gw_addr).await.unwrap();
    let raw_init_http = format!(
        "POST /mcp HTTP/1.1\r\nHost: {gw_addr}\r\nX-Test-Grant: grant-other\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{init_disc_body}",
        init_disc_body.len()
    );
    raw_init_conn
        .write_all(raw_init_http.as_bytes())
        .await
        .unwrap();
    let marker_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !init_disc_marker.exists() {
        assert!(tokio::time::Instant::now() < marker_deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Abruptly disconnect client TCP while child is blocked inside initialize (and ignores stdin EOF!).
    drop(raw_init_conn);
    tokio::time::sleep(Duration::from_millis(15)).await;

    // Fire 2 concurrent reconnects during the 200 ms STDIN_GRACE_WAIT + SIGTERM window:
    // into_terminating() keeps peak_live <= 4 while waking 1 waiter after reaping finishes (the 2nd gets 503).
    let mut init_abort_race = tokio::task::JoinSet::new();
    for k in 0..2usize {
        let c = client.clone();
        init_abort_race.spawn(async move {
            let resp = c
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("x-test-grant", "grant-third")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            json!({"jsonrpc":"2.0","id":502 + k,"method":"initialize","params":{}})
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let st = resp.status();
            let sid = resp
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let _ = resp.into_body().collect().await.unwrap();
            (st, sid)
        });
    }
    let mut abort_reclaimed_sid = None;
    let mut abort_rejected = 0usize;
    while let Some(res) = init_abort_race.join_next().await {
        let (st, sid) = res.unwrap();
        if st == StatusCode::OK {
            abort_reclaimed_sid = sid;
        } else {
            assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
            abort_rejected += 1;
        }
    }
    let abort_reclaimed_sid =
        abort_reclaimed_sid.expect("one reconnect must wake and claim the reaped handshake slot");
    assert_eq!(abort_rejected, 1);

    // Free that reclaimed 4th slot again so cur_live returns to 3 before Case B.
    let free_reclaimed = client
        .request(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("x-test-grant", "grant-third")
                .header("mcp-session-id", abort_reclaimed_sid)
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(free_reclaimed.status(), StatusCode::OK);
    let _ = free_reclaimed.into_body().collect().await.unwrap();

    // Case B: Mid-sessionless (non-SSE) TCP disconnect on a child that ignores stdin EOF, followed by immediate reconnects.
    let sl_disc_marker = tmp.path().join("sessionless_disc_ready");
    let sl_disc_body = json!({
        "jsonrpc": "2.0",
        "id": 601,
        "method": "tools/call",
        "params": {
            "name": "slow_tool",
            "arguments": { "readyMarker": sl_disc_marker.to_str().unwrap() }
        }
    })
    .to_string();
    let mut raw_sl_conn = TcpStream::connect(gw_addr).await.unwrap();
    let raw_sl_http = format!(
        "POST /mcp HTTP/1.1\r\nHost: {gw_addr}\r\nX-Test-Grant: grant-other\r\nMCP-Protocol-Version: 2026-07-28\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{sl_disc_body}",
        sl_disc_body.len()
    );
    raw_sl_conn.write_all(raw_sl_http.as_bytes()).await.unwrap();
    let sl_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !sl_disc_marker.exists() {
        assert!(tokio::time::Instant::now() < sl_deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    drop(raw_sl_conn);
    tokio::time::sleep(Duration::from_millis(15)).await;

    let mut sl_abort_race = tokio::task::JoinSet::new();
    for k in 0..2usize {
        let c = client.clone();
        sl_abort_race.spawn(async move {
            let resp = c
                .request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("http://{gw_addr}/mcp"))
                        .header("x-test-grant", "grant-third")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(bytes_body(
                            json!({"jsonrpc":"2.0","id":602 + k,"method":"initialize","params":{}})
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let st = resp.status();
            let _ = resp.into_body().collect().await.unwrap();
            st
        });
    }
    let mut sl_ok = 0usize;
    let mut sl_503 = 0usize;
    while let Some(res) = sl_abort_race.join_next().await {
        match res.unwrap() {
            StatusCode::OK => sl_ok += 1,
            StatusCode::SERVICE_UNAVAILABLE => sl_503 += 1,
            other => panic!("unexpected status: {other}"),
        }
    }
    assert_eq!(sl_ok, 1);
    assert_eq!(sl_503, 1);

    stdio_up.shutdown().await;
    gw_cancel.cancel();

    let (final_cur, final_peak) = probe_watermark(&active_dir, &peak_file, &pids_file, &lock_dir);
    assert_eq!(final_cur, 0);
    assert_eq!(final_peak, max_cap);
    for pid_line in std::fs::read_to_string(&pids_file).unwrap().lines() {
        if let Ok(pid) = pid_line.trim().parse::<u32>() {
            assert!(
                !process_exists(pid),
                "spawned child pid {pid} still alive after shutdown"
            );
        }
    }

    // Case C: Under max_sessions = 1, back-to-back serial SSE sessionless calls (Accept: application/json, text/event-stream)
    // wait on terminating_slots (140 ms reap) and BOTH succeed with 200 OK while keeping peak_live == 1.
    let sse_active_dir = tmp.path().join("sse_active_pids");
    std::fs::create_dir_all(&sse_active_dir).unwrap();
    let sse_peak_file = tmp.path().join("sse_serial_watermark.txt");
    std::fs::write(&sse_peak_file, "0 0").unwrap();
    let sse_pids_file = tmp.path().join("sse_spawned_pids.txt");
    std::fs::write(&sse_pids_file, "").unwrap();
    let sse_lock = tmp.path().join("sse_serial_lock");
    let mut sse_env = BTreeMap::new();
    sse_env.insert(
        "ACTIVE_DIR".to_owned(),
        sse_active_dir.to_str().unwrap().to_owned(),
    );
    sse_env.insert(
        "PEAK_FILE".to_owned(),
        sse_peak_file.to_str().unwrap().to_owned(),
    );
    sse_env.insert(
        "PIDS_FILE".to_owned(),
        sse_pids_file.to_str().unwrap().to_owned(),
    );
    sse_env.insert("LOCK_DIR".to_owned(), sse_lock.to_str().unwrap().to_owned());

    let sse_up = Arc::new(
        StdioUpstream::with_limits(
            StdioUpstreamSettings {
                command: python_executable().to_owned(),
                args: vec!["-u".to_owned(), script.to_str().unwrap().to_owned()],
                env: sse_env,
                cwd: Some(tmp.path().to_path_buf()),
                max_sessions: 1,
                session_idle_secs: 30,
            },
            ByteBudget::new(8 * 1024 * 1024),
            StdioLimits::default(),
        )
        .unwrap(),
    );
    let sse_ref = Arc::clone(&sse_up);
    let (sse_gw_addr, sse_gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&sse_ref);
        async move { up.handle_mcp(req, &make_token("grant-sse-serial", 0)).await }
    })
    .await;

    for call_id in [701u64, 702u64] {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{sse_gw_addr}/mcp"))
                    .header("mcp-protocol-version", "2026-07-28")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        json!({
                            "jsonrpc": "2.0",
                            "id": call_id,
                            "method": "tools/call",
                            "params": { "name": "fast_sse", "arguments": {} }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "serial SSE sessionless call {call_id} must wait for prior ephemeral reap instead of returning 503"
        );
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );
        let body_text = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(body_text.contains(&format!("\"id\":{call_id}")));
    }

    sse_up.shutdown().await;
    sse_gw_cancel.cancel();

    let (sse_cur, sse_peak) =
        probe_watermark(&sse_active_dir, &sse_peak_file, &sse_pids_file, &sse_lock);
    assert_eq!(sse_cur, 0);
    assert_eq!(sse_peak, 1);
    for pid_line in std::fs::read_to_string(&sse_pids_file).unwrap().lines() {
        if let Ok(pid) = pid_line.trim().parse::<u32>() {
            assert!(
                !process_exists(pid),
                "SSE sessionless child pid {pid} still alive after shutdown"
            );
        }
    }
}

#[tokio::test]
async fn http_session_eviction_protects_inflight_post_closes_idle_get_and_cleans_overflow() {
    type StreamTx = tokio::sync::mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>;

    let next_sid = Arc::new(AtomicUsize::new(0));
    let deleted_sids: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let delete_notify = Arc::new(tokio::sync::Notify::new());
    let held_post_streams: Arc<Mutex<Vec<(String, StreamTx)>>> = Arc::new(Mutex::new(Vec::new()));
    let held_post_notify = Arc::new(tokio::sync::Notify::new());
    let held_get_streams: Arc<Mutex<Vec<(String, StreamTx)>>> = Arc::new(Mutex::new(Vec::new()));

    let next_sid_up = Arc::clone(&next_sid);
    let deleted_up = Arc::clone(&deleted_sids);
    let delete_notify_up = Arc::clone(&delete_notify);
    let held_post_up = Arc::clone(&held_post_streams);
    let held_post_notify_up = Arc::clone(&held_post_notify);
    let held_get_up = Arc::clone(&held_get_streams);

    let (up_addr, up_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let next_sid = Arc::clone(&next_sid_up);
        let deleted = Arc::clone(&deleted_up);
        let delete_notify = Arc::clone(&delete_notify_up);
        let held_post = Arc::clone(&held_post_up);
        let held_post_notify = Arc::clone(&held_post_notify_up);
        let held_get = Arc::clone(&held_get_up);
        async move {
            let method = req.method().clone();
            let req_sid = req
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let mode = req
                .headers()
                .get("x-test-mode")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let body_bytes = req.into_body().collect().await.unwrap().to_bytes();

            if method == Method::DELETE {
                if let Some(sid) = req_sid {
                    deleted.lock().unwrap().push(sid);
                    delete_notify.notify_waiters();
                }
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(empty_body())
                    .unwrap();
            }

            if method == Method::GET {
                let sid = req_sid.unwrap_or_default();
                let (tx, body) = channel_body(8);
                let _ = tx
                    .send(Ok(Frame::data(Bytes::from_static(
                        b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n",
                    ))))
                    .await;
                held_get.lock().unwrap().push((sid.clone(), tx));
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .header("mcp-session-id", sid)
                    .body(body)
                    .unwrap();
            }

            let val: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|_| json!({}));
            if val.get("method").and_then(Value::as_str) == Some("initialize") {
                let idx = next_sid.fetch_add(1, Ordering::Relaxed);
                let sid = format!("sid-{idx}");
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("mcp-session-id", sid)
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{}}}"#,
                    ))
                    .unwrap();
            }

            let sid = req_sid.unwrap_or_default();
            if mode == "hold_post" {
                let (tx, body) = channel_body(8);
                let _ = tx
                    .send(Ok(Frame::data(Bytes::from_static(
                        b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n",
                    ))))
                    .await;
                held_post.lock().unwrap().push((sid.clone(), tx));
                held_post_notify.notify_waiters();
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .header("mcp-session-id", sid)
                    .body(body)
                    .unwrap();
            }

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header("mcp-session-id", sid)
                .body(bytes_body(r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#))
                .unwrap()
        }
    })
    .await;

    let settings = HttpUpstreamSettings {
        url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
        origin_base: Url::parse(&format!("http://{up_addr}")).unwrap(),
        public_is_https: false,
        bearer_tokens: Vec::new(),
        passthrough_prefixes: Vec::new(),
        request_timeout_secs: 30,
    };
    let http_up = Arc::new(HttpUpstream::new(settings).unwrap());
    let up_ref = Arc::clone(&http_up);
    let (gw_addr, gw_cancel) = spawn_http1_harness(move |req: Request<Incoming>| {
        let up = Arc::clone(&up_ref);
        async move { up.handle_mcp(req, &make_token("grant-http", 0)).await }
    })
    .await;

    let client = make_client();

    // 1. Fill all 32 per-grant session slots: sid-0 .. sid-31.
    let mut sids = Vec::new();
    for _ in 0..32 {
        let resp = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let sid = resp
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let _ = resp.into_body().collect().await.unwrap();
        sids.push(sid);
    }
    assert_eq!(sids[0], "sid-0");
    assert_eq!(sids[1], "sid-1");
    assert_eq!(sids[31], "sid-31");

    // 2. Start an in-flight streaming POST on sid-0 (oldest session) and read its first SSE frame.
    let mut sid0_post_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", "sid-0")
                .header("x-test-mode", "hold_post")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"long"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sid0_post_resp.status(), StatusCode::OK);
    let first_post_frame = sid0_post_resp.body_mut().frame().await.unwrap().unwrap();
    assert!(!first_post_frame.into_data().unwrap().is_empty());

    // 3. Open an idle background GET SSE listener stream on sid-1 (active_post_streams == 0).
    let mut sid1_get_resp = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", "sid-1")
                .header(header::ACCEPT, "text/event-stream")
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sid1_get_resp.status(), StatusCode::OK);
    let first_get_frame = sid1_get_resp.body_mut().frame().await.unwrap().unwrap();
    assert!(!first_get_frame.into_data().unwrap().is_empty());

    // 4. Send a completed POST on sid-2 echoing Mcp-Session-Id: sid-2 (verifying deduplicated bind_session).
    let echo_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", "sid-2")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"fast"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(echo_resp.status(), StatusCode::OK);
    let _ = echo_resp.into_body().collect().await.unwrap();

    // 5. Create 33rd session (sid-32): must skip sid-0 (active POST) and evict sid-1 (idle GET)!
    let del_wait = delete_notify.notified();
    tokio::pin!(del_wait);
    del_wait.as_mut().enable();

    let resp32 = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp32.status(), StatusCode::OK);
    let sid32 = resp32
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(sid32, "sid-32");
    let _ = resp32.into_body().collect().await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), &mut del_wait)
        .await
        .expect("evicted sid-1 DELETE must arrive");
    assert_eq!(deleted_sids.lock().unwrap().as_slice(), &["sid-1"]);

    // sid-1's open GET SSE stream must terminate promptly via per-session CancellationToken.
    let get_end = tokio::time::timeout(Duration::from_secs(2), sid1_get_resp.body_mut().frame())
        .await
        .expect("evicted session GET SSE stream must not hang");
    assert!(
        get_end.is_none() || get_end.unwrap().is_err(),
        "expected closed/aborted GET stream on evicted sid-1"
    );

    // sid-1 is now 404, whereas sid-0's in-flight POST stream continues uninterrupted!
    let sid1_after = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", "sid-1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"fast"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sid1_after.status(), StatusCode::NOT_FOUND);
    let _ = sid1_after.into_body().collect().await.unwrap();

    // 6. Now open active POST streams on the remaining 31 bound sessions (sid-2 .. sid-32) so ALL 32 have active_post_streams == 1.
    let mut active_post_resps = vec![sid0_post_resp];
    for idx in 2..=32 {
        let sid = format!("sid-{idx}");
        let mut r = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{gw_addr}/mcp"))
                    .header("mcp-session-id", sid)
                    .header("x-test-mode", "hold_post")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes_body(
                        r#"{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"long"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let f = r.body_mut().frame().await.unwrap().unwrap();
        assert!(!f.into_data().unwrap().is_empty());
        active_post_resps.push(r);
    }
    assert_eq!(active_post_resps.len(), 32);

    // 7. 34th initialize (upstream mints sid-33) while all 32 slots have active POSTs -> 503 + upstream DELETE sid-33!
    let overflow_del_wait = delete_notify.notified();
    tokio::pin!(overflow_del_wait);
    overflow_del_wait.as_mut().enable();

    let resp33 = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp33.status(), StatusCode::SERVICE_UNAVAILABLE);
    let _ = resp33.into_body().collect().await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), &mut overflow_del_wait)
        .await
        .expect("excess sid-33 must receive upstream DELETE cleanup");
    assert_eq!(
        deleted_sids.lock().unwrap().as_slice(),
        &["sid-1", "sid-33"]
    );

    // Finish all 32 in-flight POST streams cleanly and verify sid-0 still works afterwards.
    let senders: Vec<(String, StreamTx)> = std::mem::take(&mut *held_post_streams.lock().unwrap());
    assert_eq!(senders.len(), 32);
    for (_, tx) in senders {
        let _ = tx
            .send(Ok(Frame::data(Bytes::from_static(
                b"data: {\"jsonrpc\":\"2.0\",\"id\":20,\"result\":{\"done\":true}}\n\n",
            ))))
            .await;
        drop(tx);
    }
    for resp in active_post_resps {
        let tail = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            std::str::from_utf8(&tail)
                .unwrap()
                .contains("\"done\":true")
        );
    }

    let sid0_check = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/mcp"))
                .header("mcp-session-id", "sid-0")
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes_body(
                    r#"{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"fast"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sid0_check.status(), StatusCode::OK);
    let _ = sid0_check.into_body().collect().await.unwrap();

    held_get_streams.lock().unwrap().clear();
    http_up.shutdown().await;
    gw_cancel.cancel();
    up_cancel.cancel();
}
