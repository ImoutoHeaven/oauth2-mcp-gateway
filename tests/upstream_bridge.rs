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
use oauth2_mcp_gateway::types::{VerifiedToken, bytes_body, empty_body};
use oauth2_mcp_gateway::upstream_http::HttpUpstream;
use oauth2_mcp_gateway::upstream_stdio::StdioUpstream;
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
