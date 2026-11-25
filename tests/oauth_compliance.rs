use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use http_body::Frame;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper_util::rt::TokioIo;
use oauth2_mcp_gateway::config::GatewayConfig;
use oauth2_mcp_gateway::crypto::{PasswordVerifier, hmac_sha256, sha256_b64};
use oauth2_mcp_gateway::oauth::OAuthEngine;
use oauth2_mcp_gateway::store::{
    AccessTokenRecord, GraceRefreshRecord, GrantRecord, PersistedState, RefreshTokenRecord,
    STATE_VERSION, unix_now,
};
use oauth2_mcp_gateway::types::AuthChallenge;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::Barrier;
use url::Url;

const OWNER_SECRET: &str = "owner-battery-horse-staple-99";

struct TestOpts<'a> {
    public_url: &'a str,
    resource_path: Option<&'a str>,
    allowed_hosts: &'a [&'a str],
    scopes: &'a [&'a str],
    bearer_tokens: &'a [&'a str],
    refresh_grace_secs: u64,
    refresh_reuse_policy: &'a str,
    max_registered_clients: usize,
}

impl Default for TestOpts<'_> {
    fn default() -> Self {
        Self {
            public_url: "https://mcp.example.com",
            resource_path: None,
            allowed_hosts: &[],
            scopes: &["mcp", "files"],
            bearer_tokens: &["up-slot-0"],
            refresh_grace_secs: 3600,
            refresh_reuse_policy: "converge",
            max_registered_clients: 16,
        }
    }
}

fn build_config(dir: &Path, opts: &TestOpts<'_>) -> Arc<GatewayConfig> {
    let pw_hash = PasswordVerifier::from_plaintext_with_iterations(OWNER_SECRET, 10_000)
        .expect("test hash")
        .encode();
    let mut cfg_json = json!({
        "listen": "127.0.0.1:0",
        "public_url": opts.public_url,
        "state_path": dir.join("state/oauth_state.json").to_string_lossy(),
        "oauth": {
            "owner_password_hash": pw_hash,
            "scopes": opts.scopes,
            "allowed_redirect_hosts": opts.allowed_hosts,
            "access_token_ttl_secs": 3600,
            "refresh_token_ttl_secs": 86400,
            "refresh_grace_secs": opts.refresh_grace_secs,
            "refresh_reuse_policy": opts.refresh_reuse_policy,
            "max_registered_clients": opts.max_registered_clients,
        },
        "upstream": {
            "transport": "http",
            "url": "http://127.0.0.1:9090/mcp",
            "bearer_tokens": opts.bearer_tokens,
        }
    });
    if let Some(path) = opts.resource_path {
        cfg_json["resource_path"] = json!(path);
    }
    Arc::new(
        GatewayConfig::from_json_str(&cfg_json.to_string(), dir).expect("valid gateway config"),
    )
}

async fn dispatch_box_body_with_ip(
    engine: &Arc<OAuthEngine>,
    peer_ip: Option<IpAddr>,
    req: Request<BoxBody<Bytes, Infallible>>,
) -> (StatusCode, HeaderMap, Bytes) {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let eng = Arc::clone(engine);
    let srv_task = tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |mut incoming| {
            let eng = Arc::clone(&eng);
            if let Some(ip) = peer_ip {
                incoming.extensions_mut().insert(ip);
            }
            async move { Ok::<_, Infallible>(eng.handle(incoming).await) }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(server_io), svc)
            .await;
    });

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .expect("client handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender.send_request(req).await.expect("send_request");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();

    drop(sender);
    let _ = conn_task.await;
    let _ = srv_task.await;
    (status, headers, body)
}

async fn dispatch_box_body(
    engine: &Arc<OAuthEngine>,
    req: Request<BoxBody<Bytes, Infallible>>,
) -> (StatusCode, HeaderMap, Bytes) {
    dispatch_box_body_with_ip(engine, None, req).await
}

async fn send_req_from_ip(
    engine: &Arc<OAuthEngine>,
    peer_ip: Option<IpAddr>,
    method: Method,
    uri: &str,
    extra_headers: &[(&str, &str)],
    body: impl Into<Bytes>,
) -> (StatusCode, HeaderMap, Bytes) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let boxed = Full::new(body.into()).boxed();
    let req = builder.body(boxed).expect("build request");
    dispatch_box_body_with_ip(engine, peer_ip, req).await
}

async fn send_req(
    engine: &Arc<OAuthEngine>,
    method: Method,
    uri: &str,
    extra_headers: &[(&str, &str)],
    body: impl Into<Bytes>,
) -> (StatusCode, HeaderMap, Bytes) {
    send_req_from_ip(engine, None, method, uri, extra_headers, body).await
}

fn parse_json(bytes: &Bytes) -> Value {
    serde_json::from_slice(bytes).expect("response is valid JSON")
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}

fn pkce_pair(seed: &str) -> (String, String) {
    let verifier = format!("pkce-verifier-{seed:0<40}");
    let challenge = sha256_b64(&verifier);
    (verifier, challenge)
}

fn extract_hidden_input(html: &str, field_name: &str) -> String {
    let marker = format!("name=\"{field_name}\" value=\"");
    let start = html.find(&marker).expect("hidden input present") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("closing quote");
    rest[..end].to_owned()
}

fn extract_cookie_pair(headers: &HeaderMap) -> String {
    let raw = headers
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header present")
        .to_str()
        .expect("ASCII Set-Cookie");
    raw.split(';').next().unwrap().to_owned()
}

async fn register_public_client(
    engine: &Arc<OAuthEngine>,
    redirect_uri: &str,
    client_name: Option<&str>,
) -> String {
    let mut payload = json!({
        "redirect_uris": [redirect_uri],
    });
    if let Some(name) = client_name {
        payload["client_name"] = json!(name);
    }
    let (status, _, body) = send_req(
        engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        payload.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    parse_json(&body)["client_id"]
        .as_str()
        .expect("client_id string")
        .to_owned()
}

async fn authorize_and_get_code(
    engine: &Arc<OAuthEngine>,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
) -> String {
    let query = form_encode(&[
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
    ]);
    let (status, headers, body) = send_req(
        engine,
        Method::GET,
        &format!("/oauth/authorize?{query}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cookie_pair = extract_cookie_pair(&headers);
    let html = std::str::from_utf8(&body).expect("utf8 html");
    let ar_id = extract_hidden_input(html, "ar_id");
    let csrf_token = extract_hidden_input(html, "csrf_token");

    let post_body = form_encode(&[
        ("ar_id", &ar_id),
        ("csrf_token", &csrf_token),
        ("password", OWNER_SECRET),
    ]);
    let (p_status, p_headers, _) = send_req(
        engine,
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie_pair),
        ],
        post_body,
    )
    .await;
    assert_eq!(p_status, StatusCode::SEE_OTHER);
    let clear_cookie = p_headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(clear_cookie.contains("Max-Age=0"));

    let loc = p_headers.get(header::LOCATION).unwrap().to_str().unwrap();
    let parsed = Url::parse(loc).expect("valid redirect URL");
    let qmap: BTreeMap<String, String> = parsed.query_pairs().into_owned().collect();
    assert_eq!(qmap.get("state").map(String::as_str), Some(state));
    assert_eq!(
        qmap.get("iss").map(String::as_str),
        Some("https://mcp.example.com")
    );
    qmap.get("code").expect("code present").clone()
}

async fn mint_public_grant(
    engine: &Arc<OAuthEngine>,
    client_id: &str,
    redirect_uri: &str,
    seed: &str,
) -> (String, String) {
    let (verifier, challenge) = pkce_pair(seed);
    let code = authorize_and_get_code(engine, client_id, redirect_uri, &challenge, seed).await;
    let body = form_encode(&[
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", &code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", &verifier),
    ]);
    let (status, _, resp_bytes) = send_req(
        engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let val = parse_json(&resp_bytes);
    (
        val["access_token"].as_str().unwrap().to_owned(),
        val["refresh_token"].as_str().unwrap().to_owned(),
    )
}

struct ChunkStream {
    chunks: Vec<Bytes>,
    pos: usize,
    stall_after_chunks: bool,
}

impl ChunkStream {
    fn new(chunks: Vec<Bytes>) -> Self {
        Self {
            chunks,
            pos: 0,
            stall_after_chunks: false,
        }
    }
}

struct StreamAdapter(ChunkStream);

impl http_body::Body for StreamAdapter {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.0.pos >= self.0.chunks.len() {
            return if self.0.stall_after_chunks {
                Poll::Pending
            } else {
                Poll::Ready(None)
            };
        }
        let idx = self.0.pos;
        self.0.pos += 1;
        Poll::Ready(Some(Ok(Frame::data(self.0.chunks[idx].clone()))))
    }
}

#[tokio::test]
async fn incomplete_oauth_body_releases_its_connection() {
    let tmp = TempDir::new().unwrap();
    let engine = OAuthEngine::open(build_config(tmp.path(), &TestOpts::default())).unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(
            StreamAdapter(ChunkStream {
                chunks: vec![Bytes::from_static(b"grant_type=")],
                pos: 0,
                stall_after_chunks: true,
            })
            .boxed(),
        )
        .unwrap();
    let (status, headers, _) =
        tokio::time::timeout(Duration::from_secs(15), dispatch_box_body(&engine, req))
            .await
            .expect("gateway should time out the incomplete OAuth request");
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(headers[header::CONNECTION], "close");
}

#[tokio::test]
async fn custom_resource_path_drives_oauth_discovery_and_token_binding() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(
        tmp.path(),
        &TestOpts {
            resource_path: Some("/bridge/oauth2"),
            ..Default::default()
        },
    );
    let engine = OAuthEngine::open(cfg).unwrap();
    assert_eq!(engine.resource_path(), "/bridge/oauth2");
    let challenge = engine.unauthorized_reply(AuthChallenge::MissingToken);
    assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge.headers()[header::WWW_AUTHENTICATE],
        "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/bridge/oauth2\""
    );
    for (path, expected) in [
        ("/.well-known/oauth-protected-resource", StatusCode::OK),
        (
            "/.well-known/oauth-protected-resource/bridge/oauth2",
            StatusCode::OK,
        ),
        (
            "/.well-known/oauth-protected-resource/mcp",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, _, body) = send_req(&engine, Method::GET, path, &[], Bytes::new()).await;
        assert_eq!(status, expected, "{path}");
        if status == StatusCode::OK {
            assert_eq!(
                parse_json(&body)["resource"],
                "https://mcp.example.com/bridge/oauth2"
            );
        }
    }
    for (path, expected) in [
        ("/.well-known/oauth-authorization-server", StatusCode::OK),
        (
            "/.well-known/oauth-authorization-server/bridge/oauth2",
            StatusCode::OK,
        ),
        (
            "/.well-known/oauth-authorization-server/mcp",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, _, body) = send_req(&engine, Method::GET, path, &[], Bytes::new()).await;
        assert_eq!(status, expected, "{path}");
        if status == StatusCode::OK {
            assert_eq!(parse_json(&body)["issuer"], "https://mcp.example.com");
        }
    }
    let redirect = "http://127.0.0.1:19000/cb";
    let client = register_public_client(&engine, redirect, None).await;
    let (access, refresh) = mint_public_grant(&engine, &client, redirect, "custom-resource").await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {access}")).unwrap(),
    );
    let verified = engine.verify_bearer(&headers).expect("valid access token");
    assert_eq!(verified.resource, "https://mcp.example.com/bridge/oauth2");

    drop(engine);
    let engine = OAuthEngine::open(build_config(tmp.path(), &TestOpts::default())).unwrap();
    assert_eq!(
        engine.verify_bearer(&headers),
        Err(AuthChallenge::InvalidToken)
    );
    let (status, _, body) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client),
            ("refresh_token", &refresh),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&body)["error"], "invalid_grant");
}

#[tokio::test]
async fn metadata_rfc9728_and_rfc8414_subpaths_and_body_limits() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(tmp.path(), &TestOpts::default());
    let engine = OAuthEngine::open(cfg).unwrap();

    assert!(OAuthEngine::handles_path(
        "/.well-known/oauth-protected-resource"
    ));
    assert!(OAuthEngine::handles_path(
        "/.well-known/oauth-protected-resource/mcp"
    ));
    assert!(OAuthEngine::handles_path(
        "/.well-known/oauth-authorization-server"
    ));
    assert!(OAuthEngine::handles_path("/oauth/token"));
    assert!(!OAuthEngine::handles_path("/mcp"));

    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let (status, _, body) = send_req(&engine, Method::GET, path, &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let meta = parse_json(&body);
        assert_eq!(meta["resource"], "https://mcp.example.com/mcp");
        assert_eq!(
            meta["authorization_servers"],
            json!(["https://mcp.example.com"])
        );
        assert_eq!(meta["bearer_methods_supported"], json!(["header"]));
        assert_eq!(meta["scopes_supported"], json!(["mcp", "files"]));
    }

    let (status_404, _, _) = send_req(
        &engine,
        Method::GET,
        "/.well-known/oauth-protected-resource/unknown",
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(status_404, StatusCode::NOT_FOUND);

    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/mcp",
    ] {
        let (status, _, body) = send_req(&engine, Method::GET, path, &[], Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        let as_meta = parse_json(&body);
        assert_eq!(as_meta["issuer"], "https://mcp.example.com");
        assert_eq!(
            as_meta["authorization_endpoint"],
            "https://mcp.example.com/oauth/authorize"
        );
        assert_eq!(
            as_meta["token_endpoint"],
            "https://mcp.example.com/oauth/token"
        );
        assert_eq!(
            as_meta["registration_endpoint"],
            "https://mcp.example.com/oauth/register"
        );
        assert_eq!(
            as_meta["revocation_endpoint"],
            "https://mcp.example.com/oauth/revoke"
        );
        assert_eq!(as_meta["response_modes_supported"], json!(["query"]));
        assert_eq!(as_meta["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(
            as_meta["authorization_response_iss_parameter_supported"],
            true
        );
    }

    let (as_404, _, _) = send_req(
        &engine,
        Method::GET,
        "/.well-known/oauth-authorization-server/other",
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(as_404, StatusCode::NOT_FOUND);

    let oversized = vec![b'x'; 65 * 1024];
    let (lim_status, lim_headers, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        oversized,
    )
    .await;
    assert_eq!(lim_status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(lim_headers[header::CONNECTION], "close");

    let chunked_body = StreamAdapter(ChunkStream::new(vec![
        Bytes::from(vec![b'a'; 40 * 1024]),
        Bytes::from(vec![b'b'; 30 * 1024]),
    ]))
    .boxed();
    let chunked_req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(chunked_body)
        .unwrap();
    let (chunk_status, chunk_headers, _) = dispatch_box_body(&engine, chunked_req).await;
    assert_eq!(chunk_status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(chunk_headers[header::CONNECTION], "close");
}

#[tokio::test]
async fn dcr_redirect_whitelist_and_idle_client_eviction() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(
        tmp.path(),
        &TestOpts {
            allowed_hosts: &["claude.ai", "chatgpt.com"],
            max_registered_clients: 16,
            ..TestOpts::default()
        },
    );
    let engine = OAuthEngine::open(cfg).unwrap();

    let (missing_uris_st, _, missing_uris_b) = send_req(
        &engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        json!({ "client_name": "Missing URIs" }).to_string(),
    )
    .await;
    assert_eq!(missing_uris_st, StatusCode::BAD_REQUEST);
    assert_eq!(
        parse_json(&missing_uris_b)["error"],
        "invalid_client_metadata"
    );

    for bad_meta in [
        json!({ "redirect_uris": ["http://127.0.0.1:8000/cb"], "client_name": "Bidi\u{202E}Spoof" }),
        json!({ "redirect_uris": ["http://127.0.0.1:8000/cb"], "client_name": "ZeroWidth\u{200B}Name" }),
        json!({ "redirect_uris": ["http://127.0.0.1:8000/cb"], "client_name": "\u{FEFF}BomName" }),
        json!({ "redirect_uris": ["http://127.0.0.1:8000/cb"], "scope": "admin" }),
    ] {
        let (st, _, b) = send_req(
            &engine,
            Method::POST,
            "/oauth/register",
            &[("content-type", "application/json")],
            bad_meta.to_string(),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "payload {bad_meta}");
        assert_eq!(parse_json(&b)["error"], "invalid_client_metadata");
    }

    for bad_payload in [
        json!({ "redirect_uris": [] }),
        json!({ "redirect_uris": ["/relative/cb"] }),
        json!({ "redirect_uris": ["http://claude.ai/cb"] }),
        json!({ "redirect_uris": ["https://claude.ai/cb#frag"] }),
        json!({ "redirect_uris": ["https://user:pw@claude.ai/cb"] }),
        json!({ "redirect_uris": ["https://unlisted.example.org/cb"] }),
        json!({ "redirect_uris": ["https://claude.ai/cb?%73tate=old"] }),
        json!({ "redirect_uris": ["https://claude.ai/a/../cb"] }),
        json!({ "redirect_uris": ["https://claude.ai/./cb"] }),
        json!({ "redirect_uris": ["https://claude.ai/a\\b"] }),
        json!({ "redirect_uris": ["http://0x7f000001:8000/cb"] }),
        json!({ "redirect_uris": (0..17).map(|i| format!("http://127.0.0.1:8000/cb/{i}")).collect::<Vec<_>>() }),
    ] {
        let (st, _, b) = send_req(
            &engine,
            Method::POST,
            "/oauth/register",
            &[("content-type", "application/json")],
            bad_payload.to_string(),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "payload {bad_payload}");
        assert_eq!(parse_json(&b)["error"], "invalid_redirect_uri");
    }

    let ok_reg = json!({
        "client_name": "Claude Connector",
        "redirect_uris": [
            "https://Claude.AI/api/mcp/auth_callback",
            "http://127.0.0.1:54321/cb",
            "http://[::1]:54321/cb",
            "http://localhost:54321/cb"
        ],
        "software_id": "extra-rfc7591-field-ignored"
    });
    let (st0, _, b0) = send_req(
        &engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        ok_reg.to_string(),
    )
    .await;
    assert_eq!(st0, StatusCode::CREATED);
    let j0 = parse_json(&b0);
    let client0_id = j0["client_id"].as_str().unwrap().to_owned();
    assert_eq!(j0["token_endpoint_auth_method"], "none");
    assert_eq!(
        j0["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(j0["response_types"], json!(["code"]));

    let (client0_access, _) =
        mint_public_grant(&engine, &client0_id, "http://127.0.0.1:54321/cb", "c0").await;

    let mut idle_ids = Vec::new();
    for i in 1..16 {
        let cid = register_public_client(
            &engine,
            &format!("http://127.0.0.1:50000/cb/{i}"),
            Some(&format!("Idle {i}")),
        )
        .await;
        idle_ids.push(cid);
    }

    let extra_id =
        register_public_client(&engine, "https://chatgpt.com/aip/cb", Some("Extra")).await;
    assert!(!extra_id.is_empty());

    let mut auth_hdr = HeaderMap::new();
    auth_hdr.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {client0_access}")).unwrap(),
    );
    assert!(engine.verify_bearer(&auth_hdr).is_ok());

    let (_, challenge) = pkce_pair("evicted");
    let evicted_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &idle_ids[0]),
        ("redirect_uri", "http://127.0.0.1:50000/cb/1"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let (ev_status, _, _) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{evicted_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(ev_status, StatusCode::BAD_REQUEST);

    for (idx, cid) in idle_ids.iter().enumerate().skip(1) {
        let uri = format!("http://127.0.0.1:50000/cb/{}", idx + 1);
        let _ = mint_public_grant(&engine, cid, &uri, &format!("fill-{idx}")).await;
    }
    let _ = mint_public_grant(&engine, &extra_id, "https://chatgpt.com/aip/cb", "fill-16").await;

    let (full_status, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        json!({ "redirect_uris": ["http://127.0.0.1:60000/cb"] }).to_string(),
    )
    .await;
    assert_eq!(full_status, StatusCode::TOO_MANY_REQUESTS);
    assert!(engine.verify_bearer(&auth_hdr).is_ok());
}

#[tokio::test]
async fn confidential_clients_enforce_pkce_s256_basic_urldecode_and_revocation() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(tmp.path(), &TestOpts::default());
    let engine = OAuthEngine::open(cfg).unwrap();

    let cb_uri = "http://127.0.0.1:18080/callback";
    let (reg_status, _, reg_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        json!({
            "client_name": "Confidential Basic App",
            "redirect_uris": [cb_uri],
            "token_endpoint_auth_method": "client_secret_basic",
        })
        .to_string(),
    )
    .await;
    assert_eq!(reg_status, StatusCode::CREATED);
    let reg_val = parse_json(&reg_body);
    let client_id = reg_val["client_id"].as_str().unwrap().to_owned();
    let client_secret = reg_val["client_secret"].as_str().unwrap().to_owned();

    let no_pkce_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", cb_uri),
        ("state", "pkce-missing"),
    ]);
    let (no_pkce_st, no_pkce_hdr, _) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{no_pkce_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(no_pkce_st, StatusCode::SEE_OTHER);
    let no_pkce_loc = Url::parse(no_pkce_hdr[header::LOCATION].to_str().unwrap()).unwrap();
    let no_pkce_params: BTreeMap<String, String> = no_pkce_loc.query_pairs().into_owned().collect();
    assert_eq!(
        no_pkce_params.get("error").map(String::as_str),
        Some("invalid_request")
    );
    assert_eq!(
        no_pkce_params.get("state").map(String::as_str),
        Some("pkce-missing")
    );
    assert_eq!(
        no_pkce_params.get("iss").map(String::as_str),
        Some("https://mcp.example.com")
    );

    let (verifier, challenge) = pkce_pair("conf-basic");
    let plain_pkce_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", cb_uri),
        ("code_challenge", &verifier),
        ("code_challenge_method", "plain"),
        ("state", "pkce-plain"),
    ]);
    let (plain_st, plain_hdr, _) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{plain_pkce_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(plain_st, StatusCode::SEE_OTHER);
    let plain_loc = Url::parse(plain_hdr[header::LOCATION].to_str().unwrap()).unwrap();
    let plain_params: BTreeMap<String, String> = plain_loc.query_pairs().into_owned().collect();
    assert_eq!(
        plain_params.get("error").map(String::as_str),
        Some("invalid_request")
    );
    assert_eq!(
        plain_params.get("state").map(String::as_str),
        Some("pkce-plain")
    );
    assert_eq!(
        plain_params.get("iss").map(String::as_str),
        Some("https://mcp.example.com")
    );

    let bad_uri_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", "https://attacker.example/steal"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let (bad_uri_st, bad_uri_hdr, _) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{bad_uri_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(bad_uri_st, StatusCode::BAD_REQUEST);
    assert!(!bad_uri_hdr.contains_key(header::LOCATION));

    let bad_scope_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", cb_uri),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("scope", "mcp admin"),
        ("state", "st-scope"),
    ]);
    let (bs_st, bs_hdr, _) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{bad_scope_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(bs_st, StatusCode::SEE_OTHER);
    let bs_loc = Url::parse(bs_hdr.get(header::LOCATION).unwrap().to_str().unwrap()).unwrap();
    let bs_q: BTreeMap<String, String> = bs_loc.query_pairs().into_owned().collect();
    assert_eq!(bs_q.get("error").map(String::as_str), Some("invalid_scope"));
    assert_eq!(bs_q.get("state").map(String::as_str), Some("st-scope"));
    assert_eq!(
        bs_q.get("iss").map(String::as_str),
        Some("https://mcp.example.com")
    );

    let bad_res_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", cb_uri),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("resource", "https://other.example.com/mcp"),
        ("state", "st-res"),
    ]);
    let (br_st, br_hdr, _) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{bad_res_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(br_st, StatusCode::SEE_OTHER);
    let br_loc = Url::parse(br_hdr.get(header::LOCATION).unwrap().to_str().unwrap()).unwrap();
    let br_q: BTreeMap<String, String> = br_loc.query_pairs().into_owned().collect();
    assert_eq!(
        br_q.get("error").map(String::as_str),
        Some("invalid_target")
    );

    let code = authorize_and_get_code(&engine, &client_id, cb_uri, &challenge, "st-ok").await;

    let wrong_basic = STANDARD.encode(format!("{client_id}:wrong-secret"));
    let tok_form = form_encode(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", cb_uri),
        ("code_verifier", &verifier),
        ("resource", "https://mcp.example.com/"),
    ]);
    let (unauth_st, unauth_hdr, unauth_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {wrong_basic}")),
        ],
        tok_form.clone(),
    )
    .await;
    assert_eq!(unauth_st, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth_hdr.get(header::WWW_AUTHENTICATE).unwrap(), "Basic");
    assert_eq!(parse_json(&unauth_body)["error"], "invalid_client");

    let pct_id = format!(
        "%63{}",
        client_id.strip_prefix('c').expect("starts with cli_")
    );
    let first_sec_byte = client_secret.as_bytes()[0];
    let pct_secret = format!("%{first_sec_byte:02X}{}", &client_secret[1..]);
    let encoded_basic = STANDARD.encode(format!("{pct_id}:{pct_secret}"));

    let (tok_st, _, tok_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {encoded_basic}")),
        ],
        tok_form,
    )
    .await;
    assert_eq!(tok_st, StatusCode::OK);
    let tok_json = parse_json(&tok_body);
    let access_token = tok_json["access_token"].as_str().unwrap().to_owned();

    let (rev_unauth, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/revoke",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[("token", &access_token)]),
    )
    .await;
    assert_eq!(rev_unauth, StatusCode::UNAUTHORIZED);

    let (rev_ok, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/revoke",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {encoded_basic}")),
        ],
        form_encode(&[("token", &access_token)]),
    )
    .await;
    assert_eq!(rev_ok, StatusCode::OK);

    let mut hdr = HeaderMap::new();
    hdr.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {access_token}")).unwrap(),
    );
    assert_eq!(engine.verify_bearer(&hdr), Err(AuthChallenge::InvalidToken));

    let (rev_unknown, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/revoke",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {encoded_basic}")),
        ],
        form_encode(&[("token", "nonexistent-token-value")]),
    )
    .await;
    assert_eq!(rev_unknown, StatusCode::OK);
}

#[tokio::test]
async fn xss_escaping_security_headers_and_csrf_cookie_enforcement() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(tmp.path(), &TestOpts::default());
    let engine = OAuthEngine::open(cfg).unwrap();

    let xss_name = "<script>alert(1)</script>\"'&client";
    let cb_uri = "http://127.0.0.1:19000/cb;part,more?x=1&y=2";
    let other_uri = "https://other.example/callback";
    let _other_client = register_public_client(&engine, other_uri, None).await;
    let client_id = register_public_client(&engine, cb_uri, Some(xss_name)).await;
    let (_, challenge) = pkce_pair("xss-csrf");

    let q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", cb_uri),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("state", "csrf-state"),
    ]);
    let (status, headers, body) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let expected_csp =
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'";
    assert_eq!(
        headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
        expected_csp
    );
    let (unregistered_status, unregistered_headers, _) = send_req(
        &engine,
        Method::GET,
        &format!(
            "/oauth/authorize?{}",
            form_encode(&[("client_id", &client_id), ("redirect_uri", other_uri)])
        ),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(unregistered_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        unregistered_headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap(),
        expected_csp
    );
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(
        headers.get(header::REFERRER_POLICY).unwrap(),
        "strict-origin",
        "the consent form must preserve the browser's same-origin POST Origin"
    );

    let html = std::str::from_utf8(&body).unwrap();
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#x27;&amp;client"));
    assert!(html.contains("http://127.0.0.1:19000/cb;part,more?x=1&amp;y=2"));
    assert!(html.contains("https://mcp.example.com/mcp"));
    assert!(html.contains("127.0.0.1"));

    let ar_id = extract_hidden_input(html, "ar_id");
    let csrf_token = extract_hidden_input(html, "csrf_token");
    let cookie_pair = extract_cookie_pair(&headers);

    let raw_set_cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(raw_set_cookie.starts_with(&format!("__Host-mcp_ar_{ar_id}=")));
    assert!(raw_set_cookie.contains("HttpOnly"));
    assert!(raw_set_cookie.contains("SameSite=Lax"));
    assert!(raw_set_cookie.contains("Path=/;"));
    assert!(raw_set_cookie.contains("Max-Age=300"));
    assert!(raw_set_cookie.contains("Secure"));

    let valid_form = form_encode(&[
        ("ar_id", &ar_id),
        ("csrf_token", &csrf_token),
        ("password", OWNER_SECRET),
    ]);
    let (retry_status, retry_headers, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie_pair),
        ],
        form_encode(&[
            ("ar_id", &ar_id),
            ("csrf_token", &csrf_token),
            ("password", "wrong-password"),
        ]),
    )
    .await;
    assert_eq!(retry_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        retry_headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
        expected_csp
    );
    assert_eq!(
        retry_headers.get(header::REFERRER_POLICY).unwrap(),
        "strict-origin",
        "the password retry form must preserve the browser's same-origin POST Origin"
    );

    let (no_cookie_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/authorize",
        &[("content-type", "application/x-www-form-urlencoded")],
        valid_form.clone(),
    )
    .await;
    assert_eq!(no_cookie_st, StatusCode::FORBIDDEN);

    let (bad_cookie_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &format!("__Host-mcp_ar_{ar_id}=forged")),
        ],
        valid_form.clone(),
    )
    .await;
    assert_eq!(bad_cookie_st, StatusCode::FORBIDDEN);

    let forged_form = form_encode(&[
        ("ar_id", &ar_id),
        ("csrf_token", "forged-token"),
        ("password", OWNER_SECRET),
    ]);
    let (bad_form_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie_pair),
        ],
        forged_form,
    )
    .await;
    assert_eq!(bad_form_st, StatusCode::FORBIDDEN);

    let tossed_cookies = format!("__Host-mcp_ar_{ar_id}=forged; {cookie_pair}");
    let (ok_st, completed_headers, completed_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &tossed_cookies),
            ("sec-fetch-mode", "NaViGaTe"),
        ],
        valid_form.clone(),
    )
    .await;
    assert_eq!(ok_st, StatusCode::OK);
    assert_eq!(
        completed_headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap(),
        expected_csp
    );
    assert_eq!(
        completed_headers.get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert!(completed_headers.get(header::LOCATION).is_none());
    let completed_html = std::str::from_utf8(&completed_body).unwrap();
    assert!(
        completed_html
            .contains("content=\"0;url=http://127.0.0.1:19000/cb;part,more?x=1&amp;y=2&amp;code=")
    );
    assert!(completed_html.contains("&amp;state=csrf-state"));
    assert!(!completed_html.contains(other_uri));
    assert!(!completed_html.contains(OWNER_SECRET));

    let (reused_ar_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie_pair),
        ],
        valid_form,
    )
    .await;
    assert_eq!(reused_ar_st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_code_replay_immediately_revokes_issued_grant() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(tmp.path(), &TestOpts::default());
    let engine = OAuthEngine::open(cfg).unwrap();

    let cb_uri = "http://127.0.0.1:21000/cb";
    let client_id = register_public_client(&engine, cb_uri, Some("Replay Test")).await;
    let (verifier, challenge) = pkce_pair("code-replay");
    let code = authorize_and_get_code(&engine, &client_id, cb_uri, &challenge, "st-1").await;

    let token_req_body = form_encode(&[
        ("grant_type", "authorization_code"),
        ("client_id", &client_id),
        ("code", &code),
        ("redirect_uri", cb_uri),
        ("code_verifier", &verifier),
    ]);
    let (first_st, _, first_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        token_req_body.clone(),
    )
    .await;
    assert_eq!(first_st, StatusCode::OK);
    let first_json = parse_json(&first_body);
    let access_token = first_json["access_token"].as_str().unwrap();
    let refresh_token = first_json["refresh_token"].as_str().unwrap();

    let mut hdr = HeaderMap::new();
    hdr.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("bEaReR {access_token}")).unwrap(),
    );
    assert!(engine.verify_bearer(&hdr).is_ok());

    let (second_st, _, second_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        token_req_body,
    )
    .await;
    assert_eq!(second_st, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&second_body)["error"], "invalid_grant");

    assert_eq!(engine.verify_bearer(&hdr), Err(AuthChallenge::InvalidToken));

    let (rt_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", refresh_token),
        ]),
    )
    .await;
    assert_eq!(rt_st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ten_concurrent_refreshes_converge_and_post_grace_replay_revokes_all() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(
        tmp.path(),
        &TestOpts {
            refresh_grace_secs: 2,
            refresh_reuse_policy: "revoke",
            ..TestOpts::default()
        },
    );
    let engine = OAuthEngine::open(cfg).unwrap();

    let cb_uri = "http://127.0.0.1:22000/cb";
    let client_id = register_public_client(&engine, cb_uri, Some("Swarm Agent")).await;
    let (a0, r0) = mint_public_grant(&engine, &client_id, cb_uri, "swarm-0").await;

    let barrier = Arc::new(Barrier::new(10));
    let mut handles = Vec::with_capacity(10);
    for _ in 0..10 {
        let eng = Arc::clone(&engine);
        let bar = Arc::clone(&barrier);
        let cid = client_id.clone();
        let rt = r0.clone();
        handles.push(tokio::spawn(async move {
            let payload = form_encode(&[
                ("grant_type", "refresh_token"),
                ("client_id", &cid),
                ("refresh_token", &rt),
            ]);
            bar.wait().await;
            send_req(
                &eng,
                Method::POST,
                "/oauth/token",
                &[("content-type", "application/x-www-form-urlencoded")],
                payload,
            )
            .await
        }));
    }

    let mut pairs = Vec::with_capacity(10);
    for handle in handles {
        let (st, _, b) = handle.await.expect("join refresh task");
        assert_eq!(st, StatusCode::OK);
        let val = parse_json(&b);
        pairs.push((
            val["access_token"].as_str().unwrap().to_owned(),
            val["refresh_token"].as_str().unwrap().to_owned(),
        ));
    }

    let (ref a1, ref r1) = pairs[0];
    assert_ne!(a1, &a0);
    assert_ne!(r1, &r0);
    for (at, rt) in &pairs[1..] {
        assert_eq!(at, a1, "all 10 concurrent refreshes must converge on A1");
        assert_eq!(rt, r1, "all 10 concurrent refreshes must converge on R1");
    }

    let mut a1_hdr = HeaderMap::new();
    a1_hdr.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {a1}")).unwrap(),
    );
    assert!(engine.verify_bearer(&a1_hdr).is_ok());

    let (narrow_status, _, narrow_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &r0),
            ("scope", "mcp"),
        ]),
    )
    .await;
    assert_eq!(narrow_status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&narrow_body)["error"], "invalid_scope");

    let (reordered_status, _, reordered_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", r1),
            ("scope", "files mcp"),
        ]),
    )
    .await;
    assert_eq!(reordered_status, StatusCode::OK);
    let r2_json = parse_json(&reordered_body);
    let a2 = r2_json["access_token"].as_str().unwrap();
    let r2 = r2_json["refresh_token"].as_str().unwrap();

    let (retry_status, _, retry_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &r0),
        ]),
    )
    .await;
    assert_eq!(retry_status, StatusCode::OK);
    let retried = parse_json(&retry_body);
    assert_eq!(retried["access_token"], a2);
    assert_eq!(retried["refresh_token"], r2);

    tokio::time::sleep(Duration::from_millis(3150)).await;

    let (steal_st, _, steal_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &r0),
        ]),
    )
    .await;
    assert_eq!(steal_st, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&steal_body)["error"], "invalid_grant");

    assert_eq!(
        engine.verify_bearer(&a1_hdr),
        Err(AuthChallenge::InvalidToken)
    );

    let (r1_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", r1),
        ]),
    )
    .await;
    assert_eq!(r1_st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn disk_persistence_security_restart_recovery_and_rotated_retention() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(
        tmp.path(),
        &TestOpts {
            refresh_grace_secs: 60,
            refresh_reuse_policy: "revoke",
            ..TestOpts::default()
        },
    );

    let cb_uri = "http://127.0.0.1:23000/cb";
    let (client_id, client_secret, a0, r0, a1, r1, state_path) = {
        let engine = OAuthEngine::open(Arc::clone(&cfg)).unwrap();
        let (st, _, reg_b) = send_req(
            &engine,
            Method::POST,
            "/oauth/register",
            &[("content-type", "application/json")],
            json!({
                "redirect_uris": [cb_uri],
                "token_endpoint_auth_method": "client_secret_post",
            })
            .to_string(),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let rj = parse_json(&reg_b);
        let cid = rj["client_id"].as_str().unwrap().to_owned();
        let csec = rj["client_secret"].as_str().unwrap().to_owned();

        let (verifier, challenge) = pkce_pair("persist-1");
        let code = authorize_and_get_code(&engine, &cid, cb_uri, &challenge, "st-p").await;
        let (t_st, _, t_b) = send_req(
            &engine,
            Method::POST,
            "/oauth/token",
            &[("content-type", "application/x-www-form-urlencoded")],
            form_encode(&[
                ("grant_type", "authorization_code"),
                ("client_id", &cid),
                ("client_secret", &csec),
                ("code", &code),
                ("redirect_uri", cb_uri),
                ("code_verifier", &verifier),
            ]),
        )
        .await;
        assert_eq!(t_st, StatusCode::OK);
        let tj = parse_json(&t_b);
        let a0 = tj["access_token"].as_str().unwrap().to_owned();
        let r0 = tj["refresh_token"].as_str().unwrap().to_owned();

        let (rot_st, _, rot_b) = send_req(
            &engine,
            Method::POST,
            "/oauth/token",
            &[("content-type", "application/x-www-form-urlencoded")],
            form_encode(&[
                ("grant_type", "refresh_token"),
                ("client_id", &cid),
                ("client_secret", &csec),
                ("refresh_token", &r0),
            ]),
        )
        .await;
        assert_eq!(rot_st, StatusCode::OK);
        let rot_j = parse_json(&rot_b);
        let a1 = rot_j["access_token"].as_str().unwrap().to_owned();
        let r1 = rot_j["refresh_token"].as_str().unwrap().to_owned();
        (cid, csec, a0, r0, a1, r1, cfg.state_path.clone())
    };

    let raw_disk = std::fs::read_to_string(&state_path).unwrap();
    assert!(!raw_disk.contains(&client_secret));
    assert!(!raw_disk.contains(&a0));
    assert!(!raw_disk.contains(&r0));
    assert!(!raw_disk.contains(&a1));
    assert!(!raw_disk.contains(&r1));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&state_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let disk_before: PersistedState = serde_json::from_str(&raw_disk).unwrap();
    let r0_grace_before = disk_before.grants[0]
        .grace_refreshes
        .iter()
        .find(|rt| rt.token_sha256 == sha256_b64(&r0))
        .unwrap()
        .grace_until;

    let reopened = OAuthEngine::open(Arc::clone(&cfg)).unwrap();
    let mut a1_hdr = HeaderMap::new();
    a1_hdr.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {a1}")).unwrap(),
    );
    assert!(reopened.verify_bearer(&a1_hdr).is_ok());
    assert_eq!(
        reopened.verify_bearer(&HeaderMap::new()),
        Err(AuthChallenge::MissingToken)
    );
    let unauth = reopened.unauthorized_reply(AuthChallenge::MissingToken);
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauth.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp\""
    );

    let (narrow_status, _, narrow_body) = send_req(
        &reopened,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("refresh_token", &r0),
            ("scope", "mcp"),
        ]),
    )
    .await;
    assert_eq!(narrow_status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&narrow_body)["error"], "invalid_scope");

    let (mid_grace_st, _, mid_grace_b) = send_req(
        &reopened,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("refresh_token", &r0),
        ]),
    )
    .await;
    assert_eq!(mid_grace_st, StatusCode::OK);
    let mid_j = parse_json(&mid_grace_b);
    assert!(mid_j["access_token"].as_str().is_some());
    drop(reopened);

    let disk_after: PersistedState =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    let r0_grace_after = disk_after.grants[0]
        .grace_refreshes
        .iter()
        .find(|rt| rt.token_sha256 == sha256_b64(&r0))
        .unwrap()
        .grace_until;
    assert_eq!(
        r0_grace_after, r0_grace_before,
        "mid-grace restart fallback must not extend R0 grace_until"
    );

    let now = unix_now();
    let expired_at_raw = "expired-access-token-value";
    let active_at_raw = "active-access-token-value";
    let family_key = [0x5au8; 32];
    let family_key_b64 = URL_SAFE_NO_PAD.encode(family_key);
    let make_crafted_rt = |generation: u64, nonce: &str| -> String {
        let tag = URL_SAFE_NO_PAD.encode(hmac_sha256(
            &family_key,
            format!("grt_crafted.{generation}.{nonce}").as_bytes(),
        ));
        format!("rt1.grt_crafted.{generation}.{nonce}.{tag}")
    };
    let past_grace_rt_raw = make_crafted_rt(0, "nonce-zero-crafted");
    let active_rt_raw = make_crafted_rt(1, "nonce-one-crafted");

    let crafted = PersistedState {
        version: STATE_VERSION,
        clients: disk_after.clients.clone(),
        grants: vec![GrantRecord {
            grant_id: "grt_crafted".to_owned(),
            client_id: client_id.clone(),
            pool_slot: 0,
            scopes: vec!["mcp".to_owned()],
            resource: "https://mcp.example.com/mcp".to_owned(),
            issued_at: now.saturating_sub(60),
            max_expires_at: now + 86400,
            family_key_b64,
            current_gen: 1,
            current_refresh: Some(RefreshTokenRecord {
                r#gen: 1,
                token_sha256: sha256_b64(&active_rt_raw),
                expires_at: now + 7200,
            }),
            grace_refreshes: vec![GraceRefreshRecord {
                r#gen: 0,
                token_sha256: sha256_b64(&past_grace_rt_raw),
                grace_until: now.saturating_sub(5),
            }],
            access_tokens: vec![
                AccessTokenRecord {
                    token_sha256: sha256_b64(expired_at_raw),
                    expires_at: now.saturating_sub(10),
                    scopes: vec!["mcp".to_owned()],
                },
                AccessTokenRecord {
                    token_sha256: sha256_b64(active_at_raw),
                    expires_at: now + 3600,
                    scopes: vec!["mcp".to_owned()],
                },
            ],
            consumed_code_sha256: None,
        }],
    };
    std::fs::write(&state_path, serde_json::to_vec_pretty(&crafted).unwrap()).unwrap();

    let engine3 = OAuthEngine::open(Arc::clone(&cfg)).unwrap();
    let cleaned: PersistedState =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(cleaned.grants[0].access_tokens.len(), 1);
    assert!(
        cleaned.grants[0].grace_refreshes.is_empty(),
        "expired grace refresh entries are pruned while HMAC generation lineage stays O(1)"
    );
    assert!(engine3.is_grant_active("grt_crafted"));

    let mut live_hdr = HeaderMap::new();
    live_hdr.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {active_at_raw}")).unwrap(),
    );
    assert!(engine3.verify_bearer(&live_hdr).is_ok());

    let (reuse_st, _, _) = send_req(
        &engine3,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("refresh_token", &past_grace_rt_raw),
        ]),
    )
    .await;
    assert_eq!(reuse_st, StatusCode::BAD_REQUEST);
    assert!(!engine3.is_grant_active("grt_crafted"));
    assert_eq!(
        engine3.verify_bearer(&live_hdr),
        Err(AuthChallenge::InvalidToken)
    );
    drop(engine3);

    #[cfg(unix)]
    {
        let sym_dir = TempDir::new().unwrap();
        let mut sym_cfg = (*build_config(sym_dir.path(), &TestOpts::default())).clone();
        let target = sym_dir.path().join("real.json");
        std::fs::write(&target, "{}").unwrap();
        let link_path = sym_dir.path().join("symlink_state.json");
        std::os::unix::fs::symlink(&target, &link_path).unwrap();
        sym_cfg.state_path = link_path;
        assert!(OAuthEngine::open(Arc::new(sym_cfg)).is_err());

        let hard_dir = TempDir::new().unwrap();
        let mut hard_cfg = (*build_config(hard_dir.path(), &TestOpts::default())).clone();
        let orig = hard_dir.path().join("orig.json");
        let hard = hard_dir.path().join("hard.json");
        std::fs::write(&orig, "{}").unwrap();
        std::fs::hard_link(&orig, &hard).unwrap();
        hard_cfg.state_path = orig;
        assert!(OAuthEngine::open(Arc::new(hard_cfg)).is_err());
    }
}

#[tokio::test]
async fn password_rate_limiting_and_least_loaded_pool_slot_selection() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(
        tmp.path(),
        &TestOpts {
            bearer_tokens: &["tok-0", "tok-1", "tok-2"],
            ..TestOpts::default()
        },
    );
    let engine = OAuthEngine::open(cfg).unwrap();

    let cb_uri = "http://127.0.0.1:24000/cb";
    let client_id = register_public_client(&engine, cb_uri, Some("Pool Client")).await;

    let mut tokens = Vec::new();
    let mut slots = Vec::new();
    for i in 0..3 {
        let (at, _) = mint_public_grant(&engine, &client_id, cb_uri, &format!("slot-{i}")).await;
        let mut hdr = HeaderMap::new();
        hdr.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {at}")).unwrap(),
        );
        let vt = engine.verify_bearer(&hdr).unwrap();
        slots.push(vt.pool_slot);
        tokens.push(at);
    }
    assert_eq!(slots, vec![0, 1, 2]);

    let (rev_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/revoke",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[("client_id", &client_id), ("token", &tokens[1])]),
    )
    .await;
    assert_eq!(rev_st, StatusCode::OK);

    let (at4, _) = mint_public_grant(&engine, &client_id, cb_uri, "slot-refill").await;
    let mut hdr4 = HeaderMap::new();
    hdr4.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {at4}")).unwrap(),
    );
    assert_eq!(
        engine.verify_bearer(&hdr4).unwrap().pool_slot,
        1,
        "must pick slot 1 because it has 0 active grants while slots 0 and 2 have 1"
    );

    let mut tie_slots = Vec::new();
    for i in 0..3 {
        let (at, _) = mint_public_grant(&engine, &client_id, cb_uri, &format!("tie-{i}")).await;
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {at}")).unwrap(),
        );
        tie_slots.push(engine.verify_bearer(&h).unwrap().pool_slot);
    }
    assert_eq!(tie_slots, vec![2, 0, 1]);

    let (_, challenge) = pkce_pair("pw-limit");
    let q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", cb_uri),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let open_ar = || async {
        let (g_st, g_hdr, g_body) = send_req(
            &engine,
            Method::GET,
            &format!("/oauth/authorize?{q}"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(g_st, StatusCode::OK);
        let cookie = extract_cookie_pair(&g_hdr);
        let html = std::str::from_utf8(&g_body).unwrap();
        let ar_id = extract_hidden_input(html, "ar_id");
        let csrf = extract_hidden_input(html, "csrf_token");
        (cookie, ar_id, csrf)
    };

    let (cookie, ar_id, csrf) = open_ar().await;
    for attempt in 0..10 {
        let (st, _, _) = send_req(
            &engine,
            Method::POST,
            "/oauth/authorize",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("cookie", &cookie),
            ],
            form_encode(&[
                ("ar_id", &ar_id),
                ("csrf_token", &csrf),
                ("password", &format!("wrong-pw-{attempt}")),
            ]),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    let (throttled_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie),
        ],
        form_encode(&[
            ("ar_id", &ar_id),
            ("csrf_token", &csrf),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(throttled_st, StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn config_validates_bidirectional_overlap_scopes_bearer_tokens_and_redacts_debug() {
    let pw_hash = PasswordVerifier::from_plaintext_with_iterations(OWNER_SECRET, 10_000)
        .unwrap()
        .encode();

    // Bidirectional overlap: resource_path is a parent of passthrough_prefixes and vice versa.
    for (resource_path, prefix) in [("/api", "/api/files/"), ("/api/files", "/api/")] {
        let cfg_json = json!({
            "listen": "127.0.0.1:0",
            "public_url": "https://mcp.example.com",
            "resource_path": resource_path,
            "state_path": "state.json",
            "oauth": { "owner_password_hash": pw_hash },
            "upstream": {
                "transport": "http",
                "url": "http://127.0.0.1:9090/upstream",
                "passthrough_prefixes": [prefix],
            }
        });
        let err = GatewayConfig::from_json_str(&cfg_json.to_string(), Path::new("/tmp"))
            .expect_err("overlapping resource_path and passthrough_prefix must fail");
        assert!(err.contains("overlaps passthrough prefix"), "{err}");
    }

    // Scopes: deduplication preserves order; invalid RFC 6749 §3.3 chars are rejected.
    let dedup_json = json!({
        "listen": "127.0.0.1:0",
        "public_url": "https://mcp.example.com",
        "state_path": "state.json",
        "oauth": {
            "owner_password_hash": pw_hash,
            "scopes": ["files", "mcp", "files", "read:all", "mcp"]
        },
        "upstream": {
            "transport": "http",
            "url": "http://127.0.0.1:9090/mcp",
            "bearer_tokens": ["super-secret-upstream-token"]
        }
    });
    let cfg = GatewayConfig::from_json_str(&dedup_json.to_string(), Path::new("/tmp")).unwrap();
    assert_eq!(cfg.oauth.scopes, vec!["files", "mcp", "read:all"]);

    // Debug formatting must not leak verifier material or bearer tokens.
    let debug_http = format!("{cfg:?}");
    assert!(!debug_http.contains("super-secret-upstream-token"));
    let verifier_dbg = format!("{:?}", cfg.oauth.verifier);
    assert!(verifier_dbg.contains("PasswordVerifier"));
    assert!(verifier_dbg.contains("iterations"));
    assert!(!verifier_dbg.contains("salt"));
    assert!(!verifier_dbg.contains("expected"));

    let stdio_json = json!({
        "listen": "127.0.0.1:0",
        "public_url": "https://mcp.example.com",
        "state_path": "state.json",
        "oauth": { "owner_password_hash": pw_hash },
        "upstream": {
            "transport": "stdio",
            "command": "echo",
            "env": { "API_KEY": "top-secret-stdio-env" }
        }
    });
    let stdio_cfg =
        GatewayConfig::from_json_str(&stdio_json.to_string(), Path::new("/tmp")).unwrap();
    let debug_stdio = format!("{stdio_cfg:?}");
    assert!(debug_stdio.contains("API_KEY"));
    assert!(!debug_stdio.contains("top-secret-stdio-env"));

    for bad_scope in ["has\"quote", "has\\slash", "has space", "nonascii-é", ""] {
        let bad_json = json!({
            "listen": "127.0.0.1:0",
            "public_url": "https://mcp.example.com",
            "state_path": "state.json",
            "oauth": {
                "owner_password_hash": pw_hash,
                "scopes": [bad_scope]
            },
            "upstream": {
                "transport": "stdio",
                "command": "echo"
            }
        });
        assert!(
            GatewayConfig::from_json_str(&bad_json.to_string(), Path::new("/tmp")).is_err(),
            "scope {bad_scope:?} should be rejected"
        );
    }

    for bad_token in ["tok with space", "tok\twith-tab", "nonascii-é", ""] {
        let bad_json = json!({
            "listen": "127.0.0.1:0",
            "public_url": "https://mcp.example.com",
            "state_path": "state.json",
            "oauth": { "owner_password_hash": pw_hash },
            "upstream": {
                "transport": "http",
                "url": "http://127.0.0.1:9090/mcp",
                "bearer_tokens": [bad_token]
            }
        });
        assert!(
            GatewayConfig::from_json_str(&bad_json.to_string(), Path::new("/tmp")).is_err(),
            "bearer token {bad_token:?} should be rejected"
        );
    }
}

#[tokio::test]
async fn cross_client_isolation_for_code_refresh_and_revoke() {
    let tmp = TempDir::new().unwrap();
    let engine = OAuthEngine::open(build_config(tmp.path(), &TestOpts::default())).unwrap();

    let cb_a = "http://127.0.0.1:25001/cb";
    let cb_b = "http://127.0.0.1:25002/cb";
    let client_a = register_public_client(&engine, cb_a, Some("Client A")).await;
    let client_b = register_public_client(&engine, cb_b, Some("Client B")).await;

    // Client B cannot redeem Client A's authorization code.
    let (verifier, challenge) = pkce_pair("cross-code");
    let code_a = authorize_and_get_code(&engine, &client_a, cb_a, &challenge, "st-a").await;
    let (st_code, _, body_code) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_b),
            ("code", &code_a),
            ("redirect_uri", cb_a),
            ("code_verifier", &verifier),
        ]),
    )
    .await;
    assert_eq!(st_code, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&body_code)["error"], "invalid_grant");

    // Client B cannot refresh or revoke Client A's grant.
    let (access_a, refresh_a) = mint_public_grant(&engine, &client_a, cb_a, "cross-grant").await;
    let (st_rt, _, body_rt) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_b),
            ("refresh_token", &refresh_a),
        ]),
    )
    .await;
    assert_eq!(st_rt, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&body_rt)["error"], "invalid_grant");

    let (st_rev, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/revoke",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[("client_id", &client_b), ("token", &access_a)]),
    )
    .await;
    assert_eq!(st_rev, StatusCode::OK);

    let mut hdr_a = HeaderMap::new();
    hdr_a.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {access_a}")).unwrap(),
    );
    assert!(
        engine.verify_bearer(&hdr_a).is_ok(),
        "Client B revoke must not revoke Client A grant"
    );
}

#[tokio::test]
async fn non_numeric_content_length_returns_400_and_oversized_authorize_post_returns_html() {
    let tmp = TempDir::new().unwrap();
    let engine = OAuthEngine::open(build_config(tmp.path(), &TestOpts::default())).unwrap();

    // Send a raw HTTP/1.1 request with a non-numeric Content-Length directly to the server.
    let (mut client_io, server_io) = tokio::io::duplex(16 * 1024);
    let eng = Arc::clone(&engine);
    let srv = tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |incoming| {
            let eng = Arc::clone(&eng);
            async move { Ok::<_, Infallible>(eng.handle(incoming).await) }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(server_io), svc)
            .await;
    });
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    client_io
        .write_all(
            b"POST /oauth/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: not-a-number\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut resp_buf = Vec::new();
    client_io.read_to_end(&mut resp_buf).await.unwrap();
    let _ = srv.await;
    let resp_text = String::from_utf8_lossy(&resp_buf);
    assert!(
        resp_text.starts_with("HTTP/1.1 400 "),
        "expected 400 Bad Request, got: {resp_text}"
    );

    // Oversized POST /oauth/authorize must return 413 HTML with security headers.
    let oversized = vec![b'x'; 65 * 1024];
    let (status, headers, body) = send_req(
        &engine,
        Method::POST,
        "/oauth/authorize",
        &[("content-type", "application/x-www-form-urlencoded")],
        oversized,
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );
    assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(headers.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("<!DOCTYPE html>")
    );
}

#[tokio::test]
async fn revoke_hook_fires_on_explicit_revoke_code_replay_and_refresh_replay() {
    let tmp = TempDir::new().unwrap();
    let revoked = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let hook_log = Arc::clone(&revoked);
    let engine = OAuthEngine::open_with_revoke_hook(
        build_config(
            tmp.path(),
            &TestOpts {
                refresh_grace_secs: 0,
                refresh_reuse_policy: "revoke",
                ..Default::default()
            },
        ),
        Arc::new(move |grant_id: &str| {
            hook_log.lock().unwrap().push(grant_id.to_owned());
        }),
    )
    .unwrap();

    let cb = "http://127.0.0.1:26001/cb";
    let client = register_public_client(&engine, cb, Some("Hook Test")).await;

    // 1. Explicit /oauth/revoke
    let (at1, _) = mint_public_grant(&engine, &client, cb, "hook-1").await;
    let mut h1 = HeaderMap::new();
    h1.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {at1}")).unwrap(),
    );
    let gid1 = engine.verify_bearer(&h1).unwrap().grant_id;
    let (st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/revoke",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[("client_id", &client), ("token", &at1)]),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(*revoked.lock().unwrap(), vec![gid1.clone()]);

    // 2. Authorization code replay
    let (verifier, challenge) = pkce_pair("hook-2");
    let code = authorize_and_get_code(&engine, &client, cb, &challenge, "h2").await;
    let tok_body = form_encode(&[
        ("grant_type", "authorization_code"),
        ("client_id", &client),
        ("code", &code),
        ("redirect_uri", cb),
        ("code_verifier", &verifier),
    ]);
    let (st2, _, b2) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        tok_body.clone(),
    )
    .await;
    assert_eq!(st2, StatusCode::OK);
    let at2 = parse_json(&b2)["access_token"].as_str().unwrap().to_owned();
    let mut h2 = HeaderMap::new();
    h2.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {at2}")).unwrap(),
    );
    let gid2 = engine.verify_bearer(&h2).unwrap().grant_id;
    let (st2_replay, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        tok_body,
    )
    .await;
    assert_eq!(st2_replay, StatusCode::BAD_REQUEST);
    assert_eq!(*revoked.lock().unwrap(), vec![gid1.clone(), gid2.clone()]);

    // 3. Refresh token post-grace replay (refresh_grace_secs = 0)
    let (at3, r0) = mint_public_grant(&engine, &client, cb, "hook-3").await;
    let mut h3 = HeaderMap::new();
    h3.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {at3}")).unwrap(),
    );
    let gid3 = engine.verify_bearer(&h3).unwrap().grant_id;
    let rt_form = form_encode(&[
        ("grant_type", "refresh_token"),
        ("client_id", &client),
        ("refresh_token", &r0),
    ]);
    let (st3, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        rt_form.clone(),
    )
    .await;
    assert_eq!(st3, StatusCode::OK);
    let (st3_replay, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        rt_form,
    )
    .await;
    assert_eq!(st3_replay, StatusCode::BAD_REQUEST);
    assert_eq!(*revoked.lock().unwrap(), vec![gid1, gid2, gid3]);
}

#[tokio::test]
async fn multi_hop_refresh_replay_returns_current_tip_and_survives_grace_expiry() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(
        tmp.path(),
        &TestOpts {
            refresh_grace_secs: 2,
            refresh_reuse_policy: "revoke",
            ..Default::default()
        },
    );
    let engine = OAuthEngine::open(cfg).unwrap();
    let cb = "http://127.0.0.1:27001/cb";
    let client_id = register_public_client(&engine, cb, Some("Multi-Hop Subagents")).await;
    let (_, r0) = mint_public_grant(&engine, &client_id, cb, "mhop-0").await;

    let refresh = |rt: String| {
        let eng = Arc::clone(&engine);
        let cid = client_id.clone();
        async move {
            send_req(
                &eng,
                Method::POST,
                "/oauth/token",
                &[("content-type", "application/x-www-form-urlencoded")],
                form_encode(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", &cid),
                    ("refresh_token", &rt),
                ]),
            )
            .await
        }
    };

    let (st1, _, b1) = refresh(r0.clone()).await;
    assert_eq!(st1, StatusCode::OK);
    let j1 = parse_json(&b1);
    let r1 = j1["refresh_token"].as_str().unwrap().to_owned();

    let (st2, _, b2) = refresh(r1.clone()).await;
    assert_eq!(st2, StatusCode::OK);
    let j2 = parse_json(&b2);
    let a2 = j2["access_token"].as_str().unwrap().to_owned();
    let r2 = j2["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(r2, r1);

    let (st_r0_grace, _, b_r0_grace) = refresh(r0.clone()).await;
    assert_eq!(st_r0_grace, StatusCode::OK);
    let j_grace = parse_json(&b_r0_grace);
    assert_eq!(j_grace["access_token"], a2);
    assert_eq!(j_grace["refresh_token"], r2);

    tokio::time::sleep(Duration::from_millis(3150)).await;

    let (st3, _, b3) = refresh(r2.clone()).await;
    assert_eq!(st3, StatusCode::OK);
    let j3 = parse_json(&b3);
    let a3 = j3["access_token"].as_str().unwrap().to_owned();
    let r3 = j3["refresh_token"].as_str().unwrap().to_owned();

    let mut a3_hdr = HeaderMap::new();
    a3_hdr.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {a3}")).unwrap(),
    );
    let gid = engine.verify_bearer(&a3_hdr).unwrap().grant_id;
    assert!(engine.is_grant_active(&gid));

    let (st_breach, _, _) = refresh(r1).await;
    assert_eq!(st_breach, StatusCode::BAD_REQUEST);
    assert!(!engine.is_grant_active(&gid));
    assert_eq!(
        engine.verify_bearer(&a3_hdr),
        Err(AuthChallenge::InvalidToken)
    );
    let (st_r3, _, _) = refresh(r3).await;
    assert_eq!(st_r3, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rapid_over_256_rotations_and_expired_r0_replay_revoke_grant_via_hmac_lineage() {
    let tmp = TempDir::new().unwrap();
    let revoked = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let hook_log = Arc::clone(&revoked);
    let cfg = build_config(
        tmp.path(),
        &TestOpts {
            refresh_grace_secs: 60,
            refresh_reuse_policy: "revoke",
            ..Default::default()
        },
    );
    let engine = OAuthEngine::open_with_revoke_hook(
        Arc::clone(&cfg),
        Arc::new(move |gid: &str| hook_log.lock().unwrap().push(gid.to_owned())),
    )
    .unwrap();

    let cb = "http://127.0.0.1:27002/cb";
    let client_id = register_public_client(&engine, cb, Some("Rapid Rotator")).await;
    let (_, r0) = mint_public_grant(&engine, &client_id, cb, "rapid-260").await;

    let mut cur_rt = r0.clone();
    let mut cur_at = String::new();
    for _ in 0..260 {
        let (st, _, b) = send_req(
            &engine,
            Method::POST,
            "/oauth/token",
            &[("content-type", "application/x-www-form-urlencoded")],
            form_encode(&[
                ("grant_type", "refresh_token"),
                ("client_id", &client_id),
                ("refresh_token", &cur_rt),
            ]),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let j = parse_json(&b);
        cur_at = j["access_token"].as_str().unwrap().to_owned();
        cur_rt = j["refresh_token"].as_str().unwrap().to_owned();
    }

    let persisted: PersistedState =
        serde_json::from_str(&std::fs::read_to_string(&cfg.state_path).unwrap()).unwrap();
    assert!(persisted.grants[0].grace_refreshes.len() <= 16);

    let mut hdr = HeaderMap::new();
    hdr.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {cur_at}")).unwrap(),
    );
    let gid = engine.verify_bearer(&hdr).unwrap().grant_id;

    let (replay_st, _, replay_b) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &r0),
        ]),
    )
    .await;
    assert_eq!(replay_st, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&replay_b)["error"], "invalid_grant");
    assert!(!engine.is_grant_active(&gid));
    assert_eq!(engine.verify_bearer(&hdr), Err(AuthChallenge::InvalidToken));
    assert_eq!(*revoked.lock().unwrap(), vec![gid]);
    drop(engine);

    // Expired rotated R0 replayed while R1 is still alive must also revoke the grant.
    let now = unix_now();
    let family_key = [0x33u8; 32];
    let family_key_b64 = URL_SAFE_NO_PAD.encode(family_key);
    let sign_rt = |generation: u64, nonce: &str| {
        let tag = URL_SAFE_NO_PAD.encode(hmac_sha256(
            &family_key,
            format!("grt_exp_r0.{generation}.{nonce}").as_bytes(),
        ));
        format!("rt1.grt_exp_r0.{generation}.{nonce}.{tag}")
    };
    let expired_r0 = sign_rt(0, "r0-expired-nonce");
    let live_r1 = sign_rt(1, "r1-live-nonce");
    let live_a1 = "live-a1-token";
    let state = PersistedState {
        version: STATE_VERSION,
        clients: persisted.clients,
        grants: vec![GrantRecord {
            grant_id: "grt_exp_r0".to_owned(),
            client_id: client_id.clone(),
            pool_slot: 0,
            scopes: vec!["mcp".to_owned()],
            resource: "https://mcp.example.com/mcp".to_owned(),
            issued_at: now.saturating_sub(400),
            max_expires_at: now + 7200,
            family_key_b64,
            current_gen: 1,
            current_refresh: Some(RefreshTokenRecord {
                r#gen: 1,
                token_sha256: sha256_b64(&live_r1),
                expires_at: now + 3600,
            }),
            grace_refreshes: Vec::new(),
            access_tokens: vec![AccessTokenRecord {
                token_sha256: sha256_b64(live_a1),
                expires_at: now + 3600,
                scopes: vec!["mcp".to_owned()],
            }],
            consumed_code_sha256: None,
        }],
    };
    std::fs::write(&cfg.state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let engine2 = OAuthEngine::open(cfg).unwrap();
    assert!(engine2.is_grant_active("grt_exp_r0"));
    let (exp_st, _, _) = send_req(
        &engine2,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &expired_r0),
        ]),
    )
    .await;
    assert_eq!(exp_st, StatusCode::BAD_REQUEST);
    assert!(!engine2.is_grant_active("grt_exp_r0"));
}

#[tokio::test]
async fn max_grant_lifetime_ceiling_clamps_tokens_and_expires_grant() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(tmp.path(), &TestOpts::default());
    let engine = OAuthEngine::open(Arc::clone(&cfg)).unwrap();
    let cb = "http://127.0.0.1:27003/cb";
    let client_id = register_public_client(&engine, cb, Some("Ceiling Client")).await;
    let (_, r0) = mint_public_grant(&engine, &client_id, cb, "ceiling-0").await;
    drop(engine);

    let now = unix_now();
    let mut persisted: PersistedState =
        serde_json::from_str(&std::fs::read_to_string(&cfg.state_path).unwrap()).unwrap();
    let ceiling = now + 2;
    persisted.grants[0].max_expires_at = ceiling;
    let gid = persisted.grants[0].grant_id.clone();
    std::fs::write(
        &cfg.state_path,
        serde_json::to_vec_pretty(&persisted).unwrap(),
    )
    .unwrap();

    let engine = OAuthEngine::open(Arc::clone(&cfg)).unwrap();
    let (st, _, b) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &r0),
        ]),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let j = parse_json(&b);
    assert!(j["expires_in"].as_u64().unwrap() <= 2);
    let a1 = j["access_token"].as_str().unwrap().to_owned();
    let r1 = j["refresh_token"].as_str().unwrap().to_owned();

    let after_rot: PersistedState =
        serde_json::from_str(&std::fs::read_to_string(&cfg.state_path).unwrap()).unwrap();
    assert_eq!(
        after_rot.grants[0]
            .current_refresh
            .as_ref()
            .unwrap()
            .expires_at,
        ceiling
    );

    tokio::time::sleep(Duration::from_millis(3150)).await;

    assert!(!engine.is_grant_active(&gid));
    let mut hdr = HeaderMap::new();
    hdr.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {a1}")).unwrap(),
    );
    assert_eq!(engine.verify_bearer(&hdr), Err(AuthChallenge::InvalidToken));

    let (exp_st, _, exp_b) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &r1),
        ]),
    )
    .await;
    assert_eq!(exp_st, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&exp_b)["error"], "invalid_grant");
}

#[tokio::test]
async fn revoke_requires_client_auth_without_token_oracle_and_restart_code_replay_revokes() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(tmp.path(), &TestOpts::default());
    let engine = OAuthEngine::open(Arc::clone(&cfg)).unwrap();

    let cb = "http://127.0.0.1:27004/cb";
    let (reg_st, _, reg_b) = send_req(
        &engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        json!({
            "redirect_uris": [cb],
            "token_endpoint_auth_method": "client_secret_basic",
        })
        .to_string(),
    )
    .await;
    assert_eq!(reg_st, StatusCode::CREATED);
    let rj = parse_json(&reg_b);
    let conf_id = rj["client_id"].as_str().unwrap().to_owned();
    let conf_sec = rj["client_secret"].as_str().unwrap().to_owned();
    let basic = STANDARD.encode(format!("{conf_id}:{conf_sec}"));

    let (verifier, challenge) = pkce_pair("oracle-check");
    let code = authorize_and_get_code(&engine, &conf_id, cb, &challenge, "st-o").await;
    let tok_form = form_encode(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", cb),
        ("code_verifier", &verifier),
    ]);
    let (tok_st, _, tok_b) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {basic}")),
        ],
        tok_form.clone(),
    )
    .await;
    assert_eq!(tok_st, StatusCode::OK);
    let conf_at = parse_json(&tok_b)["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    // Unauthenticated revoke must return identical 401 invalid_client for active and unknown tokens.
    let (st_unknown, _, b_unknown) = send_req(
        &engine,
        Method::POST,
        "/oauth/revoke",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[("token", "completely-unknown-token")]),
    )
    .await;
    let (st_active, _, b_active) = send_req(
        &engine,
        Method::POST,
        "/oauth/revoke",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[("token", &conf_at)]),
    )
    .await;
    assert_eq!(st_unknown, StatusCode::UNAUTHORIZED);
    assert_eq!(st_active, StatusCode::UNAUTHORIZED);
    assert_eq!(parse_json(&b_unknown), parse_json(&b_active));
    assert_eq!(parse_json(&b_active)["error"], "invalid_client");

    let mut conf_hdr = HeaderMap::new();
    conf_hdr.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {conf_at}")).unwrap(),
    );
    assert!(engine.verify_bearer(&conf_hdr).is_ok());

    // Public client also requires client_id at /oauth/revoke.
    let pub_id = register_public_client(&engine, cb, None).await;
    let (pub_at, _) = mint_public_grant(&engine, &pub_id, cb, "pub-rev").await;
    let (pub_no_id, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/revoke",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[("token", &pub_at)]),
    )
    .await;
    assert_eq!(pub_no_id, StatusCode::UNAUTHORIZED);

    // Restart engine and confirm auth-code replay still revokes conf_at via persisted consumed_code_sha256.
    drop(engine);
    let reopened = OAuthEngine::open(cfg).unwrap();
    assert!(reopened.verify_bearer(&conf_hdr).is_ok());
    let (replay_st, _, _) = send_req(
        &reopened,
        Method::POST,
        "/oauth/token",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &format!("Basic {basic}")),
        ],
        tok_form,
    )
    .await;
    assert_eq!(replay_st, StatusCode::BAD_REQUEST);
    assert_eq!(
        reopened.verify_bearer(&conf_hdr),
        Err(AuthChallenge::InvalidToken)
    );
}

#[tokio::test]
async fn per_ip_lockout_isolation_ar_burn_pending_cap_and_mid_login_dcr_protection() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(
        tmp.path(),
        &TestOpts {
            max_registered_clients: 16,
            ..Default::default()
        },
    );
    let engine = OAuthEngine::open(cfg).unwrap();
    let cb = "http://127.0.0.1:27005/cb";
    let mid_login_client = register_public_client(&engine, cb, Some("Mid Login")).await;

    let attacker_ip: IpAddr = "203.0.113.9".parse().unwrap();
    let owner_ip: IpAddr = "198.51.100.7".parse().unwrap();
    let flood_ip: IpAddr = "203.0.113.55".parse().unwrap();

    let (owner_verifier, owner_challenge) = pkce_pair("owner-login");
    let owner_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &mid_login_client),
        ("redirect_uri", cb),
        ("code_challenge", &owner_challenge),
        ("code_challenge_method", "S256"),
        ("state", "owner-st"),
    ]);
    let (og_st, og_hdr, og_body) = send_req_from_ip(
        &engine,
        Some(owner_ip),
        Method::GET,
        &format!("/oauth/authorize?{owner_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(og_st, StatusCode::OK);
    let owner_cookie = extract_cookie_pair(&og_hdr);
    let owner_html = std::str::from_utf8(&og_body).unwrap();
    let owner_ar = extract_hidden_input(owner_html, "ar_id");
    let owner_csrf = extract_hidden_input(owner_html, "csrf_token");

    // Fill all 16 client slots with active grants/codes; DCR must NOT evict active clients.
    let _ = mint_public_grant(&engine, &mid_login_client, cb, "active-0").await;
    for i in 1..16 {
        let uri = format!("http://127.0.0.1:28000/cb/{i}");
        let cid = register_public_client(&engine, &uri, None).await;
        let _ = mint_public_grant(&engine, &cid, &uri, &format!("active-{i}")).await;
    }
    let (dcr_full_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        json!({ "redirect_uris": ["http://127.0.0.1:28999/cb"] }).to_string(),
    )
    .await;
    assert_eq!(dcr_full_st, StatusCode::TOO_MANY_REQUESTS);

    // Stateless GET /oauth/authorize serves >32 requests from flood_ip without 429 or lockup.
    for i in 0..40 {
        let (_, ch) = pkce_pair(&format!("flood-{i}"));
        let fq = form_encode(&[
            ("response_type", "code"),
            ("client_id", &mid_login_client),
            ("redirect_uri", cb),
            ("code_challenge", &ch),
            ("code_challenge_method", "S256"),
        ]);
        let (fst, _, _) = send_req_from_ip(
            &engine,
            Some(flood_ip),
            Method::GET,
            &format!("/oauth/authorize?{fq}"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(fst, StatusCode::OK);
    }

    // Attacker IP hits per-IP 429 at 10 failures without affecting owner_ip.
    let open_attacker_ar = || async {
        let (_, ch) = pkce_pair("atk");
        let aq = form_encode(&[
            ("response_type", "code"),
            ("client_id", &mid_login_client),
            ("redirect_uri", cb),
            ("code_challenge", &ch),
            ("code_challenge_method", "S256"),
        ]);
        let (st, hdr, b) = send_req_from_ip(
            &engine,
            Some(attacker_ip),
            Method::GET,
            &format!("/oauth/authorize?{aq}"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let html = std::str::from_utf8(&b).unwrap();
        (
            extract_cookie_pair(&hdr),
            extract_hidden_input(html, "ar_id"),
            extract_hidden_input(html, "csrf_token"),
        )
    };

    let (atk_cookie, atk_ar, atk_csrf) = open_attacker_ar().await;
    for _ in 0..10 {
        let (st, _, _) = send_req_from_ip(
            &engine,
            Some(attacker_ip),
            Method::POST,
            "/oauth/authorize",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("cookie", &atk_cookie),
            ],
            form_encode(&[
                ("ar_id", &atk_ar),
                ("csrf_token", &atk_csrf),
                ("password", "bad-guess"),
            ]),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    let (atk_locked, _, _) = send_req_from_ip(
        &engine,
        Some(attacker_ip),
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &atk_cookie),
        ],
        form_encode(&[
            ("ar_id", &atk_ar),
            ("csrf_token", &atk_csrf),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(atk_locked, StatusCode::TOO_MANY_REQUESTS);

    // Owner IP is NOT locked out and mid_login_client completes login + token exchange.
    let (owner_post_st, owner_post_hdr, _) = send_req_from_ip(
        &engine,
        Some(owner_ip),
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &owner_cookie),
        ],
        form_encode(&[
            ("ar_id", &owner_ar),
            ("csrf_token", &owner_csrf),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(owner_post_st, StatusCode::SEE_OTHER);
    let loc = Url::parse(owner_post_hdr[header::LOCATION].to_str().unwrap()).unwrap();
    let qmap: BTreeMap<String, String> = loc.query_pairs().into_owned().collect();
    let owner_code = qmap.get("code").unwrap();

    let (tok_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", &mid_login_client),
            ("code", owner_code),
            ("redirect_uri", cb),
            ("code_verifier", &owner_verifier),
        ]),
    )
    .await;
    assert_eq!(tok_st, StatusCode::OK);
}

#[tokio::test]
async fn insufficient_scope_403_and_per_access_token_scope_preservation() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(
        tmp.path(),
        &TestOpts {
            scopes: &["mcp", "files"],
            ..Default::default()
        },
    );
    let engine = OAuthEngine::open(cfg).unwrap();
    let cb = "http://127.0.0.1:27006/cb";
    let client_id = register_public_client(&engine, cb, Some("Scoped Client")).await;
    let (a0, r0) = mint_public_grant(&engine, &client_id, cb, "scope-0").await;

    let (st1, _, b1) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &r0),
            ("scope", "mcp"),
        ]),
    )
    .await;
    assert_eq!(st1, StatusCode::OK);
    let j1 = parse_json(&b1);
    assert_eq!(j1["scope"], "mcp");
    let a1 = j1["access_token"].as_str().unwrap().to_owned();
    let r1 = j1["refresh_token"].as_str().unwrap().to_owned();

    let mut h0 = HeaderMap::new();
    h0.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {a0}")).unwrap(),
    );
    let mut h1 = HeaderMap::new();
    h1.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {a1}")).unwrap(),
    );
    assert_eq!(
        engine.verify_bearer(&h0).unwrap().scopes,
        vec!["mcp", "files"]
    );
    assert_eq!(engine.verify_bearer(&h1).unwrap().scopes, vec!["mcp"]);

    // Unscoped refresh restores grant scopes on A2 while A1 remains narrowed to ["mcp"].
    let (st2, _, b2) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &r1),
        ]),
    )
    .await;
    assert_eq!(st2, StatusCode::OK);
    let a2 = parse_json(&b2)["access_token"].as_str().unwrap().to_owned();
    let mut h2 = HeaderMap::new();
    h2.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {a2}")).unwrap(),
    );
    assert_eq!(
        engine.verify_bearer(&h2).unwrap().scopes,
        vec!["mcp", "files"]
    );
    assert_eq!(engine.verify_bearer(&h1).unwrap().scopes, vec!["mcp"]);
    drop(engine);

    // Reopen requiring ["files"] only: A0 passes, A1 fails with 403 InsufficientScope.
    let files_only_cfg = build_config(
        tmp.path(),
        &TestOpts {
            scopes: &["files"],
            ..Default::default()
        },
    );
    let reopened = OAuthEngine::open(files_only_cfg).unwrap();
    assert!(reopened.verify_bearer(&h0).is_ok());
    assert_eq!(
        reopened.verify_bearer(&h1),
        Err(AuthChallenge::InsufficientScope)
    );
    let reply = reopened.unauthorized_reply(AuthChallenge::InsufficientScope);
    assert_eq!(reply.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        reply.headers()[header::WWW_AUTHENTICATE],
        "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp\", error=\"insufficient_scope\", scope=\"files\""
    );
}

#[tokio::test]
async fn case_insensitive_rfc8707_resource_loopback_cookie_dcr_scope_and_deny_button() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(tmp.path(), &TestOpts::default());
    let engine = OAuthEngine::open(cfg).unwrap();
    let cb = "http://127.0.0.1:27007/cb";

    let (reg_st, _, reg_b) = send_req(
        &engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        json!({
            "redirect_uris": [cb],
            "scope": "mcp",
        })
        .to_string(),
    )
    .await;
    assert_eq!(reg_st, StatusCode::CREATED);
    let rj = parse_json(&reg_b);
    assert_eq!(rj["scope"], "mcp");
    let client_id = rj["client_id"].as_str().unwrap().to_owned();

    let (verifier, challenge) = pkce_pair("res-case");
    let over_scope_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", cb),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("scope", "mcp files"),
    ]);
    let (os_st, os_hdr, _) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{over_scope_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(os_st, StatusCode::SEE_OTHER);
    assert!(
        os_hdr[header::LOCATION]
            .to_str()
            .unwrap()
            .contains("error=invalid_scope")
    );

    let long_state = "s".repeat(1025);
    let long_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", cb),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("state", &long_state),
    ]);
    let (ls_st, _, _) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{long_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(ls_st, StatusCode::BAD_REQUEST);

    // Case-insensitive RFC 8707 resource origin on authorize, token exchange, and refresh.
    let auth_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", cb),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("resource", "HTTPS://MCP.EXAMPLE.COM:443/mcp"),
        ("state", "ok-res"),
    ]);
    let (g_st, g_hdr, g_b) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{auth_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(g_st, StatusCode::OK);
    let cookie = extract_cookie_pair(&g_hdr);
    let html = std::str::from_utf8(&g_b).unwrap();
    let ar_id = extract_hidden_input(html, "ar_id");
    let csrf = extract_hidden_input(html, "csrf_token");

    let (p_st, p_hdr, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie),
        ],
        form_encode(&[
            ("ar_id", &ar_id),
            ("csrf_token", &csrf),
            ("password", OWNER_SECRET),
            ("decision", "approve"),
        ]),
    )
    .await;
    assert_eq!(p_st, StatusCode::SEE_OTHER);
    let loc = Url::parse(p_hdr[header::LOCATION].to_str().unwrap()).unwrap();
    let qmap: BTreeMap<String, String> = loc.query_pairs().into_owned().collect();
    let code = qmap.get("code").unwrap();

    let (t_st, _, t_b) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id),
            ("code", code),
            ("redirect_uri", cb),
            ("code_verifier", &verifier),
            ("resource", "https://MCP.Example.Com/"),
        ]),
    )
    .await;
    assert_eq!(t_st, StatusCode::OK);
    let tj = parse_json(&t_b);
    assert_eq!(tj["scope"], "mcp");
    let rt = tj["refresh_token"].as_str().unwrap();

    let (rf_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", rt),
            ("resource", "HTTPS://mcp.example.com/mcp"),
        ]),
    )
    .await;
    assert_eq!(rf_st, StatusCode::OK);

    // HTTP loopback keeps mcp_ar_<ar_id> with Path=/oauth/authorize, and Deny returns access_denied.
    let tmp_http = TempDir::new().unwrap();
    let http_cfg = build_config(
        tmp_http.path(),
        &TestOpts {
            public_url: "http://127.0.0.1:8080",
            ..Default::default()
        },
    );
    let http_engine = OAuthEngine::open(http_cfg).unwrap();
    let http_cid = register_public_client(&http_engine, cb, Some("Loopback App")).await;
    let (_, ch_deny) = pkce_pair("deny-test");
    let dq = form_encode(&[
        ("response_type", "code"),
        ("client_id", &http_cid),
        ("redirect_uri", cb),
        ("code_challenge", &ch_deny),
        ("code_challenge_method", "S256"),
        ("state", "deny-state"),
    ]);
    let (dg_st, dg_hdr, dg_b) = send_req(
        &http_engine,
        Method::GET,
        &format!("/oauth/authorize?{dq}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(dg_st, StatusCode::OK);
    let raw_http_cookie = dg_hdr[header::SET_COOKIE].to_str().unwrap();
    assert!(raw_http_cookie.starts_with("mcp_ar_"));
    assert!(raw_http_cookie.contains("Path=/oauth/authorize;"));
    assert!(!raw_http_cookie.contains("Secure"));

    let d_cookie = extract_cookie_pair(&dg_hdr);
    let d_html = std::str::from_utf8(&dg_b).unwrap();
    let d_ar = extract_hidden_input(d_html, "ar_id");
    let d_csrf = extract_hidden_input(d_html, "csrf_token");
    assert!(d_html.contains("name=\"decision\" value=\"deny\""));

    let (dp_st, dp_hdr, _) = send_req(
        &http_engine,
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &d_cookie),
        ],
        form_encode(&[
            ("ar_id", &d_ar),
            ("csrf_token", &d_csrf),
            ("decision", "deny"),
        ]),
    )
    .await;
    assert_eq!(dp_st, StatusCode::SEE_OTHER);
    assert!(
        dp_hdr[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let deny_loc = Url::parse(dp_hdr[header::LOCATION].to_str().unwrap()).unwrap();
    let deny_q: BTreeMap<String, String> = deny_loc.query_pairs().into_owned().collect();
    assert_eq!(
        deny_q.get("error").map(String::as_str),
        Some("access_denied")
    );
    assert_eq!(deny_q.get("state").map(String::as_str), Some("deny-state"));
    assert_eq!(
        deny_q.get("iss").map(String::as_str),
        Some("http://127.0.0.1:8080")
    );
}

#[tokio::test]
async fn refresh_grace_defaults_to_access_token_ttl_one_hour_and_syncs_with_access_ttl() {
    let tmp = TempDir::new().unwrap();
    let hash = PasswordVerifier::from_plaintext_with_iterations("secret123", 10_000)
        .unwrap()
        .encode();
    let default_cfg = GatewayConfig::from_json_str(
        &json!({
            "listen": "127.0.0.1:0",
            "public_url": "http://127.0.0.1:8080",
            "state_path": tmp.path().join("default-state.json").to_string_lossy(),
            "oauth": {
                "owner_password_hash": hash,
                "scopes": ["mcp"]
            },
            "upstream": {
                "transport": "http",
                "url": "http://127.0.0.1:9999/mcp"
            }
        })
        .to_string(),
        tmp.path(),
    )
    .unwrap();
    assert_eq!(default_cfg.oauth.access_token_ttl_secs, 3600);
    assert_eq!(default_cfg.oauth.refresh_grace_secs, 3600);

    let synced_cfg = GatewayConfig::from_json_str(
        &json!({
            "listen": "127.0.0.1:0",
            "public_url": "http://127.0.0.1:8080",
            "state_path": tmp.path().join("synced-state.json").to_string_lossy(),
            "oauth": {
                "owner_password_hash": hash,
                "access_token_ttl_secs": 1800,
                "scopes": ["mcp"]
            },
            "upstream": {
                "transport": "http",
                "url": "http://127.0.0.1:9999/mcp"
            }
        })
        .to_string(),
        tmp.path(),
    )
    .unwrap();
    assert_eq!(synced_cfg.oauth.refresh_grace_secs, 1800);

    let over_cap = GatewayConfig::from_json_str(
        &json!({
            "listen": "127.0.0.1:0",
            "public_url": "http://127.0.0.1:8080",
            "state_path": tmp.path().join("over-state.json").to_string_lossy(),
            "oauth": {
                "owner_password_hash": hash,
                "refresh_grace_secs": 86_401,
                "scopes": ["mcp"]
            },
            "upstream": {
                "transport": "http",
                "url": "http://127.0.0.1:9999/mcp"
            }
        })
        .to_string(),
        tmp.path(),
    );
    assert!(over_cap.is_err());
}

#[tokio::test]
async fn converge_policy_preserves_same_client_continuity_past_grace_and_restart_while_enforcing_boundaries()
 {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(
        tmp.path(),
        &TestOpts {
            refresh_grace_secs: 1,
            refresh_reuse_policy: "converge",
            ..Default::default()
        },
    );
    let engine = OAuthEngine::open(Arc::clone(&cfg)).unwrap();

    let cb_a = "http://127.0.0.1:28101/cb";
    let cb_b = "http://127.0.0.1:28102/cb";
    let client_a = register_public_client(&engine, cb_a, Some("Parent+Subagents")).await;
    let client_b = register_public_client(&engine, cb_b, Some("Other Client")).await;

    let (_a0, r0) = mint_public_grant(&engine, &client_a, cb_a, "conv-0").await;

    // Subagent rotates R0 -> R1 -> R2.
    let (s1, _, b1) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_a),
            ("refresh_token", &r0),
        ]),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    let r1 = parse_json(&b1)["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let (s2, _, b2) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_a),
            ("refresh_token", &r1),
        ]),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    let j2 = parse_json(&b2);
    let a2 = j2["access_token"].as_str().unwrap().to_owned();
    let r2 = j2["refresh_token"].as_str().unwrap().to_owned();

    // Wait past refresh_grace_secs (1s) so R0 is outside the grace window.
    tokio::time::sleep(Duration::from_millis(2100)).await;

    // Same authenticated client presenting stale R0 converges to live tip (a2, r2) without revoking grant.
    let (s_late, _, b_late) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_a),
            ("refresh_token", &r0),
        ]),
    )
    .await;
    assert_eq!(s_late, StatusCode::OK);
    let j_late = parse_json(&b_late);
    assert_eq!(j_late["access_token"], a2);
    assert_eq!(j_late["refresh_token"], r2);

    // Cross-client replay of R0 is rejected and does NOT revoke client_a's grant.
    let (s_cross, _, b_cross) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_b),
            ("refresh_token", &r0),
        ]),
    )
    .await;
    assert_eq!(s_cross, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&b_cross)["error"], "invalid_grant");

    // Simulate gateway restart (in-memory grace_cache cleared); stale R0 still converges cleanly.
    drop(engine);
    let restarted = OAuthEngine::open(Arc::clone(&cfg)).unwrap();
    let (s_restart, _, b_restart) = send_req(
        &restarted,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_a),
            ("refresh_token", &r0),
        ]),
    )
    .await;
    assert_eq!(s_restart, StatusCode::OK);
    let j_restart = parse_json(&b_restart);
    let r3 = j_restart["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(r3, r2);

    // Explicit /oauth/revoke permanently invalidates the entire family including R0 and R3.
    let (s_rev, _, _) = send_req(
        &restarted,
        Method::POST,
        "/oauth/revoke",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[("client_id", &client_a), ("token", &r3)]),
    )
    .await;
    assert_eq!(s_rev, StatusCode::OK);

    let (s_after_rev, _, b_after_rev) = send_req(
        &restarted,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_a),
            ("refresh_token", &r0),
        ]),
    )
    .await;
    assert_eq!(s_after_rev, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&b_after_rev)["error"], "invalid_grant");
}

#[tokio::test]
async fn trusted_proxies_xff_extraction_and_untrusted_loopback_token_bucket() {
    let tmp = TempDir::new().unwrap();
    let pw_hash = PasswordVerifier::from_plaintext_with_iterations(OWNER_SECRET, 10_000)
        .unwrap()
        .encode();
    let proxy_cfg = Arc::new(
        GatewayConfig::from_json_str(
            &json!({
                "listen": "127.0.0.1:0",
                "public_url": "https://mcp.example.com",
                "state_path": "proxy_state.json",
                "trusted_proxies": ["127.0.0.1", "10.0.0.1"],
                "oauth": { "owner_password_hash": pw_hash },
                "upstream": {
                    "transport": "http",
                    "url": "http://127.0.0.1:9090/mcp",
                    "bearer_tokens": ["up-tok"]
                }
            })
            .to_string(),
            tmp.path(),
        )
        .unwrap(),
    );
    let proxy_engine = OAuthEngine::open(proxy_cfg).unwrap();
    let cb = "http://127.0.0.1:29100/cb";
    let cid = register_public_client(&proxy_engine, cb, Some("Proxy Test")).await;

    let open_form = |eng: Arc<OAuthEngine>, client_id: String| async move {
        let (_, ch) = pkce_pair("proxy-pkce");
        let q = form_encode(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", cb),
            ("code_challenge", &ch),
            ("code_challenge_method", "S256"),
        ]);
        let (st, hdr, b) = send_req(
            &eng,
            Method::GET,
            &format!("/oauth/authorize?{q}"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let html = std::str::from_utf8(&b).unwrap();
        (
            extract_cookie_pair(&hdr),
            extract_hidden_input(html, "ar_id"),
            extract_hidden_input(html, "csrf_token"),
        )
    };

    let proxy_peer: IpAddr = "127.0.0.1".parse().unwrap();
    let (cookie, ar_id, csrf) = open_form(Arc::clone(&proxy_engine), cid.clone()).await;

    // Rightmost non-trusted IP in XFF (203.0.113.77) is isolated from spoofed leftmost IP (198.51.100.250).
    for _ in 0..10 {
        let (st, _, _) = send_req_from_ip(
            &proxy_engine,
            Some(proxy_peer),
            Method::POST,
            "/oauth/authorize",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("cookie", &cookie),
                ("x-forwarded-for", "198.51.100.250, 203.0.113.77, 10.0.0.1"),
            ],
            form_encode(&[
                ("ar_id", &ar_id),
                ("csrf_token", &csrf),
                ("password", "wrong-guess"),
            ]),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    let (locked_st, _, _) = send_req_from_ip(
        &proxy_engine,
        Some(proxy_peer),
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie),
            ("x-forwarded-for", "198.51.100.9, 203.0.113.77, 10.0.0.1"),
        ],
        form_encode(&[
            ("ar_id", &ar_id),
            ("csrf_token", &csrf),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(locked_st, StatusCode::TOO_MANY_REQUESTS);

    // Legitimate user 198.51.100.250 behind the same trusted proxy succeeds cleanly.
    let (ok_st, _, _) = send_req_from_ip(
        &proxy_engine,
        Some(proxy_peer),
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie),
            ("x-forwarded-for", "198.51.100.250, 10.0.0.1"),
        ],
        form_encode(&[
            ("ar_id", &ar_id),
            ("csrf_token", &csrf),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(ok_st, StatusCode::SEE_OTHER);

    // Direct untrusted peer ignores forged X-Forwarded-For referencing locked-out 203.0.113.77.
    let (cookie2, ar_id2, csrf2) = open_form(Arc::clone(&proxy_engine), cid.clone()).await;
    let untrusted_peer: IpAddr = "198.51.100.55".parse().unwrap();
    let (direct_st, _, _) = send_req_from_ip(
        &proxy_engine,
        Some(untrusted_peer),
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie2),
            ("x-forwarded-for", "203.0.113.77"),
        ],
        form_encode(&[
            ("ar_id", &ar_id2),
            ("csrf_token", &csrf2),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(direct_st, StatusCode::SEE_OTHER);

    // Untrusted loopback (trusted_proxies empty) uses short-window token bucket rather than 15m lockout.
    let loop_cfg = build_config(tmp.path(), &TestOpts::default());
    let loop_engine = OAuthEngine::open(loop_cfg).unwrap();
    let loop_cid = register_public_client(&loop_engine, cb, Some("Loopback Bucket")).await;
    let (l_cookie, l_ar, l_csrf) = open_form(Arc::clone(&loop_engine), loop_cid).await;

    let mut saw_throttled = false;
    for _ in 0..14 {
        let (st, _, _) = send_req_from_ip(
            &loop_engine,
            Some(proxy_peer),
            Method::POST,
            "/oauth/authorize",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("cookie", &l_cookie),
            ],
            form_encode(&[
                ("ar_id", &l_ar),
                ("csrf_token", &l_csrf),
                ("password", "wrong-loop"),
            ]),
        )
        .await;
        if st == StatusCode::TOO_MANY_REQUESTS {
            saw_throttled = true;
            break;
        }
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    assert!(
        saw_throttled,
        "loopback burst must trigger short-window 429"
    );

    tokio::time::sleep(Duration::from_millis(2200)).await;
    let (bucket_refilled_st, _, _) = send_req_from_ip(
        &loop_engine,
        Some(proxy_peer),
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &l_cookie),
        ],
        form_encode(&[
            ("ar_id", &l_ar),
            ("csrf_token", &l_csrf),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(bucket_refilled_st, StatusCode::SEE_OTHER);

    // check_authorization computes union of unexpired access_tokens when grant has no refresh_token.
    let (reg_no_rt_st, _, reg_no_rt_body) = send_req(
        &loop_engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        json!({
            "redirect_uris": [cb],
            "grant_types": ["authorization_code"],
            "scope": "mcp"
        })
        .to_string(),
    )
    .await;
    assert_eq!(reg_no_rt_st, StatusCode::CREATED);
    let no_rt_cid = parse_json(&reg_no_rt_body)["client_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (nr_ver, nr_ch) = pkce_pair("no-rt-grant");
    let nr_code = authorize_and_get_code(&loop_engine, &no_rt_cid, cb, &nr_ch, "st-nr").await;
    let (nr_tok_st, _, nr_tok_body) = send_req(
        &loop_engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", &no_rt_cid),
            ("code", &nr_code),
            ("redirect_uri", cb),
            ("code_verifier", &nr_ver),
        ]),
    )
    .await;
    assert_eq!(nr_tok_st, StatusCode::OK);
    let nr_tok_json = parse_json(&nr_tok_body);
    assert!(nr_tok_json.get("refresh_token").is_none());
    let nr_at = nr_tok_json["access_token"].as_str().unwrap();
    let mut nr_hdrs = HeaderMap::new();
    nr_hdrs.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {nr_at}")).unwrap(),
    );
    let verified = loop_engine.verify_bearer(&nr_hdrs).unwrap();
    let nr_aref =
        oauth2_mcp_gateway::crypto::compute_auth_ref(&verified.resource, &verified.grant_id);
    let chk = loop_engine.check_authorization(&nr_aref);
    assert_eq!(chk["active"], true);
    assert_eq!(chk["scopes"], json!(["mcp"]));
    assert_eq!(chk["principal"], nr_aref);
}

#[tokio::test]
async fn cidr_trusted_proxies_and_x_real_ip_fallback() {
    let tmp = TempDir::new().unwrap();
    let pw_hash = PasswordVerifier::from_plaintext_with_iterations(OWNER_SECRET, 10_000)
        .unwrap()
        .encode();
    let cfg = Arc::new(
        GatewayConfig::from_json_str(
            &json!({
                "listen": "127.0.0.1:0",
                "public_url": "https://mcp.example.com",
                "state_path": "cidr_state.json",
                "trusted_proxies": ["10.0.0.0/8", "fd00::/8"],
                "oauth": { "owner_password_hash": pw_hash },
                "upstream": {
                    "transport": "http",
                    "url": "http://127.0.0.1:9090/mcp",
                    "bearer_tokens": ["up-tok"]
                }
            })
            .to_string(),
            tmp.path(),
        )
        .unwrap(),
    );
    let engine = OAuthEngine::open(cfg).unwrap();
    let cb = "http://127.0.0.1:29200/cb";
    let cid = register_public_client(&engine, cb, Some("CIDR Proxy Test")).await;

    let open_form = || {
        let eng = Arc::clone(&engine);
        let client_id = cid.clone();
        async move {
            let (_, ch) = pkce_pair("cidr-pkce");
            let q = form_encode(&[
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", cb),
                ("code_challenge", &ch),
                ("code_challenge_method", "S256"),
            ]);
            let (st, hdr, b) = send_req(
                &eng,
                Method::GET,
                &format!("/oauth/authorize?{q}"),
                &[],
                Bytes::new(),
            )
            .await;
            assert_eq!(st, StatusCode::OK);
            let html = std::str::from_utf8(&b).unwrap();
            (
                extract_cookie_pair(&hdr),
                extract_hidden_input(html, "ar_id"),
                extract_hidden_input(html, "csrf_token"),
            )
        }
    };

    // 1. IPv4 CIDR 10.0.0.0/8 strips 10.1.2.3 hop from X-Forwarded-For and isolates 198.51.100.20.
    let v4_proxy: IpAddr = "10.42.99.5".parse().unwrap();
    let (c1, ar1, csrf1) = open_form().await;
    for _ in 0..10 {
        let (st, _, _) = send_req_from_ip(
            &engine,
            Some(v4_proxy),
            Method::POST,
            "/oauth/authorize",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("cookie", &c1),
                ("x-forwarded-for", "198.51.100.20, 10.1.2.3"),
            ],
            form_encode(&[
                ("ar_id", &ar1),
                ("csrf_token", &csrf1),
                ("password", "wrong"),
            ]),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    let (v4_locked, _, _) = send_req_from_ip(
        &engine,
        Some(v4_proxy),
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &c1),
            ("x-forwarded-for", "198.51.100.20, 10.1.2.3"),
        ],
        form_encode(&[
            ("ar_id", &ar1),
            ("csrf_token", &csrf1),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(v4_locked, StatusCode::TOO_MANY_REQUESTS);

    // 2. IPv6 CIDR fd00::/8 falls back to X-Real-IP when X-Forwarded-For is absent.
    let v6_proxy: IpAddr = "fd12:3456::9".parse().unwrap();
    let (c2, ar2, csrf2) = open_form().await;
    for _ in 0..10 {
        let (st, _, _) = send_req_from_ip(
            &engine,
            Some(v6_proxy),
            Method::POST,
            "/oauth/authorize",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("cookie", &c2),
                ("x-real-ip", "2001:db8::44"),
            ],
            form_encode(&[
                ("ar_id", &ar2),
                ("csrf_token", &csrf2),
                ("password", "wrong"),
            ]),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    let (v6_locked, _, _) = send_req_from_ip(
        &engine,
        Some(v6_proxy),
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &c2),
            ("x-real-ip", "2001:db8::44"),
        ],
        form_encode(&[
            ("ar_id", &ar2),
            ("csrf_token", &csrf2),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(v6_locked, StatusCode::TOO_MANY_REQUESTS);

    let (v6_other_ok, _, _) = send_req_from_ip(
        &engine,
        Some(v6_proxy),
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &c2),
            ("x-real-ip", "2001:db8::55"),
        ],
        form_encode(&[
            ("ar_id", &ar2),
            ("csrf_token", &csrf2),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(v6_other_ok, StatusCode::SEE_OTHER);

    // 3. Untrusted peer outside CIDR ignores forged X-Real-IP.
    let (c3, ar3, csrf3) = open_form().await;
    let untrusted: IpAddr = "11.0.0.5".parse().unwrap();
    let (untrusted_ok, _, _) = send_req_from_ip(
        &engine,
        Some(untrusted),
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &c3),
            ("x-real-ip", "2001:db8::44"),
        ],
        form_encode(&[
            ("ar_id", &ar3),
            ("csrf_token", &csrf3),
            ("password", OWNER_SECRET),
        ]),
    )
    .await;
    assert_eq!(untrusted_ok, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn rfc8252_literal_loopback_dynamic_port_matching_and_token_port_binding() {
    let tmp = TempDir::new().unwrap();
    let cfg = build_config(tmp.path(), &TestOpts::default());
    let engine = OAuthEngine::open(cfg).unwrap();

    let (reg_st, _, reg_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        json!({
            "client_name": "Native CLI",
            "redirect_uris": [
                "http://127.0.0.1:41000/callback",
                "http://[::1]:41000/callback?mode=cli",
                "http://localhost:41000/callback",
                "https://127.0.0.1:41000/secure"
            ]
        })
        .to_string(),
    )
    .await;
    assert_eq!(reg_st, StatusCode::CREATED);
    let client_id = parse_json(&reg_body)["client_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Reject path/query mismatch, port 0, localhost dynamic port, and https dynamic port.
    let (_, ch_bad) = pkce_pair("bad-dyn");
    for rejected_uri in [
        "http://127.0.0.1:53991/other",
        "http://127.0.0.1:53991/callback?extra=1",
        "http://[::1]:61444/callback?mode=wrong",
        "http://127.0.0.1:0/callback",
        "http://[::1]:0/callback?mode=cli",
        "http://localhost:53991/callback",
        "https://127.0.0.1:53991/secure",
    ] {
        let q = form_encode(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", rejected_uri),
            ("code_challenge", &ch_bad),
            ("code_challenge_method", "S256"),
        ]);
        let (st, hdr, _) = send_req(
            &engine,
            Method::GET,
            &format!("/oauth/authorize?{q}"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "expected {rejected_uri} to be rejected"
        );
        assert!(!hdr.contains_key(header::LOCATION));
    }

    // Authorize with dynamic ephemeral port 53991, then verify /oauth/token rejects port 41000.
    let ephem_v4_a = "http://127.0.0.1:53991/callback";
    let (ver_a, ch_a) = pkce_pair("dyn-v4-a");
    let code_a = authorize_and_get_code(&engine, &client_id, ephem_v4_a, &ch_a, "st-a").await;
    let (mismatch_tok_st, _, mismatch_tok_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id),
            ("code", &code_a),
            ("redirect_uri", "http://127.0.0.1:41000/callback"),
            ("code_verifier", &ver_a),
        ]),
    )
    .await;
    assert_eq!(mismatch_tok_st, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&mismatch_tok_body)["error"], "invalid_grant");

    // Authorize on a second ephemeral IPv4 port 58123 and exchange with exact matching redirect_uri.
    let ephem_v4_b = "http://127.0.0.1:58123/callback";
    let (ver_b, ch_b) = pkce_pair("dyn-v4-b");
    let code_b = authorize_and_get_code(&engine, &client_id, ephem_v4_b, &ch_b, "st-b").await;
    let (ok_v4_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id),
            ("code", &code_b),
            ("redirect_uri", ephem_v4_b),
            ("code_verifier", &ver_b),
        ]),
    )
    .await;
    assert_eq!(ok_v4_st, StatusCode::OK);

    // Authorize on ephemeral IPv6 [::1] port with exact query preservation and exchange.
    let ephem_v6 = "http://[::1]:61444/callback?mode=cli";
    let (ver_v6, ch_v6) = pkce_pair("dyn-v6");
    let code_v6 = authorize_and_get_code(&engine, &client_id, ephem_v6, &ch_v6, "st-v6").await;
    let (ok_v6_st, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/token",
        &[("content-type", "application/x-www-form-urlencoded")],
        form_encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id),
            ("code", &code_v6),
            ("redirect_uri", ephem_v6),
            ("code_verifier", &ver_v6),
        ]),
    )
    .await;
    assert_eq!(ok_v6_st, StatusCode::OK);
}
