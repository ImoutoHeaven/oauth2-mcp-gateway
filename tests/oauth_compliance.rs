use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use http_body::Frame;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper_util::rt::TokioIo;
use oauth2_mcp_gateway::config::GatewayConfig;
use oauth2_mcp_gateway::crypto::{PasswordVerifier, sha256_b64};
use oauth2_mcp_gateway::oauth::OAuthEngine;
use oauth2_mcp_gateway::store::{
    AccessTokenRecord, GrantRecord, PersistedState, RefreshTokenRecord, STATE_VERSION, unix_now,
};
use oauth2_mcp_gateway::types::AuthChallenge;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::convert::Infallible;
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
            refresh_grace_secs: 120,
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

async fn dispatch_box_body(
    engine: &Arc<OAuthEngine>,
    req: Request<BoxBody<Bytes, Infallible>>,
) -> (StatusCode, HeaderMap, Bytes) {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let eng = Arc::clone(engine);
    let srv_task = tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |incoming| {
            let eng = Arc::clone(&eng);
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

async fn send_req(
    engine: &Arc<OAuthEngine>,
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
    dispatch_box_body(engine, req).await
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
    let (lim_status, _, _) = send_req(
        &engine,
        Method::POST,
        "/oauth/register",
        &[("content-type", "application/json")],
        oversized,
    )
    .await;
    assert_eq!(lim_status, StatusCode::PAYLOAD_TOO_LARGE);

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
    let (chunk_status, _, _) = dispatch_box_body(&engine, chunked_req).await;
    assert_eq!(chunk_status, StatusCode::PAYLOAD_TOO_LARGE);
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

    for bad_payload in [
        json!({ "redirect_uris": [] }),
        json!({ "redirect_uris": ["/relative/cb"] }),
        json!({ "redirect_uris": ["http://claude.ai/cb"] }),
        json!({ "redirect_uris": ["https://claude.ai/cb#frag"] }),
        json!({ "redirect_uris": ["https://user:pw@claude.ai/cb"] }),
        json!({ "redirect_uris": ["https://unlisted.example.org/cb"] }),
        json!({ "redirect_uris": ["https://claude.ai/cb?%73tate=old"] }),
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
    ]);
    let (no_pkce_st, no_pkce_hdr, _) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{no_pkce_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(no_pkce_st, StatusCode::BAD_REQUEST);
    assert!(!no_pkce_hdr.contains_key(header::LOCATION));

    let (verifier, challenge) = pkce_pair("conf-basic");
    let plain_pkce_q = form_encode(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", cb_uri),
        ("code_challenge", &verifier),
        ("code_challenge_method", "plain"),
    ]);
    let (plain_st, _, _) = send_req(
        &engine,
        Method::GET,
        &format!("/oauth/authorize?{plain_pkce_q}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(plain_st, StatusCode::BAD_REQUEST);

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
    let expected_csp = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'";
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
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
    );
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(headers.get(header::REFERRER_POLICY).unwrap(), "no-referrer");

    let raw_set_cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(raw_set_cookie.contains("HttpOnly"));
    assert!(raw_set_cookie.contains("SameSite=Lax"));
    assert!(raw_set_cookie.contains("Path=/oauth/authorize"));
    assert!(raw_set_cookie.contains("Max-Age=300"));
    assert!(raw_set_cookie.contains("Secure"));

    let html = std::str::from_utf8(&body).unwrap();
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#x27;&amp;client"));
    assert!(html.contains("http://127.0.0.1:19000/cb;part,more?x=1&amp;y=2"));

    let ar_id = extract_hidden_input(html, "ar_id");
    let csrf_token = extract_hidden_input(html, "csrf_token");
    let cookie_pair = extract_cookie_pair(&headers);

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
            ("cookie", &format!("mcp_ar_{ar_id}=forged")),
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

    let (ok_st, completed_headers, completed_body) = send_req(
        &engine,
        Method::POST,
        "/oauth/authorize",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", &cookie_pair),
            ("sec-fetch-mode", "navigate"),
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

    let (reordered_status, _, _) = send_req(
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
    assert_eq!(retried["access_token"], *a1);
    assert_eq!(retried["refresh_token"], *r1);

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
        .refresh_tokens
        .iter()
        .find(|rt| rt.token_sha256 == sha256_b64(&r0))
        .unwrap()
        .grace_until
        .unwrap();

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
        .refresh_tokens
        .iter()
        .find(|rt| rt.token_sha256 == sha256_b64(&r0))
        .unwrap()
        .grace_until
        .unwrap();
    assert_eq!(
        r0_grace_after, r0_grace_before,
        "mid-grace restart fallback must not extend R0 grace_until"
    );

    let now = unix_now();
    let expired_at_raw = "expired-access-token-value";
    let past_grace_rt_raw = "rotated-past-grace-but-unexpired-rt";
    let active_at_raw = "active-access-token-value";
    let active_rt_raw = "active-refresh-token-value";
    let crafted = PersistedState {
        version: STATE_VERSION,
        clients: disk_after.clients.clone(),
        grants: vec![GrantRecord {
            grant_id: "grt_crafted".to_owned(),
            client_id: client_id.clone(),
            pool_slot: 0,
            scopes: vec!["mcp".to_owned()],
            resource: "https://mcp.example.com/mcp".to_owned(),
            access_tokens: vec![
                AccessTokenRecord {
                    token_sha256: sha256_b64(expired_at_raw),
                    expires_at: now.saturating_sub(10),
                },
                AccessTokenRecord {
                    token_sha256: sha256_b64(active_at_raw),
                    expires_at: now + 3600,
                },
            ],
            refresh_tokens: vec![
                RefreshTokenRecord {
                    token_sha256: sha256_b64(past_grace_rt_raw),
                    expires_at: now + 7200,
                    grace_until: Some(now.saturating_sub(5)),
                },
                RefreshTokenRecord {
                    token_sha256: sha256_b64(active_rt_raw),
                    expires_at: now + 7200,
                    grace_until: None,
                },
            ],
        }],
    };
    std::fs::write(&state_path, serde_json::to_vec_pretty(&crafted).unwrap()).unwrap();

    let engine3 = OAuthEngine::open(Arc::clone(&cfg)).unwrap();
    let cleaned: PersistedState =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(cleaned.grants[0].access_tokens.len(), 1);
    assert_eq!(
        cleaned.grants[0].refresh_tokens.len(),
        2,
        "rotated refresh token with unexpired expires_at must survive startup cleanup"
    );

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
            ("refresh_token", past_grace_rt_raw),
        ]),
    )
    .await;
    assert_eq!(reuse_st, StatusCode::BAD_REQUEST);
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
