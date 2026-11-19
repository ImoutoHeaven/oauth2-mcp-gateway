use crate::config::{GatewayConfig, UpstreamSettings, is_loopback_host};
use crate::oauth::OAuthEngine;
use crate::types::{HttpReply, ReplyBody, empty_body, json_reply, method_not_allowed};
use crate::upstream_http::{HttpUpstream, close_empty_reply, is_safe_request_path};
use crate::upstream_stdio::StdioUpstream;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

const MAX_CONCURRENT_CONNECTIONS: usize = 256;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(60);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(5);

struct RateLimitedLog {
    last_logged: Option<Instant>,
    suppressed: u64,
    interval: Duration,
}

impl RateLimitedLog {
    fn new(interval: Duration) -> Self {
        Self {
            last_logged: None,
            suppressed: 0,
            interval,
        }
    }

    fn log(&mut self, msg: &str) {
        let now = Instant::now();
        let should_log = self
            .last_logged
            .is_none_or(|prev| now.duration_since(prev) >= self.interval);
        if should_log {
            if self.suppressed > 0 {
                eprintln!("[gateway] {msg} ({} suppressed)", self.suppressed);
                self.suppressed = 0;
            } else {
                eprintln!("[gateway] {msg}");
            }
            self.last_logged = Some(now);
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
        }
    }
}

#[derive(Clone)]
enum UpstreamRuntime {
    Http(Arc<HttpUpstream>),
    Stdio(Arc<StdioUpstream>),
}

impl UpstreamRuntime {
    async fn terminate_grant(&self, grant_id: &str) {
        match self {
            Self::Http(http) => http.terminate_grant(grant_id).await,
            Self::Stdio(stdio) => stdio.terminate_grant(grant_id).await,
        }
    }

    async fn shutdown(&self) {
        match self {
            Self::Http(http) => http.shutdown().await,
            Self::Stdio(stdio) => stdio.shutdown().await,
        }
    }
}

#[derive(Clone)]
struct HostPolicy {
    public_host: String,
    public_port: u16,
    public_default_port: u16,
    allow_loopback: bool,
}

impl HostPolicy {
    fn from_config(config: &GatewayConfig, local_addr: Option<SocketAddr>) -> Result<Self, String> {
        let parsed =
            Url::parse(&config.public_url).map_err(|e| format!("invalid public_url: {e}"))?;
        let public_host = parsed
            .host_str()
            .ok_or_else(|| "public_url must specify a host".to_owned())?
            .to_ascii_lowercase();
        let public_default_port = if config.public_is_https { 443 } else { 80 };
        let public_port = parsed.port().unwrap_or(public_default_port);
        let allow_loopback =
            config.listen.ip().is_loopback() || local_addr.is_some_and(|a| a.ip().is_loopback());
        Ok(Self {
            public_host,
            public_port,
            public_default_port,
            allow_loopback,
        })
    }

    fn allows(&self, headers: &HeaderMap, uri_authority: Option<&str>) -> bool {
        let mut iter = headers.get_all(header::HOST).iter();
        let Some(raw_hdr) = iter.next() else {
            return false;
        };
        if iter.next().is_some() {
            return false;
        }
        let Ok(raw_str) = raw_hdr.to_str() else {
            return false;
        };
        if !self.matches_authority(raw_str) {
            return false;
        }
        if let Some(auth) = uri_authority
            && !self.matches_authority(auth)
        {
            return false;
        }
        true
    }

    fn matches_authority(&self, raw: &str) -> bool {
        let Some((host, port)) = parse_host_authority(raw.trim_ascii()) else {
            return false;
        };
        if host == self.public_host && port.unwrap_or(self.public_default_port) == self.public_port
        {
            return true;
        }
        self.allow_loopback && is_loopback_host(&host)
    }
}

fn parse_host_authority(raw: &str) -> Option<(String, Option<u16>)> {
    if raw.is_empty()
        || raw
            .bytes()
            .any(|b| b <= 0x20 || b >= 0x7f || matches!(b, b'/' | b'\\' | b'?' | b'#' | b'@'))
    {
        return None;
    }

    if raw.starts_with('[') {
        let close = raw.find(']')?;
        let ipv6: Ipv6Addr = raw[1..close].parse().ok()?;
        let rest = &raw[close + 1..];
        let port = if rest.is_empty() {
            None
        } else {
            Some(parse_port(rest.strip_prefix(':')?)?)
        };
        return Some((format!("[{ipv6}]"), port));
    }

    if raw.contains('[') || raw.contains(']') {
        return None;
    }

    let (host_part, port) = match raw.split_once(':') {
        Some((h, p)) => (h, Some(parse_port(p)?)),
        None => (raw, None),
    };
    if host_part.is_empty() {
        return None;
    }

    if host_part.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let ipv4: Ipv4Addr = host_part.parse().ok()?;
        return Some((ipv4.to_string(), port));
    }

    if host_part.ends_with('.') {
        return None;
    }
    let parsed = Host::parse(host_part).ok()?;
    if !matches!(parsed, Host::Domain(_)) {
        return None;
    }
    Some((parsed.to_string().to_ascii_lowercase(), port))
}

fn parse_port(raw: &str) -> Option<u16> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u16>().ok().filter(|&p| p > 0)
}

struct ConnActivity {
    in_flight: AtomicUsize,
    last_idle_ns: AtomicU64,
    idle_notify: Notify,
    epoch: Instant,
}

impl ConnActivity {
    fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            last_idle_ns: AtomicU64::new(0),
            idle_notify: Notify::new(),
            epoch: Instant::now(),
        }
    }
}

struct ActiveReqGuard {
    activity: Arc<ConnActivity>,
}

impl Drop for ActiveReqGuard {
    fn drop(&mut self) {
        if self.activity.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.activity
                .last_idle_ns
                .store(elapsed_ns(self.activity.epoch), Ordering::Release);
            self.activity.idle_notify.notify_waiters();
        }
    }
}

struct ActiveReplyBody {
    inner: ReplyBody,
    guard: Option<ActiveReqGuard>,
}

impl Body for ActiveReplyBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(polled, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            this.guard = None;
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn elapsed_ns(epoch: Instant) -> u64 {
    u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

async fn wait_for_conn_idle(activity: &ConnActivity, timeout: Duration) {
    let timeout_ns = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
    loop {
        let notified = activity.idle_notify.notified();
        if activity.in_flight.load(Ordering::Acquire) > 0 {
            notified.await;
            continue;
        }
        let last_idle = activity.last_idle_ns.load(Ordering::Acquire);
        let now = elapsed_ns(activity.epoch);
        let idle_for = now.saturating_sub(last_idle);
        if idle_for >= timeout_ns {
            if activity.in_flight.load(Ordering::Acquire) == 0
                && activity.last_idle_ns.load(Ordering::Acquire) == last_idle
            {
                return;
            }
            continue;
        }
        tokio::time::sleep(Duration::from_nanos(timeout_ns - idle_for)).await;
    }
}

pub async fn run(config: Arc<GatewayConfig>, shutdown: CancellationToken) -> Result<(), String> {
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("cannot bind {}: {e}", config.listen))?;
    serve_with_listener(listener, config, shutdown).await
}

pub async fn serve_with_listener(
    listener: TcpListener,
    config: Arc<GatewayConfig>,
    shutdown: CancellationToken,
) -> Result<(), String> {
    let host_policy = Arc::new(HostPolicy::from_config(
        &config,
        listener.local_addr().ok(),
    )?);
    let upstream = match &config.upstream {
        UpstreamSettings::Http(settings) => {
            UpstreamRuntime::Http(Arc::new(HttpUpstream::new(settings.clone())?))
        }
        UpstreamSettings::Stdio(settings) => {
            UpstreamRuntime::Stdio(Arc::new(StdioUpstream::new(settings.clone())?))
        }
    };

    let revoke_tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let revoke_tasks_hook = Arc::clone(&revoke_tasks);
    let upstream_for_revoke = upstream.clone();
    let handle = tokio::runtime::Handle::current();
    let oauth = OAuthEngine::open_with_revoke_hook(
        Arc::clone(&config),
        Arc::new(move |grant_id| {
            let up = upstream_for_revoke.clone();
            let gid = grant_id.to_owned();
            let jh = handle.spawn(async move {
                up.terminate_grant(&gid).await;
            });
            let mut tasks = revoke_tasks_hook.lock().unwrap_or_else(|p| p.into_inner());
            tasks.retain(|h| !h.is_finished());
            tasks.push(jh);
        }),
    )?;

    let public_url: Arc<str> = Arc::from(config.public_url.as_str());
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut connections = JoinSet::new();
    let mut accept_err_log = RateLimitedLog::new(ERROR_LOG_INTERVAL);
    let mut full_conn_log = RateLimitedLog::new(ERROR_LOG_INTERVAL);

    loop {
        while connections.try_join_next().is_some() {}

        tokio::select! {
            _ = shutdown.cancelled() => break,
            accept_res = listener.accept() => {
                let (stream, peer_addr) = match accept_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        accept_err_log.log(&format!("accept failed: {err}"));
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };

                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    full_conn_log.log("connection limit reached, dropping incoming socket");
                    drop(stream);
                    continue;
                };

                let _ = stream.set_nodelay(true);
                let peer_ip = peer_addr.ip();
                let io = TokioIo::new(stream);
                let oauth_ref = Arc::clone(&oauth);
                let upstream_ref = upstream.clone();
                let public_url_ref = Arc::clone(&public_url);
                let host_policy_ref = Arc::clone(&host_policy);
                let conn_shutdown = shutdown.clone();
                let activity = Arc::new(ConnActivity::new());
                let svc_activity = Arc::clone(&activity);

                connections.spawn(async move {
                    let _permit = permit;
                    let svc = service_fn(move |mut req: Request<Incoming>| {
                        svc_activity.in_flight.fetch_add(1, Ordering::AcqRel);
                        let req_guard = ActiveReqGuard {
                            activity: Arc::clone(&svc_activity),
                        };
                        req.extensions_mut().insert(peer_ip);
                        let oauth_inner = Arc::clone(&oauth_ref);
                        let upstream_inner = upstream_ref.clone();
                        let public_url_inner = Arc::clone(&public_url_ref);
                        let host_inner = Arc::clone(&host_policy_ref);
                        async move {
                            let resp = route_request(
                                req,
                                &oauth_inner,
                                &upstream_inner,
                                &public_url_inner,
                                &host_inner,
                            )
                            .await;
                            // Hold active guard until the response body finishes streaming.
                            let wrapped = resp.map(|body| {
                                ActiveReplyBody {
                                    inner: body,
                                    guard: Some(req_guard),
                                }
                                .boxed()
                            });
                            Ok::<HttpReply, Infallible>(wrapped)
                        }
                    });

                    let mut builder = http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT);
                    let conn = builder.serve_connection(io, svc);
                    let idle_expired = wait_for_conn_idle(&activity, IDLE_KEEPALIVE_TIMEOUT);
                    tokio::pin!(conn);
                    tokio::pin!(idle_expired);

                    tokio::select! {
                        _ = &mut conn => {}
                        _ = &mut idle_expired => {
                            conn.as_mut().graceful_shutdown();
                            let _ = tokio::time::timeout(HEADER_READ_TIMEOUT, &mut conn).await;
                        }
                        _ = conn_shutdown.cancelled() => {
                            conn.as_mut().graceful_shutdown();
                            let _ = conn.await;
                        }
                    }
                });
            }
        }
    }

    drop(listener);
    let _ = tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}

    let pending_revokes: Vec<JoinHandle<()>> =
        std::mem::take(&mut *revoke_tasks.lock().unwrap_or_else(|p| p.into_inner()));
    for jh in pending_revokes {
        let _ = jh.await;
    }

    upstream.shutdown().await;
    Ok(())
}

async fn route_request(
    req: Request<Incoming>,
    oauth: &OAuthEngine,
    upstream: &UpstreamRuntime,
    public_url: &str,
    host_policy: &HostPolicy,
) -> HttpReply {
    let uri_authority = req.uri().authority().map(|a| a.as_str());
    if !host_policy.allows(req.headers(), uri_authority) {
        return close_empty_reply(StatusCode::BAD_REQUEST);
    }

    let raw_path = req.uri().path();
    let resource_path = oauth.resource_path();

    if raw_path == "/healthz" {
        return match *req.method() {
            Method::GET => json_reply(StatusCode::OK, &json!({ "ok": true })),
            Method::HEAD => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CACHE_CONTROL, "no-store")
                .body(empty_body())
                .expect("valid HEAD /healthz reply"),
            _ => method_not_allowed("GET, HEAD"),
        };
    }

    if is_safe_request_path(raw_path) && is_discovery_route(raw_path) {
        return handle_discovery_route(req, oauth).await;
    }

    if raw_path.starts_with("/oauth/") {
        if !is_allowed_origin(req.headers(), public_url) {
            return close_empty_reply(StatusCode::FORBIDDEN);
        }
        if is_safe_request_path(raw_path) && OAuthEngine::handles_path(raw_path) {
            return oauth.handle(req).await;
        }
        return close_empty_reply(StatusCode::NOT_FOUND);
    }

    if let UpstreamRuntime::Http(http_up) = upstream
        && http_up.matches_passthrough(raw_path)
    {
        if !is_allowed_origin(req.headers(), public_url) {
            return close_empty_reply(StatusCode::FORBIDDEN);
        }
        return http_up.handle_passthrough(req).await;
    }

    if raw_path == resource_path {
        if !is_allowed_origin(req.headers(), public_url) {
            return close_empty_reply(StatusCode::FORBIDDEN);
        }
        let token = match oauth.verify_bearer(req.headers()) {
            Ok(tok) => tok,
            Err(challenge) => return oauth.unauthorized_reply(challenge),
        };
        return match upstream {
            UpstreamRuntime::Http(http_up) => http_up.handle_mcp(req, &token).await,
            UpstreamRuntime::Stdio(stdio_up) => stdio_up.handle_mcp(req, &token).await,
        };
    }

    close_empty_reply(StatusCode::NOT_FOUND)
}

fn is_discovery_route(path: &str) -> bool {
    path == "/.well-known/oauth-protected-resource"
        || path.starts_with("/.well-known/oauth-protected-resource/")
        || path == "/.well-known/oauth-authorization-server"
        || path.starts_with("/.well-known/oauth-authorization-server/")
}

async fn handle_discovery_route(req: Request<Incoming>, oauth: &OAuthEngine) -> HttpReply {
    if *req.method() == Method::OPTIONS {
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS")
            .header(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "MCP-Protocol-Version, Accept, Content-Type",
            )
            .header(header::ACCESS_CONTROL_MAX_AGE, "86400")
            .header(header::CACHE_CONTROL, "no-store")
            .body(empty_body())
            .expect("valid discovery preflight reply");
    }

    let is_get = *req.method() == Method::GET;
    let mut resp = oauth.handle(req).await;
    if is_get {
        resp.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
    } else if resp.status() == StatusCode::METHOD_NOT_ALLOWED {
        resp.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, OPTIONS"));
    }
    resp
}

fn is_allowed_origin(headers: &HeaderMap, public_url: &str) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let Some(first) = origins.next() else {
        return true;
    };
    if origins.next().is_some() {
        return false;
    }
    let Ok(raw) = first.to_str() else {
        return false;
    };
    let trimmed = raw.trim_ascii();
    if trimmed.is_empty() || trimmed.ends_with('/') {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return false;
    }
    parsed.origin().ascii_serialization() == public_url
}
