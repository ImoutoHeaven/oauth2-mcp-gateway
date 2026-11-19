use crate::config::{GatewayConfig, UpstreamSettings};
use crate::oauth::OAuthEngine;
use crate::types::{HttpReply, json_reply};
use crate::upstream_http::{HttpUpstream, close_empty_reply, is_safe_request_path};
use crate::upstream_stdio::StdioUpstream;
use http::{HeaderMap, Method, Request, StatusCode, header};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const MAX_CONCURRENT_CONNECTIONS: usize = 256;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
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
    async fn shutdown(&self) {
        if let Self::Stdio(stdio) = self {
            stdio.shutdown().await;
        }
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
    let upstream = match &config.upstream {
        UpstreamSettings::Http(settings) => {
            UpstreamRuntime::Http(Arc::new(HttpUpstream::new(settings.clone())?))
        }
        UpstreamSettings::Stdio(settings) => {
            UpstreamRuntime::Stdio(Arc::new(StdioUpstream::new(settings.clone())?))
        }
    };
    let oauth = match &upstream {
        UpstreamRuntime::Stdio(stdio) => {
            let stdio_ref = Arc::clone(stdio);
            let handle = tokio::runtime::Handle::current();
            OAuthEngine::open_with_revoke_hook(
                Arc::clone(&config),
                Arc::new(move |grant_id| {
                    let stdio_inner = Arc::clone(&stdio_ref);
                    let gid = grant_id.to_owned();
                    handle.spawn(async move {
                        stdio_inner.terminate_grant(&gid).await;
                    });
                }),
            )?
        }
        UpstreamRuntime::Http(_) => OAuthEngine::open(Arc::clone(&config))?,
    };

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
                let (stream, _) = match accept_res {
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
                let io = TokioIo::new(stream);
                let oauth_ref = Arc::clone(&oauth);
                let upstream_ref = upstream.clone();
                let public_url_ref = Arc::clone(&public_url);
                let conn_shutdown = shutdown.clone();

                connections.spawn(async move {
                    let _permit = permit;
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let oauth_inner = Arc::clone(&oauth_ref);
                        let upstream_inner = upstream_ref.clone();
                        let public_url_inner = Arc::clone(&public_url_ref);
                        async move {
                            Ok::<HttpReply, Infallible>(
                                route_request(req, &oauth_inner, &upstream_inner, &public_url_inner)
                                    .await,
                            )
                        }
                    });

                    let mut builder = http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT);
                    let conn = builder.serve_connection(io, svc);
                    tokio::pin!(conn);

                    tokio::select! {
                        _ = &mut conn => {}
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

    upstream.shutdown().await;
    Ok(())
}

async fn route_request(
    req: Request<Incoming>,
    oauth: &OAuthEngine,
    upstream: &UpstreamRuntime,
    public_url: &str,
) -> HttpReply {
    let raw_path = req.uri().path();

    if *req.method() == Method::GET && raw_path == "/healthz" {
        return json_reply(StatusCode::OK, &json!({ "ok": true }));
    }

    if (raw_path == "/mcp" || raw_path.starts_with("/oauth/"))
        && !is_allowed_origin(req.headers(), public_url)
    {
        return close_empty_reply(StatusCode::FORBIDDEN);
    }

    if is_safe_request_path(raw_path) && OAuthEngine::handles_path(raw_path) {
        return oauth.handle(req).await;
    }

    if let UpstreamRuntime::Http(http_up) = upstream
        && http_up.matches_passthrough(raw_path)
    {
        return http_up.handle_passthrough(req).await;
    }

    if raw_path == "/mcp" {
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

fn is_allowed_origin(headers: &HeaderMap, public_url: &str) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let Some(first) = origins.next() else {
        return true;
    };
    if origins.next().is_some() {
        return false;
    }
    first.to_str().ok() == Some(public_url)
}
