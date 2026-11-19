#![allow(dead_code)]

use bytes::Bytes;
use http::Request;
use http_body::Frame;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use oauth2_mcp_gateway::config::GatewayConfig;
use oauth2_mcp_gateway::server;
use oauth2_mcp_gateway::types::{HttpReply, ReplyBody};
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub type TestClient = Client<HttpConnector, ReplyBody>;
pub type FrameSender = mpsc::Sender<Result<Frame<Bytes>, io::Error>>;

pub struct ReceiverBody {
    pub rx: mpsc::Receiver<Result<Frame<Bytes>, io::Error>>,
}

impl http_body::Body for ReceiverBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

pub fn channel_body(buffer: usize) -> (FrameSender, ReplyBody) {
    let (tx, rx) = mpsc::channel(buffer);
    (tx, ReceiverBody { rx }.boxed())
}

pub fn make_client() -> TestClient {
    Client::builder(TokioExecutor::new()).build_http()
}

pub async fn spawn_http1_harness<F, Fut>(handler: F) -> (SocketAddr, CancellationToken)
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = HttpReply> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind harness listener");
    let addr = listener.local_addr().expect("harness local_addr");
    let cancel = CancellationToken::new();
    let cancel_loop = cancel.clone();
    let handler = Arc::new(handler);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_loop.cancelled() => break,
                res = listener.accept() => {
                    let Ok((stream, _)) = res else { break };
                    let _ = stream.set_nodelay(true);
                    let h = Arc::clone(&handler);
                    tokio::spawn(async move {
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let h_inner = Arc::clone(&h);
                            async move { Ok::<HttpReply, Infallible>(h_inner(req).await) }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            }
        }
    });

    (addr, cancel)
}

pub async fn spawn_gateway(
    cfg: Arc<GatewayConfig>,
) -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway listener");
    let addr = listener.local_addr().expect("gateway local_addr");
    let shutdown = CancellationToken::new();
    let shutdown_run = shutdown.clone();
    let handle =
        tokio::spawn(async move { server::serve_with_listener(listener, cfg, shutdown_run).await });
    (addr, shutdown, handle)
}

pub fn python_executable() -> &'static str {
    #[cfg(windows)]
    {
        "python"
    }
    #[cfg(not(windows))]
    {
        "python3"
    }
}

pub fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if unsafe { libc::kill(raw_pid, 0) != 0 }
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            return false;
        }
        let status_path = format!("/proc/{pid}/status");
        if let Ok(content) = std::fs::read_to_string(&status_path) {
            return !content.lines().any(|l| l.starts_with("State:\tZ"));
        }
        if let Ok(out) = std::process::Command::new("ps")
            .args(["-o", "state=", "-p", &pid.to_string()])
            .output()
        {
            let state = String::from_utf8_lossy(&out.stdout);
            let trimmed = state.trim();
            return !trimmed.is_empty() && !trimmed.starts_with(['Z', 'z']);
        }
        false
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
        unsafe {
            CloseHandle(handle);
        }
        ok != 0 && exit_code == STILL_ACTIVE as u32
    }
}

pub async fn wait_process_gone(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if !process_exists(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
