#![allow(dead_code)]

use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use oauth2_mcp_gateway::types::ReplyBody;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

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
        let status_path = format!("/proc/{pid}/status");
        if let Ok(content) = std::fs::read_to_string(&status_path)
            && content.lines().any(|l| l.starts_with("State:\tZ"))
        {
            return false;
        }
        let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        unsafe { libc::kill(raw_pid, 0) == 0 }
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

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

pub async fn wait_process_gone(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
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
