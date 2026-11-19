use crate::config::HttpUpstreamSettings;
use crate::types::{HttpReply, ReplyBody, VerifiedToken, empty_body};
use bytes::{Bytes, BytesMut};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, header,
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, ResponseFuture, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use std::collections::HashSet;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

pub const MAX_MCP_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_PRIMING_BUFFER_BYTES: usize = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);
const POOL_MAX_IDLE_PER_HOST: usize = 64;

enum HttpClient {
    Plain(Client<HttpConnector, ReplyBody>),
    Tls(Client<HttpsConnector<HttpConnector>, ReplyBody>),
}

impl HttpClient {
    fn request(&self, req: Request<ReplyBody>) -> ResponseFuture {
        match self {
            Self::Plain(c) => c.request(req),
            Self::Tls(c) => c.request(req),
        }
    }
}

pub struct HttpUpstream {
    settings: HttpUpstreamSettings,
    client: HttpClient,
    origin_base_str: String,
    mcp_url_str: String,
    upstream_host: HeaderValue,
    forwarded_proto: HeaderValue,
}

impl HttpUpstream {
    pub fn new(settings: HttpUpstreamSettings) -> Result<Self, String> {
        let mut http_connector = HttpConnector::new();
        http_connector.set_connect_timeout(Some(CONNECT_TIMEOUT));
        http_connector.set_nodelay(true);
        http_connector.set_keepalive(Some(TCP_KEEPALIVE));

        let client = if settings.url.scheme() == "http" {
            HttpClient::Plain(
                Client::builder(TokioExecutor::new())
                    .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
                    .build(http_connector),
            )
        } else {
            http_connector.enforce_http(false);
            let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .map_err(|e| format!("failed to load native TLS roots: {e}"))?
                .https_or_http()
                .enable_http1()
                .wrap_connector(http_connector);
            HttpClient::Tls(
                Client::builder(TokioExecutor::new())
                    .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
                    .build(https_connector),
            )
        };

        let host_str = settings
            .url
            .host_str()
            .ok_or_else(|| "upstream.url must specify a host".to_owned())?;
        let authority = match settings.url.port() {
            Some(port) => format!("{host_str}:{port}"),
            None => host_str.to_owned(),
        };
        let upstream_host = HeaderValue::from_str(&authority)
            .map_err(|e| format!("invalid upstream Host header {authority:?}: {e}"))?;
        let forwarded_proto = if settings.public_is_https {
            HeaderValue::from_static("https")
        } else {
            HeaderValue::from_static("http")
        };
        let origin_base_str = settings
            .origin_base
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        let mcp_url_str = settings.url.as_str().to_owned();

        Ok(Self {
            settings,
            client,
            origin_base_str,
            mcp_url_str,
            upstream_host,
            forwarded_proto,
        })
    }

    pub fn matches_passthrough(&self, raw_path: &str) -> bool {
        if self.settings.passthrough_prefixes.is_empty() {
            return false;
        }
        let Some(decoded) = validate_and_decode_path(raw_path) else {
            return false;
        };
        let path = raw_path.split('?').next().unwrap_or(raw_path);
        self.settings.passthrough_prefixes.iter().any(|prefix| {
            let pb = prefix.as_bytes();
            path.as_bytes().starts_with(pb) && decoded.starts_with(pb)
        })
    }

    pub async fn handle_passthrough(&self, req: Request<Incoming>) -> HttpReply {
        let raw_path = req.uri().path();
        if !is_safe_request_path(raw_path) {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        }
        if !self.matches_passthrough(raw_path) {
            return close_empty_reply(StatusCode::NOT_FOUND);
        }

        let method = req.method().clone();
        if !matches!(method, Method::GET | Method::HEAD | Method::PUT) {
            return method_not_allowed("GET, HEAD, PUT");
        }

        let pq = req
            .uri()
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or(raw_path);
        if pq
            .bytes()
            .any(|b| b == b'\\' || b == 0 || b < 0x20 || b == 0x7f)
        {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        }
        let target_str = format!("{}{pq}", self.origin_base_str);
        let Ok(target_uri) = target_str.parse::<Uri>() else {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        };

        let (parts, incoming) = req.into_parts();
        let mut out_req = Request::builder().method(method).uri(target_uri);
        if let Some(headers) = out_req.headers_mut() {
            copy_filtered_headers(&parts.headers, headers, true);
            headers.insert(header::HOST, self.upstream_host.clone());
            headers.insert(
                HeaderName::from_static("x-forwarded-proto"),
                self.forwarded_proto.clone(),
            );
        }

        let stream_body = incoming.map_err(io::Error::other).boxed();
        let Ok(out_req) = out_req.body(stream_body) else {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        };

        let timeout_dur = Duration::from_secs(self.settings.request_timeout_secs);
        let up_resp = match tokio::time::timeout(timeout_dur, self.client.request(out_req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(_)) => return empty_status_reply(StatusCode::BAD_GATEWAY),
            Err(_) => return empty_status_reply(StatusCode::GATEWAY_TIMEOUT),
        };

        let (up_parts, up_body) = up_resp.into_parts();
        let mut reply = Response::builder().status(up_parts.status);
        if let Some(headers) = reply.headers_mut() {
            copy_filtered_headers(&up_parts.headers, headers, false);
        }
        reply
            .body(up_body.map_err(io::Error::other).boxed())
            .unwrap_or_else(|_| empty_status_reply(StatusCode::BAD_GATEWAY))
    }

    pub async fn handle_mcp(&self, req: Request<Incoming>, token: &VerifiedToken) -> HttpReply {
        let method = req.method().clone();
        if !matches!(method, Method::POST | Method::GET | Method::DELETE) {
            return method_not_allowed("POST, GET, DELETE");
        }

        match check_content_length_limit(req.headers(), MAX_MCP_BODY_BYTES as u64) {
            ContentLengthCheck::Ok => {}
            ContentLengthCheck::Invalid => return close_empty_reply(StatusCode::BAD_REQUEST),
            ContentLengthCheck::TooLarge => {
                return close_empty_reply(StatusCode::PAYLOAD_TOO_LARGE);
            }
        }
        if req.body().size_hint().lower() > MAX_MCP_BODY_BYTES as u64 {
            return close_empty_reply(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let target_str = match req.uri().query() {
            Some(q) if !q.is_empty() => {
                if q.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
                    return close_empty_reply(StatusCode::BAD_REQUEST);
                }
                format!("{}?{q}", self.mcp_url_str)
            }
            _ => self.mcp_url_str.clone(),
        };
        let Ok(target_uri) = target_str.parse::<Uri>() else {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        };

        let (parts, incoming) = req.into_parts();
        let mut out_req = Request::builder().method(method).uri(target_uri);
        if let Some(headers) = out_req.headers_mut() {
            copy_filtered_headers(&parts.headers, headers, true);
            if !self.settings.bearer_tokens.is_empty() {
                let slot = token.pool_slot % self.settings.bearer_tokens.len();
                let auth_val = format!("Bearer {}", self.settings.bearer_tokens[slot]);
                if let Ok(hv) = HeaderValue::from_str(&auth_val) {
                    headers.insert(header::AUTHORIZATION, hv);
                }
            }
            headers.insert(header::HOST, self.upstream_host.clone());
            headers.insert(
                HeaderName::from_static("x-forwarded-proto"),
                self.forwarded_proto.clone(),
            );
        }

        let limit_exceeded = Arc::new(AtomicBool::new(false));
        let limit_flag = Arc::clone(&limit_exceeded);
        let limited_body = Limited::new(incoming, MAX_MCP_BODY_BYTES)
            .map_err(move |err| {
                if err.is::<LengthLimitError>() {
                    limit_flag.store(true, Ordering::Relaxed);
                }
                io::Error::other(err)
            })
            .boxed();

        let Ok(out_req) = out_req.body(limited_body) else {
            return close_empty_reply(StatusCode::BAD_REQUEST);
        };

        let timeout_dur = Duration::from_secs(self.settings.request_timeout_secs);
        let up_resp = match tokio::time::timeout(timeout_dur, self.client.request(out_req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(_)) if limit_exceeded.load(Ordering::Relaxed) => {
                return close_empty_reply(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Ok(Err(_)) => return empty_status_reply(StatusCode::BAD_GATEWAY),
            Err(_) => return empty_status_reply(StatusCode::GATEWAY_TIMEOUT),
        };

        let (up_parts, up_body) = up_resp.into_parts();
        let is_sse = is_event_stream(&up_parts.headers);

        let mut reply = Response::builder().status(up_parts.status);
        if let Some(headers) = reply.headers_mut() {
            copy_filtered_headers(&up_parts.headers, headers, false);
            if is_sse {
                headers.remove(header::CONTENT_LENGTH);
            }
            headers.insert(
                HeaderName::from_static("x-accel-buffering"),
                HeaderValue::from_static("no"),
            );
        }

        let out_body: ReplyBody = if is_sse {
            SsePrimingFilterBody::new(up_body).boxed()
        } else {
            up_body.map_err(io::Error::other).boxed()
        };

        reply
            .body(out_body)
            .unwrap_or_else(|_| empty_status_reply(StatusCode::BAD_GATEWAY))
    }
}

pub(crate) fn is_safe_request_path(raw_path: &str) -> bool {
    validate_and_decode_path(raw_path).is_some()
}

const MAX_PERCENT_DECODE_ROUNDS: usize = 8;

fn validate_and_decode_path(raw_path: &str) -> Option<Vec<u8>> {
    if raw_path.is_empty()
        || !raw_path.starts_with('/')
        || raw_path.contains('\\')
        || raw_path.contains('\0')
        || raw_path.contains('#')
        || raw_path.chars().any(char::is_control)
    {
        return None;
    }
    let path = raw_path.split('?').next().unwrap_or(raw_path);
    if !path.starts_with('/') {
        return None;
    }

    let raw_bytes = path.as_bytes();
    if has_malformed_percent(raw_bytes) || !is_safe_path_slice(raw_bytes) {
        return None;
    }

    let mut current = raw_bytes.to_vec();
    let mut settled = false;
    for _ in 0..MAX_PERCENT_DECODE_ROUNDS {
        let (next, changed) = decode_percent_pairs(&current);
        if !is_safe_path_slice(&next) {
            return None;
        }
        current = next;
        if !changed {
            settled = true;
            break;
        }
    }
    if !settled && has_decodable_percent(&current) {
        return None;
    }
    Some(current)
}

fn has_malformed_percent(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || hex_nibble(bytes[i + 1]).is_none()
                || hex_nibble(bytes[i + 2]).is_none()
            {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

fn has_decodable_percent(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%'
            && hex_nibble(bytes[i + 1]).is_some()
            && hex_nibble(bytes[i + 2]).is_some()
        {
            return true;
        }
        i += 1;
    }
    false
}

fn decode_percent_pairs(bytes: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            changed = true;
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    (out, changed)
}

fn is_safe_path_slice(bytes: &[u8]) -> bool {
    if bytes
        .iter()
        .any(|&b| b == 0 || b == b'\\' || b < 0x20 || b == 0x7f)
    {
        return false;
    }
    for seg in bytes.split(|&b| b == b'/') {
        let base = seg.split(|&b| b == b';').next().unwrap_or(seg);
        if seg == b"." || seg == b".." || base == b"." || base == b".." {
            return false;
        }
    }
    true
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(crate) enum ContentLengthCheck {
    Ok,
    Invalid,
    TooLarge,
}

pub(crate) fn check_content_length_limit(headers: &HeaderMap, limit: u64) -> ContentLengthCheck {
    let mut seen: Option<u64> = None;
    for raw in headers.get_all(header::CONTENT_LENGTH) {
        let Ok(text) = raw.to_str() else {
            return ContentLengthCheck::Invalid;
        };
        let trimmed = text.trim();
        if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
            return ContentLengthCheck::Invalid;
        }
        let Ok(val) = trimmed.parse::<u64>() else {
            return ContentLengthCheck::TooLarge;
        };
        if let Some(prev) = seen
            && prev != val
        {
            return ContentLengthCheck::Invalid;
        }
        seen = Some(val);
        if val > limit {
            return ContentLengthCheck::TooLarge;
        }
    }
    ContentLengthCheck::Ok
}

fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CONTENT_TYPE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|ct| {
            let media = ct.split(';').next().unwrap_or(ct).trim();
            media.eq_ignore_ascii_case("text/event-stream")
        })
}

fn copy_filtered_headers(src: &HeaderMap, dst: &mut HeaderMap, is_request: bool) {
    let mut connection_tokens: HashSet<String> = HashSet::new();
    for val in src.get_all(header::CONNECTION) {
        if let Ok(s) = val.to_str() {
            for tok in s.split(',') {
                let name = tok.trim();
                if !name.is_empty() {
                    connection_tokens.insert(name.to_ascii_lowercase());
                }
            }
        }
    }

    for (name, value) in src.iter() {
        let lower = name.as_str();
        if is_hop_by_hop_header(lower) || connection_tokens.contains(lower) {
            continue;
        }
        if is_request && is_stripped_request_header(lower) {
            continue;
        }
        if !is_request && lower == "set-cookie" {
            continue;
        }
        dst.append(name.clone(), value.clone());
    }
}

fn is_stripped_request_header(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "authorization"
            | "cookie"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-real-ip"
    )
}

fn is_hop_by_hop_header(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

pub(crate) fn close_empty_reply(status: StatusCode) -> HttpReply {
    Response::builder()
        .status(status)
        .header(header::CONNECTION, "close")
        .header(header::CACHE_CONTROL, "no-store")
        .body(empty_body())
        .expect("valid close reply")
}

fn empty_status_reply(status: StatusCode) -> HttpReply {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .body(empty_body())
        .expect("valid status reply")
}

pub(crate) fn method_not_allowed(allow: &'static str) -> HttpReply {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::ALLOW, allow)
        .header(header::CACHE_CONTROL, "no-store")
        .body(empty_body())
        .expect("valid 405 reply")
}

struct SsePrimingFilterBody<B> {
    inner: B,
    buf: BytesMut,
    filtering: bool,
    pending_frame: Option<Frame<Bytes>>,
}

impl<B> SsePrimingFilterBody<B> {
    fn new(inner: B) -> Self {
        Self {
            inner,
            buf: BytesMut::new(),
            filtering: true,
            pending_frame: None,
        }
    }
}

impl<B> Body for SsePrimingFilterBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            if !this.filtering && !this.buf.is_empty() {
                let out = this.buf.split().freeze();
                return Poll::Ready(Some(Ok(Frame::data(out))));
            }
            if let Some(frame) = this.pending_frame.take() {
                return Poll::Ready(Some(Ok(frame)));
            }

            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Some(Err(io::Error::other(err))));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if !this.filtering {
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    match frame.into_data() {
                        Ok(chunk) => {
                            if chunk.is_empty() {
                                continue;
                            }
                            this.buf.extend_from_slice(&chunk);
                            drain_empty_leading_sse_blocks(&mut this.buf, &mut this.filtering);
                            if !this.filtering && !this.buf.is_empty() {
                                let out = this.buf.split().freeze();
                                return Poll::Ready(Some(Ok(Frame::data(out))));
                            }
                        }
                        Err(non_data_frame) => {
                            this.filtering = false;
                            if block_has_data_line(&this.buf) {
                                this.pending_frame = Some(non_data_frame);
                                let out = this.buf.split().freeze();
                                return Poll::Ready(Some(Ok(Frame::data(out))));
                            }
                            this.buf.clear();
                            return Poll::Ready(Some(Ok(non_data_frame)));
                        }
                    }
                }
                Poll::Ready(None) => {
                    if this.filtering {
                        this.filtering = false;
                        if block_has_data_line(&this.buf) {
                            let out = this.buf.split().freeze();
                            return Poll::Ready(Some(Ok(Frame::data(out))));
                        }
                        this.buf.clear();
                    }
                    return Poll::Ready(None);
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn drain_empty_leading_sse_blocks(buf: &mut BytesMut, filtering: &mut bool) {
    while let Some(end) = find_sse_block_end(buf) {
        if block_has_data_line(&buf[..end]) {
            *filtering = false;
            return;
        }
        let _ = buf.split_to(end);
    }

    // Switch immediately once an incomplete block already contains a `data:` line.
    if block_has_data_line(buf) || buf.len() > MAX_PRIMING_BUFFER_BYTES {
        *filtering = false;
    }
}

fn find_sse_block_end(buf: &[u8]) -> Option<usize> {
    if buf.starts_with(b"\r\n") {
        return Some(2);
    }
    if buf.starts_with(b"\n") {
        return Some(1);
    }
    let mut i = 0;
    while i < buf.len() {
        if i + 3 < buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
        if i + 2 < buf.len() && (&buf[i..i + 3] == b"\r\n\n" || &buf[i..i + 3] == b"\n\r\n") {
            return Some(i + 3);
        }
        if i + 1 < buf.len() && &buf[i..i + 2] == b"\n\n" {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

fn block_has_data_line(block: &[u8]) -> bool {
    block.split(|&b| b == b'\n').any(|raw_line| {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        line.starts_with(b"data:")
    })
}
