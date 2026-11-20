use bytes::{Bytes, BytesMut};
use http::{Response, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

pub type ReplyBody = BoxBody<Bytes, io::Error>;
pub type HttpReply = Response<ReplyBody>;

pub const DEFAULT_PROCESS_BYTE_BUDGET: usize = 1024 * 1024 * 1024;
const STREAM_CHUNK_BYTES: usize = 64 * 1024;

static GLOBAL_BYTE_BUDGET: LazyLock<Arc<ByteBudget>> =
    LazyLock::new(|| ByteBudget::new(DEFAULT_PROCESS_BYTE_BUDGET));

#[derive(Debug)]
pub struct ByteBudget {
    limit: usize,
    used: AtomicUsize,
}

impl ByteBudget {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    pub fn global() -> Arc<Self> {
        Arc::clone(&GLOBAL_BYTE_BUDGET)
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    fn try_add(&self, delta: usize) -> bool {
        let mut cur = self.used.load(Ordering::Acquire);
        loop {
            let Some(next) = cur.checked_add(delta).filter(|&n| n <= self.limit) else {
                return false;
            };
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn try_acquire(self: &Arc<Self>, bytes: usize) -> Option<ByteLease> {
        if bytes == 0 {
            return Some(ByteLease {
                budget: Arc::clone(self),
                held: 0,
            });
        }
        if !self.try_add(bytes) {
            return None;
        }
        Some(ByteLease {
            budget: Arc::clone(self),
            held: bytes,
        })
    }
}

#[derive(Debug)]
pub struct ByteLease {
    budget: Arc<ByteBudget>,
    held: usize,
}

impl ByteLease {
    pub fn held(&self) -> usize {
        self.held
    }

    pub fn shrink_to(&mut self, target_bytes: usize) {
        if target_bytes < self.held {
            let delta = self.held - target_bytes;
            self.budget.used.fetch_sub(delta, Ordering::AcqRel);
            self.held = target_bytes;
        }
    }

    pub fn release(&mut self) {
        self.shrink_to(0);
    }

    // Releases all held bytes on failure so streaming callers never hold partial budget.
    pub fn try_reserve(&mut self, target_bytes: usize) -> bool {
        if target_bytes <= self.held {
            self.shrink_to(target_bytes);
            return true;
        }
        let need = target_bytes - self.held;
        if self.budget.try_add(need) {
            self.held = target_bytes;
            true
        } else {
            self.release();
            false
        }
    }
}

impl Drop for ByteLease {
    fn drop(&mut self) {
        if self.held > 0 {
            self.budget.used.fetch_sub(self.held, Ordering::AcqRel);
            self.held = 0;
        }
    }
}

pub(crate) struct LeasedFrameCursor {
    prefix: &'static [u8],
    payload: Vec<u8>,
    offset: usize,
    suffix: &'static [u8],
    lease: Option<ByteLease>,
    done: bool,
}

impl LeasedFrameCursor {
    pub(crate) fn new(
        prefix: &'static [u8],
        payload: Vec<u8>,
        suffix: &'static [u8],
        lease: Option<ByteLease>,
    ) -> Self {
        Self {
            prefix,
            payload,
            offset: 0,
            suffix,
            lease,
            done: false,
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    fn finish_and_release(&mut self) {
        self.prefix = b"";
        self.payload = Vec::new();
        self.offset = 0;
        self.suffix = b"";
        self.done = true;
        self.lease = None;
    }

    pub(crate) fn next_frame(&mut self) -> Option<Frame<Bytes>> {
        if self.done {
            return None;
        }
        let rem_payload = self.payload.len().saturating_sub(self.offset);
        let rem_total = self.prefix.len() + rem_payload + self.suffix.len();
        if rem_total == 0 {
            self.finish_and_release();
            return None;
        }
        if rem_total <= STREAM_CHUNK_BYTES {
            let out = if self.prefix.is_empty() && self.suffix.is_empty() {
                if self.offset == 0
                    && self.lease.is_none()
                    && self.payload.capacity() <= STREAM_CHUNK_BYTES
                {
                    Bytes::from(std::mem::take(&mut self.payload))
                } else {
                    Bytes::copy_from_slice(&self.payload[self.offset..])
                }
            } else {
                let mut buf = BytesMut::with_capacity(rem_total);
                buf.extend_from_slice(self.prefix);
                buf.extend_from_slice(&self.payload[self.offset..]);
                buf.extend_from_slice(self.suffix);
                buf.freeze()
            };
            self.finish_and_release();
            return Some(Frame::data(out));
        }
        if !self.prefix.is_empty() {
            let take = (STREAM_CHUNK_BYTES - self.prefix.len()).min(rem_payload);
            let mut buf = BytesMut::with_capacity(self.prefix.len() + take);
            buf.extend_from_slice(self.prefix);
            buf.extend_from_slice(&self.payload[self.offset..self.offset + take]);
            self.prefix = b"";
            self.offset += take;
            return Some(Frame::data(buf.freeze()));
        }
        if rem_payload > STREAM_CHUNK_BYTES {
            let end = self.offset + STREAM_CHUNK_BYTES;
            let chunk = Bytes::copy_from_slice(&self.payload[self.offset..end]);
            self.offset = end;
            return Some(Frame::data(chunk));
        }
        let out = Bytes::copy_from_slice(&self.payload[self.offset..]);
        self.offset = self.payload.len();
        if self.suffix.is_empty() {
            self.finish_and_release();
        }
        Some(Frame::data(out))
    }
}

struct LeasedReplyBody {
    cursor: LeasedFrameCursor,
}

impl Body for LeasedReplyBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        Poll::Ready(this.cursor.next_frame().map(Ok))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

pub(crate) fn leased_body(
    prefix: &'static [u8],
    payload: Vec<u8>,
    suffix: &'static [u8],
    lease: Option<ByteLease>,
) -> ReplyBody {
    if prefix.is_empty() && suffix.is_empty() && lease.is_none() {
        return bytes_body(payload);
    }
    LeasedReplyBody {
        cursor: LeasedFrameCursor::new(prefix, payload, suffix, lease),
    }
    .boxed()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedToken {
    pub grant_id: String,
    pub client_id: String,
    pub pool_slot: usize,
    pub scopes: Vec<String>,
    pub resource: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthChallenge {
    MissingToken,
    InvalidToken,
    InsufficientScope,
}

pub fn empty_body() -> ReplyBody {
    Full::new(Bytes::new())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

pub fn bytes_body(bytes: impl Into<Bytes>) -> ReplyBody {
    Full::new(bytes.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

pub fn json_reply(status: StatusCode, value: &serde_json::Value) -> HttpReply {
    let payload = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(bytes_body(payload))
        .expect("valid JSON response")
}

pub fn text_reply(
    status: StatusCode,
    content_type: &'static str,
    text: impl Into<Bytes>,
) -> HttpReply {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(bytes_body(text))
        .expect("valid text response")
}

pub fn method_not_allowed(allow: &'static str) -> HttpReply {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::ALLOW, allow)
        .header(header::CACHE_CONTROL, "no-store")
        .body(empty_body())
        .expect("valid 405 reply")
}

pub fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leased_frame_cursor_copies_independent_chunks_and_frees_vec_with_lease_on_final_chunk() {
        let len = 150 * 1024;
        let budget = ByteBudget::new(256 * 1024);
        let lease = ByteBudget::try_acquire(&budget, len).unwrap();
        let mut cursor = LeasedFrameCursor::new(b"data: ", vec![b'Q'; len], b"\n\n", Some(lease));

        let mut held_frames = Vec::new();
        // First two 64 KiB frames leave ~22 KiB + "\n\n" remaining; Vec and lease must remain active.
        for _ in 0..2 {
            let frame = cursor.next_frame().unwrap();
            held_frames.push(frame);
            assert!(!cursor.is_done());
            assert!(cursor.payload.capacity() >= len);
            assert_eq!(budget.used(), len);
        }

        // Taking the final chunk frees `payload` (capacity == 0) and drops `lease` synchronously,
        // even while earlier `Frame<Bytes>` items stay pinned in a downstream write queue.
        let last = cursor.next_frame().unwrap();
        held_frames.push(last);
        assert!(cursor.is_done());
        assert_eq!(cursor.payload.capacity(), 0);
        assert_eq!(budget.used(), 0);
        assert!(cursor.next_frame().is_none());

        let mut assembled = Vec::new();
        for f in held_frames {
            assembled.extend_from_slice(&f.into_data().unwrap());
        }
        assert_eq!(assembled.len(), 6 + len + 2);
        assert!(assembled.starts_with(b"data: QQQQ"));
        assert!(assembled.ends_with(b"QQQQ\n\n"));

        // Boundary split where payload finishes in frame 2 (`65535` B left) and `"\n\n"` lands in frame 3.
        let split_len = (STREAM_CHUNK_BYTES - 6) + (STREAM_CHUNK_BYTES - 1);
        let split_lease = ByteBudget::try_acquire(&budget, split_len).unwrap();
        let mut split_cursor =
            LeasedFrameCursor::new(b"data: ", vec![b'R'; split_len], b"\n\n", Some(split_lease));
        let _f1 = split_cursor.next_frame().unwrap();
        let _f2 = split_cursor.next_frame().unwrap();
        assert!(!split_cursor.is_done());
        assert_eq!(budget.used(), split_len);
        let f3 = split_cursor.next_frame().unwrap();
        assert_eq!(&f3.into_data().unwrap()[..], b"\n\n");
        assert!(split_cursor.is_done());
        assert_eq!(split_cursor.payload.capacity(), 0);
        assert_eq!(budget.used(), 0);
    }
}
