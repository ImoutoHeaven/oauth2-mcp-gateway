use bytes::Bytes;
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

    // Keep the old lease until the caller frees its buffer after a failed growth.
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
            false
        }
    }

    pub(crate) fn reserve_vec(
        &mut self,
        buffer: &mut Vec<u8>,
        needed: usize,
        max_capacity: usize,
    ) -> bool {
        if needed > max_capacity {
            return false;
        }
        let old_capacity = buffer.capacity();
        if needed <= old_capacity {
            return self.try_reserve(old_capacity);
        }
        let preferred = old_capacity.saturating_mul(2).max(needed).min(max_capacity);
        let available = self
            .budget
            .limit()
            .saturating_sub(self.budget.used())
            .saturating_add(self.held);
        let target = if old_capacity
            .checked_add(preferred)
            .is_some_and(|peak| peak <= available)
        {
            preferred
        } else {
            needed
        };
        let Some(peak) = old_capacity.checked_add(target) else {
            return false;
        };
        let previous_held = self.held;
        if !self.try_reserve(peak.max(previous_held)) {
            return false;
        }
        // Keep both allocations charged until the copied-from buffer has been freed.
        let mut replacement = Vec::new();
        let allocated = replacement.try_reserve_exact(target).is_ok()
            && replacement.capacity() <= max_capacity
            && old_capacity
                .checked_add(replacement.capacity())
                .is_some_and(|actual_peak| self.try_reserve(actual_peak.max(previous_held)));
        if !allocated {
            drop(replacement);
            self.shrink_to(previous_held);
            return false;
        }
        replacement.extend_from_slice(buffer);
        drop(std::mem::replace(buffer, replacement));
        self.shrink_to(buffer.capacity());
        true
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

struct LeasedBytes {
    payload: Vec<u8>,
    _lease: ByteLease,
}

impl AsRef<[u8]> for LeasedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.payload
    }
}

pub(crate) fn leased_bytes(payload: Vec<u8>, lease: Option<ByteLease>) -> Bytes {
    match lease {
        Some(lease) => Bytes::from_owner(LeasedBytes {
            payload,
            _lease: lease,
        }),
        None => Bytes::from(payload),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadBodyError {
    TooLarge,
    Invalid,
    Overloaded,
}

/// Accumulate only after reserving the allocation; returned slices keep its lease.
pub(crate) async fn read_bounded_body<B>(
    mut body: B,
    budget: &Arc<ByteBudget>,
    limit: usize,
) -> Result<Bytes, ReadBodyError>
where
    B: Body<Data = Bytes> + Unpin,
{
    // On cancellation, field order frees the buffer before returning its byte lease.
    let mut owned = LeasedBytes {
        payload: Vec::new(),
        _lease: budget.try_acquire(0).expect("empty byte lease"),
    };
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ReadBodyError::Invalid)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let Some(needed) = owned
            .payload
            .len()
            .checked_add(data.len())
            .filter(|&n| n <= limit)
        else {
            return Err(ReadBodyError::TooLarge);
        };
        if !owned._lease.reserve_vec(&mut owned.payload, needed, limit) {
            return Err(ReadBodyError::Overloaded);
        }
        owned.payload.extend_from_slice(&data);
    }
    Ok(Bytes::from_owner(owned))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum JsonEncodeError {
    Invalid,
    Overloaded,
}

pub(crate) fn json_encoded_len<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<usize, serde_json::Error> {
    struct Counter(usize);
    impl io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("JSON length overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}

/// The counting pass allocates no payload; encoding begins only after admission.
pub(crate) fn encode_json_leased<T: serde::Serialize + ?Sized>(
    value: &T,
    suffix: &[u8],
    budget: &Arc<ByteBudget>,
) -> Result<(Vec<u8>, ByteLease), JsonEncodeError> {
    let len = json_encoded_len(value)
        .map_err(|_| JsonEncodeError::Invalid)?
        .checked_add(suffix.len())
        .ok_or(JsonEncodeError::Overloaded)?;
    let mut owned = LeasedBytes {
        payload: Vec::new(),
        _lease: budget.try_acquire(len).ok_or(JsonEncodeError::Overloaded)?,
    };
    if !owned._lease.reserve_vec(&mut owned.payload, len, len) {
        return Err(JsonEncodeError::Overloaded);
    }
    serde_json::to_writer(&mut owned.payload, value).map_err(|_| JsonEncodeError::Invalid)?;
    owned.payload.extend_from_slice(suffix);
    debug_assert_eq!(owned.payload.len(), len);
    Ok((owned.payload, owned._lease))
}

pub(crate) fn request_overloaded_reply() -> HttpReply {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONNECTION, "close")
        .body(bytes_body(Bytes::from_static(
            b"process active byte budget exceeded",
        )))
        .expect("valid overload reply")
}

pub(crate) struct LeasedFrameCursor {
    prefix: &'static [u8],
    payload: Bytes,
    suffix: &'static [u8],
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
            payload: leased_bytes(payload, lease),
            suffix,
            done: false,
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    pub(crate) fn next_frame(&mut self) -> Option<Frame<Bytes>> {
        if self.done {
            return None;
        }
        if !self.prefix.is_empty() {
            return Some(Frame::data(Bytes::from_static(std::mem::take(
                &mut self.prefix,
            ))));
        }
        if !self.payload.is_empty() {
            let chunk = self
                .payload
                .split_to(self.payload.len().min(STREAM_CHUNK_BYTES));
            if self.payload.is_empty() {
                self.payload = Bytes::new();
                self.done = self.suffix.is_empty();
            }
            return Some(Frame::data(chunk));
        }
        self.payload = Bytes::new();
        self.done = true;
        if self.suffix.is_empty() {
            None
        } else {
            Some(Frame::data(Bytes::from_static(std::mem::take(
                &mut self.suffix,
            ))))
        }
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
    fn reserve_vec_charges_replacement_peak_and_uses_required_capacity_when_tight() {
        for limit in [16, 17, 18, 23, 24, 25] {
            let budget = ByteBudget::new(limit);
            let mut buffer = b"abcdefgh".to_vec();
            let mut lease = budget.try_acquire(buffer.capacity()).unwrap();
            let before = buffer.as_ptr();
            let grown = lease.reserve_vec(&mut buffer, 9, 32);
            assert_eq!(grown, limit >= 17, "8 old + 9 required at pool {limit}");
            assert_eq!(buffer, b"abcdefgh");
            if grown {
                assert_eq!(buffer.capacity(), if limit < 24 { 9 } else { 16 });
                assert_eq!(budget.used(), buffer.capacity());
                let occupied = budget.try_acquire(limit - budget.used()).unwrap();
                let current = buffer.as_ptr();
                assert!(lease.reserve_vec(&mut buffer, 9, 32));
                assert_eq!(buffer.as_ptr(), current);
                drop(occupied);
            } else {
                assert_eq!(buffer.as_ptr(), before);
                assert_eq!(buffer.capacity(), 8);
                assert_eq!(lease.held(), 8);
                assert_eq!(budget.used(), 8);
            }
            drop(buffer);
            drop(lease);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn reserve_vec_preserves_prepaid_leases_and_failed_allocations() {
        let budget = ByteBudget::new(8);
        let mut lease = budget.try_acquire(8).unwrap();
        let mut buffer = Vec::new();
        assert!(lease.reserve_vec(&mut buffer, 8, 8));
        assert_eq!(buffer.capacity(), 8);
        assert_eq!(budget.used(), 8, "first allocation uses the prepaid lease");
        let pointer = buffer.as_ptr();
        assert!(lease.reserve_vec(&mut buffer, 4, 8));
        assert_eq!(buffer.as_ptr(), pointer);
        assert!(!lease.reserve_vec(&mut buffer, 9, 8));
        assert_eq!(lease.held(), 8);
        drop(buffer);
        drop(lease);
        assert_eq!(budget.used(), 0);

        // Vec rejects capacities above isize::MAX without allocating; the larger case also overflows C + T.
        for needed in [(isize::MAX as usize) + 1, usize::MAX] {
            let budget = ByteBudget::new(usize::MAX);
            let mut buffer = b"abcdefgh".to_vec();
            let mut lease = budget.try_acquire(11).unwrap();
            let pointer = buffer.as_ptr();
            assert!(!lease.reserve_vec(&mut buffer, needed, usize::MAX));
            assert_eq!(buffer, b"abcdefgh");
            assert_eq!(buffer.as_ptr(), pointer);
            assert_eq!(buffer.capacity(), 8);
            assert_eq!(
                lease.held(),
                11,
                "failure restores the entire previous lease"
            );
            assert_eq!(budget.used(), 11);
            drop(buffer);
            drop(lease);
            assert_eq!(budget.used(), 0);
        }
    }

    struct RequestChunks {
        chunks: std::collections::VecDeque<Bytes>,
        pending: bool,
    }

    impl Body for RequestChunks {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
            match self.chunks.pop_front() {
                Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                None if self.pending => Poll::Pending,
                None => Poll::Ready(None),
            }
        }
    }

    fn request_chunks(chunks: &[&'static [u8]], pending: bool) -> RequestChunks {
        RequestChunks {
            chunks: chunks
                .iter()
                .map(|bytes| Bytes::from_static(bytes))
                .collect(),
            pending,
        }
    }

    #[tokio::test]
    async fn request_body_growth_requires_old_and_new_capacity() {
        for limit in [9, 10, 11] {
            let budget = ByteBudget::new(limit);
            let result =
                read_bounded_body(request_chunks(&[b"abcd", b"ef"], false), &budget, 6).await;
            if limit < 10 {
                assert!(matches!(result, Err(ReadBodyError::Overloaded)));
            } else {
                let bytes = result.unwrap();
                assert_eq!(bytes, b"abcdef".as_slice());
                assert_eq!(budget.used(), 6);
                drop(bytes);
            }
            assert_eq!(budget.used(), 0);
        }
    }

    #[tokio::test]
    async fn request_body_keeps_capacity_charged_through_forwarded_bytes() {
        let budget = ByteBudget::new(16);
        let bytes = read_bounded_body(request_chunks(&[b"a", b"bc", b"d"], false), &budget, 16)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"abcd");
        assert_eq!(budget.used(), 6, "growth spare capacity remains charged");
        let forwarded = bytes.slice(1..);
        drop(bytes);
        assert_eq!(budget.used(), 6);
        assert!(budget.try_acquire(11).is_none());
        drop(forwarded);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn request_body_releases_partial_reads_and_preserves_empty_control_bodies() {
        let budget = ByteBudget::new(1);
        assert!(matches!(
            read_bounded_body(request_chunks(&[b"{", b"}"], false), &budget, 2).await,
            Err(ReadBodyError::Overloaded),
        ));
        assert_eq!(budget.used(), 0);
        let occupied = budget.try_acquire(1).unwrap();
        assert!(
            read_bounded_body(request_chunks(&[], false), &budget, 2)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(budget.used(), 1);
        drop(occupied);

        let mut pending = Box::pin(read_bounded_body(request_chunks(&[b"{"], true), &budget, 2));
        let waiting = std::future::poll_fn(|cx| {
            Poll::Ready(std::future::Future::poll(pending.as_mut(), cx).is_pending())
        })
        .await;
        assert!(waiting);
        assert_eq!(budget.used(), 1);
        drop(pending);
        assert_eq!(budget.used(), 0);

        assert!(matches!(
            read_bounded_body(request_chunks(&[b"{}"], false), &budget, 1).await,
            Err(ReadBodyError::TooLarge),
        ));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn request_json_encoding_admits_exact_length_before_allocating() {
        let value = serde_json::json!({"text": "hello\n世界"});
        let len = json_encoded_len(&value).unwrap() + 1;
        let budget = ByteBudget::new(len);
        let occupied = budget.try_acquire(1).unwrap();
        assert!(matches!(
            encode_json_leased(&value, b"\n", &budget),
            Err(JsonEncodeError::Overloaded),
        ));
        assert_eq!(budget.used(), 1);
        drop(occupied);
        let (bytes, lease) = encode_json_leased(&value, b"\n", &budget).unwrap();
        assert_eq!(bytes.len(), len);
        assert_eq!(bytes.capacity(), budget.used());
        let forwarded = leased_bytes(bytes, Some(lease));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&forwarded).unwrap(),
            value
        );
        assert_eq!(budget.used(), len);
        drop(forwarded);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn returned_frames_keep_allocated_capacity_leased() {
        let payload = vec![b'X'; 150 * 1024];
        let budget = ByteBudget::new(payload.capacity());
        let lease = budget.try_acquire(payload.capacity()).unwrap();
        let mut cursor = LeasedFrameCursor::new(b"data: ", payload, b"\n\n", Some(lease));
        let mut frames = Vec::new();
        while let Some(frame) = cursor.next_frame() {
            frames.push(frame);
        }
        assert_eq!(budget.used(), budget.limit());
        assert!(budget.try_acquire(1).is_none());
        drop(cursor);
        assert_eq!(budget.used(), budget.limit());
        drop(frames);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn leased_frame_cursor_preserves_sse_bytes_and_bounds_each_frame() {
        for len in [0, STREAM_CHUNK_BYTES - 1, 2 * STREAM_CHUNK_BYTES + 1] {
            let budget = ByteBudget::new(len);
            let lease = budget.try_acquire(len).unwrap();
            let mut cursor =
                LeasedFrameCursor::new(b"data: ", vec![b'Q'; len], b"\n\n", Some(lease));
            let mut assembled = Vec::new();
            while let Some(frame) = cursor.next_frame() {
                let bytes = frame.into_data().unwrap();
                assert!(bytes.len() <= STREAM_CHUNK_BYTES);
                assembled.extend_from_slice(&bytes);
            }
            assert!(cursor.is_done());
            assert_eq!(budget.used(), 0);
            assert_eq!(
                assembled,
                [b"data: ".as_slice(), &vec![b'Q'; len], b"\n\n"].concat()
            );
        }
    }
}
