use bytes::Bytes;
use http::{Response, StatusCode, header};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use std::convert::Infallible;
use std::io;

pub type ReplyBody = BoxBody<Bytes, io::Error>;
pub type HttpReply = Response<ReplyBody>;

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
