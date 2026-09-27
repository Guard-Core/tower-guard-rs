//! Short-circuit responses emitted by the guard.

use bytes::Bytes;
use http::header::{CONTENT_TYPE, RETRY_AFTER};
use http::{Response, StatusCode};
use http_body_util::Full;

/// Detail message carried by the `400 Bad Request` block response.
pub const BLOCKED_MESSAGE: &str = "Suspicious activity detected";

/// Detail message carried by the IP gate's `403 Forbidden` response.
pub const FORBIDDEN_MESSAGE: &str = "Forbidden";

/// Detail message carried by the ban stage's `403 Forbidden` response.
pub const BANNED_MESSAGE: &str = "IP address banned";

/// Detail message carried by the `403 Forbidden` response when a detected
/// threat crossed an auto-ban threshold and the ban fired on this request.
pub const ACTIVITY_BANNED_MESSAGE: &str = "IP has been banned";

/// Detail message carried by the `429 Too Many Requests` response.
pub const RATE_LIMITED_MESSAGE: &str = "Too many requests";

/// Detail message carried by the `413 Payload Too Large` response.
pub const OVERSIZE_MESSAGE: &str = "Payload too large";

/// Detail message carried by the fail-secure `500` response.
pub const FAILURE_MESSAGE: &str = "Security check failed";

pub(crate) fn forbidden() -> Response<Full<Bytes>> {
    plain_text(StatusCode::FORBIDDEN, FORBIDDEN_MESSAGE)
}

pub(crate) fn oversize() -> Response<Full<Bytes>> {
    plain_text(StatusCode::PAYLOAD_TOO_LARGE, OVERSIZE_MESSAGE)
}

pub(crate) fn failure() -> Response<Full<Bytes>> {
    plain_text(StatusCode::INTERNAL_SERVER_ERROR, FAILURE_MESSAGE)
}

/// The engine stage's block answer rendered in the family shape: the
/// custom-error body override wins over the reference default message, and
/// the throttled shape carries `Retry-After: <window seconds>`.
pub(crate) fn stage(stage: &guard_core_rs::tower::StageResponse) -> Response<Full<Bytes>> {
    let mut response = match &stage.custom_body {
        Some(body) => plain_text_owned(stage.status, body.clone()),
        None => plain_text(stage.status, stage.body),
    };
    if let Some(retry_after) = stage.retry_after
        && let Ok(value) = retry_after.to_string().parse()
    {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

/// The plain-text shape for a composed (non-`static`) body.
fn plain_text_owned(status: StatusCode, message: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(message)))
        .expect("static status and header values are always valid")
}

/// The family block shape with a composed body override.
pub(crate) fn blocked_with_body(status: u16, message: &str) -> Response<Full<Bytes>> {
    let status = StatusCode::from_u16(status).expect("a valid block status");
    plain_text_owned(status, message.to_owned())
}

/// The ecosystem's error shape: the bare message as the body,
/// `text/plain; charset=utf-8` (same as the Python family).
fn plain_text(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(message.as_bytes())))
        .expect("static status and header values are always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_bytes<B>(body: B) -> Bytes
    where
        B: http_body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        body.collect().await.expect("body").to_bytes()
    }

    #[tokio::test]
    async fn forbidden_response_shape() {
        let response = forbidden();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(body_bytes(response.into_body()).await, FORBIDDEN_MESSAGE);
    }

    #[tokio::test]
    async fn oversize_response_shape() {
        let response = oversize();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(body_bytes(response.into_body()).await, OVERSIZE_MESSAGE);
    }

    #[tokio::test]
    async fn failure_response_shape() {
        let response = failure();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(body_bytes(response.into_body()).await, FAILURE_MESSAGE);
    }
}
