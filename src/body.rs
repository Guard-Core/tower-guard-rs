//! The response body type emitted by [`GuardService`](crate::GuardService).

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::Full;
use std::error::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Boxed error type used by [`GuardBody`].
///
/// Identical to `tower::BoxError`; redefined here so the body type does not
/// force a `tower` re-export onto downstream type signatures.
pub type BoxError = Box<dyn Error + Send + Sync>;

/// Response body produced by [`GuardService`](crate::GuardService).
///
/// Either the inner service's response body, forwarded untouched, or a
/// Guard-generated body for a short-circuited response (`400`, `403`, `413`,
/// `429`, or `500`). This type is nameable because it appears in
/// `<GuardService<S> as Service<Request<B>>>::Response`.
#[derive(Debug)]
pub enum GuardBody<B> {
    /// The inner service's response body, forwarded untouched.
    Passthrough(B),
    /// A Guard-generated plain-text body.
    Generated(Full<Bytes>),
}

impl<B> Body for GuardBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // `Self: Unpin` holds because both variants hold `Unpin` bodies, so
        // `get_mut` is enough; no pin projection required.
        match self.get_mut() {
            Self::Passthrough(inner) => Pin::new(inner).poll_frame(cx).map_err(Into::into),
            Self::Generated(body) => Pin::new(body).poll_frame(cx).map_err(Into::into),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Passthrough(inner) => inner.is_end_stream(),
            Self::Generated(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Passthrough(inner) => inner.size_hint(),
            Self::Generated(body) => body.size_hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::task::Waker;

    /// A minimal body for exercising the passthrough variant.
    #[derive(Debug)]
    struct CopyBody(Full<Bytes>);

    impl Body for CopyBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Pin::new(&mut self.0).poll_frame(cx)
        }

        fn is_end_stream(&self) -> bool {
            self.0.is_end_stream()
        }

        fn size_hint(&self) -> SizeHint {
            self.0.size_hint()
        }
    }

    /// A body that never yields a frame (the transport stalls).
    #[derive(Debug)]
    struct PendingBody;

    impl Body for PendingBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    fn poll_once<B>(body: &mut B) -> Option<Result<Frame<Bytes>, BoxError>>
    where
        B: Body<Data = Bytes, Error: Into<BoxError>> + Unpin,
    {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match Body::poll_frame(Pin::new(body), &mut cx) {
            Poll::Ready(frame) => frame.map(|frame| frame.map_err(Into::into)),
            Poll::Pending => panic!("expected a ready frame"),
        }
    }

    #[test]
    fn passthrough_forwards_frames_untouched() {
        let mut body = GuardBody::Passthrough(CopyBody(Full::new(Bytes::from_static(b"ok"))));
        let frame = poll_once(&mut body).expect("frame").expect("data");
        assert_eq!(frame.into_data().expect("data"), &b"ok"[..]);
    }

    #[test]
    fn passthrough_delegates_the_body_metadata() {
        let body = GuardBody::Passthrough(CopyBody(Full::new(Bytes::from_static(b"ok"))));
        assert!(!body.is_end_stream(), "bytes remain");
        let hint = body.size_hint();
        assert_eq!(hint.exact(), Some(2));
    }

    #[test]
    fn generated_reports_its_exact_size() {
        let mut body: GuardBody<Full<Bytes>> =
            GuardBody::Generated(Full::new(Bytes::from_static(b"blocked")));
        assert_eq!(body.size_hint().exact(), Some(7));
        let frame = poll_once(&mut body).expect("frame").expect("data");
        assert_eq!(frame.into_data().expect("data"), &b"blocked"[..]);
        assert!(body.is_end_stream(), "the frame was consumed");
    }

    #[test]
    #[should_panic(expected = "expected a ready frame")]
    fn poll_once_panics_when_the_body_pends() {
        let mut body = GuardBody::Passthrough(PendingBody);
        let _ = poll_once(&mut body);
    }

    #[test]
    fn generated_yields_the_static_body() {
        let mut body: GuardBody<Full<Bytes>> =
            GuardBody::Generated(Full::new(Bytes::from_static(b"blocked")));
        let frame = poll_once(&mut body).expect("frame").expect("data");
        assert_eq!(frame.into_data().expect("data"), &b"blocked"[..]);
        assert!(body.is_end_stream());
    }

    #[test]
    fn passthrough_of_a_full_body_delegates_the_metadata() {
        // The passthrough arms of the metadata delegates, exercised on the
        // plain `Full` body the middleware forwards most often.
        let body = GuardBody::Passthrough(Full::new(Bytes::from_static(b"ok")));
        assert!(!body.is_end_stream(), "bytes remain");
        assert_eq!(body.size_hint().exact(), Some(2));
    }

    /// A body that delivers exactly one frame and then stalls: the transport
    /// handed over a chunk but never completes.
    #[derive(Debug)]
    struct FrameThenPending {
        first: Full<Bytes>,
        delivered: bool,
    }

    impl Body for FrameThenPending {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.delivered {
                return Poll::Pending;
            }
            self.delivered = true;
            Pin::new(&mut self.first).poll_frame(cx)
        }
    }

    fn frame_then_pending() -> GuardBody<FrameThenPending> {
        GuardBody::Passthrough(FrameThenPending {
            first: Full::new(Bytes::from_static(b"chunk")),
            delivered: false,
        })
    }

    #[test]
    fn frame_then_pending_yields_its_frame_before_stalling() {
        let mut body = frame_then_pending();
        let frame = poll_once(&mut body).expect("frame").expect("data");
        assert_eq!(frame.into_data().expect("data"), &b"chunk"[..]);
    }

    #[test]
    #[should_panic(expected = "expected a ready frame")]
    fn frame_then_pending_poll_panics_once_the_transport_stalls() {
        let mut body = frame_then_pending();
        let frame = poll_once(&mut body).expect("frame").expect("data");
        assert_eq!(frame.into_data().expect("data"), &b"chunk"[..]);
        // The next poll stalls: `poll_once` panics on the pending transport.
        let _ = poll_once(&mut body);
    }
}
