//! Production-shaped guarded service.
//!
//! Differences from `simple_app`:
//!
//! - The engine [`DetectConfig`] and the adapter body cap are driven by
//!   environment variables (see `env_config` below), so a deployment tunes
//!   detection without a rebuild.
//! - Route-scoped guard configuration: `/admin/*` traffic is screened by a
//!   second, stricter [`GuardLayer`] (lower threat-score threshold), while
//!   general routes use the default-derived config. The adapter surface has
//!   no route IDs, so the scoping is expressed the tower way: two guarded
//!   service trees, selected by path prefix.
//! - `/health` stays in front of both guards, mirroring excluded-path
//!   behavior.
//!
//! The guard-core-rs engine currently ships the CPU-bound detection pipeline
//! only: there is no rate limiter, ban manager, or Redis surface to drive, so
//! this example scopes guard configuration per route tree and stops there.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tower::{Layer, Service};
use tower_guard_rs::{DetectConfig, GuardBody, GuardLayer, GuardService, default_config};

/// The application listen address.
const DEFAULT_ADDR: &str = "0.0.0.0:8080";

/// Request body handed to the guards: wire body or rebuilt buffered bytes.
pub enum AppBody {
    /// The body as it arrived from the socket.
    Wire(Incoming),
    /// A body rebuilt from buffered bytes (or an empty body).
    Buffered(Full<Bytes>),
}

impl Body for AppBody {
    type Data = Bytes;
    type Error = tower_guard_rs::BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Wire(inner) => Pin::new(inner)
                .poll_frame(cx)
                .map_err(|error| Box::new(error) as tower_guard_rs::BoxError),
            Self::Buffered(inner) => Pin::new(inner)
                .poll_frame(cx)
                .map_err(|error: std::convert::Infallible| match error {}),
        }
    }
}

impl From<Bytes> for AppBody {
    fn from(bytes: Bytes) -> Self {
        Self::Buffered(Full::new(bytes))
    }
}

/// The guard-generated or forwarded response body.
type GuardResponseBody = GuardBody<Full<Bytes>>;

/// The application: two guarded route trees behind one path dispatcher.
#[derive(Clone)]
struct App {
    general: GuardService<Router>,
    admin: GuardService<AdminRouter>,
}

impl Service<Request<AppBody>> for App {
    type Response = Response<GuardResponseBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.general.poll_ready(cx)?.is_pending() {
            return Poll::Pending;
        }
        self.admin.poll_ready(cx)
    }

    fn call(&mut self, request: Request<AppBody>) -> Self::Future {
        // Excluded path: answered before any guard sees the request.
        if request.uri().path() == "/health" {
            let response = plain_response(StatusCode::OK, "ok\n");
            return Box::pin(async move { Ok(Response::map(response, GuardBody::Passthrough)) });
        }
        if request.uri().path().starts_with("/admin") {
            return Box::pin(self.admin.call(request));
        }
        Box::pin(self.general.call(request))
    }
}

/// Maps hyper's wire body into [`AppBody`].
#[derive(Clone)]
struct BodyMapped {
    inner: App,
}

impl Service<Request<Incoming>> for BodyMapped {
    type Response = Response<GuardResponseBody>;
    type Error = Infallible;
    type Future = <App as Service<Request<AppBody>>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        self.inner.call(request.map(AppBody::Wire))
    }
}

/// General routes: default-derived guard configuration.
#[derive(Clone, Copy)]
struct Router;

impl Service<Request<AppBody>> for Router {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<AppBody>) -> Self::Future {
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let bytes = read_body(body).await;
            match (parts.method, parts.uri.path()) {
                (http::Method::GET, "/") => Ok(plain_response(
                    StatusCode::OK,
                    "tower-guard-rs advanced app\n",
                )),
                (http::Method::GET, "/search") => Ok(plain_response(StatusCode::OK, "search ok\n")),
                (http::Method::POST, "/echo") => Ok(plain_response_bytes(StatusCode::OK, &bytes)),
                _ => Ok(plain_response(StatusCode::NOT_FOUND, "not found\n")),
            }
        })
    }
}

/// Admin routes: screened by the stricter `/admin` guard layer.
#[derive(Clone, Copy)]
struct AdminRouter;

impl Service<Request<AppBody>> for AdminRouter {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<AppBody>) -> Self::Future {
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            read_body(body).await;
            match (parts.method, parts.uri.path()) {
                (http::Method::GET, "/admin/stats") => {
                    Ok(plain_response(StatusCode::OK, "stats\n"))
                }
                _ => Ok(plain_response(StatusCode::NOT_FOUND, "not found\n")),
            }
        })
    }
}

async fn read_body(body: AppBody) -> Bytes {
    match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    }
}

fn plain_response(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    plain_response_bytes(status, text.as_bytes())
}

fn plain_response_bytes(status: StatusCode, bytes: &[u8]) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::copy_from_slice(bytes)))
        .expect("static response parts")
}

/// Build the engine [`DetectConfig`] from environment variables.
///
/// Every knob is optional; unset variables fall back to the ecosystem
/// defaults pinned in [`default_config`].
///
/// | Variable | Field | Default |
/// |---|---|---|
/// | `GUARD_MAX_CONTENT_LENGTH` | `max_content_length` | `10000` |
/// | `GUARD_MAX_FULL_SCAN_BYTES` | `max_full_scan_bytes` | `262144` |
/// | `GUARD_PRESERVE_ATTACK_PATTERNS` | `preserve_attack_patterns` | `true` |
/// | `GUARD_SEMANTIC_THRESHOLD` | `semantic_threshold` | `0.7` |
/// | `GUARD_THREAT_SCORE_THRESHOLD` | `threat_score_threshold` | `1.0` |
/// | `GUARD_BINARY_MIN_RUN_LENGTH` | `binary_min_run_length` | `16` |
/// | `GUARD_MAX_SCAN_VALUES` | `max_scan_values` | `512` |
/// | `GUARD_MAX_SCAN_CHARS` | `max_scan_chars` | `65536` |
/// | `GUARD_MAX_JSON_DEPTH` | `max_json_depth` | `32` |
fn env_config() -> DetectConfig {
    let defaults = default_config();
    DetectConfig {
        max_content_length: env_usize("GUARD_MAX_CONTENT_LENGTH", defaults.max_content_length),
        max_full_scan_bytes: env_usize("GUARD_MAX_FULL_SCAN_BYTES", defaults.max_full_scan_bytes),
        preserve_attack_patterns: env_bool(
            "GUARD_PRESERVE_ATTACK_PATTERNS",
            defaults.preserve_attack_patterns,
        ),
        semantic_threshold: env_f64("GUARD_SEMANTIC_THRESHOLD", defaults.semantic_threshold),
        threat_score_threshold: env_f64(
            "GUARD_THREAT_SCORE_THRESHOLD",
            defaults.threat_score_threshold,
        ),
        binary_min_run_length: env_usize(
            "GUARD_BINARY_MIN_RUN_LENGTH",
            defaults.binary_min_run_length,
        ),
        max_scan_values: env_usize("GUARD_MAX_SCAN_VALUES", defaults.max_scan_values),
        max_scan_chars: env_usize("GUARD_MAX_SCAN_CHARS", defaults.max_scan_chars),
        max_json_depth: env_usize("GUARD_MAX_JSON_DEPTH", defaults.max_json_depth),
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => default,
    }
}

#[tokio::main]
async fn main() {
    let addr: std::net::SocketAddr = std::env::var("APP_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.to_string())
        .parse()
        .expect("APP_ADDR must be a socket address");

    let config = env_config();
    let body_cap = env_usize("GUARD_BODY_CAP", config.max_full_scan_bytes);
    // The admin tree screens with a stricter threshold: every env override
    // applies, but the score threshold is lowered relative to the general
    // config so borderline payloads are caught on admin surface only.
    let mut admin_config = config;
    admin_config.threat_score_threshold = env_f64(
        "GUARD_ADMIN_THREAT_SCORE_THRESHOLD",
        (config.threat_score_threshold * 0.5).min(1.0),
    );

    let app = App {
        general: GuardLayer::new(config)
            .with_body_cap(body_cap)
            .layer(Router),
        admin: GuardLayer::new(admin_config)
            .with_body_cap(body_cap)
            .layer(AdminRouter),
    };

    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind {addr}: {error}"));
    eprintln!("tower-guard-rs advanced app listening on {addr}");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("accept failed: {error}");
                continue;
            }
        };
        let app = BodyMapped { inner: app.clone() };
        tokio::spawn(async move {
            let _ = ConnBuilder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
                .await;
        });
    }
}
