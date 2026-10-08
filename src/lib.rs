//! # tower-guard-rs
//!
//! Application-layer security middleware for
//! [tower](https://github.com/tower-rs/tower)-based services, powered by the
//! [guard-core-rs](https://github.com/rennf93/guard-core-rs) detection engine.
//! Part of the [Guard ecosystem](https://github.com/rennf93). It works with
//! any framework built on [`tower::Service`], including
//! [axum](https://github.com/tokio-rs/axum) (the [`axum-guard-rs`] wrapper
//! composes this crate), [hyper](https://github.com/hyperium/hyper), and
//! [warp](https://github.com/seanmonstar/warp).
//!
//! ## Status: implemented (v0.1.0)
//!
//! [`GuardLayer`] is a working [`tower::Layer`] and [`GuardService`] a working
//! [`tower::Service`] over `http::Request<B>`. The engine is wired in through
//! `guard-core-engine` (a path dependency until the engine is tagged and
//! published). Per the ecosystem boundary rules, this adapter holds framework
//! glue only: every detection decision comes from the engine.
//!
//! ## What it inspects
//!
//! One engine call per request view, mirroring the mapping used by the
//! sibling TypeScript adapters (`guard-core-ts`):
//!
//! | Request part | Engine context | Notes |
//! |---|---|---|
//! | Path | `url_path` | Skipped for `/` |
//! | Query string | `query_param` | Skipped when empty |
//! | Header values | `header` | Skips `sec-*` and hop-by-hop/negotiation headers (see `EXCLUDED_HEADERS`) |
//! | Body | `request_body` | Buffered first, capped (see below); routed by content type, so urlencoded fields, multipart parts, and JSON bodies are extracted into the values the reference engine scans individually instead of one whole-body blob |
//!
//! The HTTP method is not fed to the engine: the engine's `detect` signature
//! takes content plus a context, and the reference adapters do not scan the
//! method either.
//!
//! ## Body cap
//!
//! Request bodies are buffered so the engine can inspect them, and the buffer
//! is bounded by [`GuardLayer::with_body_cap`]. It defaults to the engine's
//! full-scan cap (`DetectConfig::max_full_scan_bytes`, 262 144 bytes in the
//! ecosystem default). A request whose body exceeds the cap is rejected with
//! `413 Payload Too Large` rather than forwarded unscanned: the engine would
//! only ever see a truncated prefix, which would be a bypass vector.
//!
//! ## Engine surfaces (the 4.2.0 wave, all publicly configurable)
//!
//! Every stateful decision and emission goes through the engine facade's
//! rate-limit stage (`guard_core_rs::tower::RateLimitStage`); the layer's
//! builders are the public configuration:
//!
//! | Surface | Builder / idiom |
//! |---|---|
//! | Rate-limit tiers | [`GuardLayer::with_route_tiers`] (`path -> Option<RouteRateLimits>`, a [`RouteRateLimits`] request extension wins), [`GuardLayer::with_geo_handler`] (geo tiers) |
//! | Detection exclusions | [`GuardLayer::with_detection_exclusions`] (global), a [`RouteDetectionExclusions`] request extension (per route) |
//! | Events + log settings | [`GuardLayer::with_event_bus`], [`GuardLayer::with_observability`] (`log_suspicious_level`, `muted_check_logs`, the `log_sensitive_*` redaction sets) |
//! | `on_block` + custom errors | [`GuardLayer::with_on_block`], [`GuardLayer::with_custom_error_responses`] |
//! | Distributed mode | [`GuardLayer::with_distributed_store`] + [`GuardLayer::with_distributed_ban_store`] |
//! | Passive mode | [`GuardLayer::with_passive_mode`] (log-only: windows and counters record, no block renders, auto-ban feeds suppressed) |
//!
//! Scan semantics note: the query string is now scanned as `parse_qsl`-
//! decoded per-parameter pairs (the reference reads decoded values), which
//! is what makes `excluded_detection_params` functional, and the header
//! set the resolution marks as excluded scans with its known
//! false-positive categories suppressed (`ssrf` for address-chain values)
//! instead of a blanket skip.

//! ## Responses
//!
//! | Situation | Status | Body |
//! |---|---|---|
//! | The IP gate denies the client IP (blacklisted, or a non-empty whitelist matches neither the IP nor an exemption) | `403 Forbidden` | `Forbidden` |
//! | The ban stage finds a live ban on the client IP | `403 Forbidden` | `IP address banned` |
//! | The rate limiter records a crossing of `rate_limit` | `429 Too Many Requests` (+ `Retry-After: <window>`) | `Too many requests` |
//! | Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
//! | Engine flags a view and the crossed auto-ban threshold bans on the spot | `403 Forbidden` | `IP has been banned` |
//! | Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
//! | Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |
//!
//! The IP gate is optional (`GuardLayer::with_ip_gate`); when it is
//! configured, `exempt_ips` (like a whitelist match) only sets the skip state
//! on the request, never a deny path of its own - the exempt-vs-whitelist
//! contract in the engine's `ip_gate` module. The stateful stages honor that
//! contract: the rate limiter (`GuardLayer::with_rate_limiting`) and the
//! ban/auto-ban stage (`GuardLayer::with_ip_banning`) skip whitelisted and
//! exempt IPs for exactly what the reference skips (rate limiting, violation
//! counting, banning) and never skip detection, which always scans every
//! request, exempt or not.
//!
//! ## The full stage surface (the reference 17-check pipeline, wired)
//!
//! Every reference check the engine ships is now installable on
//! [`GuardLayer`], and [`GuardService`] runs the installed set in the
//! reference pipeline order (see the composition table in `docs/` and
//! [`provided_layers`] for the standalone-layer form):
//!
//! | Reference check | Builder |
//! |---|---|
//! | 2 `emergency_mode` | [`GuardLayer::with_emergency_mode`] |
//! | 3 `https_enforcement` | [`GuardLayer::with_https_enforcement`] |
//! | 4 `request_logging` | [`GuardLayer::with_request_logging`] |
//! | 5 `request_size_content` | [`GuardLayer::with_body_cap`] (413) |
//! | 6 + 7 `required_headers` / authentication | [`GuardLayer::with_headers_auth`] |
//! | 8 referrer | [`GuardLayer::with_referrer_gate`] |
//! | 9 `custom_validators` | [`GuardLayer::with_custom_checks`] |
//! | 10 `time_window` | [`GuardLayer::with_time_window_gate`] |
//! | 12b geo country blocking | [`GuardLayer::with_geo_blocking`] |
//! | 13 `cloud_provider` | [`GuardLayer::with_cloud_provider`] |
//! | 14 `user_agent` | [`GuardLayer::with_user_agent`] |
//! | 12a / 15 / 16 bans / `rate_limit` / detection feed | [`GuardLayer::with_rate_limiting`] + [`GuardLayer::with_ip_banning`] |
//! | 17 `custom_request` | [`GuardLayer::with_custom_checks`] |
//! | response pass (return rules + security headers + CORS) | [`GuardLayer::with_response_processor`] |
//! | per-route carrier (`bypassed_checks`, `require_https`, per-route UA/size limits, the rate and detection views) | [`GuardLayer::with_route_configs`] |
//!
//! These bodies follow the ecosystem's plain-text convention (the bare
//! message, `text/plain; charset=utf-8`, same as the Python family) but
//! the adapter is deliberately **fail-secure**, unlike the TypeScript adapters
//! whose check pipeline logs and skips on error: any failure to complete the
//! security check results in `500`, never in an uninspected passthrough.
//!
//! A panic is caught with [`std::panic::catch_unwind`], so the default panic
//! hook still prints. `panic = "abort"` in the release profile disables that
//! recovery, because the process dies before the guard can respond.
//!
//! ## Example
//!
//! ```
//! use bytes::Bytes;
//! use http::{Request, Response, StatusCode};
//! use http_body_util::{BodyExt, Full};
//! use std::convert::Infallible;
//! use tower::{Layer, Service, ServiceExt};
//!
//! # let runtime = tokio::runtime::Builder::new_current_thread()
//! #     .enable_all()
//! #     .build()
//! #     .unwrap();
//! # runtime.block_on(async {
//! // Any `Service<Request<B>>` works, for example a router.
//! let upstream = tower::service_fn(|request: Request<Full<Bytes>>| async move {
//!     let body = request.into_body().collect().await.unwrap().to_bytes();
//!     Ok::<_, Infallible>(Response::new(Full::new(body)))
//! });
//!
//! let mut service =
//!     tower_guard_rs::GuardLayer::new(tower_guard_rs::default_config()).layer(upstream);
//!
//! // Benign traffic passes through untouched.
//! let request = Request::builder()
//!     .uri("/search?q=hello")
//!     .body(Full::new(Bytes::new()))
//!     .unwrap();
//! let response = service.ready().await.unwrap().call(request).await.unwrap();
//! assert_eq!(response.status(), StatusCode::OK);
//!
//! // Attack traffic is blocked by the engine.
//! let request = Request::builder()
//!     .uri("/files/../../etc/passwd")
//!     .body(Full::new(Bytes::new()))
//!     .unwrap();
//! let response = service.ready().await.unwrap().call(request).await.unwrap();
//! assert_eq!(response.status(), StatusCode::BAD_REQUEST);
//! # });
//! ```
//!
//! [`axum-guard-rs`]: https://github.com/rennf93/axum-guard-rs

mod body;
mod response;
mod service;
mod stages;

pub mod status;

pub use crate::body::{BoxError, GuardBody};
pub use crate::response::{
    ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, BLOCKED_MESSAGE, FAILURE_MESSAGE, FORBIDDEN_MESSAGE,
    OVERSIZE_MESSAGE, RATE_LIMITED_MESSAGE,
};
pub use crate::service::GuardService;
pub use crate::stages::{GuardStageLayer, GuardStageService, provided_layers};
pub use guard_core_engine::behavior::BehaviorRule;
pub use guard_core_engine::cors::CorsConfig;
pub use guard_core_engine::detect::{DetectConfig, DetectVerdict, Threat};
pub use guard_core_engine::detection_exclusions::{
    DetectionExclusionConfig, RouteDetectionExclusions,
};
pub use guard_core_engine::distributed::{BanStore, SlidingWindowStore};
pub use guard_core_engine::geo::GeoIpHandler;
pub use guard_core_engine::headers_auth::{
    AuthVerifier, HeaderAuthRules, REQUIRED_SENTINEL, RequiredHeader,
};
pub use guard_core_engine::ip_ban::{
    BanError, BanRecord, Clock, IpBanConfig, IpBanConfigError, IpBanManager, ResolvedBan,
    ThreatBanEntry, ViolationCounters,
};
pub use guard_core_engine::ip_gate::{
    IpGateConfig, IpGateDecision, IpGateDenial, IpGateError, IpGateVerdict,
};
pub use guard_core_engine::payload::{OnErrorFn, ResponseModifierFn};
pub use guard_core_engine::rate_limit::{
    RateLimitConfig, RateLimitConfigError, RateLimitDecision, RateLimitEntry, RateLimitTier,
    RateLimiter, RouteRateLimits, TierDecision,
};
pub use guard_core_engine::route_config::{RouteConfig, RouteConfigResolver};
pub use guard_core_engine::security_config::{
    BufferOverflowPolicy, LogFormat, LogLevel, SecurityConfig, SecurityConfigError,
};
pub use guard_core_engine::security_headers::SecurityHeadersConfig;
pub use guard_core_engine::user_agent::UserAgentFilter;
pub use guard_core_rs::cloud_provider::{CloudDecision, CloudProviderStage};
pub use guard_core_rs::custom_checks::CustomChecksStage;
pub use guard_core_rs::emergency_mode::{EmergencyAnswer, EmergencyModeStage};
pub use guard_core_rs::events::SecurityEventBus;
pub use guard_core_rs::geo::{GeoDecision, GeoStage, GeoStageConfig};
pub use guard_core_rs::headers_auth::{
    HeadersAuthStage, RouteGuard, StageAnswer as HeadersAuthAnswer,
};
pub use guard_core_rs::https_enforcement::{
    HttpsEnforcementStage, HttpsRedirectAnswer as HttpsRedirect,
};
pub use guard_core_rs::process_response::ResponseProcessor;
pub use guard_core_rs::request_logging::{RequestLoggingStage, RequestLoggingStageConfig};
pub use guard_core_rs::responses::{BlockPayload, CustomErrorResponses, OnBlockHook};
pub use guard_core_rs::route_gates::{GateAnswer, ReferrerStage, TimeWindowStage};
pub use guard_core_rs::tower::{ObservabilityConfig, RequestObservation, StageResponse};
pub use guard_core_rs::tower::{RateLimitStage, RateLimitStageConfig, RouteRateResolver};
pub use guard_core_rs::user_agent::{UserAgentConfigError, UserAgentStage, UserAgentStageConfig};
use std::net::IpAddr;
use std::sync::Arc;
use tower::Layer;

/// Why [`GuardLayer::from_security_config`] refused a value: the engine
/// constructor that rejected it, fail-closed.
#[derive(Debug)]
pub enum GuardConfigError {
    /// An IP/CIDR list entry the gate cannot parse.
    IpGate(IpGateError),
    /// A zero rate-limit knob.
    RateLimit(RateLimitConfigError),
    /// A blocked user-agent pattern the `ReDoS` validator rejected.
    UserAgent(UserAgentConfigError),
    /// An invalid auto-ban knob group.
    Ban(IpBanConfigError),
}

impl std::fmt::Display for GuardConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpGate(error) => write!(f, "ip list: {error}"),
            Self::RateLimit(error) => write!(f, "rate limit: {error}"),
            Self::UserAgent(error) => write!(f, "blocked user agent: {error}"),
            Self::Ban(error) => write!(f, "ip ban: {error}"),
        }
    }
}

impl std::error::Error for GuardConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IpGate(error) => Some(error),
            Self::RateLimit(error) => Some(error),
            Self::UserAgent(error) => Some(error),
            Self::Ban(error) => Some(error),
        }
    }
}

impl From<IpGateError> for GuardConfigError {
    fn from(error: IpGateError) -> Self {
        Self::IpGate(error)
    }
}

impl From<RateLimitConfigError> for GuardConfigError {
    fn from(error: RateLimitConfigError) -> Self {
        Self::RateLimit(error)
    }
}

impl From<UserAgentConfigError> for GuardConfigError {
    fn from(error: UserAgentConfigError) -> Self {
        Self::UserAgent(error)
    }
}

impl From<IpBanConfigError> for GuardConfigError {
    fn from(error: IpBanConfigError) -> Self {
        Self::Ban(error)
    }
}

/// The engine log level mapped onto the logging facade's enum (the
/// reference literals are the same strings).
fn map_log_level(level: LogLevel) -> guard_core_rs::logging::LogLevel {
    match level {
        LogLevel::Info => guard_core_rs::logging::LogLevel::Info,
        LogLevel::Debug => guard_core_rs::logging::LogLevel::Debug,
        LogLevel::Warning => guard_core_rs::logging::LogLevel::Warning,
        LogLevel::Error => guard_core_rs::logging::LogLevel::Error,
        LogLevel::Critical => guard_core_rs::logging::LogLevel::Critical,
    }
}

/// The client IP the IP gate evaluates, carried in request extensions.
///
/// The tower [`tower::Service`] surface is framework-neutral, so there is no
/// single place a peer address lives: insert this extension upstream and the
/// configured gate ([`GuardLayer::with_ip_gate`]) evaluates it. Without the
/// extension the gate cannot attribute the request and does not run; the
/// request still goes through detection.
///
/// axum applications map `ConnectInfo<SocketAddr>` into it (axum-guard-rs
/// ships [`axum_guard_rs::client_ip_layer`] for exactly that); a proxy
/// frontend can insert its resolved client IP instead.
///
/// [`axum_guard_rs::client_ip_layer`]: https://docs.rs/axum-guard-rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardClientIp(pub IpAddr);

/// Reference default detection configuration.
///
/// The engine's [`DetectConfig`] carries no `Default` impl, so the adapter
/// pins the ecosystem defaults here. They are the values the conformance
/// corpus records for the reference implementation:
///
/// | Knob | Value |
/// |---|---|
/// | `max_content_length` | `10_000` |
/// | `max_full_scan_bytes` | `262_144` |
/// | `preserve_attack_patterns` | `true` |
/// | `semantic_threshold` | `0.7` |
/// | `threat_score_threshold` | `1.0` |
/// | `binary_min_run_length` | `16` |
///
/// # Example
///
/// ```
/// let config = tower_guard_rs::default_config();
/// let layer = tower_guard_rs::GuardLayer::new(config);
/// # let _ = layer;
/// ```
#[must_use]
pub const fn default_config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
        max_scan_values: 512,
        max_scan_chars: 65_536,
        max_json_depth: 32,
    }
}

/// The multi-surface scan entry point stored in the layer.
///
/// Indirection exists so unit tests can substitute a panicking scan and
/// exercise the fail-secure path; production builds always store
/// [`guard_core_engine::detection_exclusions::scan_request`].
pub(crate) type ScanFn = fn(
    &guard_core_engine::detection_exclusions::RequestSurfaces<'_>,
    &guard_core_engine::detection_exclusions::ResolvedExclusions,
    &DetectConfig,
) -> guard_core_engine::detection_exclusions::RequestScanVerdict;

/// The stateful stage's ban half: the shared ban store, the shared violation
/// counters (one middleware instance = one store pair), and the config that
/// gates banning and threshold resolution. The pair is injected into the
/// engine stage (`RateLimitStageBuilder::ban_manager`), so out-of-band
/// handles stay authoritative.
pub(crate) struct BanState {
    manager: IpBanManager,
    counters: ViolationCounters,
    config: IpBanConfig,
}

impl core::fmt::Debug for BanState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BanState")
            .field("manager", &self.manager)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Screens requests with the Guard engine before they reach the wrapped
/// service.
///
/// Wraps any service whose response body type satisfies the bounds documented
/// on the [`tower::Service`] implementation (see [`GuardService`]), which
/// includes `axum`'s `Router` (and therefore [`axum-guard-rs`]).
///
/// [`axum-guard-rs`]: https://github.com/rennf93/axum-guard-rs
///
/// # Example
///
/// ```
/// use tower::Layer;
/// use tower_guard_rs::GuardLayer;
///
/// let layer = GuardLayer::new(tower_guard_rs::default_config())
///     // Reject bodies larger than 1 MiB with 413 instead of buffering more.
///     .with_body_cap(1_048_576);
/// # let _ = layer;
/// ```
#[derive(Clone)]
pub struct GuardLayer {
    config: DetectConfig,
    body_cap: usize,
    ip_gate: Option<IpGateConfig>,
    rate_limiter: Option<Arc<RateLimiter>>,
    ban_state: Option<Arc<BanState>>,
    /// The per-route rate-limit tier resolver (`path -> Option<RouteRateLimits>`).
    route_tiers: Option<RouteRateResolver>,
    /// The reference `RouteConfigResolver` (`(method, path) ->
    /// Option<Arc<RouteConfig>>`): the per-route carrier the pipeline
    /// consumes (bypassed checks, `require_https`, per-route UA and size
    /// limits, the rate-limit and detection views). An
    /// `Arc<RouteConfig>` request extension wins over the resolver.
    route_configs: Option<RouteConfigResolver>,
    /// The geolocation seam the geo rate-limit tier resolves through.
    geo_handler: Option<Arc<dyn GeoIpHandler>>,
    /// The event bus the stage's security events dispatch through.
    events: Option<Arc<SecurityEventBus>>,
    /// The log/redaction knobs the stage's `log_activity` emissions read.
    observability: Option<ObservabilityConfig>,
    /// The reference `on_block` callback, fired once per blocked request.
    on_block: Option<OnBlockHook>,
    /// The reference `custom_response_modifier`: mutates every response
    /// the response pass touches (forwarded and blocked alike) before it
    /// leaves the pipeline.
    response_modifier: Option<guard_core_engine::payload::ResponseModifierFn>,
    /// The reference `on_error` best-effort hook.
    on_error: Option<guard_core_rs::responses::OnErrorHook>,
    /// The status-to-body overrides for every block answer.
    custom_error_responses: CustomErrorResponses,
    /// The reference `passive_mode`: log-only, no block is ever rendered.
    passive_mode: bool,
    /// The distributed window store plus the reference Redis knobs.
    distributed: Option<(Arc<dyn SlidingWindowStore>, String, bool)>,
    /// The distributed ban store (only meaningful with `distributed`).
    distributed_ban_store: Option<Arc<dyn BanStore>>,
    /// The global detection-exclusion config.
    detection_exclusions: Option<DetectionExclusionConfig>,
    /// Check 2: the emergency-mode stage.
    emergency_mode: Option<EmergencyModeStage>,
    /// Check 3: the HTTPS-enforcement stage.
    https_enforcement: Option<HttpsEnforcementStage>,
    /// Check 4: the request-logging stage (compose-only, never blocks).
    request_logging: Option<RequestLoggingStage>,
    /// Checks 6 + 7: the required-headers and authentication stage.
    headers_auth: Option<HeadersAuthStage>,
    /// Check 8: the route referrer gate.
    referrer_gate: Option<ReferrerStage>,
    /// Check 9 + 17: the custom-checks stage (validators and the global
    /// `custom_request` function).
    custom_checks: Option<CustomChecksStage>,
    /// Check 10: the route time-window gate.
    time_window_gate: Option<TimeWindowStage>,
    /// Check 12b: the geo country-blocking stage.
    geo_blocking: Option<GeoStage>,
    /// Check 13: the cloud-provider blocking stage.
    cloud_provider: Option<CloudProviderStage>,
    /// Check 14: the blocked user-agent stage.
    user_agent: Option<UserAgentStage>,
    /// The response-side pass (behavioral return rules + security headers
    /// + CORS) applied to every response the guard touches.
    response_processor: Option<Arc<ResponseProcessor>>,
    /// The reference `exclude_paths`: request paths that bypass the whole
    /// pipeline (the docs/static carve-out).
    exclude_paths: Vec<String>,
    /// The reference `enable_penetration_detection`: the global scan
    /// toggle (the reference default `true`). `false` skips the
    /// multi-surface detection scan entirely - the verdict pipeline
    /// downstream (violations, auto-ban feed) sees a clean request.
    penetration_detection_enabled: bool,
    /// The scan entry point (test-only panic injection).
    scan_fn: ScanFn,
    /// The stage built by [`GuardLayer::layer`](tower::Layer::layer) from
    /// the fields above; `None` until the layer wraps a service.
    stage: Option<Arc<RateLimitStage>>,
    /// The cloud-refresh seam the `refresh_cloud_ip_ranges` maintenance
    /// call drives (the reference `refresh_cloud_ip_ranges`'s handler).
    cloud_refresh: Option<(
        Arc<guard_core_rs::geo_lifecycle::CloudRefreshScheduler>,
        Arc<guard_core_engine::cloud_provider::CloudIpTable>,
    )>,
}

/// The `agent_stats` answer (the reference middleware property shape):
/// whether an agent is wired and whether its start degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentStats {
    /// Whether an agent handler is wired (`enabled`).
    pub enabled: bool,
    /// Whether the agent started with failures (`degraded`).
    pub degraded: bool,
}

impl GuardLayer {
    /// Build a layer from an engine [`DetectConfig`].
    ///
    /// The body buffering cap starts at `config.max_full_scan_bytes`. No IP
    /// gate, rate limiter, or ban store is configured (each can be added
    /// with [`GuardLayer::with_ip_gate`], [`GuardLayer::with_rate_limiting`],
    /// and [`GuardLayer::with_ip_banning`]).
    #[must_use]
    pub fn new(config: DetectConfig) -> Self {
        Self {
            config,
            body_cap: config.max_full_scan_bytes,
            ip_gate: None,
            rate_limiter: None,
            ban_state: None,
            route_tiers: None,
            route_configs: None,
            geo_handler: None,
            events: None,
            observability: None,
            on_block: None,
            custom_error_responses: CustomErrorResponses::new(),
            response_modifier: None,
            on_error: None,
            passive_mode: false,
            distributed: None,
            distributed_ban_store: None,
            detection_exclusions: None,
            emergency_mode: None,
            https_enforcement: None,
            request_logging: None,
            headers_auth: None,
            referrer_gate: None,
            custom_checks: None,
            time_window_gate: None,
            geo_blocking: None,
            cloud_provider: None,
            user_agent: None,
            response_processor: None,
            exclude_paths: Vec::new(),
            penetration_detection_enabled: true,
            scan_fn: guard_core_engine::detection_exclusions::scan_request,
            stage: None,
            cloud_refresh: None,
        }
    }

    /// Build a layer with [`default_config`].
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(default_config())
    }

    /// The request paths that bypass the whole pipeline (the reference
    /// `exclude_paths` carve-out, exact path match).
    #[must_use]
    pub fn exclude_paths(&self) -> &[String] {
        &self.exclude_paths
    }

    /// The global scan toggle (`enable_penetration_detection`, the
    /// reference default `true`).
    pub(crate) const fn penetration_detection_enabled(&self) -> bool {
        self.penetration_detection_enabled
    }

    /// Set the global scan toggle (`enable_penetration_detection`): the
    /// reference default is enabled, so only a `false` changes behavior -
    /// the detection scan is skipped and the request proceeds clean.
    #[must_use]
    pub fn with_penetration_detection(mut self, enabled: bool) -> Self {
        self.penetration_detection_enabled = enabled;
        self
    }

    /// Set the `exclude_paths` carve-out.
    #[must_use]
    pub fn with_exclude_paths(mut self, paths: Vec<String>) -> Self {
        self.exclude_paths = paths;
        self
    }

    /// Build the layer from the unified `SecurityConfig`
    /// (the reference configuration surface): every field the layer
    /// consumes maps onto the wired stage or knob it owns, in one place,
    /// with the reference semantics.
    ///
    /// The stages that need a host-provided collaborator (the geo handler,
    /// the distributed stores, the event bus, the custom checks, the
    /// time-window and referrer resolvers) stay opt-in through their own
    /// builders: the config carries no such object.
    ///
    /// # Errors
    ///
    /// [`GuardConfigError`] when an engine constructor rejects a value
    /// (an invalid IP/CIDR list entry, a zero rate-limit knob, or a
    /// ReDoS-unsafe blocked user-agent pattern).
    #[allow(clippy::too_many_lines)]
    pub fn from_security_config(
        config: &guard_core_engine::security_config::SecurityConfig,
    ) -> Result<Self, GuardConfigError> {
        let mut layer = Self::new(DetectConfig {
            max_content_length: config.detection_max_content_length,
            max_full_scan_bytes: config.detection_max_body_inspect_bytes,
            preserve_attack_patterns: config.detection_preserve_attack_patterns,
            semantic_threshold: config.detection_semantic_threshold,
            threat_score_threshold: config.detection_threat_score_threshold,
            binary_min_run_length: config.detection_binary_min_run_length,
            max_scan_values: config.detection_max_scan_values,
            max_scan_chars: config.detection_max_scan_chars,
            max_json_depth: config.detection_max_json_depth,
        })
        .with_passive_mode(config.passive_mode)
        .with_penetration_detection(config.enable_penetration_detection)
        .with_exclude_paths(config.exclude_paths.clone());

        if config.whitelist.is_some()
            || !config.blacklist.is_empty()
            || !config.exempt_ips.is_empty()
        {
            layer = layer.with_ip_gate(guard_core_engine::ip_gate::IpGateConfig::new(
                config.whitelist.clone().unwrap_or_default(),
                config.blacklist.iter().cloned(),
                config.exempt_ips.iter().cloned(),
            )?);
        }

        if config.enable_rate_limiting {
            let limiter = RateLimiter::new(RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: config.rate_limit,
                rate_limit_window: config.rate_limit_window,
                ..RateLimitConfig::default()
            })?;
            layer = layer.with_rate_limiting(limiter);
        }

        if config.enable_ip_banning {
            layer = layer.with_ip_banning(IpBanManager::new(), config.ip_ban_config());
        }

        // Check 3: the global HTTPS arm; `X-Forwarded-Proto` trust rides
        // the same knobs the reference reads them from.
        layer = layer.with_https_enforcement(
            HttpsEnforcementStage::builder(
                guard_core_rs::https_enforcement::HttpsEnforcementStageConfig {
                    enforce_https: config.enforce_https,
                    trust_x_forwarded_proto: config.trust_x_forwarded_proto,
                    passive_mode: config.passive_mode,
                },
            )
            .build()?,
        );

        if config.emergency_mode || !config.emergency_whitelist.is_empty() {
            layer = layer.with_emergency_mode(
                EmergencyModeStage::builder(
                    guard_core_rs::emergency_mode::EmergencyModeStageConfig {
                        emergency_mode: config.emergency_mode,
                        passive_mode: config.passive_mode,
                    },
                )
                .emergency_whitelist(config.emergency_whitelist.iter().cloned())
                .build()?,
            );
        }

        if !config.custom_error_responses.is_empty() {
            layer = layer.with_custom_error_responses(
                config
                    .custom_error_responses
                    .iter()
                    .map(|(status, body)| (*status, body.clone()))
                    .collect(),
            );
        }

        if let Some(hook) = config.on_block.clone() {
            layer = layer.with_on_block(hook);
        }

        if !config.excluded_detection_headers.is_empty()
            || !config.excluded_detection_params.is_empty()
            || !config.excluded_detection_body_fields.is_empty()
            || !config.enabled_detection_categories.is_empty()
        {
            layer = layer.with_detection_exclusions(DetectionExclusionConfig {
                excluded_detection_headers: config
                    .excluded_detection_headers
                    .iter()
                    .cloned()
                    .collect(),
                excluded_detection_params: config
                    .excluded_detection_params
                    .iter()
                    .cloned()
                    .collect(),
                excluded_detection_body_fields: config
                    .excluded_detection_body_fields
                    .iter()
                    .cloned()
                    .collect(),
                enabled_detection_categories: (!config.enabled_detection_categories.is_empty())
                    .then(|| {
                        config
                            .enabled_detection_categories
                            .iter()
                            .cloned()
                            .collect()
                    }),
                detection_scan_body: Some(config.detection_scan_body),
            });
        }

        if let Some(level) = config.log_request_level {
            // The reference construction gate: the request-logging check
            // exists only when `log_request_level` is set.
            layer =
                layer.with_request_logging(RequestLoggingStage::new(RequestLoggingStageConfig {
                    log_request_level: Some(map_log_level(level)),
                    muted_check_logs: Some(config.muted_check_logs.iter().cloned().collect()),
                    sensitive: guard_core_rs::redact::SensitiveNames::new(
                        Some(&config.log_sensitive_headers.iter().cloned().collect()),
                        Some(&config.log_sensitive_params.iter().cloned().collect()),
                        Some(&config.log_sensitive_body_fields.iter().cloned().collect()),
                    ),
                }));
        }

        if let Some(level) = config.log_suspicious_level {
            layer = layer.with_observability(ObservabilityConfig {
                log_suspicious_level: Some(map_log_level(level)),
                log_request_level: config.log_request_level.map(map_log_level),
                log_country_check_level: config.log_country_check_level.map(map_log_level),
                muted_check_logs: Some(config.muted_check_logs.iter().cloned().collect()),
                sensitive: guard_core_rs::redact::SensitiveNames::new(
                    Some(&config.log_sensitive_headers.iter().cloned().collect()),
                    Some(&config.log_sensitive_params.iter().cloned().collect()),
                    Some(&config.log_sensitive_body_fields.iter().cloned().collect()),
                ),
            });
        } else if let Some(country_level) = config.log_country_check_level {
            // Country verdicts compose even without a suspicious level.
            layer = layer.with_observability(ObservabilityConfig {
                log_suspicious_level: None,
                log_request_level: config.log_request_level.map(map_log_level),
                log_country_check_level: Some(map_log_level(country_level)),
                muted_check_logs: Some(config.muted_check_logs.iter().cloned().collect()),
                sensitive: guard_core_rs::redact::SensitiveNames::new(
                    Some(&config.log_sensitive_headers.iter().cloned().collect()),
                    Some(&config.log_sensitive_params.iter().cloned().collect()),
                    Some(&config.log_sensitive_body_fields.iter().cloned().collect()),
                ),
            });
        }

        if !config.blocked_user_agents.is_empty() {
            layer = layer.with_user_agent(
                UserAgentStage::builder(guard_core_rs::user_agent::UserAgentStageConfig {
                    // The error arm takes its own line: the coverage
                    // mapping attributes the `?` return to the function
                    // exit, so an inline `?` here renders count 0 forever.
                    blocked_user_agents: UserAgentFilter::new(
                        config.blocked_user_agents.iter().cloned(),
                    )
                    .map_err(GuardConfigError::from)?,
                    ip_ban: config.ip_ban_config(),
                    passive_mode: config.passive_mode,
                })
                .build()?,
            );
        }

        let wants_headers = config.security_headers.enabled;
        if wants_headers || config.enable_cors || !config.global_behavior_rules.is_empty() {
            let cors = config
                .enable_cors
                .then(|| guard_core_engine::cors::CorsConfig {
                    enabled: true,
                    allow_origins: config.cors_allow_origins.clone(),
                    allow_methods: config.cors_allow_methods.clone(),
                    allow_headers: config.cors_allow_headers.clone(),
                    allow_credentials: config.cors_allow_credentials,
                    max_age: config.cors_max_age,
                });
            layer = layer.with_response_processor(ResponseProcessor::new(
                wants_headers.then_some(config.security_headers.clone()),
                cors,
                config.global_behavior_rules.clone(),
                Arc::new(std::sync::Mutex::new(
                    guard_core_engine::behavior::BehaviorTracker::new(),
                )),
                IpBanManager::new(),
                config.behavior_scan_response_body,
                config.behavior_max_response_body_inspect_bytes,
                config.passive_mode,
            ));
        }

        Ok(layer)
    }

    /// Replace the body buffering cap, in bytes.
    ///
    /// A body larger than the cap is rejected with `413 Payload Too Large`.
    /// A cap of `0` rejects every request that carries a non-empty body.
    #[must_use]
    pub fn with_body_cap(mut self, body_cap: usize) -> Self {
        self.body_cap = body_cap;
        self
    }

    /// Install the global IP gate: a `whitelist`/`blacklist`/`exempt_ips`
    /// config built with [`IpGateConfig::new`] (which fails closed on an
    /// invalid entry).
    ///
    /// The gate runs before body buffering and before detection: an IP on the
    /// `blacklist` is denied with `403 Forbidden`, and so is any IP when a
    /// non-empty `whitelist` matches neither it nor an `exempt_ips` entry. A
    /// passed request gets the gate's [`IpGateDecision`] inserted into the
    /// request extensions, so downstream handlers can read the skip state
    /// (`is_whitelisted` / `is_exempt`). The client IP comes from the
    /// [`GuardClientIp`] extension; a request without it is not attributed and
    /// goes through detection unconditionally - detection still screens every
    /// request, exempt or not.
    ///
    /// # Example
    ///
    /// ```
    /// use tower::Layer;
    /// use tower_guard_rs::{GuardLayer, IpGateConfig};
    ///
    /// let gate = IpGateConfig::new(
    ///     [] as [&str; 0],
    ///     ["203.0.113.9"],
    ///     ["198.51.100.0/28"],
    /// )
    /// .expect("valid lists");
    /// let layer = GuardLayer::new(tower_guard_rs::default_config()).with_ip_gate(gate);
    /// # let _ = layer;
    /// ```
    #[must_use]
    pub fn with_ip_gate(mut self, ip_gate: IpGateConfig) -> Self {
        self.ip_gate = Some(ip_gate);
        self
    }

    /// Install the rate limiter: an engine [`RateLimiter`] built over a
    /// [`RateLimitConfig`] (whose constructor fails closed on a zero limit or
    /// window). The limiter's own `enable_rate_limiting` switch decides
    /// whether it records and blocks, so attaching a disabled limiter is
    /// inert.
    ///
    /// The limiter stage runs after the IP gate and the ban stage and before
    /// body buffering and detection: a crossing is answered with
    /// `429 Too Many Requests` carrying `Retry-After: <window seconds>`,
    /// the references' rate-limit shape. When the limiter's
    /// `enable_rate_limit_auto_ban` is on and IP banning is configured
    /// ([`GuardLayer::with_ip_banning`]), every crossing counts one
    /// `rate_limit` violation toward the auto-ban engine. Both stages skip
    /// whitelisted and exempt IPs (the `exempt_ips` contract), and requests
    /// without a [`GuardClientIp`] extension cannot be attributed and are
    /// not rate limited - detection still screens them.
    ///
    /// Cloning the layer (or layering several services with it) shares the
    /// one limiter: the window store is process-global by design, exactly
    /// like the reference's middleware-scoped store.
    ///
    /// # Example
    ///
    /// ```
    /// use tower::Layer;
    /// use tower_guard_rs::{GuardLayer, RateLimitConfig, RateLimiter};
    ///
    /// let limiter = RateLimiter::new(RateLimitConfig {
    ///     enable_rate_limiting: true,
    ///     rate_limit: 30,
    ///     rate_limit_window: 10,
    ///     ..RateLimitConfig::default()
    /// })
    /// .expect("valid config");
    /// let layer = GuardLayer::new(tower_guard_rs::default_config()).with_rate_limiting(limiter);
    /// # let _ = layer;
    /// ```
    #[must_use]
    pub fn with_rate_limiting(mut self, limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(Arc::new(limiter));
        self
    }

    /// Install the dynamic ban store and the auto-ban engine: an
    /// [`IpBanManager`] (optionally built with trusted proxies via
    /// `IpBanManager::with_trusted_proxies`) and an [`IpBanConfig`]
    /// (whose constructor fails closed on an invalid `threat_ban_config`).
    ///
    /// The ban stage runs after the IP gate and before body buffering and
    /// detection: a live ban on the client IP is answered with
    /// `403 Forbidden` (`IP address banned`), before rate limiting. The
    /// stage's violation counters feed the auto-ban engine exactly like the
    /// reference pipeline's suspicious-activity stage: every detected
    /// threat counts its categories per client IP (whitelisted IPs never
    /// count - the reference suspicious-activity stage skips a whitelisted
    /// IP only; exempt IPs DO count, which makes a crossed threshold ban
    /// even an exempt attacker), and a crossed
    /// `threat_ban_config` entry (or the flat `auto_ban_threshold`)
    /// bans on the spot, answering `403 Forbidden` (`IP has been banned`).
    /// The `config.enable_ip_banning` switch gates all of it; with it off
    /// the stage counts violations but never bans.
    ///
    /// Requests without a [`GuardClientIp`] extension cannot be attributed
    /// and are neither banned nor counted.
    ///
    /// Cloning the layer (or layering several services with it) shares the
    /// one store pair: bans and counts are process-global by design, exactly
    /// like the reference's middleware-scoped stores.
    ///
    /// # Example
    ///
    /// ```
    /// use tower::Layer;
    /// use tower_guard_rs::{GuardLayer, IpBanConfig, IpBanManager, ThreatBanEntry};
    ///
    /// let manager = IpBanManager::new();
    /// let config = IpBanConfig::new(
    ///     true,
    ///     10,
    ///     3600,
    ///     [("sqli", ThreatBanEntry { threshold: 3, duration: 1800 })],
    /// )
    /// .expect("valid config");
    /// let layer = GuardLayer::new(tower_guard_rs::default_config())
    ///     .with_ip_banning(manager, config);
    /// # let _ = layer;
    /// ```
    #[must_use]
    pub fn with_ip_banning(mut self, manager: IpBanManager, config: IpBanConfig) -> Self {
        self.ban_state = Some(Arc::new(BanState {
            manager,
            counters: ViolationCounters::new(),
            config,
        }));
        self
    }

    /// Install the per-route rate-limit tier resolver:
    /// `path -> Option<RouteRateLimits>` (the tower counterpart of the
    /// reference's `request.state.route_config`). A
    /// [`RouteRateLimits`] request extension, when a stack provides one,
    /// wins over the resolver. The tier's `rate_limit`/`rate_limit_window`
    /// (and its per-country `geo_rate_limits`, resolved through
    /// [`GuardLayer::with_geo_handler`]) apply on top of the global tier;
    /// the first tier that crosses decides, answering the same
    /// `429 + Retry-After` shape.
    ///
    /// # Example
    ///
    /// ```
    /// use tower::Layer;
    /// use tower_guard_rs::{GuardLayer, RouteRateLimits, default_config};
    ///
    /// let layer = GuardLayer::new(default_config()).with_route_tiers(std::sync::Arc::new(|path| {
    ///     if path.starts_with("/login") {
    ///         Some(RouteRateLimits::new(Some(5), None, None).expect("valid tiers"))
    ///     } else {
    ///         None
    ///     }
    /// }));
    /// # let _ = layer;
    /// ```
    #[must_use]
    pub fn with_route_tiers(mut self, resolver: RouteRateResolver) -> Self {
        self.route_tiers = Some(resolver);
        self
    }

    /// Install the reference `RouteConfigResolver` (the
    /// [`guard_core_engine::route_config::RouteConfig`] carrier):
    /// `(method, path) -> Option<Arc<RouteConfig>>`. The resolved route's
    /// knobs apply on top of the global config for that route only, the
    /// reference `RouteConfigResolver` semantics:
    ///
    /// - `bypassed_checks` (and the `"all"` wildcard) skip the named
    ///   reference checks for the route (see the pipeline table for the
    ///   fused-stage mapping),
    /// - `require_https` forces the reference `301` for the route,
    /// - `max_request_size` replaces the body cap for the route,
    /// - `blocked_user_agents` is evaluated additively before the global
    ///   filter (the reference `check_user_agent_allowed` order),
    /// - `rate_limit`/`rate_limit_window`/`geo_rate_limits` become the
    ///   route's rate-limit tier,
    /// - the five detection-exclusion knobs resolve through the engine's
    ///   detection view for the route.
    ///
    /// An `Arc<RouteConfig>` request extension wins over the resolver
    /// (the app attaches a route's config directly, the reference
    /// `request.state.route_config` idiom).
    #[must_use]
    pub fn with_route_configs(mut self, resolver: RouteConfigResolver) -> Self {
        self.route_configs = Some(resolver);
        self
    }

    /// The installed route-config resolver, if any.
    pub(crate) const fn route_configs(&self) -> Option<&RouteConfigResolver> {
        self.route_configs.as_ref()
    }

    /// Install the geolocation seam the geo rate-limit tier resolves
    /// through (`geo_handler.get_country(ip)`; the MMDB reading is the
    /// host's work, [`GeoIpHandler`] is the engine trait). Without a
    /// handler the geo tier never applies, exactly the reference's
    /// `if not geo_handler: return None`.
    #[must_use]
    pub fn with_geo_handler(mut self, handler: Arc<dyn GeoIpHandler>) -> Self {
        self.geo_handler = Some(handler);
        self
    }

    /// Install the [`SecurityEventBus`] the stage's security events
    /// dispatch through (`penetration_attempt`, `rate_limited`,
    /// `ip_banned`, with the reference fields and metadata). The
    /// response-side pass joins the stream: when the security-header set
    /// lands on a forwarded response, the composed
    /// `security_headers_applied` event (action `headers_added`, the
    /// display-redacted path plus `headers_count`/`has_csp`/`has_hsts`)
    /// dispatches too; guard-generated answers apply the headers without
    /// firing (the reference's `create_error_response` lane). Handlers
    /// receive every event and own the transport.
    #[must_use]
    pub fn with_event_bus(mut self, bus: Arc<SecurityEventBus>) -> Self {
        self.events = Some(bus);
        self
    }

    /// Install the observability knobs ([`ObservabilityConfig`]): the
    /// `log_suspicious_level` (`None` composes no suspicious line), the
    /// `muted_check_logs` set, and the `log_sensitive_headers` /
    /// `log_sensitive_params` / `log_sensitive_body_fields` redaction sets
    /// (merged over the engine defaults) that the suspicious log lines,
    /// the event endpoint/user-agent fields, and the `on_block` payload
    /// redact through.
    #[must_use]
    pub fn with_observability(mut self, observability: ObservabilityConfig) -> Self {
        self.observability = Some(observability);
        self
    }

    /// Install the reference `on_block` callback: fired exactly once per
    /// blocked request (and once per passive-flagged detection, with
    /// `status_code = None`) with the reference [`BlockPayload`] keys
    /// (check name, reason, trigger, redacted path, method, status).
    /// Matching the engine stage's contract, the hook receives redacted
    /// payloads only when an [`ObservabilityConfig`] is installed.
    #[must_use]
    pub fn with_on_block(mut self, hook: OnBlockHook) -> Self {
        self.on_block = Some(hook);
        self
    }

    /// Install the reference `custom_response_modifier`: the callback
    /// runs LAST in the response pass (after the CORS verdict) over
    /// every response the guard touches - forwarded and blocked alike.
    /// A panicking callback leaves the response unmodified (the
    /// reference's except arm) and reports through the `on_error` hook
    /// when one is installed.
    #[must_use]
    pub fn with_custom_response_modifier(
        mut self,
        modifier: guard_core_engine::payload::ResponseModifierFn,
    ) -> Self {
        self.response_modifier = Some(modifier);
        self
    }

    /// Install the reference `on_error` best-effort hook: invoked when a
    /// middleware step fails, receiving `(stage, error, context)`. A
    /// raising callback is caught and dropped, never propagated.
    #[must_use]
    pub fn with_on_error(mut self, hook: guard_core_rs::responses::OnErrorHook) -> Self {
        self.on_error = Some(hook);
        self
    }

    /// Install the reference `custom_error_responses` map: status code to
    /// message body, overriding the family default for that status on
    /// every block answer the guard renders (`429`, both `403` banned
    /// shapes, the `503` Redis-unavailable shape, and the `400`
    /// detection block).
    #[must_use]
    pub fn with_custom_error_responses(
        mut self,
        custom_error_responses: CustomErrorResponses,
    ) -> Self {
        self.custom_error_responses = custom_error_responses;
        self
    }

    /// Set the reference `passive_mode` (default `false`): log-only
    /// security. Sliding windows and violation counters still record, the
    /// log lines and events still fire, but no `400`/`403`/`429` is ever
    /// rendered and the auto-ban feeds are suppressed - the reference's
    /// passive paths.
    #[must_use]
    pub fn with_passive_mode(mut self, passive_mode: bool) -> Self {
        self.passive_mode = passive_mode;
        self
    }

    /// Run the limiter and ban engine over a distributed store (the
    /// reference `enable_redis && redis_handler` conjunction): a
    /// [`SlidingWindowStore`] plus the reference `redis_prefix` and
    /// `redis_fail_open` knobs. `redis_fail_open = false` (the default)
    /// answers the fail-closed `503 "Redis rate limiting unavailable"` on
    /// a backend error; `true` degrades to the in-memory window. Install
    /// a [`BanStore`] alongside with
    /// [`GuardLayer::with_distributed_ban_store`]. The traits are
    /// engine-side and client-free; `guard-core-rs`' `redis` feature
    /// ships a ready `RedisStore` backend.
    #[must_use]
    pub fn with_distributed_store(
        mut self,
        window_store: Arc<dyn SlidingWindowStore>,
        redis_prefix: &str,
        redis_fail_open: bool,
    ) -> Self {
        self.distributed = Some((window_store, redis_prefix.to_owned(), redis_fail_open));
        self
    }

    /// Attach the distributed ban store the ban engine shares (the
    /// reference `{prefix}banned_ips:{ip}` namespace). Only meaningful
    /// together with [`GuardLayer::with_distributed_store`].
    #[must_use]
    pub fn with_distributed_ban_store(mut self, ban_store: Arc<dyn BanStore>) -> Self {
        self.distributed_ban_store = Some(ban_store);
        self
    }

    /// Install the global detection-exclusion config
    /// ([`DetectionExclusionConfig`], the reference `SecurityConfig`
    /// fields of the same names): `excluded_detection_headers` (merged
    /// with the engine defaults), `excluded_detection_params`,
    /// `excluded_detection_body_fields`, `enabled_detection_categories`,
    /// and `detection_scan_body`. A
    /// [`RouteDetectionExclusions`] request extension (the per-route
    /// decorator surface) resolves on top of it per request: a non-`None`
    /// route value replaces the global set for that surface (the header
    /// set always merges).
    #[must_use]
    pub fn with_detection_exclusions(
        mut self,
        detection_exclusions: DetectionExclusionConfig,
    ) -> Self {
        self.detection_exclusions = Some(detection_exclusions);
        self
    }

    /// Install the emergency-mode stage (check 2): while the mode is on,
    /// every IP outside the emergency whitelist answers `503 Service
    /// temporarily unavailable` before any later stage runs (fail secure:
    /// an unattributable request is outside the whitelist). Build the
    /// stage with [`EmergencyModeStage::builder`] so its event bus, hook,
    /// and custom-error overrides ride along.
    #[must_use]
    pub fn with_emergency_mode(mut self, stage: EmergencyModeStage) -> Self {
        self.emergency_mode = Some(stage);
        self
    }

    /// Install the HTTPS-enforcement stage (check 3): a plain-HTTP request
    /// under the global `enforce_https` arm (or a route's `require_https`)
    /// answers the reference `301` redirect to the scheme-upgraded URL.
    #[must_use]
    pub fn with_https_enforcement(mut self, stage: HttpsEnforcementStage) -> Self {
        self.https_enforcement = Some(stage);
        self
    }

    /// Install the request-logging stage (check 4): composes the reference
    /// `log_activity` "Request from {ip}: {method} {url}" line (redacted,
    /// muted-set aware) per request and never blocks. The composed line is
    /// the host's to emit - install an [`ObservabilityConfig`] for the
    /// redaction knobs or leave the stage out for silence.
    #[must_use]
    pub fn with_request_logging(mut self, stage: RequestLoggingStage) -> Self {
        self.request_logging = Some(stage);
        self
    }

    /// Install the required-headers and authentication stage (checks 6 +
    /// 7): the route resolver picks the [`RouteGuard`] per path, and a
    /// failed rule answers the reference dynamic `400` header shape or the
    /// fixed `401` authentication shape.
    #[must_use]
    pub fn with_headers_auth(mut self, stage: HeadersAuthStage) -> Self {
        self.headers_auth = Some(stage);
        self
    }

    /// Install the route referrer gate (check 8): a route with a
    /// `require_referrer` list answers `403` (`Referrer required` /
    /// `Invalid referrer`) when the `referer` header is missing or outside
    /// the allowed domains.
    #[must_use]
    pub fn with_referrer_gate(mut self, stage: ReferrerStage) -> Self {
        self.referrer_gate = Some(stage);
        self
    }

    /// Install the custom-checks stage (checks 9 + 17): the route's
    /// validators run in order (first blocking response wins, the
    /// validator's own response shape), and the global `custom_request`
    /// function runs after the rate-limit stage at the reference's
    /// seventeenth position.
    #[must_use]
    pub fn with_custom_checks(mut self, stage: CustomChecksStage) -> Self {
        self.custom_checks = Some(stage);
        self
    }

    /// Install the route time-window gate (check 10): a route with
    /// `time_restrictions` answers `403` (`Access not allowed at this
    /// time`) outside the window.
    #[must_use]
    pub fn with_time_window_gate(mut self, stage: TimeWindowStage) -> Self {
        self.time_window_gate = Some(stage);
        self
    }

    /// Install the geo country-blocking stage (check 12b, the reference
    /// runs it inside `ip_security`): a country outside a restrictive
    /// `whitelist_countries` or inside `blocked_countries` answers `403
    /// Forbidden`. Resolve countries with an MMDB reader ([`GeoIpHandler`]
    /// implementations; `guard_core_rs::mmdb` ships one) or any other
    /// country resolver.
    #[must_use]
    pub fn with_geo_blocking(mut self, stage: GeoStage) -> Self {
        self.geo_blocking = Some(stage);
        self
    }

    /// Install the cloud-provider blocking stage (check 13): a client IP
    /// inside a blocked provider's ranges answers `403` (`Cloud provider
    /// IP not allowed`). Feed the stage's table with
    /// [`CloudIpTable::set_provider_ranges`] and refresh it from a
    /// background fetcher (`guard_core_rs::cloud_fetch`).
    ///
    /// [`CloudIpTable::set_provider_ranges`]:
    /// guard_core_rs::cloud_provider::CloudIpTable::set_provider_ranges
    #[must_use]
    pub fn with_cloud_provider(mut self, stage: CloudProviderStage) -> Self {
        self.cloud_provider = Some(stage);
        self
    }

    /// Install the cloud-refresh seam the [`GuardLayer::refresh_cloud_ip_ranges`]
    /// maintenance call drives: the scheduler (the facade's
    /// `CloudRefreshScheduler`, carrying the provider set and any endpoint
    /// overrides) plus the table the refresh swaps ranges into - the same
    /// table the cloud-provider stage consults (clones share the store).
    #[must_use]
    pub fn with_cloud_refresh_scheduler(
        mut self,
        scheduler: Arc<guard_core_rs::geo_lifecycle::CloudRefreshScheduler>,
        table: Arc<guard_core_engine::cloud_provider::CloudIpTable>,
    ) -> Self {
        self.cloud_refresh = Some((scheduler, table));
        self
    }

    /// The reference `refresh_cloud_ip_ranges` (fastapi-guard
    /// `guard/middleware.py`): schedule one background cloud-ranges refresh
    /// through the installed scheduler (single-flight: `false` while one
    /// is in flight, the reference's concurrent-caller gate). No scheduler
    /// installed answers `false` - the reference's no-op for an empty
    /// `block_cloud_providers`. The refreshed ranges land in the shared
    /// table (each provider's row restamps), so the status payload and the
    /// blocking stage see them without a restart.
    #[must_use]
    pub fn refresh_cloud_ip_ranges(&self) -> bool {
        match &self.cloud_refresh {
            Some((scheduler, table)) => scheduler.schedule_refresh(table),
            None => false,
        }
    }

    /// The reference `reset()` (fastapi-guard `guard/middleware.py`):
    /// drop every rate-limit window the guard tracks, so every identity
    /// starts its windows afresh. The bans, violation counts, and the
    /// cloud table are untouched - the reference resets the rate-limit
    /// handler only.
    pub fn reset(&self) {
        if let Some(limiter) = &self.rate_limiter {
            limiter.reset();
        }
    }

    /// The reference `agent_stats` (fastapi-guard `guard/middleware.py`
    /// property) in its no-agent shape: `{"enabled": false, "degraded":
    /// false}`. The adapter owns no agent slot (the engine-to-agent seam
    /// lives in `guard-core-rs` / `guard-agent-rs`), so the enabled arm
    /// has no surface here yet.
    #[must_use]
    pub const fn agent_stats(&self) -> AgentStats {
        AgentStats {
            enabled: false,
            degraded: false,
        }
    }

    /// Install the blocked user-agent stage (check 14): a `User-Agent`
    /// matching the global blocklist (or the route's) answers `403`
    /// (`User-Agent not allowed`), and a detection threat on the same
    /// request feeds the auto-ban engine (the reference
    /// `escalate_identity_violation`).
    #[must_use]
    pub fn with_user_agent(mut self, stage: UserAgentStage) -> Self {
        self.user_agent = Some(stage);
        self
    }

    /// Install the response-side pass (the reference `process_response`):
    /// the global `return_pattern` behavior rules evaluate every response
    /// the guard touches (a crossed `ban` action lands in the processor's
    /// IP-ban store), then the security-header set renders, then the CORS
    /// verdict headers compose on top. Applied to forwarded responses and
    /// to every block answer alike.
    #[must_use]
    pub fn with_response_processor(mut self, processor: ResponseProcessor) -> Self {
        self.response_processor = Some(Arc::new(processor));
        self
    }

    pub(crate) const fn config(&self) -> &DetectConfig {
        &self.config
    }

    pub(crate) const fn body_cap(&self) -> usize {
        self.body_cap
    }

    pub(crate) const fn ip_gate(&self) -> Option<&IpGateConfig> {
        self.ip_gate.as_ref()
    }

    pub(crate) const fn detection_exclusions(&self) -> Option<&DetectionExclusionConfig> {
        self.detection_exclusions.as_ref()
    }

    pub(crate) const fn observability(&self) -> Option<&ObservabilityConfig> {
        self.observability.as_ref()
    }

    pub(crate) const fn on_block(&self) -> Option<&OnBlockHook> {
        self.on_block.as_ref()
    }

    pub(crate) const fn custom_error_responses(&self) -> &CustomErrorResponses {
        &self.custom_error_responses
    }

    pub(crate) const fn emergency_mode(&self) -> Option<&EmergencyModeStage> {
        self.emergency_mode.as_ref()
    }

    pub(crate) const fn https_enforcement(&self) -> Option<&HttpsEnforcementStage> {
        self.https_enforcement.as_ref()
    }

    pub(crate) const fn request_logging(&self) -> Option<&RequestLoggingStage> {
        self.request_logging.as_ref()
    }

    pub(crate) const fn headers_auth(&self) -> Option<&HeadersAuthStage> {
        self.headers_auth.as_ref()
    }

    pub(crate) const fn referrer_gate(&self) -> Option<&ReferrerStage> {
        self.referrer_gate.as_ref()
    }

    pub(crate) const fn custom_checks(&self) -> Option<&CustomChecksStage> {
        self.custom_checks.as_ref()
    }

    pub(crate) const fn time_window_gate(&self) -> Option<&TimeWindowStage> {
        self.time_window_gate.as_ref()
    }

    pub(crate) const fn geo_blocking(&self) -> Option<&GeoStage> {
        self.geo_blocking.as_ref()
    }

    pub(crate) const fn cloud_provider(&self) -> Option<&CloudProviderStage> {
        self.cloud_provider.as_ref()
    }

    pub(crate) const fn user_agent(&self) -> Option<&UserAgentStage> {
        self.user_agent.as_ref()
    }

    pub(crate) const fn response_processor(&self) -> Option<&Arc<ResponseProcessor>> {
        self.response_processor.as_ref()
    }

    /// The configured rate-limit stage (built during
    /// [`GuardLayer::layer`](tower::Layer::layer), or on demand here for
    /// [`provided_layers`] on a not-yet-wrapped layer).
    pub(crate) fn rate_limit_stage(&self) -> Option<RateLimitStage> {
        if let Some(stage) = self.stage.as_deref() {
            return Some(stage.clone());
        }
        (self.rate_limiter.is_some() || self.ban_state.is_some()).then(|| self.build_stage())
    }

    /// The installed engine stage (set by
    /// [`GuardLayer::layer`](tower::Layer::layer)); every stateful
    /// decision and emission goes through it.
    pub(crate) fn stage(&self) -> Option<&RateLimitStage> {
        self.stage.as_deref()
    }

    /// Build the engine stage from the configured handles and seams.
    /// Every injected config is already validated (the `with_*` builders
    /// take pre-validated engine objects), so the stage build cannot
    /// fail; a panic here is a construction bug, not a runtime path.
    pub(crate) fn build_stage(&self) -> RateLimitStage {
        let rate_limit = self.rate_limiter.as_deref().map_or(
            RateLimitConfig {
                enable_rate_limiting: false,
                ..RateLimitConfig::default()
            },
            |limiter| limiter.config().clone(),
        );
        let ip_ban = self.ban_state.as_deref().map_or(
            IpBanConfig {
                enable_ip_banning: false,
                ..IpBanConfig::default()
            },
            |state| state.config.clone(),
        );
        let mut builder = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit,
            ip_ban,
            passive_mode: self.passive_mode,
            custom_error_responses: self.custom_error_responses.clone(),
        });
        if let Some(limiter) = &self.rate_limiter {
            builder = builder.limiter(limiter.as_ref().clone());
        }
        if let Some(state) = &self.ban_state {
            builder = builder.ban_manager(state.manager.clone(), state.counters.clone());
        }
        if let Some(resolver) = &self.route_tiers {
            {
                let resolver = Arc::clone(resolver);
                builder = builder.route_resolver(move |path| resolver(path));
            }
        }
        if let Some(handler) = &self.geo_handler {
            builder = builder.geo_handler(Arc::clone(handler));
        }
        if let Some(bus) = &self.events {
            builder = builder.events(Arc::clone(bus));
        }
        if let Some(observability) = &self.observability {
            builder = builder.observability(observability.clone());
        }
        if let Some(hook) = &self.on_block {
            builder = builder.on_block(Arc::clone(hook));
        }
        if let Some((store, prefix, fail_open)) = &self.distributed {
            builder = builder.distributed_store(Arc::clone(store), prefix, *fail_open);
        }
        if let Some(ban_store) = &self.distributed_ban_store {
            builder = builder.distributed_ban_store(Arc::clone(ban_store));
        }
        builder
            .build()
            .expect("guard configs are validated by their constructors")
    }

    #[cfg(test)]
    pub(crate) fn with_scan_fn(mut self, scan_fn: ScanFn) -> Self {
        self.scan_fn = scan_fn;
        self
    }

    pub(crate) const fn scan_fn(&self) -> ScanFn {
        self.scan_fn
    }
}

impl<S> Layer<S> for GuardLayer {
    type Service = GuardService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let mut layered = self.clone();
        if layered.stage.is_none() {
            layered.stage = Some(Arc::new(self.build_stage()));
        }
        GuardService::new(inner, layered)
    }
}

/// Manual [`core::fmt::Debug`]: the hook, resolver, and store seams are
/// trait objects without `Debug`, so the layer prints its configuration
/// shape and stops (`finish_non_exhaustive`).
impl core::fmt::Debug for GuardLayer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuardLayer")
            .field("config", &self.config)
            .field("body_cap", &self.body_cap)
            .field("ip_gate", &self.ip_gate)
            .field("rate_limiter", &self.rate_limiter)
            .field("ban_state", &self.ban_state)
            .field("custom_error_responses", &self.custom_error_responses)
            .field("passive_mode", &self.passive_mode)
            .field("detection_exclusions", &self.detection_exclusions)
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;

    fn ip(literal: &str) -> std::net::IpAddr {
        literal.parse().expect("ip")
    }

    #[test]
    fn reset_drops_every_rate_limit_window() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 60,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let probe = limiter.clone();
        let layer = GuardLayer::with_defaults().with_rate_limiting(limiter);
        let client = ip("203.0.113.9");
        // The first request passes, the second crosses the window.
        assert!(probe.check(client, None).allowed);
        assert!(!probe.check(client, None).allowed);

        // The reference `reset()`: the same identity starts afresh.
        layer.reset();
        assert!(probe.check(client, None).allowed);
    }

    #[test]
    fn refresh_cloud_ip_ranges_answers_false_without_a_scheduler() {
        let layer = GuardLayer::with_defaults();
        assert!(!layer.refresh_cloud_ip_ranges());
    }

    #[tokio::test]
    async fn refresh_cloud_ip_ranges_schedules_through_the_installed_seam() {
        let scheduler = Arc::new(
            guard_core_rs::geo_lifecycle::CloudRefreshScheduler::new()
                .with_providers(vec!["AWS"])
                .with_provider_endpoint("AWS", String::from("http://127.0.0.1:1/aws-ranges")),
        );
        let table = Arc::new(guard_core_engine::cloud_provider::CloudIpTable::default());
        let layer = GuardLayer::with_defaults()
            .with_cloud_refresh_scheduler(Arc::clone(&scheduler), Arc::clone(&table));
        // The schedule starts (the unroutable endpoint fails the fetch in
        // the background thread, the single-flight gate clears when the
        // body lands - the scheduler's own suite pins that).
        assert!(layer.refresh_cloud_ip_ranges());
        // The gate clears when the body lands (the failed fetch cleared
        // the provider, the reference's failed-refresh shape).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while scheduler.refresh_in_flight() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!scheduler.refresh_in_flight());
        // The service surface delegates to the layer (and stays a working
        // service: one dispatch answers through).
        let layer = GuardLayer::with_defaults();
        let service: GuardService<_> = Layer::layer(
            &layer,
            tower::service_fn(|_: http::Request<Full<Bytes>>| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::new())))
            }),
        );
        assert!(!service.refresh_cloud_ip_ranges());
        let response = tower::ServiceExt::oneshot(service, downcast_free_request())
            .await
            .expect("infallible");
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    /// A request body the maintenance tests' `Full<Bytes>` upstreams
    /// accept (the guard's request type is generic in `B`; the probe
    /// request just needs to typecheck against the upstream).
    fn downcast_free_request() -> http::Request<Full<Bytes>> {
        http::Request::builder()
            .uri("/health")
            .body(Full::new(Bytes::new()))
            .expect("static request")
    }

    #[tokio::test]
    async fn the_service_surface_delegates_reset_to_the_layer() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 60,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let probe = limiter.clone();
        let layer = GuardLayer::with_defaults().with_rate_limiting(limiter);
        let service: GuardService<_> = Layer::layer(
            &layer,
            tower::service_fn(|_: http::Request<Full<Bytes>>| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::new())))
            }),
        );
        let client = ip("203.0.113.9");
        assert!(probe.check(client, None).allowed);
        assert!(!probe.check(client, None).allowed);
        service.reset();
        assert!(probe.check(client, None).allowed);
        // The wrapped service still answers after the maintenance call.
        let response = tower::ServiceExt::oneshot(service, downcast_free_request())
            .await
            .expect("infallible");
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn agent_stats_answers_the_no_agent_shape() {
        let layer = GuardLayer::with_defaults();
        assert_eq!(
            layer.agent_stats(),
            AgentStats {
                enabled: false,
                degraded: false
            }
        );
        let layer = GuardLayer::with_defaults();
        let service: GuardService<_> = Layer::layer(
            &layer,
            tower::service_fn(|_: http::Request<Full<Bytes>>| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::new())))
            }),
        );
        assert_eq!(service.agent_stats(), layer.agent_stats());
        let response = tower::ServiceExt::oneshot(service, downcast_free_request())
            .await
            .expect("infallible");
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    #[test]
    fn guard_config_error_display_and_source_cover_every_variant() {
        let ip_gate: GuardConfigError = IpGateError {
            list: "whitelist",
            entry: String::from("nope"),
        }
        .into();
        assert!(ip_gate.to_string().contains("ip list"));
        assert!(std::error::Error::source(&ip_gate).is_some());

        let rate_limit: GuardConfigError = RateLimitConfigError {
            field: std::borrow::Cow::Borrowed("rate_limit"),
            reason: "must be at least 1",
        }
        .into();
        assert!(rate_limit.to_string().contains("rate limit"));
        assert!(std::error::Error::source(&rate_limit).is_some());

        let user_agent: GuardConfigError = UserAgentConfigError {
            entry: String::from("bad-bot"),
            reason: String::from("rejected"),
        }
        .into();
        assert!(user_agent.to_string().contains("blocked user agent"));
        assert!(std::error::Error::source(&user_agent).is_some());

        let ban: GuardConfigError = IpBanConfigError::NonPositive {
            field: "auto_ban_threshold",
        }
        .into();
        assert!(ban.to_string().contains("ip ban"));
        assert!(std::error::Error::source(&ban).is_some());
    }

    #[test]
    fn map_log_level_covers_every_reference_level() {
        assert!(matches!(
            map_log_level(LogLevel::Info),
            guard_core_rs::logging::LogLevel::Info
        ));
        assert!(matches!(
            map_log_level(LogLevel::Debug),
            guard_core_rs::logging::LogLevel::Debug
        ));
        assert!(matches!(
            map_log_level(LogLevel::Warning),
            guard_core_rs::logging::LogLevel::Warning
        ));
        assert!(matches!(
            map_log_level(LogLevel::Error),
            guard_core_rs::logging::LogLevel::Error
        ));
        assert!(matches!(
            map_log_level(LogLevel::Critical),
            guard_core_rs::logging::LogLevel::Critical
        ));
    }

    #[test]
    fn from_security_config_observability_carries_the_level_and_redaction() {
        let mut sensitive = std::collections::BTreeSet::new();
        sensitive.insert(String::from("x-custom-secret"));
        let config = SecurityConfig {
            log_suspicious_level: Some(LogLevel::Error),
            muted_check_logs: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("custom_request"));
                set
            },
            log_sensitive_headers: sensitive,
            ..SecurityConfig::default()
        };
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        let observability = layer.observability().expect("observability wired");
        assert!(matches!(
            observability.log_suspicious_level,
            Some(guard_core_rs::logging::LogLevel::Error)
        ));
        let muted = observability.muted_check_logs.as_ref().expect("muted set");
        assert!(muted.contains("custom_request"));
        assert!(observability.sensitive.headers.contains("x-custom-secret"));
    }

    #[test]
    fn from_security_config_exclude_paths_round_trip_through_the_accessor() {
        let config = SecurityConfig {
            exclude_paths: vec![String::from("/docs")],
            ..SecurityConfig::default()
        };
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        assert_eq!(layer.exclude_paths(), ["/docs"]);
    }

    #[test]
    fn from_security_config_user_agent_stage_is_wired() {
        let config = SecurityConfig {
            blocked_user_agents: vec![String::from("bad-bot")],
            ..SecurityConfig::default()
        };
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        assert!(layer.user_agent().is_some());
    }

    #[test]
    fn default_config_matches_corpus_knobs() {
        let config = default_config();
        assert_eq!(config.max_content_length, 10_000);
        assert_eq!(config.max_full_scan_bytes, 262_144);
        assert!(config.preserve_attack_patterns);
        assert!((config.semantic_threshold - 0.7).abs() < f64::EPSILON);
        assert!((config.threat_score_threshold - 1.0).abs() < f64::EPSILON);
        assert_eq!(config.binary_min_run_length, 16);
    }

    #[test]
    fn body_cap_defaults_to_full_scan_cap_and_is_overridable() {
        let layer = GuardLayer::new(default_config());
        assert_eq!(layer.body_cap(), 262_144);
        let layer = layer.with_body_cap(1024);
        assert_eq!(layer.body_cap(), 1024);
    }

    #[test]
    fn with_defaults_uses_the_corpus_config() {
        let layer = GuardLayer::with_defaults();
        assert_eq!(layer.body_cap(), 262_144);
    }

    #[test]
    fn ban_state_debug_renders_the_manager_and_config() {
        let entries: Vec<(String, ThreatBanEntry)> = Vec::new();
        let state = BanState {
            manager: IpBanManager::new(),
            counters: ViolationCounters::new(),
            config: IpBanConfig::new(true, 10, 3600, entries).expect("valid config"),
        };
        let rendered = format!("{state:?}");
        assert!(rendered.starts_with("BanState"), "{rendered}");
    }

    #[test]
    fn layer_debug_renders_the_configuration_shape() {
        let rendered = format!("{:?}", GuardLayer::new(default_config()));
        assert!(rendered.starts_with("GuardLayer"), "{rendered}");
        assert!(rendered.contains("body_cap: 262144"), "{rendered}");
    }

    #[test]
    fn rate_limit_stage_returns_the_built_stage_once_wrapped() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let layer = GuardLayer::new(default_config()).with_rate_limiting(limiter);

        // Not yet wrapped: the stage builds on demand.
        assert!(layer.rate_limit_stage().is_some());

        // Wrapped: the built stage is returned without a rebuild (the
        // `GuardLayer::layer`-cached clone's arm).
        let mut wrapped = layer.clone();
        wrapped.stage = Some(Arc::new(wrapped.build_stage()));
        assert!(wrapped.rate_limit_stage().is_some());
    }
}

#[cfg(test)]
mod layer_gap_twins {
    use super::*;
    use bytes::Bytes;
    use http::Request;
    use http::StatusCode;
    use http_body_util::Full;
    use std::convert::Infallible;

    #[tokio::test]
    async fn layer_builds_the_stage_lazily_on_first_wrap() {
        // layer() on a fresh GuardLayer takes the `stage.is_none()` arm:
        // the stage is built once and cached into the wrapped service.
        let layer = GuardLayer::new(default_config());
        let mut service = Layer::layer(
            &layer,
            tower::service_fn(|_request: Request<Full<Bytes>>| async {
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from_static(b"ok")))
                        .expect("static response"),
                )
            }),
        );
        let request = Request::builder()
            .uri("/hello")
            .body(Full::new(Bytes::from_static(b"ping")))
            .expect("request");
        let response = tower::Service::call(&mut service, request)
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::OK);

        // A threat through the same instantiation: the block path runs
        // inside this service's own monomorphization as well, so both arms
        // of the fused pipeline execute for the lazy-built stage.
        let threat = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(Full::new(Bytes::from_static(b"ping")))
            .expect("request");
        let response = tower::Service::call(&mut service, threat)
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
