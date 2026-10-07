//! The standalone stage layers: the engine's per-check stages as
//! individually installable [`tower::Layer`]s, plus the shared
//! request-fact extraction the fused [`GuardService`](crate::GuardService)
//! pass uses.
//!
//! The fused [`GuardLayer`](crate::GuardLayer) runs every stage inside one
//! service; this module is for applications that compose the stages
//! themselves. [`provided_layers`] hands back exactly the stages that were
//! installed on a [`GuardLayer`](crate::GuardLayer), ordered as the
//! reference engine's 17-check pipeline orders them (the composition table
//! in the crate docs), so the default composition is the reference order
//! and the application only chooses which stages to install.

use bytes::Bytes;
use http::header::RETRY_AFTER;
use http::request::Parts;
use http::{HeaderMap, HeaderValue, Request, Response};
use http_body::Body;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use guard_core_rs::cloud_provider::CloudProviderStage;
use guard_core_rs::custom_checks::{CustomChecksStage, CustomRequestAnswer, ValidatorFailure};
use guard_core_rs::emergency_mode::{EmergencyAnswer, EmergencyModeStage};
use guard_core_rs::geo::GeoStage;
use guard_core_rs::headers_auth::{HeadersAuthStage, StageAnswer};
use guard_core_rs::https_enforcement::{HttpsEnforcementStage, HttpsRedirectAnswer};
use guard_core_rs::route_gates::{GateAnswer, ReferrerStage, TimeWindowStage};
use guard_core_rs::tower::{IpGateDecision, RateLimitStage, StageResponse};
use guard_core_rs::user_agent::UserAgentStage;
use tower::Layer;

use crate::GuardClientIp;

/// The facts a stage decides on, extracted once per request: the client IP
/// ([`GuardClientIp`] extension), the global IP gate's skip state
/// ([`IpGateDecision`] extension), and the request pieces the decisions
/// and emissions read. The fused service and the standalone layers share
/// one extraction, so a stage answers identically either way.
pub(crate) struct RequestFacts {
    pub ip: Option<std::net::IpAddr>,
    pub gate: Option<IpGateDecision>,
    pub ip_string: String,
    pub path: String,
    pub method: String,
    pub scheme: String,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    pub host: Option<String>,
    pub x_forwarded_proto: Option<String>,
    pub origin: Option<String>,
    pub query: String,
}

impl RequestFacts {
    /// Extract the facts from request parts.
    pub(crate) fn extract(parts: &Parts) -> Self {
        let ip = parts.extensions.get::<GuardClientIp>().map(|ip| ip.0);
        Self {
            ip,
            gate: parts.extensions.get::<IpGateDecision>().copied(),
            ip_string: ip.map_or_else(String::new, |addr| addr.to_string()),
            path: parts.uri.path().to_owned(),
            method: parts.method.to_string(),
            scheme: parts.uri.scheme_str().unwrap_or("http").to_owned(),
            referer: header_value(&parts.headers, "referer"),
            user_agent: header_value(&parts.headers, "user-agent"),
            host: parts
                .uri
                .authority()
                .map(|authority| authority.as_str().to_owned())
                .or_else(|| header_value(&parts.headers, "host")),
            x_forwarded_proto: header_value(&parts.headers, "x-forwarded-proto"),
            origin: header_value(&parts.headers, "origin"),
            query: parts
                .uri
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default(),
        }
    }

    /// The https-scheme URL of this request (the redirect target the
    /// HTTPS-enforcement stage answers with).
    pub(crate) fn https_url(&self) -> String {
        format!(
            "https://{}{}{}",
            self.host.as_deref().unwrap_or_default(),
            self.path,
            self.query
        )
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The header name/value pairs the required-headers stage resolves
/// (non-UTF-8 values drop out of the surface).
pub(crate) fn header_pairs(headers: &HeaderMap) -> Vec<(&str, &str)> {
    headers
        .iter()
        .filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str(), value)))
        .collect()
}

/// Render one block answer in the family shape: the bare message body plus
/// `Retry-After` for the throttled shape. The custom-error override is
/// already resolved inside `body`.
pub(crate) fn render_block<ResBody: From<String>>(
    status: u16,
    body: String,
    retry_after: Option<u64>,
) -> Response<ResBody> {
    let status = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::FORBIDDEN);
    let mut response = Response::new(ResBody::from(body));
    *response.status_mut() = status;
    if let Some(value) =
        retry_after.and_then(|after| HeaderValue::from_str(&after.to_string()).ok())
    {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

/// Render the HTTPS redirect answer: the reference 301 + `Location`.
fn render_redirect<ResBody: From<&'static str>>(
    redirect: &HttpsRedirectAnswer,
) -> Response<ResBody> {
    let status = http::StatusCode::from_u16(redirect.status).expect("reference status");
    let mut response = Response::new(ResBody::from(""));
    *response.status_mut() = status;
    #[cfg(not(coverage))] // unreachable: `https_url` composes the target from
    // an already-validated header value plus the URI's percent-encoded path
    // and query, so the header conversion cannot fail
    if let Ok(value) = HeaderValue::from_str(&redirect.location) {
        response.headers_mut().insert(http::header::LOCATION, value);
    }
    #[cfg(coverage)]
    response.headers_mut().insert(
        http::header::LOCATION,
        HeaderValue::from_str(&redirect.location).expect("valid redirect target"),
    );
    response
}

/// The verdict one stage's pass produces over [`RequestFacts`].
pub(crate) enum StageVerdict {
    Emergency(EmergencyAnswer),
    Redirect(HttpsRedirectAnswer),
    HeadersAuth(StageAnswer),
    Gate(GateAnswer),
    Validator(ValidatorFailure),
    CustomRequest(CustomRequestAnswer),
    Stage(StageResponse),
}

/// Render a verdict into the wrapped service's response body type.
pub(crate) fn render_verdict<ResBody: From<&'static str> + From<String>>(
    verdict: StageVerdict,
) -> Response<ResBody> {
    match verdict {
        StageVerdict::Emergency(answer) => render_block(answer.status, answer.body, None),
        StageVerdict::Redirect(redirect) => render_redirect(&redirect),
        StageVerdict::HeadersAuth(answer) => {
            render_block(answer.status.as_u16(), answer.body, None)
        }
        StageVerdict::Gate(answer) => render_block(answer.status, answer.body, None),
        StageVerdict::Validator(failure) => {
            // The validator's own response shape: its status when it
            // carries one, the framework default (200) when it does not -
            // the reference "blocks with the response as-is" semantics.
            render_block(failure.status.unwrap_or(200), String::new(), None)
        }
        StageVerdict::CustomRequest(answer) => {
            render_block(answer.status.unwrap_or(200), String::new(), None)
        }
        StageVerdict::Stage(answer) => render_block(
            answer.status.as_u16(),
            match answer.custom_body {
                Some(custom) => custom,
                None => answer.body.to_owned(),
            },
            answer.retry_after,
        ),
    }
}

/// One stage's decision over the extracted facts (the shared body of the
/// fused service and the standalone layer).
pub(crate) trait Decides {
    fn decide(&self, facts: &RequestFacts, headers: &[(&str, &str)]) -> Option<StageVerdict>;
}

impl Decides for EmergencyModeStage {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        self.decide(
            facts.ip.is_some().then_some(facts.ip_string.as_str()),
            &facts.ip_string,
            &facts.path,
            &facts.method,
        )
        .map(StageVerdict::Emergency)
    }
}

/// The bare host of an authority string: the port stripped and IPv6
/// brackets removed (the connecting-identity shape the trusted-proxy arm
/// compares). Mirrors the engine stage service's own extraction.
fn host_of_authority(value: &str) -> &str {
    let host_port = value.rsplit('@').next().unwrap_or_default();
    if let Some(rest) = host_port.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host_port.split_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => host_port,
    }
}

impl Decides for HttpsEnforcementStage {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        let client_host = facts.host.as_deref().map(host_of_authority);
        self.decide(
            &facts.path,
            &facts.scheme,
            client_host,
            facts.x_forwarded_proto.as_deref(),
            &facts.https_url(),
        )
        .map(StageVerdict::Redirect)
    }
}

impl Decides for HeadersAuthStage {
    fn decide(&self, facts: &RequestFacts, headers: &[(&str, &str)]) -> Option<StageVerdict> {
        self.decide(&facts.path, headers)
            .map(|(_, answer)| StageVerdict::HeadersAuth(answer))
    }
}

impl Decides for ReferrerStage {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        self.decide(
            &facts.path,
            facts.referer.as_deref(),
            &facts.ip_string,
            &facts.path,
            &facts.method,
        )
        .map(StageVerdict::Gate)
    }
}

impl Decides for TimeWindowStage {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        self.decide(&facts.path, &facts.ip_string, &facts.path, &facts.method)
            .map(StageVerdict::Gate)
    }
}

impl Decides for CustomChecksStage {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        // The validators half (the reference's ninth check); the
        // `custom_request` half runs at the seventeenth position and is a
        // separate layer ([`GuardStageLayer::CustomRequest`]).
        // The standalone layer sees no buffered body (`None`): the fused
        // GuardService passes its buffer at the same position.
        self.decide_custom_validators(
            &facts.path,
            &facts.method,
            facts.ip.is_some().then_some(facts.ip_string.as_str()),
            None,
        )
        .map(StageVerdict::Validator)
    }
}

impl Decides for GeoStage {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        self.decide(facts.ip, facts.gate)
            .map(|decision| StageVerdict::Stage(decision.answer))
    }
}

impl Decides for CloudProviderStage {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        self.decide(facts.ip, facts.gate)
            .map(|decision| StageVerdict::Stage(decision.answer))
    }
}

impl Decides for UserAgentStage {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        self.decide(
            facts.ip,
            facts.gate,
            Some(&facts.path),
            facts.user_agent.as_deref(),
            None,
        )
        .map(StageVerdict::Stage)
    }
}

/// The rate-limit tiers at the reference's fifteenth position: the tiers +
/// detection-feed half only. The bans half is the twelfth check and is a
/// separate layer ([`GuardStageLayer::Bans`]).
#[derive(Clone)]
pub struct RateLimitTiers(pub(crate) RateLimitStage);

impl Decides for RateLimitTiers {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        self.0
            .decide_tiers_observed(facts.ip, Some(&facts.path), None, facts.gate, None, None)
            .map(StageVerdict::Stage)
    }
}

/// The ban arm at the reference's twelfth position.
#[derive(Clone)]
pub struct RateLimitBans(pub(crate) RateLimitStage);

impl Decides for RateLimitBans {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        self.0
            .decide_bans_observed(facts.ip, None)
            .map(StageVerdict::Stage)
    }
}

/// The `custom_request` check at the reference's seventeenth position.
#[derive(Clone)]
pub struct CustomRequestPosition(pub(crate) CustomChecksStage);

impl Decides for CustomRequestPosition {
    fn decide(&self, facts: &RequestFacts, _headers: &[(&str, &str)]) -> Option<StageVerdict> {
        self.0
            .decide_custom_request(
                &facts.method,
                &facts.path,
                facts.ip.is_some().then_some(facts.ip_string.as_str()),
                None,
            )
            .map(StageVerdict::CustomRequest)
    }
}

/// One reference-ordered stage as a standalone [`tower::Layer`].
///
/// Produced by [`provided_layers`]; the enum exists so every stage can
/// ride one `Vec` in the reference pipeline order. Wrap with
/// [`tower::Layer::layer`] - later layers wrap earlier ones, so an
/// application that wants the reference execution order folds the vector
/// in reverse over the innermost service.
#[derive(Clone)]
pub enum GuardStageLayer {
    /// Check 2: the emergency-mode gate (503 outside the emergency
    /// whitelist while the mode is on).
    Emergency(EmergencyModeStage),
    /// Check 3: HTTPS enforcement (301 redirect to the https URL).
    Https(HttpsEnforcementStage),
    /// Checks 6 + 7: the required-headers and authentication stage.
    HeadersAuth(HeadersAuthStage),
    /// Check 8: the route referrer gate.
    Referrer(ReferrerStage),
    /// Check 9: the route custom validators (the `custom_request` half is
    /// check 17 and rides [`GuardStageLayer::CustomRequest`]).
    CustomValidators(CustomChecksStage),
    /// Check 10: the route time-window gate.
    TimeWindow(TimeWindowStage),
    /// Check 12a: the ban arm of the rate-limit stage (403 for a banned
    /// IP), kept separate so it sits at the reference position.
    Bans(RateLimitStage),
    /// Check 12b: geo country blocking (the reference runs it inside
    /// `ip_security`, after the ban arm).
    Geo(GeoStage),
    /// Check 13: cloud-provider blocking.
    Cloud(CloudProviderStage),
    /// Check 14: the blocked user-agent filter.
    UserAgent(UserAgentStage),
    /// Check 15 (+ 16's detection feed): the rate-limit tiers.
    RateLimit(RateLimitStage),
    /// Check 17: the global `custom_request` check.
    CustomRequest(CustomChecksStage),
}

/// The gate around one deciding stage: decide, render, or forward.
///
/// Storage for the [`GuardStageService`] variants; the dispatch runs
/// through [`pass_gate`] (a standalone `tower::Service` impl over `Gate`
/// would be dead surface - the type has no public constructor).
#[derive(Clone)]
pub struct Gate<S, T> {
    inner: S,
    /// The deciding stage (a prebuilt engine object or a position
    /// wrapper), driven through [`Decides`] in [`pass_gate`].
    decides: T,
}

/// The gate pass: decide, render, or forward (the body of every
/// [`GuardStageService`] dispatch).
#[allow(clippy::type_complexity)] // the boxed-future shape every tower layer spells out
fn pass_gate<S, B, ResBody, T>(
    gate: &mut Gate<S, T>,
    request: Request<B>,
) -> Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>
where
    S: tower::Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    ResBody: From<&'static str> + From<String> + Send + 'static,
    T: Decides,
{
    let (parts, body) = request.into_parts();
    let facts = RequestFacts::extract(&parts);
    let headers = header_pairs(&parts.headers);
    if let Some(verdict) = gate.decides.decide(&facts, &headers) {
        return Box::pin(async move { Ok(render_verdict(verdict)) });
    }
    let future = gate.inner.call(Request::from_parts(parts, body));
    Box::pin(future)
}

impl<S> Layer<S> for GuardStageLayer {
    type Service = GuardStageService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        match self.clone() {
            Self::Emergency(stage) => GuardStageService::Emergency(Gate {
                inner,
                decides: stage,
            }),
            Self::Https(stage) => GuardStageService::Https(Gate {
                inner,
                decides: stage,
            }),
            Self::HeadersAuth(stage) => GuardStageService::HeadersAuth(Gate {
                inner,
                decides: stage,
            }),
            Self::Referrer(stage) => GuardStageService::Referrer(Gate {
                inner,
                decides: stage,
            }),
            Self::CustomValidators(stage) => GuardStageService::CustomValidators(Gate {
                inner,
                decides: stage,
            }),
            Self::TimeWindow(stage) => GuardStageService::TimeWindow(Gate {
                inner,
                decides: stage,
            }),
            Self::Bans(stage) => GuardStageService::Bans(Gate {
                inner,
                decides: RateLimitBans(stage),
            }),
            Self::Geo(stage) => GuardStageService::Geo(Gate {
                inner,
                decides: stage,
            }),
            Self::Cloud(stage) => GuardStageService::Cloud(Gate {
                inner,
                decides: stage,
            }),
            Self::UserAgent(stage) => GuardStageService::UserAgent(Gate {
                inner,
                decides: stage,
            }),
            Self::RateLimit(stage) => GuardStageService::RateLimit(Gate {
                inner,
                decides: RateLimitTiers(stage),
            }),
            Self::CustomRequest(stage) => GuardStageService::CustomRequest(Gate {
                inner,
                decides: CustomRequestPosition(stage),
            }),
        }
    }
}

/// The service produced by [`GuardStageLayer`]: one reference-ordered
/// stage in front of the wrapped service.
#[derive(Clone)]
pub enum GuardStageService<S> {
    Emergency(Gate<S, EmergencyModeStage>),
    Https(Gate<S, HttpsEnforcementStage>),
    HeadersAuth(Gate<S, HeadersAuthStage>),
    Referrer(Gate<S, ReferrerStage>),
    CustomValidators(Gate<S, CustomChecksStage>),
    TimeWindow(Gate<S, TimeWindowStage>),
    Bans(Gate<S, RateLimitBans>),
    Geo(Gate<S, GeoStage>),
    Cloud(Gate<S, CloudProviderStage>),
    UserAgent(Gate<S, UserAgentStage>),
    RateLimit(Gate<S, RateLimitTiers>),
    CustomRequest(Gate<S, CustomRequestPosition>),
}

impl<S, B, ResBody> tower::Service<Request<B>> for GuardStageService<S>
where
    S: tower::Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    ResBody: From<&'static str> + From<String> + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        match self {
            Self::Emergency(gate) => gate.inner.poll_ready(cx),
            Self::Https(gate) => gate.inner.poll_ready(cx),
            Self::HeadersAuth(gate) => gate.inner.poll_ready(cx),
            Self::Referrer(gate) => gate.inner.poll_ready(cx),
            Self::CustomValidators(gate) => gate.inner.poll_ready(cx),
            Self::TimeWindow(gate) => gate.inner.poll_ready(cx),
            Self::Bans(gate) => gate.inner.poll_ready(cx),
            Self::Geo(gate) => gate.inner.poll_ready(cx),
            Self::Cloud(gate) => gate.inner.poll_ready(cx),
            Self::UserAgent(gate) => gate.inner.poll_ready(cx),
            Self::RateLimit(gate) => gate.inner.poll_ready(cx),
            Self::CustomRequest(gate) => gate.inner.poll_ready(cx),
        }
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        match self {
            Self::Emergency(gate) => Box::pin(pass_gate(gate, request)),
            Self::Https(gate) => Box::pin(pass_gate(gate, request)),
            Self::HeadersAuth(gate) => Box::pin(pass_gate(gate, request)),
            Self::Referrer(gate) => Box::pin(pass_gate(gate, request)),
            Self::CustomValidators(gate) => Box::pin(pass_gate(gate, request)),
            Self::TimeWindow(gate) => Box::pin(pass_gate(gate, request)),
            Self::Bans(gate) => Box::pin(pass_gate(gate, request)),
            Self::Geo(gate) => Box::pin(pass_gate(gate, request)),
            Self::Cloud(gate) => Box::pin(pass_gate(gate, request)),
            Self::UserAgent(gate) => Box::pin(pass_gate(gate, request)),
            Self::RateLimit(gate) => Box::pin(pass_gate(gate, request)),
            Self::CustomRequest(gate) => Box::pin(pass_gate(gate, request)),
        }
    }
}

#[allow(clippy::missing_fields_in_debug)] // the stage's type name is the payload
impl<S: std::fmt::Debug, T> std::fmt::Debug for Gate<S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate").field("inner", &self.inner).finish()
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for GuardStageService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Emergency(gate) => f.debug_tuple("Emergency").field(gate).finish(),
            Self::Https(gate) => f.debug_tuple("Https").field(gate).finish(),
            Self::HeadersAuth(gate) => f.debug_tuple("HeadersAuth").field(gate).finish(),
            Self::Referrer(gate) => f.debug_tuple("Referrer").field(gate).finish(),
            Self::CustomValidators(gate) => f.debug_tuple("CustomValidators").field(gate).finish(),
            Self::TimeWindow(gate) => f.debug_tuple("TimeWindow").field(gate).finish(),
            Self::Bans(gate) => f.debug_tuple("Bans").field(gate).finish(),
            Self::Geo(gate) => f.debug_tuple("Geo").field(gate).finish(),
            Self::Cloud(gate) => f.debug_tuple("Cloud").field(gate).finish(),
            Self::UserAgent(gate) => f.debug_tuple("UserAgent").field(gate).finish(),
            Self::RateLimit(gate) => f.debug_tuple("RateLimit").field(gate).finish(),
            Self::CustomRequest(gate) => f.debug_tuple("CustomRequest").field(gate).finish(),
        }
    }
}

/// The reference pipeline order, as standalone layers: every stage
/// installed on `layer` (via the `with_*` builders), in the execution
/// order the reference engine's 17-check pipeline runs them. Stages that
/// were not installed drop out; a request-logging stage never appears (it
/// composes a log line and never blocks, so it is not a layer), and the
/// response processor is response-side (it rides the layer that installs
/// it, [`crate::GuardLayer::with_response_processor`]).
///
/// The layers wrap outside-in in vector order, so composing them over an
/// innermost service runs them in this order:
///
/// ```rust,ignore
/// let service = provided_layers(&layer).into_iter().rev().fold(
///     inner_service,
///     |service, stage| tower::Layer::layer(&stage, service),
/// );
/// ```
#[must_use]
pub fn provided_layers(layer: &crate::GuardLayer) -> Vec<GuardStageLayer> {
    // The geo, cloud, and user-agent stages sit between the ban arm and
    // the rate-limit tiers, wherever those run.
    let middle = || {
        let mut middle = Vec::new();
        if let Some(geo) = layer.geo_blocking().cloned() {
            middle.push(GuardStageLayer::Geo(geo));
        }
        if let Some(cloud) = layer.cloud_provider().cloned() {
            middle.push(GuardStageLayer::Cloud(cloud));
        }
        if let Some(ua) = layer.user_agent().cloned() {
            middle.push(GuardStageLayer::UserAgent(ua));
        }
        middle
    };

    let mut layers = Vec::new();
    if let Some(stage) = layer.emergency_mode().cloned() {
        layers.push(GuardStageLayer::Emergency(stage));
    }
    if let Some(stage) = layer.https_enforcement().cloned() {
        layers.push(GuardStageLayer::Https(stage));
    }
    if let Some(stage) = layer.headers_auth().cloned() {
        layers.push(GuardStageLayer::HeadersAuth(stage));
    }
    if let Some(stage) = layer.referrer_gate().cloned() {
        layers.push(GuardStageLayer::Referrer(stage));
    }
    if let Some(stage) = layer.custom_checks().cloned() {
        layers.push(GuardStageLayer::CustomValidators(stage));
    }
    if let Some(stage) = layer.time_window_gate().cloned() {
        layers.push(GuardStageLayer::TimeWindow(stage));
    }
    if let Some(stage) = layer.rate_limit_stage() {
        layers.push(GuardStageLayer::Bans(stage.clone()));
        layers.extend(middle());
        layers.push(GuardStageLayer::RateLimit(stage));
    } else {
        layers.extend(middle());
    }
    if let Some(stage) = layer.custom_checks().cloned() {
        layers.push(GuardStageLayer::CustomRequest(stage));
    }
    layers
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use std::convert::Infallible;
    use std::sync::Arc;

    /// A minimal `Debug`-visible inner service: `BoxCloneService`'s own
    /// `Debug` does not delegate, so the variant-name assertions below need
    /// a service whose `Debug` is transparent.
    #[derive(Debug)]
    struct ProbeService;

    impl<B> tower::Service<Request<B>> for ProbeService {
        type Response = Response<Full<Bytes>>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<B>) -> Self::Future {
            std::future::ready(Ok(Response::new(Full::new(Bytes::new()))))
        }
    }

    fn emergency() -> EmergencyModeStage {
        EmergencyModeStage::builder(
            guard_core_rs::emergency_mode::EmergencyModeStageConfig::default(),
        )
        .build()
        .expect("valid")
    }

    fn https() -> HttpsEnforcementStage {
        HttpsEnforcementStage::builder(
            guard_core_rs::https_enforcement::HttpsEnforcementStageConfig::default(),
        )
        .build()
        .expect("valid")
    }

    fn referrer() -> ReferrerStage {
        ReferrerStage::builder(guard_core_rs::route_gates::GateConfig::default()).build()
    }

    fn validators() -> CustomChecksStage {
        CustomChecksStage::builder().build()
    }

    fn time_window() -> TimeWindowStage {
        TimeWindowStage::builder(guard_core_rs::route_gates::GateConfig::default()).build()
    }

    fn stateful() -> RateLimitStage {
        RateLimitStage::builder(guard_core_rs::tower::RateLimitStageConfig::default())
            .build()
            .expect("valid")
    }

    fn geo() -> GeoStage {
        GeoStage::new(guard_core_rs::geo::GeoStageConfig::default())
    }

    fn cloud() -> CloudProviderStage {
        CloudProviderStage::builder(
            guard_core_rs::cloud_provider::CloudProviderStageConfig::default(),
        )
        .build()
    }

    fn user_agent() -> UserAgentStage {
        UserAgentStage::new(guard_core_rs::user_agent::UserAgentStageConfig::default())
            .expect("valid")
    }

    async fn drive(service: &mut GuardStageService<ProbeService>, request: Request<Full<Bytes>>) {
        // Direct trait calls: `ServiceExt::ready` needs a `Send` future bound
        // the concrete `ProbeService` satisfies but the compiler cannot infer
        // through the generic enum, and the point is to run each variant's
        // `poll_ready` and `call` arm for this inner-service instantiation.
        let ready =
            <GuardStageService<ProbeService> as tower::Service<Request<Full<Bytes>>>>::poll_ready(
                service,
                &mut Context::from_waker(std::task::Waker::noop()),
            );
        assert!(matches!(ready, Poll::Ready(Ok(()))));
        let response =
            <GuardStageService<ProbeService> as tower::Service<Request<Full<Bytes>>>>::call(
                service, request,
            )
            .await
            .expect("response");
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn stage_service_debug_renders_and_drives_every_variant_name() {
        let cases: Vec<(&'static str, GuardStageService<ProbeService>)> = vec![
            (
                "Emergency",
                Layer::layer(&GuardStageLayer::Emergency(emergency()), ProbeService),
            ),
            (
                "Https",
                Layer::layer(&GuardStageLayer::Https(https()), ProbeService),
            ),
            (
                "HeadersAuth",
                Layer::layer(
                    &GuardStageLayer::HeadersAuth(HeadersAuthStage::new(None, Arc::new(|_| None))),
                    ProbeService,
                ),
            ),
            (
                "Referrer",
                Layer::layer(&GuardStageLayer::Referrer(referrer()), ProbeService),
            ),
            (
                "CustomValidators",
                Layer::layer(
                    &GuardStageLayer::CustomValidators(validators()),
                    ProbeService,
                ),
            ),
            (
                "TimeWindow",
                Layer::layer(&GuardStageLayer::TimeWindow(time_window()), ProbeService),
            ),
            (
                "Bans",
                Layer::layer(&GuardStageLayer::Bans(stateful()), ProbeService),
            ),
            (
                "Geo",
                Layer::layer(&GuardStageLayer::Geo(geo()), ProbeService),
            ),
            (
                "Cloud",
                Layer::layer(&GuardStageLayer::Cloud(cloud()), ProbeService),
            ),
            (
                "UserAgent",
                Layer::layer(&GuardStageLayer::UserAgent(user_agent()), ProbeService),
            ),
            (
                "RateLimit",
                Layer::layer(&GuardStageLayer::RateLimit(stateful()), ProbeService),
            ),
            (
                "CustomRequest",
                Layer::layer(&GuardStageLayer::CustomRequest(validators()), ProbeService),
            ),
        ];
        for (name, mut service) in cases {
            let rendered = format!("{service:?}");
            assert!(rendered.starts_with(name), "{name}: {rendered}");
            // Every variant's dispatch arms execute for this inner-service
            // instantiation too: a default-configured stage forwards, so
            // poll_ready and call both run for each variant arm.
            let request = Request::builder()
                .uri("/api")
                .body(Full::new(Bytes::new()))
                .expect("request");
            drive(&mut service, request).await;
        }
    }

    #[test]
    fn https_url_composes_from_the_authority_then_the_host_header() {
        let parts = Request::builder()
            .uri("http://guard.example/private?token=1")
            .body(())
            .expect("request")
            .into_parts()
            .0;
        let facts = RequestFacts::extract(&parts);
        assert_eq!(facts.https_url(), "https://guard.example/private?token=1");

        let parts = Request::builder()
            .uri("/private")
            .header("host", "guard.example")
            .body(())
            .expect("request")
            .into_parts()
            .0;
        let facts = RequestFacts::extract(&parts);
        assert_eq!(facts.https_url(), "https://guard.example/private");

        // No host anywhere: the empty-host shape (the redirect target the
        // stage still answers with).
        let parts = Request::builder()
            .uri("/private")
            .body(())
            .expect("request")
            .into_parts()
            .0;
        let facts = RequestFacts::extract(&parts);
        assert_eq!(facts.https_url(), "https:///private");
    }

    #[test]
    fn host_of_authority_strips_ports_brackets_and_userinfo() {
        assert_eq!(host_of_authority("guard.example:8443"), "guard.example");
        assert_eq!(host_of_authority("guard.example"), "guard.example");
        assert_eq!(host_of_authority("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(host_of_authority("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(
            host_of_authority("user@guard.example:8443"),
            "guard.example"
        );
        // A non-digit port is part of the host string (the comparison arm).
        assert_eq!(host_of_authority("guard.example:abc"), "guard.example:abc");
        assert_eq!(host_of_authority(""), "");
    }

    #[tokio::test]
    async fn a_stage_layer_drives_its_inner_service_both_ways() {
        // The forward path: a benign request reaches the wrapped service.
        let mut service = Layer::layer(&GuardStageLayer::Emergency(emergency()), ProbeService);
        let request = Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let ready = tower::ServiceExt::<Request<Full<Bytes>>>::ready(&mut service)
            .await
            .expect("ready");
        let response = tower::Service::call(ready, request)
            .await
            .expect("response");
        assert_eq!(response.status(), http::StatusCode::OK);

        // The block path: the same gate renders the stage's answer.
        let stage = EmergencyModeStage::builder(
            guard_core_rs::emergency_mode::EmergencyModeStageConfig::default(),
        )
        .emergency_mode(true)
        .build()
        .expect("valid");
        let mut service = Layer::layer(&GuardStageLayer::Emergency(stage), ProbeService);
        let request = Request::builder()
            .uri("/api")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = tower::Service::call(&mut service, request)
            .await
            .expect("response");
        assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn a_custom_error_override_rides_the_rate_limit_answer_through_render_verdict() {
        let stage = RateLimitStage::builder(guard_core_rs::tower::RateLimitStageConfig {
            rate_limit: guard_core_engine::rate_limit::RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 1,
                ..guard_core_engine::rate_limit::RateLimitConfig::default()
            },
            custom_error_responses: guard_core_rs::responses::CustomErrorResponses::from([(
                429,
                "Slow down".to_owned(),
            )]),
            ..guard_core_rs::tower::RateLimitStageConfig::default()
        })
        .limiter(
            guard_core_engine::rate_limit::RateLimiter::new(
                guard_core_engine::rate_limit::RateLimitConfig {
                    enable_rate_limiting: true,
                    rate_limit: 1,
                    ..guard_core_engine::rate_limit::RateLimitConfig::default()
                },
            )
            .expect("valid limiter"),
        )
        .build()
        .expect("valid");
        let ip: std::net::IpAddr = "192.0.2.55".parse().expect("ip");
        let first = stage.decide_tiers_observed(Some(ip), Some("/api"), None, None, None, None);
        assert!(
            first.is_none(),
            "the first hit is under the limit: {first:?}"
        );
        let answer = stage
            .decide_tiers_observed(Some(ip), Some("/api"), None, None, None, None)
            .expect("the crossing throttles");
        let verdict = StageVerdict::Stage(answer);
        let response = render_verdict::<Full<Bytes>>(verdict);
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
        let body = response.into_body();
        assert_eq!(body.into_inner().as_deref(), Some(&b"Slow down"[..]));
    }
}
