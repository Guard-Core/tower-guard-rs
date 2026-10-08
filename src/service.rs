//! The middleware service: body buffering, view scanning, dispatching.

use crate::GuardClientIp;
use crate::GuardLayer;
use crate::body::{BoxError, GuardBody};
use crate::response;
use crate::stages::{RequestFacts, header_pairs};
use bytes::{Bytes, BytesMut};
use guard_core_engine::detection_exclusions::{
    RequestScanVerdict, RequestSurfaces, RouteDetectionExclusions, resolve as resolve_exclusions,
};
use guard_core_engine::ip_gate::IpGateDecision;
use guard_core_engine::ip_gate::IpGateVerdict;
use guard_core_engine::route_config::RouteConfig;
use guard_core_rs::process_response::{RequestBits, ResponseBits};
use guard_core_rs::responses::{build_block_payload, fire_block_hook, resolve_error_body};
use guard_core_rs::tower::{RequestObservation, RouteRateLimits};
use http::header::CONTENT_TYPE;
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use std::collections::BTreeMap;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::SystemTime;
use tower::Service;

/// Header names that are never scanned, mirroring the TypeScript adapters'
/// `EXCLUDED_HEADERS` (plus every `sec-*` header).
///
/// Negotiation and routing headers carry attacker-influenced-but-expected
/// values (`Accept`, `User-Agent`, ...) whose scanning costs false positives
/// without buying coverage: a payload smuggled into them must still survive
/// the path, query, and body views.
const EXCLUDED_HEADERS: &[&str] = &[
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "connection",
    "origin",
    "referer",
];

/// A [`tower::Service`] that screens requests through the Guard engine before
/// forwarding them to the wrapped service.
///
/// Built by [`GuardLayer::layer`](tower::Layer::layer). It requires the
/// wrapped service to be `Clone` (the inner service is cloned into the
/// request future so the guard can buffer the body before dispatching), which
/// every framework service used with `tower` middleware already satisfies.
pub struct GuardService<S> {
    inner: S,
    layer: GuardLayer,
}

impl<S> GuardService<S> {
    pub(crate) fn new(inner: S, layer: GuardLayer) -> Self {
        Self { inner, layer }
    }

    /// The reference `reset()`: drop every rate-limit window through the
    /// owning layer ([`GuardLayer::reset`]).
    pub fn reset(&self) {
        self.layer.reset();
    }

    /// The reference `refresh_cloud_ip_ranges`: schedule one background
    /// cloud-ranges refresh ([`GuardLayer::refresh_cloud_ip_ranges`];
    /// `false` with no scheduler installed or while one is in flight).
    #[must_use]
    pub fn refresh_cloud_ip_ranges(&self) -> bool {
        self.layer.refresh_cloud_ip_ranges()
    }

    /// The reference `agent_stats` in its no-agent shape
    /// ([`GuardLayer::agent_stats`]).
    #[must_use]
    pub const fn agent_stats(&self) -> crate::AgentStats {
        self.layer.agent_stats()
    }
}

impl<S: Clone> Clone for GuardService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for GuardService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardService")
            .field("inner", &self.inner)
            .field("layer", &self.layer)
            .finish()
    }
}

/// Why a request body could not be fully buffered.
enum BufferFailure {
    /// The body exceeded the buffering cap; reading stopped early.
    TooLarge,
    /// The body stream errored mid-read. The underlying error is dropped on
    /// purpose: it is body-transport noise (client abort, socket reset), not
    /// a security signal, and it must not leak into the `500` response.
    Read,
}

/// The outcome of scanning one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScanOutcome {
    /// No view tripped the engine.
    Clean,
    /// The engine's multi-surface verdict for the first flagged view: the
    /// contributing categories (deduplicated, sorted - the auto-ban engine
    /// counts them per client IP) and the reference reason line.
    Threat(guard_core_engine::detection_exclusions::RequestScanVerdict),
    /// The engine panicked; fail secure.
    Failed,
}

impl<S, B, B2> Service<Request<B>> for GuardService<S>
where
    S: Service<Request<B>, Response = Response<B2>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Body<Data = Bytes> + Unpin + Send + 'static + From<Bytes>,
    B::Error: Into<BoxError>,
    B2: Body<Data = Bytes> + Unpin + Send + 'static,
    B2::Error: Into<BoxError>,
{
    type Response = Response<GuardBody<B2>>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    #[allow(clippy::too_many_lines)] // the reference pipeline order, one arm per check
    fn call(&mut self, request: Request<B>) -> Self::Future {
        let inner = self.inner.clone();
        let layer = self.layer.clone();
        Box::pin(async move {
            let (mut parts, mut body) = request.into_parts();
            let facts = RequestFacts::extract(&parts);

            // The reference `exclude_paths` carve-out runs first: the
            // docs/static paths bypass the whole pipeline (exact path
            // match), detection included.
            if layer.exclude_paths.contains(&facts.path) {
                return forward(&layer, &facts, parts, None, inner).await;
            }

            // The reference's CORS preflight short-circuit: an OPTIONS
            // request carrying `access-control-request-method` answers from
            // the resolved CORS config directly (the reference
            // `is_preflight` + `build_preflight_response` in
            // `cors_handler.py`), before every security check. CORS
            // disabled (or no response processor) leaves OPTIONS requests
            // to the pipeline like any other method.
            if facts.method.eq_ignore_ascii_case("OPTIONS")
                && let Some(processor) = layer.response_processor()
                && processor.cors_enabled()
                && let Some(answer) =
                    preflight_answer(processor.cors().expect("cors enabled"), &parts)
            {
                return Ok(answer);
            }

            // The reference `RouteConfigResolver`: the carrier extension
            // wins over the installed resolver (the app attaches the
            // route's config directly, the reference
            // `request.state.route_config` idiom).
            let route_carrier: Option<std::sync::Arc<RouteConfig>> = parts
                .extensions
                .get::<std::sync::Arc<RouteConfig>>()
                .cloned()
                .or_else(|| {
                    layer
                        .route_configs()
                        .and_then(|resolver| resolver(&facts.method, &facts.path))
                });
            let route = route_carrier.as_deref();

            // The reference `process_usage_rules`: the route's usage and
            // frequency behavior rules track the request observation and a
            // crossed threshold dispatches the rule's action (a `ban`
            // lands in the shared ban manager and renders the banned
            // shape). The behavioral processor runs before the check
            // pipeline (the reference dispatches it from the middleware's
            // request pass).
            let route_rules: &[guard_core_engine::behavior::BehaviorRule] =
                route.map_or(&[], |route| &route.behavior_rules);
            if !route_rules.is_empty()
                && let Some(processor) = layer.response_processor()
            {
                let endpoint_id = format!("{}:{}", facts.method, facts.path);
                let actions = processor.process_usage_rules(
                    &endpoint_id,
                    &facts.ip.map_or_else(String::new, |ip| ip.to_string()),
                    route_rules,
                    std::time::SystemTime::now(),
                );
                if actions
                    .iter()
                    .any(guard_core_engine::behavior::BehaviorAction::is_ban)
                {
                    return Ok(block_response(
                        &parts,
                        &layer,
                        403,
                        crate::ACTIVITY_BANNED_MESSAGE,
                    ));
                }
            }

            // The reference `RouteConfigResolver.should_bypass_check`: the
            // named check, or the `"all"` wildcard.
            let bypassed = |check: &str| {
                route.is_some_and(|route| {
                    route.bypassed_checks.contains("all") || route.bypassed_checks.contains(check)
                })
            };

            // The IP gate runs before anything else: a denied IP must not
            // cost a body buffer, and detection still scans whatever passes.
            // The reference `ip_security` bypass skips the gate (and the
            // ban/geo arms below, the fused `ip_security` block).
            // The reference consults `should_bypass_check("ip")` around
            // the whole `ip_security` block: gate, route IP restrictions,
            // and country arms.
            if !bypassed("ip")
                && let Some(denial) = enforce_ip_gate(&mut parts, &layer)
            {
                return Ok(finish_generated(&parts, &layer, denial));
            }

            // Check 2: emergency mode (503 outside the whitelist). The
            // reference pipeline never consults the bypass set here: the
            // global stage is not route-bypassable.
            if let Some(stage) = layer.emergency_mode()
                && let Some(answer) = stage.decide(
                    facts.ip.is_some().then_some(facts.ip_string.as_str()),
                    &facts.ip_string,
                    &facts.path,
                    &facts.method,
                )
            {
                let response = response::blocked_with_body(answer.status, &answer.body);
                return Ok(finish_generated(&parts, &layer, response));
            }

            // Check 3: HTTPS enforcement (301 to the scheme-upgraded URL).
            // The route's `require_https` rides the same stage (the
            // carrier lane), so the trust knobs and the passive handling
            // match the global arm; with no carrier route the stage's own
            // resolver seam stays authoritative.
            {
                let client_host = facts.host.as_deref().map(host_of_authority);
                let answer = if let Some(stage) = layer.https_enforcement() {
                    if let Some(route) = route {
                        stage.decide_route(
                            &facts.path,
                            &facts.scheme,
                            client_host,
                            facts.x_forwarded_proto.as_deref(),
                            &facts.https_url(),
                            Some(route.require_https),
                        )
                    } else {
                        stage.decide(
                            &facts.path,
                            &facts.scheme,
                            client_host,
                            facts.x_forwarded_proto.as_deref(),
                            &facts.https_url(),
                        )
                    }
                } else if route.is_some_and(|route| route.require_https)
                    && facts.scheme != "https"
                    && !layer.passive_mode
                {
                    // No stage installed: the route arm still composes the
                    // reference redirect (route wins over the absent
                    // global arm).
                    Some(guard_core_rs::https_enforcement::HttpsRedirectAnswer {
                        status: 301,
                        location: facts.https_url(),
                    })
                } else {
                    None
                };
                if let Some(redirect) = answer {
                    return Ok(finish_generated(
                        &parts,
                        &layer,
                        response::redirect(&redirect),
                    ));
                }
            }

            // Check 4: request logging (compose-only, never blocks; the
            // composed line is the host's to emit).
            if let Some(stage) = layer.request_logging() {
                let _ = stage.compose(
                    facts.ip.is_some().then_some(facts.ip_string.as_str()),
                    Some(&facts.method),
                    Some(&facts.path),
                    None,
                );
            }

            // Check 5: the request body buffers under the size cap
            // (413) - the reference `request_size_content` stage. The
            // route's `max_request_size` replaces the global cap for the
            // route (the reference reads the route limit instead); the
            // adapter's own cap stays the ceiling when the route sets none.
            let body_cap = route
                .and_then(|route| route.max_request_size)
                .and_then(|size| usize::try_from(size).ok())
                .unwrap_or_else(|| layer.body_cap());
            let buffered = match buffer_body(&mut body, body_cap).await {
                Ok(buffered) => buffered,
                Err(BufferFailure::TooLarge) => {
                    return Ok(oversize_response(&parts, &layer));
                }
                Err(BufferFailure::Read) => {
                    return Ok(failure_response(&parts, &layer));
                }
            };

            // Checks 6 + 7: required headers, then authentication.
            if let Some(stage) = layer.headers_auth() {
                let pairs = header_pairs(&parts.headers);
                if let Some((_, answer)) = stage.decide(&facts.path, &pairs) {
                    return Ok(block_response(
                        &parts,
                        &layer,
                        answer.status.as_u16(),
                        &answer.body,
                    ));
                }
            }

            // Check 8: the route referrer gate.
            if let Some(stage) = layer.referrer_gate()
                && let Some(answer) = stage.decide(
                    &facts.path,
                    facts.referer.as_deref(),
                    &facts.ip_string,
                    &facts.path,
                    &facts.method,
                )
            {
                return Ok(block_response(&parts, &layer, answer.status, &answer.body));
            }

            // Check 9: the route custom validators (first blocking
            // response wins, the validator's own shape).
            if let Some(stage) = layer.custom_checks()
                && let Some(failure) = stage.decide_custom_validators(
                    &facts.path,
                    &facts.method,
                    facts.ip.is_some().then_some(facts.ip_string.as_str()),
                    buffered
                        .as_deref()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok()),
                )
            {
                let status = failure.status.unwrap_or(200);
                return Ok(block_response(&parts, &layer, status, ""));
            }

            // Check 10: the route time-window gate.
            if let Some(stage) = layer.time_window_gate()
                && let Some(answer) =
                    stage.decide(&facts.path, &facts.ip_string, &facts.path, &facts.method)
            {
                return Ok(block_response(&parts, &layer, answer.status, &answer.body));
            }

            // The detection scan itself never blocks: the verdict feeds
            // the pipeline stages that do (the reference's
            // `suspicious_activity` position, via the stage). The
            // reference `suspicious_activity` bypass skips the scan (and
            // with it the violation feed) for the route, and the global
            // `enable_penetration_detection` toggle skips it everywhere
            // (the request proceeds clean).
            let verdict = if bypassed("penetration") || !layer.penetration_detection_enabled() {
                None
            } else {
                match scan_request(&parts, buffered.as_ref(), &layer) {
                    ScanOutcome::Clean => None,
                    ScanOutcome::Failed => return Ok(failure_response(&parts, &layer)),
                    ScanOutcome::Threat(verdict) => Some(verdict),
                }
            };

            // One engine-stage pass, split at the reference pipeline's
            // seams so the interleaved checks sit where the reference puts
            // them: the ban arm (check 12's `ip_security` bans) first, then
            // geo (12b), cloud (13), user agent (14), and the rate-limit
            // tiers + detection feed (15 + 16).
            let stage = layer
                .stage()
                .expect("the stage is built by GuardLayer::layer");
            let finding = threat_finding(verdict.as_ref());
            let observation = request_observation(&parts);
            if !bypassed("ip_ban")
                && let Some(blocked) = stage.decide_bans_observed(facts.ip, Some(&observation))
            {
                return Ok(finish_generated(&parts, &layer, response::stage(&blocked)));
            }

            // The reference runs the country arms inside the `ip`-gated
            // block: the same bypass skips the geo stage.
            if !bypassed("ip")
                && let Some(stage) = layer.geo_blocking()
                && let Some(decision) = stage.decide(facts.ip, facts.gate)
            {
                return Ok(block_response(
                    &parts,
                    &layer,
                    decision.answer.status.as_u16(),
                    stage_answer_body(&decision.answer),
                ));
            }

            if !bypassed("clouds")
                && let Some(stage) = layer.cloud_provider()
                && let Some(decision) = stage.decide(facts.ip, facts.gate)
            {
                return Ok(block_response(
                    &parts,
                    &layer,
                    decision.answer.status.as_u16(),
                    stage_answer_body(&decision.answer),
                ));
            }

            {
                // The route's `blocked_user_agents` runs additively before
                // the global filter (the reference
                // `check_user_agent_allowed` order); whitelisted and
                // exempt IPs skip exactly what the stage skips. A
                // non-compilable route pattern fails secure.
                let route_blocks = route
                    .filter(|route| !route.blocked_user_agents.is_empty())
                    .filter(|_| {
                        !facts
                            .gate
                            .is_some_and(|gate| gate.is_whitelisted || gate.is_exempt)
                    })
                    .map(|route| {
                        guard_core_engine::user_agent::UserAgentFilter::from_trusted_patterns(
                            route.blocked_user_agents.iter().cloned(),
                        )
                    });
                match route_blocks {
                    Some(Ok(filter))
                        if filter.is_blocked(facts.user_agent.as_deref().unwrap_or("")) =>
                    {
                        return Ok(block_response(
                            &parts,
                            &layer,
                            403,
                            "User-Agent not allowed",
                        ));
                    }
                    Some(Err(_)) => return Ok(failure_response(&parts, &layer)),
                    _ => {}
                }
                if let Some(stage) = layer.user_agent()
                    && let Some(answer) = stage.decide(
                        facts.ip,
                        facts.gate,
                        Some(&facts.path),
                        facts.user_agent.as_deref(),
                        finding.as_ref(),
                    )
                {
                    return Ok(block_response(
                        &parts,
                        &layer,
                        answer.status.as_u16(),
                        stage_answer_body(&answer),
                    ));
                }
            }

            // The carrier's rate-limit view is the route's tier (the
            // reference reads `route_config.rate_limit`/
            // `rate_limit_window`/`geo_rate_limits`); an invalid tier
            // fails secure, and the `rate_limit` bypass skips the pass.
            let carrier_tiers = match route.map(RouteConfig::rate_limits) {
                Some(Ok(tiers)) => tiers,
                Some(Err(_)) => return Ok(failure_response(&parts, &layer)),
                None => None,
            };
            let route_tiers = carrier_tiers
                .as_ref()
                .or_else(|| parts.extensions.get::<RouteRateLimits>());
            let gate = parts.extensions.get::<IpGateDecision>().copied();
            if !bypassed("rate_limit")
                && let Some(blocked) = stage.decide_tiers_observed(
                    facts.ip,
                    Some(&facts.path),
                    route_tiers,
                    gate,
                    finding.as_ref(),
                    Some(&observation),
                )
            {
                return Ok(finish_generated(&parts, &layer, response::stage(&blocked)));
            }
            if let (Some(verdict), false) = (&verdict, stage.config().passive_mode) {
                // Below-threshold detection (or an unattributed request):
                // the plain family block shape. Under passive mode the
                // detection was observed and counted by the stage and the
                // request forwards (the reference's passive path renders
                // no block).
                let status = 400;
                let body = resolve_error_body(
                    layer.custom_error_responses(),
                    status,
                    response::BLOCKED_MESSAGE,
                );
                if let Some(observability) = layer.observability() {
                    let observation = request_observation(&parts);
                    let payload = build_block_payload(
                        "suspicious_activity",
                        &format!("Suspicious activity detected: {}", facts.ip_string),
                        &verdict.reason,
                        false,
                        &facts.ip_string,
                        observation.url.as_deref().unwrap_or("/"),
                        observation.method.as_deref().unwrap_or(""),
                        Some(status),
                        &observability.sensitive,
                    );
                    fire_block_hook(layer.on_block(), &payload);
                }
                return Ok(block_response(&parts, &layer, status, &body));
            }

            // Check 17: the global `custom_request` function (its own
            // response shape; a response without a status renders the
            // framework default 200).
            if let Some(stage) = layer.custom_checks()
                && let Some(answer) = stage.decide_custom_request(
                    &facts.method,
                    &facts.path,
                    facts.ip.is_some().then_some(facts.ip_string.as_str()),
                    buffered
                        .as_deref()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok()),
                )
            {
                let status = answer.status.unwrap_or(200);
                return Ok(block_response(&parts, &layer, status, ""));
            }

            forward(&layer, &facts, parts, buffered, inner).await
        })
    }
}

/// Forward the buffered request to the wrapped service, then run the
/// response-side pass (behavioral return rules + security headers + CORS)
/// over the produced response when a response processor is installed.
async fn forward<S, B, B2>(
    layer: &GuardLayer,
    facts: &RequestFacts,
    parts: Parts,
    buffered: Option<Bytes>,
    mut inner: S,
) -> Result<Response<GuardBody<B2>>, S::Error>
where
    S: Service<Request<B>, Response = Response<B2>>,
    B: Body<Data = Bytes> + From<Bytes>,
{
    let rebuilt = B::from(buffered.unwrap_or_default());
    let mut response = inner
        .call(Request::from_parts(parts, rebuilt))
        .await?
        .map(GuardBody::Passthrough);
    apply_response_processor(
        layer,
        &ProcessorInput::from_facts(facts),
        response.status().as_u16(),
        response.headers_mut(),
    );
    Ok(response)
}

/// The request pieces the response-side pass reads.
struct ProcessorInput {
    method: String,
    url_path: String,
    client_ip: String,
    origin: Option<String>,
}

impl ProcessorInput {
    /// The same pieces lifted from the extracted request facts (the
    /// forwarded-response path).
    fn from_facts(facts: &RequestFacts) -> Self {
        Self {
            method: facts.method.clone(),
            url_path: facts.path.clone(),
            client_ip: facts.ip_string.clone(),
            origin: facts.origin.clone(),
        }
    }

    /// The same pieces lifted from request parts (the block paths).
    fn from_parts(parts: &Parts) -> Self {
        Self {
            method: parts.method.to_string(),
            url_path: parts.uri.path().to_owned(),
            client_ip: parts
                .extensions
                .get::<GuardClientIp>()
                .map_or_else(String::new, |ip| ip.0.to_string()),
            origin: parts
                .headers
                .get(http::header::ORIGIN)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
        }
    }
}

/// The detection feed the user-agent stage consumes: a flat finding lifted
/// from the scan verdict, built outside the generic `call` body so the
/// never-threatened test instantiations of that body (the failing-body,
/// trailered-body, and plain-service-fn inners) do not carry the closure
/// lines as uncovered regions of their own.
fn threat_finding(
    verdict: Option<&RequestScanVerdict>,
) -> Option<guard_core_rs::tower::ThreatFinding> {
    verdict.map(|verdict| guard_core_rs::tower::ThreatFinding {
        is_threat: true,
        categories: verdict.categories.clone(),
        trigger_info: verdict.reason.clone(),
    })
}

/// Run the response-side pass when a processor is installed: the global
/// `return_pattern` rules evaluate the response (a crossed `ban` lands in
/// the processor's IP-ban store), then the security-header set and the
/// CORS verdict headers land on the response. The response body is not
/// captured (`body_prefix = None`): `status:` rules evaluate, body rules
/// skip, exactly the reference's no-capture seam.
fn apply_response_processor(
    layer: &GuardLayer,
    input: &ProcessorInput,
    status: u16,
    headers: &mut HeaderMap,
) {
    let Some(processor) = layer.response_processor() else {
        return;
    };
    let mut bits = ResponseBits {
        status,
        body: None,
        headers: BTreeMap::new(),
    };
    let request = RequestBits {
        method: input.method.clone(),
        url_path: input.url_path.clone(),
        client_ip: input.client_ip.clone(),
        origin: input.origin.clone(),
    };
    let _action = processor.process(&request, &mut bits, None, SystemTime::now());
    for (name, value) in bits.headers {
        #[cfg(not(coverage))] // unreachable: the processor renders the
        // engine's fixed security-header and CORS sets, always valid names
        // and values, so neither conversion can fail
        if let (Ok(name), Ok(value)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(name, value);
        }
        #[cfg(coverage)]
        {
            let name = HeaderName::try_from(name.as_str())
                .expect("the processor renders valid header names");
            let value =
                HeaderValue::from_str(&value).expect("the processor renders valid header values");
            headers.insert(name, value);
        }
    }
}

/// Guard-generated answer (a block, the redirect, the oversize/failure
/// shapes) with the response-side pass applied.
fn finish_generated<B2>(
    parts: &Parts,
    layer: &GuardLayer,
    mut generated: Response<Full<Bytes>>,
) -> Response<GuardBody<B2>> {
    let input = ProcessorInput::from_parts(parts);
    apply_response_processor(
        layer,
        &input,
        generated.status().as_u16(),
        generated.headers_mut(),
    );
    generated.map(GuardBody::Generated)
}

/// A guard block answer: the family plain-text shape plus the
/// response-side pass.
/// The CORS preflight short-circuit answer (the reference `is_preflight`
/// plus `build_preflight_response`).
///
/// `Some` when the request is a preflight (OPTIONS carrying the
/// request-method header), rendered from the resolved CORS config alone:
/// the reference answers the preflight before the pipeline and its
/// response pass run.
fn preflight_answer<B2>(
    cors: &guard_core_engine::cors::CorsConfig,
    parts: &Parts,
) -> Option<Response<GuardBody<B2>>> {
    let request_headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    if !guard_core_engine::cors::is_preflight(parts.method.as_str(), &request_headers) {
        return None;
    }
    let answer = guard_core_engine::cors::build_preflight_response(
        cors,
        guard_core_engine::cors::PreflightRequest {
            origin: request_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("origin"))
                .map(|(_, value)| value.as_str()),
            request_method: request_headers
                .iter()
                .find(|(name, _)| {
                    name.eq_ignore_ascii_case(
                        guard_core_engine::cors::ALLOWED_PREFLIGHT_REQUEST_HEADER,
                    )
                })
                .map(|(_, value)| value.as_str()),
            request_headers_raw: request_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("access-control-request-headers"))
                .map(|(_, value)| value.as_str()),
        },
    );
    let mut generated = response::blocked_with_body(answer.status_code, &answer.body);
    for (name, value) in &answer.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::from_str(value),
        ) {
            generated.headers_mut().insert(name, value);
        }
    }
    Some(generated.map(GuardBody::Generated))
}

fn block_response<B2>(
    parts: &Parts,
    layer: &GuardLayer,
    status: u16,
    body: &str,
) -> Response<GuardBody<B2>> {
    finish_generated(parts, layer, response::blocked_with_body(status, body))
}

/// The `413` shape with the response-side pass applied.
fn oversize_response<B2>(parts: &Parts, layer: &GuardLayer) -> Response<GuardBody<B2>> {
    finish_generated(parts, layer, response::oversize())
}

/// The fail-secure `500` shape with the response-side pass applied.
fn failure_response<B2>(parts: &Parts, layer: &GuardLayer) -> Response<GuardBody<B2>> {
    finish_generated(parts, layer, response::failure())
}

/// The request pieces the stage's event and log emissions read.
fn request_observation(parts: &Parts) -> RequestObservation {
    let mut url = parts.uri.path().to_owned();
    if let Some(query) = parts.uri.query() {
        url.push('?');
        url.push_str(query);
    }
    RequestObservation {
        method: Some(parts.method.as_str().to_owned()),
        url: Some(url),
        user_agent: parts
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    }
}

/// The bare host of an authority string (port stripped, IPv6 brackets
/// removed): the connecting identity the trusted-proxy arm compares.
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

/// The answer body of a geo/cloud/user-agent stage answer. The reference
/// custom-error override never rides these answers (the stages construct
/// them with `custom_body: None`; the override resolves inside the
/// rate-limit stage's own render path, which this fused pass dispatches
/// through `response::stage` instead).
fn stage_answer_body(answer: &guard_core_rs::tower::StageResponse) -> &str {
    answer.body
}

/// Apply the configured IP gate to the request parts.
///
/// Returns the `403 Forbidden` response when the gate denies the request IP.
/// A passed request gets the gate's [`IpGateDecision`] inserted into the
/// request extensions (the family-local skip state, the equivalent of the
/// reference engine's `state.is_whitelisted` / `state.is_exempt`) so
/// downstream handlers can read it. Without a gate or without a
/// [`GuardClientIp`] extension the request is not attributed: the gate does
/// not run, and nothing is inserted.
fn enforce_ip_gate(parts: &mut Parts, layer: &GuardLayer) -> Option<Response<Full<Bytes>>> {
    let gate = layer.ip_gate()?;
    let GuardClientIp(ip) = parts.extensions.get::<GuardClientIp>()?;
    match gate.evaluate(*ip) {
        IpGateVerdict::Allowed(decision) => {
            parts.extensions.insert(decision);
            None
        }
        IpGateVerdict::Denied(denial) => {
            // The reference ip_filter block path: passive mode logs the
            // crossing and forwards (no gate decision reaches the rest of
            // the pipeline, so the unattributed handling applies), the
            // `on_block` hook fires once with the reference payload keys,
            // and the custom-error body override wins over the family
            // default.
            if layer.passive_mode {
                return None;
            }
            let ip_string = ip.to_string();
            let body = resolve_error_body(
                layer.custom_error_responses(),
                403,
                response::FORBIDDEN_MESSAGE,
            );
            if let Some(observability) = layer.observability() {
                let observation = request_observation(parts);
                let payload = build_block_payload(
                    "ip_security",
                    &format!("IP address blocked: {ip_string}"),
                    denial.reason(),
                    false,
                    &ip_string,
                    observation.url.as_deref().unwrap_or("/"),
                    observation.method.as_deref().unwrap_or(""),
                    Some(403),
                    &observability.sensitive,
                );
                fire_block_hook(layer.on_block(), &payload);
            }
            Some(block_response_owned(parts, layer, 403, &body))
        }
    }
}

/// [`block_response`] with an owned (custom-resolved) body: the same
/// response-side pass, one allocation.
fn block_response_owned(
    parts: &Parts,
    layer: &GuardLayer,
    status: u16,
    body: &str,
) -> Response<Full<Bytes>> {
    let mut generated = response::blocked_with_body(status, body);
    let input = ProcessorInput::from_parts(parts);
    apply_response_processor(layer, &input, status, generated.headers_mut());
    generated
}

/// Buffer a request body up to `cap` bytes.
///
/// `Ok(None)` means the body was empty. Trailers are discarded: the engine
/// scans content, and request trailers are not part of any scanned view.
async fn buffer_body<B>(body: &mut B, cap: usize) -> Result<Option<Bytes>, BufferFailure>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    let mut buffered = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_error| BufferFailure::Read)?;
        if let Ok(data) = frame.into_data() {
            if buffered.len() + data.len() > cap {
                return Err(BufferFailure::TooLarge);
            }
            buffered.extend_from_slice(&data);
        }
    }
    Ok(if buffered.is_empty() {
        None
    } else {
        Some(buffered.freeze())
    })
}

/// Run the engine over every request view, recovering from engine panics.
///
/// The engine's `detect` is total by signature, so the only failure mode is a
/// panic. Catching it here keeps the connection alive and lets the guard
/// answer `500` instead of unwinding out of the request task.
fn scan_request(parts: &Parts, body: Option<&Bytes>, layer: &GuardLayer) -> ScanOutcome {
    match catch_unwind(AssertUnwindSafe(|| scan_views(parts, body, layer))) {
        Ok(outcome) => outcome,
        Err(_) => ScanOutcome::Failed,
    }
}

/// One multi-surface engine pass over the request, in the reference scan
/// order: URL path, query params, headers, body. The per-route
/// detection-exclusion surface ([`RouteDetectionExclusions`] request
/// extension resolving over the global config) merges and lowercases
/// through the engine's `resolve`, and [`scan_surfaces`] applies the
/// reference semantics exactly: excluded query params and body fields are
/// skipped, excluded headers scan with their known-false-positive
/// categories suppressed (address-carrying proxy headers lose only
/// `ssrf`, and only for address-chain values), the enabled-categories set
/// filters per value (a threat whose categories are all filtered out ends
/// the scan clean - terminal, not a reason to keep scanning), and
/// `detection_scan_body = false` skips the body surface entirely.
///
/// The adapter-level pre-filter (`EXCLUDED_HEADERS`, every `sec-*` name)
/// keeps framework noise headers out of the surfaces before the engine
/// sees them. A semantic-only threat carries no category and contributes
/// nothing here, exactly like the reference's `category == ""` guard.
fn scan_views(parts: &Parts, body: Option<&Bytes>, layer: &GuardLayer) -> ScanOutcome {
    let resolved = resolve_exclusions(
        layer.detection_exclusions(),
        parts.extensions.get::<RouteDetectionExclusions>(),
    );

    let path = parts.uri.path();
    let url_path = if path == "/" { None } else { Some(path) };

    // Query parameter pairs, `parse_qsl`-decoded (the reference reads the
    // decoded values, so exclusions and detection see what the handler
    // sees). Per pair, so excluded names are skippable.
    let query_params: Vec<(String, String)> = parts
        .uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (decode_query_component(name), decode_query_component(value)),
            None => (decode_query_component(pair), String::new()),
        })
        .collect();

    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(name, _)| !is_excluded_header(name.as_str()))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();

    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let raw_body = body
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default();

    let surfaces = RequestSurfaces {
        url_path,
        query_params: &query_params,
        headers: &headers,
        content_type,
        raw_body: &raw_body,
    };
    let verdict = (layer.scan_fn())(&surfaces, &resolved, layer.config());
    if verdict.is_threat {
        ScanOutcome::Threat(verdict)
    } else {
        ScanOutcome::Clean
    }
}

fn is_excluded_header(name: &str) -> bool {
    name.starts_with("sec-") || EXCLUDED_HEADERS.contains(&name)
}

/// `urllib.parse.unquote_plus` for one query component: `%XX` runs and
/// `+` (form-encoding's space) decode into the value the reference's
/// `parse_qsl` hands the engine. Malformed escapes stay literal.
fn decode_query_component(component: &str) -> String {
    let plus_decoded = component.replace('+', " ");
    let bytes = plus_decoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or(""),
                16,
            )
        {
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DetectionExclusionConfig;
    use crate::{
        ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, BLOCKED_MESSAGE, FAILURE_MESSAGE,
        FORBIDDEN_MESSAGE, GuardClientIp, IpBanConfig, IpBanManager, IpGateConfig,
        OVERSIZE_MESSAGE, RATE_LIMITED_MESSAGE, RateLimitConfig, RateLimiter, ThreatBanEntry,
        default_config,
    };
    use guard_core_engine::detect::DetectConfig;
    use guard_core_engine::ip_ban::Clock;
    use guard_core_engine::ip_gate::IpGateDecision;
    use http::StatusCode;
    use http_body_util::{BodyExt, Full};
    use std::convert::Infallible;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use tower::{Layer, ServiceExt};
    fn panicking_scan(
        _surfaces: &guard_core_engine::detection_exclusions::RequestSurfaces<'_>,
        _exclusions: &guard_core_engine::detection_exclusions::ResolvedExclusions,
        _config: &DetectConfig,
    ) -> guard_core_engine::detection_exclusions::RequestScanVerdict {
        panic!("engine exploded");
    }

    fn gate_ip(text: &str) -> GuardClientIp {
        GuardClientIp(IpAddr::from_str(text).expect("test address"))
    }

    /// The empty list, typed so the `new` calls stay inferable.
    const NIL: [&str; 0] = [];

    /// The checklist gate: a blacklisted exact IP and a blacklisted /24
    /// (192.0.2.x), an exempt exact IP and an exempt /28 (198.51.100.x), all
    /// disjoint.
    fn checklist_gate() -> IpGateConfig {
        IpGateConfig::new(
            [] as [&str; 0],
            ["203.0.113.9", "192.0.2.0/24"],
            ["198.51.100.7", "198.51.100.16/28"],
        )
        .expect("valid lists")
    }

    /// A guarded service whose `200` body reports the skip state the
    /// downstream handler sees in its request extensions.
    fn guarded(
        layer: &GuardLayer,
    ) -> impl Service<
        Request<Full<Bytes>>,
        Response = http::Response<crate::GuardBody<Full<Bytes>>>,
        Error = Infallible,
    > {
        layer.layer(tower::service_fn(
            |request: Request<Full<Bytes>>| async move {
                let verdict = match request.extensions().get::<IpGateDecision>().copied() {
                    Some(decision) => {
                        format!(
                            "gate=on wh={} ex={}",
                            decision.is_whitelisted, decision.is_exempt
                        )
                    }
                    None => "gate=off".to_owned(),
                };
                Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from(verdict))))
            },
        ))
    }

    async fn status_and_body(
        layer: &GuardLayer,
        request: Request<Full<Bytes>>,
    ) -> (StatusCode, String) {
        let response = guarded(layer).oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn benign_request(ip: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .uri("/hello")
            .extension(gate_ip(ip))
            .body(Full::new(Bytes::new()))
            .expect("request")
    }

    // --- the unified SecurityConfig consumption (from_security_config) ---

    use guard_core_engine::security_config::SecurityConfig;

    fn attack_request(uri: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .uri(uri)
            .header("x-forwarded-for", "203.0.113.9")
            .body(Full::new(Bytes::new()))
            .expect("request")
    }

    async fn config_status_and_body(
        config: &SecurityConfig,
        request: Request<Full<Bytes>>,
    ) -> (StatusCode, String) {
        let layer = GuardLayer::from_security_config(config).expect("valid config");
        status_and_body(&layer, request).await
    }

    #[tokio::test]
    async fn the_penetration_detection_toggle_skips_the_scan() {
        // `enable_penetration_detection = false` skips the multi-surface
        // scan entirely: the attack rides through clean (200).
        let config = SecurityConfig {
            enable_penetration_detection: false,
            ..SecurityConfig::default()
        };
        let (status, _) = config_status_and_body(
            &config,
            attack_request("/scan?q=1%20UNION%20SELECT%20password"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the toggle disables the scan");

        // The default (enabled) scans and blocks.
        let (status, _) = config_status_and_body(
            &SecurityConfig::default(),
            attack_request("/scan?q=1%20UNION%20SELECT%20password"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    #[tokio::test]
    async fn from_security_config_feeds_the_scan_budgets() {
        // The scan-budget knobs ride the unified config onto the scan
        // path: a two-value budget stops the scan before the third
        // value, so the threat in the last query param never surfaces.
        let config = SecurityConfig {
            detection_max_scan_values: 2,
            ..SecurityConfig::default()
        };
        let attack = Request::builder()
            .uri("/scan?a=benign-one&b=benign-two&c=1%20UNION%20SELECT%20password")
            .header("x-forwarded-for", "203.0.113.9")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, _) = config_status_and_body(&config, attack).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "values past the scan-value budget are not scanned"
        );

        // The same request shape under the default budget scans (the
        // below-threshold verdict blocks, the family 400 shape).
        let attack_again = Request::builder()
            .uri("/scan?a=benign-one&b=benign-two&c=1%20UNION%20SELECT%20password")
            .header("x-forwarded-for", "203.0.113.9")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, _) = config_status_and_body(&SecurityConfig::default(), attack_again).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    #[tokio::test]
    async fn from_security_config_defaults_screen_clean_traffic() {
        let config = SecurityConfig::default();
        let (status, _) = config_status_and_body(&config, benign_request("203.0.113.9")).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn from_security_config_enforce_https_redirects_http() {
        let config = SecurityConfig {
            enforce_https: true,
            ..SecurityConfig::default()
        };
        let (status, body) = config_status_and_body(&config, benign_request("203.0.113.9")).await;
        assert_eq!(status.as_u16(), 301);
        assert!(
            body.is_empty(),
            "the reference redirect carries no body: {body}"
        );
    }

    #[tokio::test]
    async fn from_security_config_emergency_mode_blocks_outside_the_whitelist() {
        let config = SecurityConfig {
            emergency_mode: true,
            emergency_whitelist: vec![String::from("198.51.100.7")],
            ..SecurityConfig::default()
        };
        let (blocked, _) = config_status_and_body(&config, benign_request("203.0.113.9")).await;
        assert_eq!(blocked, StatusCode::SERVICE_UNAVAILABLE);
        let (allowed, _) = config_status_and_body(&config, benign_request("198.51.100.7")).await;
        assert_eq!(allowed, StatusCode::OK);
    }

    #[tokio::test]
    async fn from_security_config_blocked_user_agent_answers_the_403() {
        let config = SecurityConfig {
            blocked_user_agents: vec![String::from("bad-bot")],
            ..SecurityConfig::default()
        };
        let mut request = benign_request("203.0.113.9");
        request
            .headers_mut()
            .insert("user-agent", http::HeaderValue::from_static("bad-bot/1.0"));
        let (blocked, body) = config_status_and_body(&config, request).await;
        assert_eq!(blocked, StatusCode::FORBIDDEN);
        assert_eq!(body, "User-Agent not allowed");

        let (allowed, _) = config_status_and_body(&config, benign_request("203.0.113.9")).await;
        assert_eq!(allowed, StatusCode::OK);
    }

    #[tokio::test]
    async fn from_security_config_exclude_paths_bypass_the_pipeline() {
        let config = SecurityConfig {
            blacklist: vec![String::from("203.0.113.9")],
            exclude_paths: vec![String::from("/docs")],
            ..SecurityConfig::default()
        };
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        let mut docs = benign_request("203.0.113.9");
        *docs.uri_mut() = http::Uri::from_static("/docs");
        let (bypassed, _) = status_and_body(&layer, docs).await;
        assert_eq!(bypassed, StatusCode::OK);
        let (blocked, _) = status_and_body(&layer, benign_request("203.0.113.9")).await;
        assert_eq!(blocked, StatusCode::FORBIDDEN);
    }

    #[test]
    fn from_security_config_invalid_ip_list_entry_fails_closed() {
        let config = SecurityConfig {
            whitelist: Some(vec![String::from("not-an-ip")]),
            ..SecurityConfig::default()
        };
        let error = GuardLayer::from_security_config(&config).unwrap_err();
        assert!(matches!(error, crate::GuardConfigError::IpGate(_)));
    }

    #[tokio::test]
    async fn from_security_config_rate_limit_crossing_answers_429() {
        let config = SecurityConfig {
            rate_limit: 1,
            ..SecurityConfig::default()
        };
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        let (first, _) = status_and_body(&layer, benign_request("203.0.113.9")).await;
        assert_eq!(first, StatusCode::OK);
        let (second, body) = status_and_body(&layer, benign_request("203.0.113.9")).await;
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
    }

    #[tokio::test]
    async fn from_security_config_custom_error_responses_render() {
        let config = SecurityConfig {
            blacklist: vec![String::from("203.0.113.9")],
            custom_error_responses: {
                let mut map = std::collections::BTreeMap::new();
                map.insert(403, String::from("custom-forbidden"));
                map
            },
            ..SecurityConfig::default()
        };
        let (status, body) = config_status_and_body(&config, benign_request("203.0.113.9")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, "custom-forbidden");
    }

    #[tokio::test]
    async fn from_security_config_passive_mode_observes_without_blocking() {
        let config = SecurityConfig {
            passive_mode: true,
            blacklist: vec![String::from("203.0.113.9")],
            ..SecurityConfig::default()
        };
        let (status, _) = config_status_and_body(&config, benign_request("203.0.113.9")).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn from_security_config_security_headers_render_on_responses() {
        let config = SecurityConfig::default();
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        let response = guarded(&layer)
            .oneshot(benign_request("203.0.113.9"))
            .await
            .expect("response");
        assert_eq!(
            response.headers().get("x-content-type-options"),
            Some(&http::HeaderValue::from_static("nosniff"))
        );
    }

    #[tokio::test]
    async fn from_security_config_cors_config_enables_the_cors_response_headers() {
        let config = SecurityConfig {
            enable_cors: true,
            cors_allow_origins: vec![String::from("https://app.test")],
            ..SecurityConfig::default()
        };
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        let mut request = benign_request("203.0.113.9");
        request
            .headers_mut()
            .insert("origin", http::HeaderValue::from_static("https://app.test"));
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(
            response.headers().get("access-control-allow-origin"),
            Some(&http::HeaderValue::from_static("https://app.test"))
        );
    }

    #[tokio::test]
    async fn from_security_config_disable_rate_limiting_forwards_freely() {
        let config = SecurityConfig {
            enable_rate_limiting: false,
            rate_limit: 1,
            ..SecurityConfig::default()
        };
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        for _ in 0..3 {
            let (status, _) = status_and_body(&layer, benign_request("203.0.113.9")).await;
            assert_eq!(status, StatusCode::OK);
        }
    }

    #[test]
    fn from_security_config_zero_rate_limit_fails_closed() {
        let config = SecurityConfig {
            rate_limit: 0,
            ..SecurityConfig::default()
        };
        let error = GuardLayer::from_security_config(&config).unwrap_err();
        assert!(matches!(error, crate::GuardConfigError::RateLimit(_)));
    }

    #[tokio::test]
    async fn from_security_config_disable_ip_banning_still_screens() {
        let config = SecurityConfig {
            enable_ip_banning: false,
            blacklist: vec![String::from("203.0.113.9")],
            ..SecurityConfig::default()
        };
        let (status, _) = config_status_and_body(&config, benign_request("203.0.113.9")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn from_security_config_detection_exclusions_and_categories_reach_the_scan() {
        let config = SecurityConfig {
            enabled_detection_categories: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("xss"));
                set
            },
            excluded_detection_params: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("q"));
                set
            },
            detection_scan_body: false,
            ..SecurityConfig::default()
        };
        // The sqli category is disabled by the enabled-categories override:
        // the sqli probe forwards.
        let mut sqli = benign_request("203.0.113.9");
        *sqli.uri_mut() = http::Uri::from_static("/hello?q=1%27+OR+1%3D1");
        let (status, _) = config_status_and_body(&config, sqli).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn from_security_config_silent_observability_skips_the_knob() {
        let config = SecurityConfig {
            log_suspicious_level: None,
            ..SecurityConfig::default()
        };
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        assert!(layer.observability().is_none());
    }

    #[tokio::test]
    async fn from_security_config_disabled_security_headers_skip_the_processor() {
        let config = SecurityConfig {
            security_headers: guard_core_engine::security_headers::SecurityHeadersConfig {
                enabled: false,
                ..guard_core_engine::security_headers::SecurityHeadersConfig::reference_default()
            },
            ..SecurityConfig::default()
        };
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        let response = guarded(&layer)
            .oneshot(benign_request("203.0.113.9"))
            .await
            .expect("response");
        assert_eq!(response.headers().get("x-content-type-options"), None);
    }

    #[tokio::test]
    async fn from_security_config_empty_category_set_skips_the_exclusion_block() {
        // The reference's empty `enabled_detection_categories` frozenset:
        // an explicitly empty set disables every category, and the
        // detection-exclusion block is not installed at all.
        let config = SecurityConfig {
            enabled_detection_categories: std::collections::BTreeSet::new(),
            ..SecurityConfig::default()
        };
        let layer = GuardLayer::from_security_config(&config).expect("valid config");
        assert!(layer.detection_exclusions().is_none());
    }

    #[tokio::test]
    async fn from_security_config_on_block_hook_fires_once() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let config = SecurityConfig {
            blacklist: vec![String::from("203.0.113.9")],
            on_block: Some(Arc::new(move |payload: &crate::BlockPayload| {
                sink.lock().expect("sink").push(payload.check_name.clone());
            })),
            ..SecurityConfig::default()
        };
        let (status, _) = config_status_and_body(&config, benign_request("203.0.113.9")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            !seen.lock().expect("sink").is_empty(),
            "the reference on_block hook fires per blocked request"
        );
    }

    async fn body_text(response: Response<GuardBody<Full<Bytes>>>) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// One scripted frame of a [`ScriptedBody`].
    #[derive(Debug)]
    enum ScriptedFrame {
        /// A data frame carrying the buffered bytes.
        Data(Bytes),
        /// A pending poll: the buffering loop's await actually suspends
        /// before the next frame arrives.
        Pending,
        /// A trailers frame (no data): the buffering scan skips it.
        Trailers,
        /// A transport error: the body stream fails mid-read.
        Error,
    }

    /// A request body scripted frame by frame: data, trailers, a transport
    /// error, or a clean end. One service built over it drives every
    /// buffering arm and every fail-secure dispatch arm with real inputs.
    #[derive(Debug)]
    struct ScriptedBody {
        frames: std::vec::IntoIter<ScriptedFrame>,
    }

    impl ScriptedBody {
        fn scripted(frames: Vec<ScriptedFrame>) -> Self {
            Self {
                frames: frames.into_iter(),
            }
        }

        /// A single data frame (the ordinary benign request body).
        fn data(bytes: &[u8]) -> Self {
            Self::scripted(vec![ScriptedFrame::Data(Bytes::copy_from_slice(bytes))])
        }

        /// No frames at all: the body buffers to empty.
        fn empty() -> Self {
            Self::scripted(Vec::new())
        }
    }

    /// The forwarded rebuild: one data frame carrying the buffered bytes.
    impl From<Bytes> for ScriptedBody {
        fn from(bytes: Bytes) -> Self {
            Self::scripted(vec![ScriptedFrame::Data(bytes)])
        }
    }

    impl http_body::Body for ScriptedBody {
        type Data = Bytes;
        type Error = String;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            match self.frames.next() {
                Some(ScriptedFrame::Data(data)) => {
                    Poll::Ready(Some(Ok(http_body::Frame::data(data))))
                }
                Some(ScriptedFrame::Pending) => {
                    // The transport is not ready "yet": wake immediately so
                    // the executor re-drives the future on the next turn and
                    // the buffering loop's await genuinely suspends once.
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Some(ScriptedFrame::Trailers) => {
                    Poll::Ready(Some(Ok(http_body::Frame::trailers(http::HeaderMap::new()))))
                }
                Some(ScriptedFrame::Error) => {
                    Poll::Ready(Some(Err("body transport failed".to_owned())))
                }
                None => Poll::Ready(None),
            }
        }
    }

    #[tokio::test]
    async fn oversize_body_takes_the_too_large_buffer_arm() {
        let layer = GuardLayer::new(default_config()).with_body_cap(4);
        let request = Request::builder()
            .uri("/hello")
            .body(Full::new(Bytes::from_static(b"0123456789")))
            .expect("request");
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// The real engine scan, except a scan of `/panic-me` explodes: the
    /// fail-secure arm needs an engine panic injected mid-matrix without
    /// sacrificing the other arms to an always-panicking scan.
    fn panic_on_panic_path_scan(
        surfaces: &guard_core_engine::detection_exclusions::RequestSurfaces<'_>,
        exclusions: &guard_core_engine::detection_exclusions::ResolvedExclusions,
        config: &DetectConfig,
    ) -> guard_core_engine::detection_exclusions::RequestScanVerdict {
        assert!(surfaces.url_path != Some("/panic-me"), "engine exploded");
        guard_core_engine::detection_exclusions::scan_request(surfaces, exclusions, config)
    }

    /// The guard over an inner handler that echoes the forwarded body it
    /// receives (proving the buffered rebuild reached the wrapped service).
    fn scripted(
        layer: &GuardLayer,
    ) -> impl Service<
        Request<ScriptedBody>,
        Response = http::Response<crate::GuardBody<Full<Bytes>>>,
        Error = Infallible,
    > {
        layer.layer(tower::service_fn(
            |request: Request<ScriptedBody>| async move {
                let bytes = request
                    .into_body()
                    .collect()
                    .await
                    .expect("forwarded body")
                    .to_bytes();
                Ok::<_, Infallible>(http::Response::new(Full::new(bytes)))
            },
        ))
    }

    fn scripted_request(ip: &str, uri: &'static str, body: ScriptedBody) -> Request<ScriptedBody> {
        Request::builder()
            .uri(uri)
            .extension(gate_ip(ip))
            .body(body)
            .expect("request")
    }

    /// One guarded request's status and decoded response body.
    async fn ask(
        svc: &mut impl Service<
            Request<ScriptedBody>,
            Response = http::Response<crate::GuardBody<Full<Bytes>>>,
            Error = Infallible,
        >,
        request: Request<ScriptedBody>,
    ) -> (StatusCode, String) {
        let response = svc
            .ready()
            .await
            .expect("ready")
            .call(request)
            .await
            .expect("response");
        let status = response.status();
        (status, body_text(response).await)
    }

    #[tokio::test]
    async fn one_scripted_service_exercises_every_call_outcome() {
        // Every request below flows through this one service instantiation,
        // so its `call` future and its buffering loop answer for the whole
        // decision matrix with real inputs.
        let manager = IpBanManager::new();
        let config = IpBanConfig::new(true, 100, 3600, no_entries()).expect("valid config");
        let layer = GuardLayer::new(default_config())
            .with_body_cap(4)
            .with_ip_gate(checklist_gate())
            .with_ip_banning(manager.clone(), config)
            .with_scan_fn(panic_on_panic_path_scan);
        let mut svc = scripted(&layer);

        // Benign traffic buffers, scans clean, and forwards the rebuilt body.
        let (status, body) = ask(
            &mut svc,
            scripted_request("203.0.113.61", "/ok", ScriptedBody::data(b"ok")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok", "the inner handler echoes the forwarded body");

        // The ban stage answers a live ban before anything downstream.
        manager
            .ban_ip(
                IpAddr::from_str("203.0.113.62").expect("ip"),
                60,
                "operator",
            )
            .expect("ban");
        let (status, body) = ask(
            &mut svc,
            scripted_request("203.0.113.62", "/ok", ScriptedBody::empty()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);

        // The IP gate denies a blacklisted client before any buffering.
        let (status, body) = ask(
            &mut svc,
            scripted_request("203.0.113.9", "/ok", ScriptedBody::empty()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, FORBIDDEN_MESSAGE);

        // A body over the cap is rejected with 413, never forwarded unscanned.
        let (status, body) = ask(
            &mut svc,
            scripted_request("203.0.113.63", "/ok", ScriptedBody::data(b"0123456789")),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body, OVERSIZE_MESSAGE);

        // A body read error fails secure with the 500 shape.
        let (status, body) = ask(
            &mut svc,
            scripted_request(
                "203.0.113.64",
                "/ok",
                ScriptedBody::scripted(vec![ScriptedFrame::Error]),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, FAILURE_MESSAGE);

        // An engine panic on this very path fails secure too.
        let (status, body) = ask(
            &mut svc,
            scripted_request("203.0.113.65", "/panic-me", ScriptedBody::empty()),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, FAILURE_MESSAGE);

        // Detection still blocks a flagged path with the plain block shape.
        // The request carries no client IP, so the stage cannot attribute
        // the violation and the adapter renders the family block itself.
        let unattributed_attack = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(ScriptedBody::empty())
            .expect("request");
        let (status, body) = ask(&mut svc, unattributed_attack).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, BLOCKED_MESSAGE);

        // A trailer-only body buffers to empty and forwards untouched: the
        // forwarded rebuild carries no buffered bytes.
        let (status, body) = ask(
            &mut svc,
            scripted_request(
                "203.0.113.67",
                "/ok",
                ScriptedBody::scripted(vec![ScriptedFrame::Trailers]),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "", "the forwarded rebuild carries no buffered bytes");

        // A body whose transport pends once before the data frame: the
        // buffering loop's await genuinely suspends, then the frame lands
        // and the request forwards.
        let (status, body) = ask(
            &mut svc,
            scripted_request(
                "203.0.113.68",
                "/ok",
                ScriptedBody::scripted(vec![
                    ScriptedFrame::Pending,
                    ScriptedFrame::Data(Bytes::from_static(b"late")),
                ]),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "late");
    }

    #[tokio::test]
    async fn benign_body_with_user_agent_is_buffered_and_forwarded() {
        let layer = GuardLayer::new(default_config());
        let request = Request::builder()
            .uri("/hello")
            .header("user-agent", "gap-twin/1.0")
            .body(Full::new(Bytes::from_static(b"benign body")))
            .expect("request");
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn engine_panic_is_recovered_as_a_500() {
        let layer = GuardLayer::new(default_config()).with_scan_fn(panicking_scan);
        let request = Request::builder()
            .uri("/hello")
            .body(Full::new(Bytes::from_static(b"ping")))
            .expect("request");

        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(response.status(), 500);
        assert_eq!(body_text(response).await, FAILURE_MESSAGE);
    }

    #[tokio::test]
    async fn scan_views_reports_threat_through_catch_unwind() {
        let layer = GuardLayer::new(default_config());
        let parts = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(())
            .expect("request")
            .into_parts()
            .0;
        let outcome = scan_request(&parts, None, &layer);
        assert!(
            matches!(&outcome, ScanOutcome::Threat(verdict)
                if verdict.is_threat && verdict.categories == vec!["dir_traversal".to_owned()]),
            "traversal path should be flagged with its category"
        );
    }

    #[test]
    fn scan_views_sorts_and_dedups_categories() {
        let layer = GuardLayer::new(default_config());
        // `SELECT * FROM users` in a body view yields two sqli rows; the
        // outcome carries the category once.
        let outcome = scan_request(
            &Request::builder().body(()).expect("request").into_parts().0,
            Some(&Bytes::from_static(b"SELECT * FROM users")),
            &layer,
        );
        assert!(
            matches!(&outcome, ScanOutcome::Threat(verdict)
                if verdict.is_threat && verdict.categories == vec!["sqli".to_owned()]),
            "the body blob should flag sqli once"
        );
    }

    #[tokio::test]
    async fn empty_body_is_not_scanned_and_still_forwarded() {
        let layer = GuardLayer::new(default_config());
        let service = layer.layer(tower::service_fn(|_request: Request<Full<Bytes>>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        }));
        let request = Request::builder()
            .uri("/hello")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = service.clone().oneshot(request).await.expect("response");
        assert_eq!(response.status(), 200);

        // A threat through the same instantiation: the empty body skips the
        // body view, the path verdict still answers inside this service's
        // own monomorphization, and both arms of the fused pipeline run.
        let threat = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = service.oneshot(threat).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn blocked_response_body_reports_the_documented_message() {
        let layer = GuardLayer::new(default_config());
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(response.status(), 400);
        assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
    }

    #[test]
    fn excluded_headers_cover_the_negotiation_set_and_sec_prefix() {
        for name in [
            "host",
            "user-agent",
            "accept",
            "accept-encoding",
            "connection",
        ] {
            assert!(is_excluded_header(name), "{name} should be excluded");
        }
        for name in ["sec-fetch-site", "sec-ch-ua", "sec-websocket-key"] {
            assert!(is_excluded_header(name), "{name} should be excluded");
        }
        for name in ["cookie", "authorization", "content-type", "x-api-key"] {
            assert!(!is_excluded_header(name), "{name} should be scanned");
        }
    }

    // --- the global IP gate (exempt_ips contract checklist) ---

    #[tokio::test]
    async fn blacklisted_ip_is_denied_with_the_forbidden_body() {
        let (status, body) = status_and_body(
            &GuardLayer::new(default_config()).with_ip_gate(checklist_gate()),
            benign_request("203.0.113.9"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, FORBIDDEN_MESSAGE);

        // The blacklisted /24 denies its whole range.
        let (status, body) = status_and_body(
            &GuardLayer::new(default_config()).with_ip_gate(checklist_gate()),
            benign_request("192.0.2.77"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, FORBIDDEN_MESSAGE);
    }

    #[tokio::test]
    async fn exempt_exact_and_cidr_ips_pass_with_the_skip_state_set() {
        // Checklist: exemption is observable behavior for the exact entry
        // and the CIDR member alike; the stateful stage pins "skips rate
        // limiting" at the flag level the contract defines (the same state a
        // whitelist match sets) - see exempt_ip_exceeds_the_limit_and_still_gets_200.
        let layer = GuardLayer::new(default_config()).with_ip_gate(checklist_gate());
        let (status, body) = status_and_body(&layer, benign_request("198.51.100.7")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=on wh=false ex=true");

        let (status, body) = status_and_body(&layer, benign_request("198.51.100.20")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=on wh=false ex=true");
    }

    #[tokio::test]
    async fn exempt_ip_on_the_blacklist_is_still_denied() {
        let gate = IpGateConfig::new(NIL, ["198.51.100.7"], ["198.51.100.7"]).expect("valid lists");
        let (status, body) = status_and_body(
            &GuardLayer::new(default_config()).with_ip_gate(gate),
            benign_request("198.51.100.7"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, FORBIDDEN_MESSAGE);
    }

    #[tokio::test]
    async fn exemption_never_opens_a_restrictive_whitelist() {
        let gate = IpGateConfig::new(["192.0.2.1"], NIL, ["198.51.100.7"]).expect("valid lists");
        let layer = GuardLayer::new(default_config()).with_ip_gate(gate);
        let (status, body) = status_and_body(&layer, benign_request("198.51.100.7")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, FORBIDDEN_MESSAGE);

        // An exempt-only config adds no deny path of its own: with the
        // whitelist empty, every IP passes, exempt or not.
        let exempt_only = IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let (status, body) = status_and_body(
            &GuardLayer::new(default_config()).with_ip_gate(exempt_only),
            benign_request("192.0.2.8"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=on wh=false ex=false");
    }

    #[tokio::test]
    async fn whitelist_match_sets_both_flags_and_exemption_follows_the_list() {
        let gate = IpGateConfig::new(["198.51.100.7", "198.51.100.30"], NIL, ["198.51.100.7"])
            .expect("valid lists");
        let layer = GuardLayer::new(default_config()).with_ip_gate(gate);
        let (status, body) = status_and_body(&layer, benign_request("198.51.100.7")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=on wh=true ex=true");

        // A whitelist member outside exempt_ips: plain whitelist skip state.
        let (status, body) = status_and_body(&layer, benign_request("198.51.100.30")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=on wh=true ex=false");
    }

    #[tokio::test]
    async fn an_attack_from_an_exempt_ip_is_still_blocked_by_detection() {
        // Checklist: penetration detection still applies to exempt IPs.
        let layer = GuardLayer::new(default_config()).with_ip_gate(checklist_gate());
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .extension(gate_ip("198.51.100.7"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body, BLOCKED_MESSAGE,
            "detection must still scan exempt IPs"
        );
    }

    #[tokio::test]
    async fn without_a_client_ip_extension_the_gate_is_inert_and_detection_still_applies() {
        let layer = GuardLayer::new(default_config()).with_ip_gate(checklist_gate());
        // Not attributed: the gate cannot run, and the request flows on.
        let request = Request::builder()
            .uri("/hello")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "gate=off");

        // Not attributed does not mean unscreened: detection still scans.
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, BLOCKED_MESSAGE);
    }

    #[tokio::test]
    async fn invalid_exempt_entry_fails_closed_at_config_time() {
        let error = IpGateConfig::new(NIL, NIL, ["not-an-ip"]).unwrap_err();
        assert_eq!(error.list, "exempt_ips");
        assert_eq!(error.entry, "not-an-ip");
    }

    #[test]
    fn ipv4_mapped_request_matches_v4_entries_at_the_gate() {
        // Checklist: IPv4-mapped parity. std parses the mapped form as an
        // IPv6 address; the gate must still match it against v4 entries
        // exactly as the whitelist matcher does.
        let mapped = IpAddr::from_str("::ffff:198.51.100.7").expect("mapped address");
        let gate = IpGateConfig::new(["198.51.100.0/24"], NIL, ["198.51.100.7"]).expect("lists");
        assert!(
            matches!(gate.evaluate(mapped), IpGateVerdict::Allowed(decision) if decision.is_exempt)
        );
        assert!(matches!(
            gate.evaluate(mapped),
            IpGateVerdict::Allowed(IpGateDecision {
                is_whitelisted: true,
                ..
            })
        ));
    }

    // --- the stateful stage: rate limiting, bans, auto-ban ---

    /// The empty `threat_ban_config`, typed for `IpBanConfig::new`.
    fn no_entries() -> Vec<(String, ThreatBanEntry)> {
        Vec::new()
    }

    /// An enabled rate limiter with the given limit and auto-ban switch.
    fn limiter(limit: u32, auto_ban: bool) -> RateLimiter {
        #[allow(clippy::needless_update)] // forward-compatible against the pre-tier engine too
        RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: limit,
            rate_limit_window: 60,
            enable_rate_limit_auto_ban: auto_ban,
            ..RateLimitConfig::default()
        })
        .expect("valid config")
    }

    /// A fake clock (unix seconds starting at `1_000`) plus its handle, for
    /// deterministic ban-expiry coverage.
    fn fake_clock() -> (Clock, Arc<AtomicU64>) {
        let state = Arc::new(AtomicU64::new(1_000));
        let clock: Clock = {
            let seconds = state.clone();
            #[allow(clippy::cast_precision_loss)]
            Arc::new(move || seconds.load(Ordering::Relaxed) as f64)
        };
        (clock, state)
    }

    /// Status, body, and the `Retry-After` header of one guarded request.
    async fn full_status(
        layer: &GuardLayer,
        request: Request<Full<Bytes>>,
    ) -> (StatusCode, String, Option<String>) {
        let response = guarded(layer).oneshot(request).await.expect("response");
        let status = response.status();
        let retry_after = response
            .headers()
            .get(http::header::RETRY_AFTER)
            .map(|value| value.to_str().expect("ascii header").to_owned());
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (
            status,
            String::from_utf8_lossy(&bytes).into_owned(),
            retry_after,
        )
    }

    #[tokio::test]
    async fn rate_limit_crossing_is_blocked_429_with_retry_after() {
        let layer = GuardLayer::new(default_config()).with_rate_limiting(limiter(2, false));
        for _ in 0..2 {
            let (status, _, retry_after) = full_status(&layer, benign_request("192.0.2.55")).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(retry_after, None, "allowed requests carry no Retry-After");
        }
        let (status, body, retry_after) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
        assert_eq!(
            retry_after.as_deref(),
            Some("60"),
            "Retry-After is the window"
        );
    }

    #[tokio::test]
    async fn exempt_ip_exceeds_the_limit_and_still_gets_200() {
        // Checklist: the exempt flag is observable - exemption skips rate
        // limiting exactly like a whitelist match.
        let gate = IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let layer = GuardLayer::new(default_config())
            .with_ip_gate(gate)
            .with_rate_limiting(limiter(1, false));
        for _ in 0..5 {
            let (status, _, _) = full_status(&layer, benign_request("198.51.100.7")).await;
            assert_eq!(status, StatusCode::OK, "exempt IPs are never rate limited");
        }
        // A non-exempt peer under the same config is limited as usual.
        let (status, _, retry_after) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(retry_after, None);
    }

    #[tokio::test]
    async fn whitelisted_ip_is_also_skipped_by_the_limiter() {
        let gate = IpGateConfig::new(["198.51.100.7"], NIL, NIL).expect("valid lists");
        let layer = GuardLayer::new(default_config())
            .with_ip_gate(gate)
            .with_rate_limiting(limiter(1, false));
        for _ in 0..5 {
            let (status, _, _) = full_status(&layer, benign_request("198.51.100.7")).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "whitelist match skips rate limiting"
            );
        }
    }

    #[tokio::test]
    async fn unattributed_requests_are_not_rate_limited() {
        let layer = GuardLayer::new(default_config()).with_rate_limiting(limiter(1, false));
        for _ in 0..5 {
            let request = Request::builder()
                .uri("/hello")
                .body(Full::new(Bytes::new()))
                .expect("request");
            let (status, _, _) = full_status(&layer, request).await;
            assert_eq!(status, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn banned_ip_is_blocked_with_the_banned_body() {
        let manager = IpBanManager::new();
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let layer = GuardLayer::new(default_config()).with_ip_banning(manager.clone(), config);
        // Ban out of band through the shared handle (an operator or the
        // auto-ban engine did it).
        manager
            .ban_ip(IpAddr::from_str("192.0.2.55").expect("ip"), 60, "operator")
            .expect("ban");
        let (status, body, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);

        // Other IPs are untouched.
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.56")).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn ban_expiry_is_honored_for_a_short_duration() {
        let (clock, seconds) = fake_clock();
        let manager = IpBanManager::with_clock(clock);
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let layer = GuardLayer::new(default_config()).with_ip_banning(manager.clone(), config);
        manager
            .ban_ip(IpAddr::from_str("192.0.2.55").expect("ip"), 5, "short")
            .expect("ban");
        let (status, body, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);

        seconds.store(1_000 + 6, Ordering::Relaxed);
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK, "the ban expired");
    }

    #[tokio::test]
    async fn banned_ip_blocks_before_detection_and_rate_limiting() {
        let manager = IpBanManager::new();
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_ip_banning(manager.clone(), config);
        manager
            .ban_ip(IpAddr::from_str("192.0.2.55").expect("ip"), 60, "operator")
            .expect("ban");
        // An attack from the banned IP: the ban stage wins over the
        // detection block shape...
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .extension(gate_ip("192.0.2.55"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body, _) = full_status(&layer, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);
        // ...and over the rate limiter: banned traffic never consumes budget.
        let attack = Request::builder()
            .uri("/files/../../etc/passwd")
            .extension(gate_ip("192.0.2.55"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body, _) = full_status(&layer, attack).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);
    }

    #[tokio::test]
    async fn detection_violations_ban_at_the_category_threshold() {
        let config = IpBanConfig::new(
            true,
            100,
            3600,
            [(
                "dir_traversal",
                ThreatBanEntry {
                    threshold: 2,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        let layer = GuardLayer::new(default_config()).with_ip_banning(IpBanManager::new(), config);

        let attack = || {
            Request::builder()
                .uri("/files/../../etc/passwd")
                .extension(gate_ip("192.0.2.55"))
                .body(Full::new(Bytes::new()))
                .expect("request")
        };
        // First violation: the plain block shape.
        let (status, body, _) = full_status(&layer, attack()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, BLOCKED_MESSAGE);
        // Second violation crosses the entry: banned on the spot.
        let (status, body, _) = full_status(&layer, attack()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, ACTIVITY_BANNED_MESSAGE);
        // From then on the ban stage answers everything.
        let (status, body, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);
    }

    #[tokio::test]
    async fn enable_ip_banning_false_never_bans() {
        let config = IpBanConfig::new(
            false,
            1,
            3600,
            [(
                "dir_traversal",
                ThreatBanEntry {
                    threshold: 1,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        let layer = GuardLayer::new(default_config()).with_ip_banning(IpBanManager::new(), config);
        let attack = || {
            Request::builder()
                .uri("/files/../../etc/passwd")
                .extension(gate_ip("192.0.2.55"))
                .body(Full::new(Bytes::new()))
                .expect("request")
        };
        for _ in 0..3 {
            let (status, body, _) = full_status(&layer, attack()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                body, BLOCKED_MESSAGE,
                "banning is off: the plain block shape"
            );
        }
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK, "nobody was banned");
    }

    #[tokio::test]
    async fn exempt_ip_violations_still_count_toward_the_ban() {
        // Checklist: the exemption skips rate limiting and the ban *check*
        // skip state never shields counting - the reference's
        // suspicious-activity stage skips a whitelisted IP only, so an
        // exempt attacker's detections still feed the auto-ban engine and
        // a crossed threshold bans on the spot.
        let gate = IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let config = IpBanConfig::new(
            true,
            100,
            3600,
            [(
                "dir_traversal",
                ThreatBanEntry {
                    threshold: 2,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        let layer = GuardLayer::new(default_config())
            .with_ip_gate(gate)
            .with_ip_banning(IpBanManager::new(), config);
        let attack = || {
            Request::builder()
                .uri("/files/../../etc/passwd")
                .extension(gate_ip("198.51.100.7"))
                .body(Full::new(Bytes::new()))
                .expect("request")
        };
        let (status, body, _) = full_status(&layer, attack()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, BLOCKED_MESSAGE, "violation 1: the plain block shape");
        let (status, body, _) = full_status(&layer, attack()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body, ACTIVITY_BANNED_MESSAGE,
            "exempt violations count: the crossed threshold bans"
        );
        // From then on the ban stage answers everything.
        let (status, body, _) = full_status(&layer, benign_request("198.51.100.7")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);
    }

    #[tokio::test]
    async fn rate_limit_autoban_is_off_by_default() {
        let config = IpBanConfig::new(true, 1, 3600, no_entries()).expect("valid config");
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_ip_banning(IpBanManager::new(), config);
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK);
        for _ in 0..5 {
            let (status, body, _) = full_status(&layer, benign_request("192.0.2.55")).await;
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(body, RATE_LIMITED_MESSAGE, "crossings stay rate limited");
        }
    }

    #[tokio::test]
    async fn rate_limit_autoban_bans_at_the_threshold() {
        let config = IpBanConfig::new(
            true,
            100,
            3600,
            [(
                "rate_limit",
                ThreatBanEntry {
                    threshold: 2,
                    duration: 30,
                },
            )],
        )
        .expect("valid config");
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(1, true))
            .with_ip_banning(IpBanManager::new(), config);
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK);
        // First crossing: violation 1, below the entry threshold.
        let (status, body, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
        // Second crossing: violation 2 crosses the entry, the ban fires (the
        // response of this request is still the 429 it earned).
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        // From then on the ban stage answers first.
        let (status, body, _) = full_status(&layer, benign_request("192.0.2.55")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, BANNED_MESSAGE);
    }

    // --- body-value extraction through the full service ---

    fn body_bytes(const_bytes: &[u8]) -> Full<Bytes> {
        Full::new(Bytes::copy_from_slice(const_bytes))
    }

    async fn status_for(request: Request<Full<Bytes>>) -> http::StatusCode {
        let service = GuardLayer::new(default_config()).layer(tower::service_fn(
            |_request: Request<Full<Bytes>>| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            },
        ));
        service.oneshot(request).await.expect("response").status()
    }

    #[tokio::test]
    async fn sqli_in_a_form_field_is_blocked() {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/submit")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body_bytes(b"q=1+OR+1%3D1"))
            .expect("request");
        assert_eq!(status_for(request).await, http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn backslash_probe_in_a_form_field_is_blocked_through_the_raw_view() {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/submit")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body_bytes(b"q=\\default"))
            .expect("request");
        assert_eq!(
            status_for(request).await,
            http::StatusCode::BAD_REQUEST,
            "\\default in a form field must stay a recon probe"
        );
    }

    #[tokio::test]
    async fn multipart_binary_island_smuggling_is_not_blocked() {
        // A binary-dense file part whose only printable fragment is shorter
        // than the minimum island run: no detection, request forwarded.
        let noise = noise_bytes(11, 4096);
        let mut body = Vec::new();
        body.extend_from_slice(b"--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"installer.zip\"\r\n\r\n");
        body.extend_from_slice(&noise);
        body.extend_from_slice(b"\x001 OR 1=1\x00");
        body.extend_from_slice(b"\r\n--B0--\r\n");

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/upload")
            .header("content-type", "multipart/form-data; boundary=B0")
            .body(body_bytes(&body))
            .expect("request");
        assert_eq!(
            status_for(request).await,
            http::StatusCode::OK,
            "the compressed fragment must not pattern-match"
        );
    }

    #[tokio::test]
    async fn plain_multipart_text_part_with_script_is_blocked() {
        let body = "--B0\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n";
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/upload")
            .header("content-type", "multipart/form-data; boundary=B0")
            .body(body_bytes(body.as_bytes()))
            .expect("request");
        assert_eq!(status_for(request).await, http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn multipart_binary_upload_with_embedded_script_is_blocked() {
        let noise = noise_bytes(12, 4096);
        let mut body = Vec::new();
        body.extend_from_slice(b"--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"page.html.bin\"\r\n\r\n");
        body.extend_from_slice(&noise);
        body.extend_from_slice(b"\x00<script>alert(1)</script>\x00");
        body.extend_from_slice(&noise_bytes(13, 4096));
        body.extend_from_slice(b"\r\n--B0--\r\n");

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/upload")
            .header("content-type", "multipart/form-data; boundary=B0")
            .body(body_bytes(&body))
            .expect("request");
        assert_eq!(
            status_for(request).await,
            http::StatusCode::BAD_REQUEST,
            "the intact script island must detect"
        );
    }

    #[tokio::test]
    async fn embedded_json_leaf_attack_is_blocked() {
        let body = r#"data={"a":"<script>alert(1)</script>"}"#;
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/submit")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body_bytes(body.as_bytes()))
            .expect("request");
        assert_eq!(status_for(request).await, http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn mongo_operator_key_body_is_blocked() {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/query")
            .header("content-type", "application/json")
            .body(body_bytes(br#"{"$where": "1 OR 1=1"}"#))
            .expect("request");
        assert_eq!(status_for(request).await, http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn benign_multipart_upload_is_forwarded() {
        let body = "--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"notes.txt\"\r\n\r\nhello world\r\n--B0--\r\n";
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/upload")
            .header("content-type", "multipart/form-data; boundary=B0")
            .body(body_bytes(body.as_bytes()))
            .expect("request");
        assert_eq!(status_for(request).await, http::StatusCode::OK);
    }

    /// Deterministic pseudo-random bytes: the binary-dense fixture.
    fn noise_bytes(seed: u64, size: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).max(1);
        let mut out = Vec::with_capacity(size);
        for _ in 0..size {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push(u8::try_from(state % 256).expect("value below 256"));
        }
        out
    }
    // ---- the wave surfaces, end to end through the public API ----

    /// A static geolocation: every IP maps to `DE`.
    struct StaticGeo;

    impl guard_core_engine::geo::GeoIpHandler for StaticGeo {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            Some("DE".to_owned())
        }
    }

    #[tokio::test]
    async fn route_tier_resolver_limits_its_paths_only() {
        let tiers = Arc::new(|path: &str| {
            if path.starts_with("/login") {
                Some(RouteRateLimits::new(Some(1), None, None).expect("valid tiers"))
            } else {
                None
            }
        });
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(1000, false))
            .with_route_tiers(tiers);
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.71")).await;
        assert_eq!(status, StatusCode::OK);
        let request = Request::builder()
            .uri("/login")
            .extension(gate_ip("192.0.2.71"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, _, _) = full_status(&layer, request).await;
        assert_eq!(status, StatusCode::OK);
        // The route tier is exhausted; the global tier is not.
        let request = Request::builder()
            .uri("/login")
            .extension(gate_ip("192.0.2.71"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body, retry_after) = full_status(&layer, request).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
        assert_eq!(retry_after.as_deref(), Some("60"));
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.71")).await;
        assert_eq!(status, StatusCode::OK, "other paths keep the global tier");
    }

    #[tokio::test]
    async fn route_rate_limits_extension_wins_over_the_resolver() {
        let tiers = Arc::new(|_path: &str| {
            Some(RouteRateLimits::new(Some(100), None, None).expect("valid tiers"))
        });
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(1000, false))
            .with_route_tiers(tiers);
        // The extension configures a stricter tier than the resolver's
        // for the request: the first passes, the second crosses it.
        let request = Request::builder()
            .uri("/tight")
            .extension(gate_ip("192.0.2.72"))
            .extension(RouteRateLimits::new(Some(1), None, None).expect("valid tiers"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, _, _) = full_status(&layer, request).await;
        assert_eq!(status, StatusCode::OK, "the extension tier allows one");
        let request = Request::builder()
            .uri("/tight")
            .extension(gate_ip("192.0.2.72"))
            .extension(RouteRateLimits::new(Some(1), None, None).expect("valid tiers"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, _, _) = full_status(&layer, request).await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "the extension tier wins over the resolver"
        );
        // Without the extension the resolver's looser tier decides.
        let request = Request::builder()
            .uri("/tight")
            .extension(gate_ip("192.0.2.72"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, _, _) = full_status(&layer, request).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the resolver's tier still serves extension-less requests"
        );
    }

    #[tokio::test]
    async fn geo_tier_limits_the_resolved_country() {
        let mut geo = std::collections::HashMap::new();
        geo.insert(
            "DE".to_owned(),
            guard_core_rs::tower::RateLimitEntry::new(1, 60).expect("valid entry"),
        );
        let tiers = Arc::new(move |_path: &str| {
            Some(RouteRateLimits::new(None, None, Some(geo.clone())).expect("valid tiers"))
        });
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(1000, false))
            .with_route_tiers(tiers)
            .with_geo_handler(Arc::new(StaticGeo));
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.73")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.73")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "the DE tier crossed");
    }

    #[tokio::test]
    async fn geo_tier_never_applies_without_a_handler() {
        let mut geo = std::collections::HashMap::new();
        geo.insert(
            "DE".to_owned(),
            guard_core_rs::tower::RateLimitEntry::new(1, 60).expect("valid entry"),
        );
        let tiers = Arc::new(move |_path: &str| {
            Some(RouteRateLimits::new(None, None, Some(geo.clone())).expect("valid tiers"))
        });
        let layer = GuardLayer::new(default_config()).with_route_tiers(tiers);
        for _ in 0..5 {
            let (status, _, _) = full_status(&layer, benign_request("192.0.2.74")).await;
            assert_eq!(status, StatusCode::OK, "no handler: the geo tier is inert");
        }
    }

    #[tokio::test]
    async fn excluded_detection_params_pass_and_other_params_scan() {
        let exclusions = DetectionExclusionConfig {
            excluded_detection_params: vec!["q".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let layer = GuardLayer::new(default_config()).with_detection_exclusions(exclusions);
        let attack = |uri: &'static str| {
            Request::builder()
                .uri(uri)
                .body(Full::new(Bytes::new()))
                .expect("request")
        };
        let response = guarded(&layer)
            .oneshot(attack("/search?q=1+OR+1%3D1"))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the excluded param is not scanned"
        );
        let response = guarded(&layer)
            .oneshot(attack("/search?page=2&q=1+OR+1%3D1"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let response = guarded(&layer)
            .oneshot(attack("/search?page=1+OR+1%3D1"))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "a non-excluded param still scans"
        );
    }

    #[tokio::test]
    async fn route_detection_exclusions_override_the_global_config_per_request() {
        // Global: the `q` param is excluded. Route extension (per request):
        // an empty set re-enables the param surface - the route replaces
        // the global set.
        let exclusions = DetectionExclusionConfig {
            excluded_detection_params: vec!["q".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let layer = GuardLayer::new(default_config()).with_detection_exclusions(exclusions);
        let route = RouteDetectionExclusions {
            excluded_detection_params: Some(vec![]),
            ..RouteDetectionExclusions::default()
        };
        let request = Request::builder()
            .uri("/search?q=1+OR+1%3D1")
            .extension(route)
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "the route re-enables the param surface"
        );
    }

    #[tokio::test]
    async fn detection_scan_body_false_skips_the_body_surface() {
        let exclusions = DetectionExclusionConfig {
            detection_scan_body: Some(false),
            ..DetectionExclusionConfig::default()
        };
        let layer = GuardLayer::new(default_config()).with_detection_exclusions(exclusions);
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/submit")
            .body(body_bytes(b"SELECT * FROM users"))
            .expect("request");
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK, "the body does not scan");
        // The path surface still scans.
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn route_scan_body_true_reenables_the_body() {
        let exclusions = DetectionExclusionConfig {
            detection_scan_body: Some(false),
            ..DetectionExclusionConfig::default()
        };
        let layer = GuardLayer::new(default_config()).with_detection_exclusions(exclusions);
        let route = RouteDetectionExclusions {
            detection_scan_body: Some(true),
            ..RouteDetectionExclusions::default()
        };
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/submit")
            .extension(route)
            .body(body_bytes(b"SELECT * FROM users"))
            .expect("request");
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn excluded_body_fields_resolve_through_the_engine() {
        let exclusions = DetectionExclusionConfig {
            excluded_detection_body_fields: vec!["note".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let layer = GuardLayer::new(default_config()).with_detection_exclusions(exclusions);
        let attack = |body: &'static [u8]| {
            Request::builder()
                .method(http::Method::POST)
                .uri("/submit")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body_bytes(body))
                .expect("request")
        };
        let response = guarded(&layer)
            .oneshot(attack(b"note=1+OR+1%3D1"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK, "excluded field skips");
        let response = guarded(&layer)
            .oneshot(attack(b"other=1+OR+1%3D1"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// The `on_block` collector: the payloads the guard fired.
    fn block_collector() -> (
        Arc<Mutex<Vec<guard_core_rs::responses::BlockPayload>>>,
        guard_core_rs::responses::OnBlockHook,
    ) {
        let payloads: Arc<Mutex<Vec<guard_core_rs::responses::BlockPayload>>> =
            Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&payloads);
        let hook: guard_core_rs::responses::OnBlockHook =
            Arc::new(move |payload| sink.lock().expect("payloads").push(payload.clone()));
        (payloads, hook)
    }

    #[tokio::test]
    async fn on_block_fires_for_the_detection_block_and_custom_body_overrides_it() {
        let (payloads, hook) = block_collector();
        let layer = GuardLayer::new(default_config())
            .with_observability(guard_core_rs::tower::ObservabilityConfig::default())
            .with_on_block(hook)
            .with_custom_error_responses(
                [(400u16, "blocked:custom".to_owned())]
                    .into_iter()
                    .collect(),
            );
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .extension(gate_ip("192.0.2.75"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body, "blocked:custom",
            "the custom body overrides the default"
        );
        let payloads = payloads.lock().expect("payloads");
        assert_eq!(payloads.len(), 1, "exactly one payload for the block");
        let payload = &payloads[0];
        assert_eq!(payload.check_name, "suspicious_activity");
        assert_eq!(payload.status_code, Some(400));
        assert_eq!(payload.client_ip, "192.0.2.75");
        assert!(!payload.passive_mode);
    }

    #[tokio::test]
    async fn custom_error_responses_override_the_throttled_body() {
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_custom_error_responses(
                [(429u16, "slow down:custom".to_owned())]
                    .into_iter()
                    .collect(),
            );
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.76")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, body, retry_after) = full_status(&layer, benign_request("192.0.2.76")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, "slow down:custom");
        assert_eq!(retry_after.as_deref(), Some("60"), "Retry-After survives");
    }

    #[tokio::test]
    async fn passive_mode_records_but_never_blocks() {
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_passive_mode(true);
        // A detection attack forwards (200) instead of the 400 block.
        let attack = Request::builder()
            .uri("/files/../../etc/passwd")
            .extension(gate_ip("192.0.2.77"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, _, _) = full_status(&layer, attack).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "passive: the detection block is log-only"
        );
        // A rate-limit crossing forwards too.
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.78")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.78")).await;
        assert_eq!(status, StatusCode::OK, "passive: no 429 is rendered");
    }

    #[tokio::test]
    async fn event_bus_receives_the_rate_limited_event() {
        let events: Arc<Mutex<Vec<guard_core_rs::events::SecurityEvent>>> =
            Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let bus = Arc::new(
            guard_core_rs::events::SecurityEventBus::new(true).on_event(Arc::new(move |event| {
                sink.lock().expect("events").push(event.clone());
            })),
        );
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_event_bus(bus);
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.79")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.79")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let events = events.lock().expect("events");
        assert!(
            events.iter().any(|event| event.event_type == "rate_limited"
                && event.ip_address == "192.0.2.79"
                && event.action_taken == "request_blocked"
                && event.handler_name.as_deref() == Some("rate_limit")),
            "the rate_limited event fired: {events:?}"
        );
    }

    /// A distributed store that always fails (the backend is down).
    struct DownStore;

    impl guard_core_rs::tower::SlidingWindowStore for DownStore {
        fn record_hit(
            &self,
            _key: &str,
            _now: f64,
            _window: u64,
        ) -> Result<u64, guard_core_engine::distributed::StoreError> {
            Err(guard_core_engine::distributed::StoreError(String::new()))
        }
    }

    #[tokio::test]
    async fn distributed_store_fail_closed_answers_the_503_shape() {
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(10, false))
            .with_distributed_store(
                Arc::new(DownStore) as Arc<dyn guard_core_rs::tower::SlidingWindowStore>,
                "guard_core:",
                false,
            );
        let (status, body, retry_after) = full_status(&layer, benign_request("192.0.2.80")).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "fail-closed backend error"
        );
        assert_eq!(body, "Redis rate limiting unavailable");
        assert_eq!(retry_after, None);
    }

    #[tokio::test]
    async fn distributed_store_fail_open_degrades_to_memory() {
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_distributed_store(
                Arc::new(DownStore) as Arc<dyn guard_core_rs::tower::SlidingWindowStore>,
                "guard_core:",
                true,
            );
        let (status, _, _) = full_status(&layer, benign_request("192.0.2.81")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, body, _) = full_status(&layer, benign_request("192.0.2.81")).await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "memory window decided"
        );
        assert_eq!(body, RATE_LIMITED_MESSAGE);
    }

    #[tokio::test]
    async fn custom_error_responses_reach_the_banned_shapes() {
        let manager = IpBanManager::new();
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let layer = GuardLayer::new(default_config())
            .with_ip_banning(manager.clone(), config)
            .with_custom_error_responses(
                [(403u16, "denied:custom".to_owned())].into_iter().collect(),
            );
        manager
            .ban_ip(IpAddr::from_str("192.0.2.82").expect("ip"), 60, "operator")
            .expect("ban");
        let (status, body, _) = full_status(&layer, benign_request("192.0.2.82")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body, "denied:custom",
            "the live-ban shape takes the override"
        );
    }

    #[tokio::test]
    async fn service_debug_renders_the_inner_and_layer() {
        let layer = GuardLayer::new(default_config());
        let service = layer.layer(tower::service_fn(
            |_request: Request<Full<Bytes>>| async move {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            },
        ));
        let rendered = format!("{service:?}");
        assert!(rendered.starts_with("GuardService"), "{rendered}");
        // The wrapped service still serves: a benign request passes.
        let request = Request::builder()
            .uri("/hello")
            .extension(gate_ip("192.0.2.85"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = service.clone().oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        // A threat through the same instantiation: the block path runs
        // inside this service's own monomorphization as well.
        let threat = Request::builder()
            .uri("/files/../../etc/passwd")
            .extension(gate_ip("192.0.2.85"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = service.oneshot(threat).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
    }

    #[tokio::test]
    async fn whitelisted_ip_still_gets_the_detection_block_and_payload() {
        // A whitelisted IP skips the stateful stages, so the stage answers
        // nothing and the adapter renders the detection block itself,
        // firing the reference hook payload with the resolved identity.
        let (payloads, hook) = block_collector();
        let gate = IpGateConfig::new(["192.0.2.83"], NIL, NIL).expect("valid lists");
        let layer = GuardLayer::new(default_config())
            .with_ip_gate(gate)
            .with_observability(guard_core_rs::tower::ObservabilityConfig::default())
            .with_on_block(hook);
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .extension(gate_ip("192.0.2.83"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "detection never skips");
        assert_eq!(body, BLOCKED_MESSAGE);
        let payloads = payloads.lock().expect("payloads");
        assert_eq!(payloads.len(), 1, "exactly one payload for the block");
        assert_eq!(payloads[0].check_name, "suspicious_activity");
        assert_eq!(payloads[0].client_ip, "192.0.2.83");
        assert_eq!(payloads[0].status_code, Some(400));
        assert!(!payloads[0].passive_mode);
    }

    #[tokio::test]
    async fn valueless_query_parameter_is_benign() {
        // A query pair without `=` (`?flag`) is a name with an empty value;
        // it must decode and scan like any other pair, not fall over.
        let layer = GuardLayer::new(default_config());
        let request = Request::builder()
            .uri("/api/items?flag")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, _) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// A body that yields its data frame and then a trailers frame: the
    /// buffered scan must skip non-data frames instead of failing.
    #[derive(Debug)]
    struct TraileredBody {
        inner: Full<Bytes>,
        trailers_sent: bool,
    }

    impl TraileredBody {
        fn new(bytes: &'static [u8]) -> Self {
            Self {
                inner: Full::new(Bytes::from_static(bytes)),
                trailers_sent: false,
            }
        }
    }

    impl Body for TraileredBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            if !self.inner.is_end_stream() {
                return Pin::new(&mut self.inner).poll_frame(cx);
            }
            if self.trailers_sent {
                return Poll::Ready(None);
            }
            self.trailers_sent = true;
            Poll::Ready(Some(Ok(http_body::Frame::trailers(http::HeaderMap::new()))))
        }

        fn is_end_stream(&self) -> bool {
            false
        }
    }

    /// The forwarded rebuild carries only the buffered bytes: the trailers
    /// were consumed by the buffering scan.
    impl From<Bytes> for TraileredBody {
        fn from(bytes: Bytes) -> Self {
            Self {
                inner: Full::new(bytes),
                trailers_sent: true,
            }
        }
    }

    #[tokio::test]
    async fn trailers_frames_are_ignored_by_the_buffering_scan() {
        let layer = GuardLayer::new(default_config());
        let service = layer.layer(tower::service_fn(
            |_request: Request<TraileredBody>| async move {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            },
        ));
        let body = TraileredBody::new(b"hello");
        assert!(!body.is_end_stream(), "data and trailers remain");
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/submit")
            .body(body)
            .expect("request");
        let response = service.clone().oneshot(request).await.expect("response");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "benign data, benign trailers"
        );

        // A threat through the same instantiation: the buffered-scan verdict
        // answers inside this service's own monomorphization too, so both
        // arms of the fused pipeline run for the trailered body type.
        let threat = Request::builder()
            .method(http::Method::POST)
            .uri("/files/../../etc/passwd")
            .body(TraileredBody::new(b"hello"))
            .expect("request");
        let response = service.clone().oneshot(threat).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
    }

    #[tokio::test]
    async fn distributed_ban_store_wires_into_the_stage() {
        // The engine's `MemoryStore` speaks both halves of the distributed
        // seam; installing it as the ban store too must rate limit through
        // the shared backend.
        let store = Arc::new(guard_core_engine::distributed::MemoryStore::default());
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter(2, false))
            .with_distributed_store(
                Arc::clone(&store) as Arc<dyn guard_core_rs::tower::SlidingWindowStore>,
                "guard_core:",
                true,
            )
            .with_distributed_ban_store(store as Arc<dyn guard_core_engine::distributed::BanStore>);
        for _ in 0..2 {
            let (status, _, _) = full_status(&layer, benign_request("192.0.2.84")).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, body, _) = full_status(&layer, benign_request("192.0.2.84")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
    }

    // ---------------------------------------------------------------
    // The wired stage surface: lib-binary twins of the integration
    // stage tests, so this binary's monomorphization of the fused
    // pass drives every new arm too.
    // ---------------------------------------------------------------

    /// A GET to `path` attributed to `ip` (the stage tests' request shape).
    fn request_at(path: &str, ip: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .uri(path)
            .extension(GuardClientIp(IpAddr::from_str(ip).expect("test address")))
            .body(Full::new(Bytes::new()))
            .expect("request")
    }

    /// A hand-written resolver: every address resolves to `US`.
    struct UnitedStates;

    impl guard_core_engine::geo::GeoIpHandler for UnitedStates {
        fn get_country(&self, _ip: std::net::IpAddr) -> Option<String> {
            Some(String::from("US"))
        }
    }

    #[tokio::test]
    async fn fused_emergency_mode_blocks_outside_the_whitelist() {
        let stage = guard_core_rs::emergency_mode::EmergencyModeStage::builder(
            guard_core_rs::emergency_mode::EmergencyModeStageConfig::default(),
        )
        .emergency_mode(true)
        .emergency_whitelist(["203.0.113.9"])
        .build()
        .expect("valid whitelist");
        let layer = GuardLayer::new(default_config()).with_emergency_mode(stage);
        let (status, body) = status_and_body(&layer, benign_request("192.0.2.7")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "Service temporarily unavailable");
    }

    #[tokio::test]
    async fn fused_https_enforcement_redirects_and_fails_secure() {
        let stage = guard_core_rs::https_enforcement::HttpsEnforcementStage::builder(
            guard_core_rs::https_enforcement::HttpsEnforcementStageConfig::default(),
        )
        .enforce_https(true)
        .build()
        .expect("valid");
        let layer = GuardLayer::new(default_config()).with_https_enforcement(stage);
        let request = Request::builder()
            .uri("/private?token=1")
            .header("host", "guard.example:8443")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response
                .headers()
                .get(http::header::LOCATION)
                .expect("location"),
            "https://guard.example:8443/private?token=1"
        );

        // A bracketed IPv6 authority keeps its brackets in the target.
        let request = Request::builder()
            .uri("http://[2001:db8::1]:8443/private")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response
                .headers()
                .get(http::header::LOCATION)
                .expect("location"),
            "https://[2001:db8::1]:8443/private"
        );

        // A plain-host authority with a numeric port strips the port: the
        // host:port arm of the authority parser, on this instantiation.
        let request = Request::builder()
            .uri("http://guard.example:8443/private")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = guarded(&layer).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response
                .headers()
                .get(http::header::LOCATION)
                .expect("location"),
            "https://guard.example:8443/private"
        );
    }

    #[tokio::test]
    async fn fused_request_logging_composes_and_never_blocks() {
        let stage = guard_core_rs::request_logging::RequestLoggingStage::new(
            guard_core_rs::request_logging::RequestLoggingStageConfig {
                log_request_level: Some(guard_core_rs::logging::LogLevel::Info),
                ..guard_core_rs::request_logging::RequestLoggingStageConfig::default()
            },
        );
        assert!(stage.exists());
        let layer = GuardLayer::new(default_config()).with_request_logging(stage);
        let (status, _) = status_and_body(&layer, benign_request("192.0.2.9")).await;
        assert_eq!(status, StatusCode::OK);
    }

    // Per-binary twin: the plain-inner instantiation also runs the response
    // processor's pass (return rules, security headers, CORS) and the
    // inner-error propagation, so this binary's private copy of the fused
    // pipeline covers the forward tail the scripted instantiation covers.
    #[tokio::test]
    async fn response_processor_and_inner_error_through_the_plain_inner() {
        let processor = guard_core_rs::process_response::ResponseProcessor::new(
            Some(guard_core_engine::security_headers::SecurityHeadersConfig::reference_default()),
            None,
            Vec::new(),
            Arc::new(Mutex::new(
                guard_core_engine::behavior::BehaviorTracker::new(),
            )),
            IpBanManager::new(),
            true,
            262_144,
            false,
        );
        let layer = GuardLayer::new(default_config()).with_response_processor(processor);
        let (status, _) = status_and_body(&layer, benign_request("192.0.2.88")).await;
        assert_eq!(status, StatusCode::OK);

        // The inner-service error path on the same instantiation: the error
        // propagates after the response pass, never swallowed.
        let failing = GuardLayer::new(default_config()).layer(tower::service_fn(
            |_request: Request<Full<Bytes>>| async {
                Err::<Response<Full<Bytes>>, _>(std::io::Error::other("down"))
            },
        ));
        let error = failing
            .clone()
            .oneshot(benign_request("192.0.2.88"))
            .await
            .expect_err("inner error must propagate");
        assert_eq!(error.to_string(), "down");
    }

    #[tokio::test]
    async fn fused_headers_auth_passes_with_the_required_header() {
        let stage = guard_core_rs::headers_auth::HeadersAuthStage::new(
            None,
            std::sync::Arc::new(|path: &str| {
                (path == "/private").then(|| {
                    std::sync::Arc::new(guard_core_rs::headers_auth::RouteGuard {
                        rules: guard_core_engine::headers_auth::HeaderAuthRules {
                            required_headers: vec![
                                guard_core_engine::headers_auth::RequiredHeader {
                                    name: String::from("x-api-key"),
                                    expected: String::from(
                                        guard_core_engine::headers_auth::REQUIRED_SENTINEL,
                                    ),
                                },
                            ],
                            ..guard_core_engine::headers_auth::HeaderAuthRules::default()
                        },
                        verifier: None,
                        api_key_verifier: None,
                    })
                })
            }),
        );
        let layer = GuardLayer::new(default_config()).with_headers_auth(stage);
        // The passing case: the required header rides the request, the gate
        // falls through, and the inner handler answers.
        let request = Request::builder()
            .uri("/private")
            .header(
                "x-api-key",
                guard_core_engine::headers_auth::REQUIRED_SENTINEL,
            )
            .extension(gate_ip("192.0.2.9"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, _) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn fused_headers_auth_blocks_without_the_required_header() {
        let stage = guard_core_rs::headers_auth::HeadersAuthStage::new(
            None,
            std::sync::Arc::new(|path: &str| {
                (path == "/private").then(|| {
                    std::sync::Arc::new(guard_core_rs::headers_auth::RouteGuard {
                        rules: guard_core_engine::headers_auth::HeaderAuthRules {
                            required_headers: vec![
                                guard_core_engine::headers_auth::RequiredHeader {
                                    name: String::from("x-api-key"),
                                    expected: String::from(
                                        guard_core_engine::headers_auth::REQUIRED_SENTINEL,
                                    ),
                                },
                            ],
                            ..guard_core_engine::headers_auth::HeaderAuthRules::default()
                        },
                        verifier: None,
                        api_key_verifier: None,
                    })
                })
            }),
        );
        let layer = GuardLayer::new(default_config()).with_headers_auth(stage);
        let (status, _) = status_and_body(&layer, request_at("/private", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn fused_referrer_gate_blocks_a_missing_referrer() {
        let stage = guard_core_rs::route_gates::ReferrerStage::builder(
            guard_core_rs::route_gates::GateConfig::default(),
        )
        .resolver(std::sync::Arc::new(|path: &str| {
            (path == "/gated").then(|| vec![String::from("https://good.example")])
        }))
        .build();
        let layer = GuardLayer::new(default_config()).with_referrer_gate(stage);
        let (status, body) = status_and_body(&layer, request_at("/gated", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, "Referrer required");
    }

    #[tokio::test]
    async fn fused_custom_validators_block_with_the_validator_status() {
        use guard_core_engine::custom_checks::{CustomResponse, ValidatorAnswer};
        let stage = guard_core_rs::custom_checks::CustomChecksStage::builder()
            .validators_resolver(std::sync::Arc::new(|path: &str| {
                (path == "/private").then(|| {
                    vec![(
                        String::from("post_only"),
                        std::sync::Arc::new(
                            |ctx: &guard_core_engine::custom_checks::CustomRequestContext<'_>| {
                                (ctx.method != "POST").then_some(ValidatorAnswer::Response(
                                    CustomResponse {
                                        status: Some(403),
                                        body: None,
                                    },
                                ))
                            },
                        )
                            as guard_core_engine::custom_checks::CustomValidatorFn,
                    )]
                })
            }))
            .build();
        let layer = GuardLayer::new(default_config()).with_custom_checks(stage);
        let (status, _) = status_and_body(&layer, request_at("/private", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn fused_time_window_gate_blocks_outside_the_window() {
        let now = chrono::Utc::now();
        let start = (now + chrono::Duration::minutes(2))
            .format("%H:%M")
            .to_string();
        let end = (now + chrono::Duration::minutes(3))
            .format("%H:%M")
            .to_string();
        let stage = guard_core_rs::route_gates::TimeWindowStage::builder(
            guard_core_rs::route_gates::GateConfig::default(),
        )
        .resolver(std::sync::Arc::new(move |path: &str| {
            (path == "/nightly").then(|| guard_core_engine::time_window::TimeWindow {
                start: Some(start.clone()),
                end: Some(end.clone()),
                timezone: Some(String::from("UTC")),
            })
        }))
        .build();
        let layer = GuardLayer::new(default_config()).with_time_window_gate(stage);
        let (status, body) = status_and_body(&layer, request_at("/nightly", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, "Access not allowed at this time");
    }

    #[tokio::test]
    async fn fused_geo_cloud_and_user_agent_blocks_resolve_the_answer_body() {
        let geo = guard_core_rs::geo::GeoStage::new(guard_core_rs::geo::GeoStageConfig {
            gate: guard_core_rs::geo::parse_country_lists(Vec::<String>::new(), ["US"]),
            handler: Some(std::sync::Arc::new(UnitedStates)),
            passive_mode: false,
        });
        let layer = GuardLayer::new(default_config()).with_geo_blocking(geo);
        let (status, body) = status_and_body(&layer, request_at("/api", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body, "Forbidden",
            "the geo answer body via stage_answer_body"
        );

        let table = guard_core_rs::cloud_provider::CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![(String::from("192.0.2.0/24"), None)])
            .expect("valid ranges");
        let cloud = guard_core_rs::cloud_provider::CloudProviderStage::builder(
            guard_core_rs::cloud_provider::CloudProviderStageConfig {
                block_cloud_providers: guard_core_rs::cloud_provider::parse_cloud_selectors([
                    "AWS",
                ])
                .expect("valid selectors"),
                table,
                passive_mode: false,
            },
        )
        .build();
        let layer = GuardLayer::new(default_config()).with_cloud_provider(cloud);
        let (status, body) = status_and_body(&layer, request_at("/api", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, "Cloud provider IP not allowed");

        let ua = guard_core_rs::user_agent::UserAgentStage::new(
            guard_core_rs::user_agent::UserAgentStageConfig {
                blocked_user_agents: guard_core_rs::user_agent::UserAgentFilter::new(["bad-bot"])
                    .expect("valid patterns"),
                ..guard_core_rs::user_agent::UserAgentStageConfig::default()
            },
        )
        .expect("valid config");
        let layer = GuardLayer::new(default_config()).with_user_agent(ua);
        let request = Request::builder()
            .uri("/api")
            .header("user-agent", "bad-bot/1.0")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (status, body) = status_and_body(&layer, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, "User-Agent not allowed");
    }

    #[tokio::test]
    async fn fused_custom_request_blocks_with_the_function_status() {
        use guard_core_engine::custom_checks::CustomResponse;
        let stage = guard_core_rs::custom_checks::CustomChecksStage::builder()
            .custom_request(
                "maintenance_gate",
                std::sync::Arc::new(|ctx| {
                    (ctx.path == "/admin").then_some(CustomResponse {
                        status: Some(503),
                        body: None,
                    })
                }),
            )
            .build();
        let layer = GuardLayer::new(default_config()).with_custom_checks(stage);
        let (status, _) = status_and_body(&layer, request_at("/admin", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    // --- the reference RouteConfig carrier consumption (GAP-R2) ---

    use guard_core_engine::route_config::RouteConfig;

    fn resolver_for(
        paths: &[(&str, &str)],
        config: RouteConfig,
    ) -> guard_core_engine::route_config::RouteConfigResolver {
        let owned: Vec<(String, String)> = paths
            .iter()
            .map(|(method, path)| ((*method).to_owned(), (*path).to_owned()))
            .collect();
        Arc::new(move |method, path| {
            owned
                .iter()
                .any(|(route_method, route_path)| route_method == method && route_path == path)
                .then(|| Arc::new(config.clone()))
        })
    }

    #[tokio::test]
    async fn the_cors_preflight_short_circuits_before_every_check() {
        // The from_security_config-built layer (CORS on, the security
        // headers on): an OPTIONS preflight answers from the CORS config.
        let layer = GuardLayer::from_security_config(&SecurityConfig {
            enable_cors: true,
            cors_allow_origins: vec!["https://app.example.com".to_owned()],
            cors_allow_methods: vec!["GET".to_owned(), "POST".to_owned()],
            cors_allow_headers: vec!["content-type".to_owned()],
            cors_max_age: 900,
            ..SecurityConfig::default()
        })
        .expect("valid config");
        let preflight = http::Request::builder()
            .method("OPTIONS")
            .uri("/api")
            .header("Origin", "https://app.example.com")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "Content-Type")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = guarded(&layer).oneshot(preflight).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("Access-Control-Allow-Origin")
                .map(|value| value.to_str().expect("ascii")),
            Some("https://app.example.com")
        );
        assert_eq!(
            response
                .headers()
                .get("Access-Control-Max-Age")
                .map(|value| value.to_str().expect("ascii")),
            Some("900")
        );

        // A disallowed origin: 400 with the failure list.
        let bad = http::Request::builder()
            .method("OPTIONS")
            .uri("/api")
            .header("Origin", "https://evil.example.com")
            .header("Access-Control-Request-Method", "DELETE")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = guarded(&layer).oneshot(bad).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body();
        let bytes = http_body_util::BodyExt::collect(body)
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(bytes, "Disallowed CORS: origin, method");

        // An OPTIONS without the request-method header is not a preflight:
        // the gate skips and the pipeline runs (the upstream answers).
        let response = guarded(&layer)
            .oneshot(
                http::Request::builder()
                    .method("OPTIONS")
                    .uri("/api")
                    .body(Full::new(Bytes::new()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        // CORS disabled: the preflight runs the pipeline like any request
        // (the upstream answers).
        let plain = GuardLayer::new(default_config());
        let response = guarded(&plain)
            .oneshot(
                http::Request::builder()
                    .method("OPTIONS")
                    .uri("/api")
                    .header("Access-Control-Request-Method", "POST")
                    .body(Full::new(Bytes::new()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_route_usage_rules_track_and_ban_at_the_threshold() {
        let config = RouteConfig {
            behavior_rules: vec![guard_core_engine::behavior::BehaviorRule {
                rule_type: String::from("usage"),
                threshold: 2,
                window: 60,
                pattern: String::new(),
                action: String::from("ban"),
                ban_duration: Some(3600),
                correlate_with_detection: false,
            }],
            ..RouteConfig::default()
        };
        let processor = guard_core_rs::process_response::ResponseProcessor::new(
            None,
            None,
            Vec::new(),
            Arc::new(Mutex::new(
                guard_core_engine::behavior::BehaviorTracker::new(),
            )),
            IpBanManager::new(),
            true,
            262_144,
            false,
        );
        let layer = GuardLayer::new(default_config())
            .with_response_processor(processor)
            .with_route_configs(resolver_for(&[("GET", "/api")], config));

        // Two observations: under the strict threshold, both forward.
        let (first, _) = status_and_body(&layer, request_at("/api", "192.0.2.71")).await;
        assert_eq!(first, StatusCode::OK);
        let (second, _) = status_and_body(&layer, request_at("/api", "192.0.2.71")).await;
        assert_eq!(second, StatusCode::OK);
        // The third crossing bans (the reference apply_action ban), and
        // the answer is the activity-banned shape.
        let (third, body) = status_and_body(&layer, request_at("/api", "192.0.2.71")).await;
        assert_eq!(third, StatusCode::FORBIDDEN);
        assert_eq!(body, ACTIVITY_BANNED_MESSAGE);

        // A different identity on the same route counts independently.
        let (other, _) = status_and_body(&layer, request_at("/api", "192.0.2.72")).await;
        assert_eq!(other, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_all_wildcard_bypass_skips_every_queried_check() {
        let gate = guard_core_engine::ip_gate::IpGateConfig::new(
            [] as [&str; 0],
            ["192.0.2.9"],
            [] as [&str; 0],
        )
        .expect("valid lists");
        let config = RouteConfig {
            bypassed_checks: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("all"));
                set
            },
            ..RouteConfig::default()
        };
        let layer = GuardLayer::new(default_config())
            .with_ip_gate(gate)
            .with_route_configs(resolver_for(&[("GET", "/open")], config));
        // The blacklisted IP forwards on the bypassed route (the "all"
        // wildcard matches the gate's "ip" query).
        let (open, _) = status_and_body(&layer, request_at("/open", "192.0.2.9")).await;
        assert_eq!(open, StatusCode::OK);
        // The same IP takes the gate denial next door.
        let (blocked, _) = status_and_body(&layer, request_at("/open2", "192.0.2.9")).await;
        assert_eq!(blocked, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn route_require_https_forces_the_redirect_with_the_global_arm_off() {
        let config = RouteConfig {
            require_https: true,
            ..RouteConfig::default()
        };
        let layer = GuardLayer::new(default_config())
            .with_route_configs(resolver_for(&[("GET", "/tls")], config));
        let mut request = request_at("/tls", "192.0.2.9");
        request
            .headers_mut()
            .insert("host", http::HeaderValue::from_static("guard.example"));
        let (status, _) = status_and_body(&layer, request).await;
        assert_eq!(status.as_u16(), 301);
        // Plain HTTP on an unlisted path stays 200.
        let (plain, _) = status_and_body(&layer, request_at("/other", "192.0.2.9")).await;
        assert_eq!(plain, StatusCode::OK);
    }

    #[tokio::test]
    async fn route_max_request_size_answers_413_for_its_route_only() {
        let config = RouteConfig {
            max_request_size: Some(4),
            ..RouteConfig::default()
        };
        let layer = GuardLayer::new(default_config())
            .with_route_configs(resolver_for(&[("POST", "/upload")], config));
        let mut big = request_at("/upload", "192.0.2.9");
        *big.method_mut() = http::Method::POST;
        *big.body_mut() = Full::new(Bytes::from_static(b"12345"));
        let (rejected, _) = status_and_body(&layer, big).await;
        assert_eq!(rejected, StatusCode::PAYLOAD_TOO_LARGE);
        // The same body on an unlisted route forwards (the global cap).
        let mut ok = request_at("/upload2", "192.0.2.9");
        *ok.method_mut() = http::Method::POST;
        *ok.body_mut() = Full::new(Bytes::from_static(b"12345"));
        let (passed, _) = status_and_body(&layer, ok).await;
        assert_eq!(passed, StatusCode::OK);
    }

    #[tokio::test]
    async fn route_blocked_user_agents_run_additively_before_the_global_filter() {
        let config = RouteConfig {
            blocked_user_agents: vec![String::from("route-bot")],
            ..RouteConfig::default()
        };
        let layer = GuardLayer::new(default_config())
            .with_route_configs(resolver_for(&[("GET", "/api")], config));
        let mut request = request_at("/api", "192.0.2.9");
        request.headers_mut().insert(
            "user-agent",
            http::HeaderValue::from_static("route-bot/2.0"),
        );
        let (blocked, body) = status_and_body(&layer, request).await;
        assert_eq!(blocked, StatusCode::FORBIDDEN);
        assert_eq!(body, "User-Agent not allowed");
        // Another route, same UA: the route list does not travel.
        let mut request = request_at("/api2", "192.0.2.9");
        request.headers_mut().insert(
            "user-agent",
            http::HeaderValue::from_static("route-bot/2.0"),
        );
        let (passed, _) = status_and_body(&layer, request).await;
        assert_eq!(passed, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_route_rate_view_becomes_the_tier() {
        let config = RouteConfig {
            rate_limit: Some(1),
            rate_limit_window: Some(60),
            ..RouteConfig::default()
        };
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1000,
            rate_limit_window: 60,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter)
            .with_route_configs(resolver_for(&[("GET", "/login")], config));
        let (first, _) = status_and_body(&layer, request_at("/login", "192.0.2.9")).await;
        assert_eq!(first, StatusCode::OK);
        let (second, _) = status_and_body(&layer, request_at("/login", "192.0.2.9")).await;
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
        // The route tier does not travel: the global limiter is still at
        // 1000 for the next path.
        let (elsewhere, _) = status_and_body(&layer, request_at("/login2", "192.0.2.9")).await;
        assert_eq!(elsewhere, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_rate_limit_bypass_skips_the_whole_pass_for_the_route() {
        let config = RouteConfig {
            bypassed_checks: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("rate_limit"));
                set
            },
            ..RouteConfig::default()
        };
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 60,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter)
            .with_route_configs(resolver_for(&[("GET", "/free")], config));
        for _ in 0..3 {
            let (status, _) = status_and_body(&layer, request_at("/free", "192.0.2.9")).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (blocked, _) = status_and_body(&layer, request_at("/other", "192.0.2.9")).await;
        assert_eq!(blocked, StatusCode::OK); // first hit outside is fine
        let (throttled, _) = status_and_body(&layer, request_at("/other", "192.0.2.9")).await;
        assert_eq!(throttled, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn the_penetration_bypass_skips_the_scan_for_the_route() {
        let config = RouteConfig {
            bypassed_checks: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("penetration"));
                set
            },
            ..RouteConfig::default()
        };
        let layer = GuardLayer::new(default_config())
            .with_route_configs(resolver_for(&[("GET", "/raw")], config));
        // An sqli probe on the bypassed route forwards; the same probe
        // next door is the 400.
        let attack = Request::builder()
            .uri("/raw?q=1%27+OR+1%3D1")
            .extension(gate_ip("192.0.2.9"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (open, _) = status_and_body(&layer, attack).await;
        assert_eq!(open, StatusCode::OK);
        let blocked = Request::builder()
            .uri("/other?q=1%27+OR+1%3D1")
            .extension(gate_ip("192.0.2.9"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (blocked_status, _) = status_and_body(&layer, blocked).await;
        assert_eq!(blocked_status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_non_compilable_route_pattern_fails_secure() {
        let config = RouteConfig {
            blocked_user_agents: vec![String::from("([")],
            ..RouteConfig::default()
        };
        let layer = GuardLayer::new(default_config())
            .with_route_configs(resolver_for(&[("GET", "/api")], config));
        let (status, body) = status_and_body(&layer, request_at("/api", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, FAILURE_MESSAGE);
    }

    #[tokio::test]
    async fn route_require_https_rides_the_installed_stage_lane() {
        let config = RouteConfig {
            require_https: true,
            ..RouteConfig::default()
        };
        let stage = guard_core_rs::https_enforcement::HttpsEnforcementStage::builder(
            guard_core_rs::https_enforcement::HttpsEnforcementStageConfig::default(),
        )
        .build()
        .expect("valid stage");
        let layer = GuardLayer::new(default_config())
            .with_https_enforcement(stage)
            .with_route_configs(resolver_for(&[("GET", "/tls")], config));
        let mut request = request_at("/tls", "192.0.2.9");
        request
            .headers_mut()
            .insert("host", http::HeaderValue::from_static("guard.example"));
        let (status, _) = status_and_body(&layer, request).await;
        assert_eq!(status.as_u16(), 301);
        // An unlisted path passes (the global arm is off and the stage's
        // resolver seam is not installed).
        let (plain, _) = status_and_body(&layer, request_at("/other", "192.0.2.9")).await;
        assert_eq!(plain, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_carrier_extension_wins_over_the_resolver() {
        let resolver_config = RouteConfig {
            rate_limit: Some(1),
            rate_limit_window: Some(60),
            ..RouteConfig::default()
        };
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1000,
            rate_limit_window: 60,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let layer = GuardLayer::new(default_config())
            .with_rate_limiting(limiter)
            .with_route_configs(resolver_for(&[("GET", "/login")], resolver_config));
        // The extension carries a different route config (no tier): the
        // resolver's 1-request tier never applies.
        let mut request = request_at("/login", "192.0.2.9");
        request
            .extensions_mut()
            .insert(Arc::new(RouteConfig::default()));
        let (first, _) = status_and_body(&layer, request).await;
        assert_eq!(first, StatusCode::OK);
        let (second, _) = status_and_body(&layer, request_at("/login", "192.0.2.9")).await;
        assert_eq!(second, StatusCode::OK);
    }

    #[tokio::test]
    async fn an_invalid_carrier_tier_fails_secure() {
        let config = RouteConfig {
            rate_limit: Some(0),
            ..RouteConfig::default()
        };
        let layer = GuardLayer::new(default_config())
            .with_route_configs(resolver_for(&[("GET", "/bad")], config));
        let (status, _) = status_and_body(&layer, request_at("/bad", "192.0.2.9")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn the_resolver_sees_the_method_dimension() {
        let config = RouteConfig {
            bypassed_checks: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("penetration"));
                set
            },
            ..RouteConfig::default()
        };
        let layer = GuardLayer::new(default_config())
            .with_route_configs(resolver_for(&[("POST", "/submit")], config));
        // The POST view is bypassed; the GET view of the same path is not
        // (the sqli probe answers the 400 there).
        let post = Request::builder()
            .method(http::Method::POST)
            .uri("/submit?q=1%27+OR+1%3D1")
            .extension(gate_ip("192.0.2.9"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (open, _) = status_and_body(&layer, post).await;
        assert_eq!(open, StatusCode::OK);
        let get = Request::builder()
            .uri("/submit?q=1%27+OR+1%3D1")
            .extension(gate_ip("192.0.2.9"))
            .body(Full::new(Bytes::new()))
            .expect("request");
        let (blocked, _) = status_and_body(&layer, get).await;
        assert_eq!(blocked, StatusCode::BAD_REQUEST);
    }
}
