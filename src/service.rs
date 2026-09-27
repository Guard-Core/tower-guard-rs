//! The middleware service: body buffering, view scanning, dispatching.

use crate::GuardClientIp;
use crate::GuardLayer;
use crate::body::{BoxError, GuardBody};
use crate::response;
use bytes::{Bytes, BytesMut};
use guard_core_engine::body_scan::extract_body_scan_values;
use guard_core_engine::detect::Threat;
use guard_core_engine::ip_ban::RATE_LIMIT_CATEGORY;
use guard_core_engine::ip_gate::IpGateDecision;
use guard_core_engine::ip_gate::IpGateVerdict;
use http::header::CONTENT_TYPE;
use http::request::Parts;
use http::{Request, Response};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};
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
    /// At least one view was flagged as a threat; the detection categories
    /// of the first flagged view, deduplicated and sorted (the auto-ban
    /// engine counts them per client IP).
    Threat(Vec<String>),
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

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let mut inner = self.inner.clone();
        let layer = self.layer.clone();
        Box::pin(async move {
            let (mut parts, mut body) = request.into_parts();

            // The IP gate runs before anything else: a denied IP must not
            // cost a body buffer, and detection still scans whatever passes.
            if let Some(denial) = enforce_ip_gate(&mut parts, &layer) {
                return Ok(denial.map(GuardBody::Generated));
            }

            // The stateful stage (dynamic bans, then rate limiting) runs on
            // every attributed, non-exempt request before a body buffer is
            // spent on it.
            if let Some(blocked) = enforce_state_stage(&parts, &layer) {
                return Ok(blocked.map(GuardBody::Generated));
            }

            let buffered = match buffer_body(&mut body, layer.body_cap()).await {
                Ok(buffered) => buffered,
                Err(BufferFailure::TooLarge) => {
                    return Ok(response::oversize().map(GuardBody::Generated));
                }
                Err(BufferFailure::Read) => {
                    return Ok(response::failure().map(GuardBody::Generated));
                }
            };
            match scan_request(&parts, buffered.as_ref(), &layer) {
                ScanOutcome::Clean => {
                    let rebuilt = B::from(buffered.unwrap_or_default());
                    let response = inner.call(Request::from_parts(parts, rebuilt)).await?;
                    Ok(response.map(GuardBody::Passthrough))
                }
                ScanOutcome::Threat(categories) => {
                    Ok(detect_block(&parts, &layer, &categories).map(GuardBody::Generated))
                }
                ScanOutcome::Failed => Ok(response::failure().map(GuardBody::Generated)),
            }
        })
    }
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
        IpGateVerdict::Denied(_) => Some(response::forbidden()),
    }
}

/// The client IP, when the request is attributable and not skipped by the
/// `exempt_ips` contract: the stateful stage's gate.
///
/// Unattributed requests cannot be banned, rate limited, or counted (the
/// stage cannot tell who to hold responsible); whitelisted and exempt IPs
/// skip exactly what the reference skips for a whitelist match. Detection
/// applies to both, always.
fn attributed_and_counting(parts: &Parts) -> Option<std::net::IpAddr> {
    let GuardClientIp(ip) = parts.extensions.get::<GuardClientIp>()?;
    let decision = parts
        .extensions
        .get::<IpGateDecision>()
        .copied()
        .unwrap_or_default();
    if decision.is_whitelisted || decision.is_exempt {
        return None;
    }
    Some(*ip)
}

/// The stateful stage: dynamic bans, then rate limiting, in the reference
/// pipeline's order (an IP ban check precedes the rate limiter).
///
/// Returns the block response when the stage denies the request:
/// `403 Forbidden` (`IP address banned`) for a live ban,
/// `429 Too Many Requests` with `Retry-After: <window>` for a crossing.
fn enforce_state_stage(parts: &Parts, layer: &GuardLayer) -> Option<Response<Full<Bytes>>> {
    let ip = attributed_and_counting(parts)?;

    // Ban check first: a banned IP is denied before its rate window is
    // touched, so banned traffic neither consumes budget nor counts
    // violations (the request never reaches the limiter).
    if let Some(ban) = layer.ban_state()
        && ban.config.enable_ip_banning
        && ban.manager.is_banned(ip)
    {
        return Some(response::banned_ip());
    }

    let limiter = layer.rate_limiter()?;
    let decision = limiter.check(ip, None);
    if decision.allowed {
        return None;
    }
    // Rate-limit autoban: every active crossing counts one `rate_limit`
    // violation toward the auto-ban engine (the reference's
    // `_record_rate_limit_autoban`). The response stays 429; the ban takes
    // effect on the next request, which the ban stage answers with 403.
    if limiter.config().enable_rate_limit_auto_ban
        && let Some(ban) = layer.ban_state()
    {
        ban.register_violations(ip, &[RATE_LIMIT_CATEGORY], "rate_limit_exceeded");
    }
    Some(response::rate_limited(decision.retry_after()))
}

/// The detection block for one flagged request, with the auto-ban engine
/// attached: the flagged view's categories count as violations for the
/// client IP, and a crossed threshold bans on the spot (the reference
/// pipeline's suspicious-activity stage). Banning configured and fired
/// answers `IP has been banned`; everything else keeps the family's
/// `Suspicious activity detected` block shape.
fn detect_block(parts: &Parts, layer: &GuardLayer, categories: &[String]) -> Response<Full<Bytes>> {
    // Counting is attribute-gated only: the engine's resolution refuses to
    // ban while the config's enable_ip_banning is off, and the violations
    // still count (enabling banning later starts from observed history).
    if let (Some(ban), Some(ip)) = (layer.ban_state(), attributed_and_counting(parts)) {
        let category_refs: Vec<&str> = categories.iter().map(String::as_str).collect();
        if ban
            .register_violations(ip, &category_refs, "penetration_attempt")
            .is_some()
        {
            return response::activity_banned();
        }
    }
    response::blocked()
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
        Ok(ScanOutcome::Threat(categories)) => ScanOutcome::Threat(sort_categories(categories)),
        Ok(outcome) => outcome,
        Err(_) => ScanOutcome::Failed,
    }
}

/// Deduplicate and sort the flagged view's categories: the deterministic
/// order the auto-ban engine resolves thresholds in (the Go port sorts too).
fn sort_categories(mut categories: Vec<String>) -> Vec<String> {
    categories.sort_unstable();
    categories.dedup();
    categories
}

/// One engine call per view, in the documented order: path, query, headers,
/// body. The first view the engine flags wins, and its categories are the
/// violation categories the auto-ban engine counts.
fn scan_views(parts: &Parts, body: Option<&Bytes>, layer: &GuardLayer) -> ScanOutcome {
    let path = parts.uri.path();
    if path != "/"
        && let Some(categories) = categories_for(layer, path, "url_path")
    {
        return ScanOutcome::Threat(categories);
    }

    if let Some(query) = parts.uri.query()
        && !query.is_empty()
        && let Some(categories) = categories_for(layer, query, "query_param")
    {
        return ScanOutcome::Threat(categories);
    }

    for (name, value) in &parts.headers {
        if is_excluded_header(name.as_str()) {
            continue;
        }
        // Opaque (non-ASCII) header values cannot be represented as `&str`.
        // They are skipped rather than guessed at, mirroring the string-typed
        // header maps the TypeScript adapters hand to the engine.
        let Ok(value) = value.to_str() else {
            continue;
        };
        if let Some(categories) = categories_for(layer, value, "header") {
            return ScanOutcome::Threat(categories);
        }
    }

    if let Some(bytes) = body {
        // Content-type routing (urlencoded fields, multipart parts, JSON
        // walks, blob fallback) happens in the engine; every extracted value
        // is scanned with its reference context instead of the lossy
        // whole-body blob.
        let content_type = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        if let Some(categories) = body_categories(layer, content_type, bytes) {
            return ScanOutcome::Threat(categories);
        }
    }

    ScanOutcome::Clean
}

/// Scan the buffered request body through the engine's body-value extraction
/// (`request_body` view).
///
/// Every extracted value goes through the normal detect path with the context
/// label the reference engine scans it under (`request_body:form_field`,
/// `request_body:multipart_field`, `:embedded_json` leaves, ...); the first
/// threat wins. A value with a forced category (a JSON mongo operator key the
/// reference reports straight from the JSON walk) is a threat outright. An
/// empty (or whitespace-only) body is not scanned, mirroring the previous
/// behavior.
fn body_categories(
    layer: &GuardLayer,
    content_type: Option<&str>,
    bytes: &[u8],
) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(bytes);
    if text.trim().is_empty() {
        return None;
    }
    for value in extract_body_scan_values(&text, content_type.unwrap_or(""), layer.config()) {
        if let Some(forced) = value.forced_category {
            return Some(vec![forced.to_owned()]);
        }
        if let Some(categories) = categories_for(layer, &value.content, &value.context) {
            return Some(categories);
        }
    }
    None
}

/// One engine call: the flagged view's threat categories, or `None` when the
/// engine clears the content. Regex threats carry the pattern table's
/// category; semantic threats carry their attack type.
fn categories_for(layer: &GuardLayer, content: &str, view: &str) -> Option<Vec<String>> {
    let verdict = (layer.detect_fn())(content, view, layer.config());
    if !verdict.is_threat {
        return None;
    }
    Some(
        verdict
            .threats
            .iter()
            .map(|threat| match threat {
                Threat::Regex(regex) => regex.category.clone(),
                Threat::Semantic(semantic) => semantic.attack_type.clone(),
            })
            .collect(),
    )
}

fn is_excluded_header(name: &str) -> bool {
    name.starts_with("sec-") || EXCLUDED_HEADERS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, BLOCKED_MESSAGE, FAILURE_MESSAGE,
        FORBIDDEN_MESSAGE, GuardClientIp, IpBanConfig, IpBanManager, IpGateConfig,
        RATE_LIMITED_MESSAGE, RateLimitConfig, RateLimiter, ThreatBanEntry, default_config,
    };
    use guard_core_engine::detect::{DetectConfig, DetectVerdict};
    use guard_core_engine::ip_ban::Clock;
    use guard_core_engine::ip_gate::IpGateDecision;
    use http::StatusCode;
    use http_body_util::Full;
    use std::convert::Infallible;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tower::{Layer, ServiceExt};
    fn panicking_detect(_content: &str, _context: &str, _config: &DetectConfig) -> DetectVerdict {
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

    async fn body_text(response: Response<GuardBody<Full<Bytes>>>) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn engine_panic_is_recovered_as_a_500() {
        let layer = GuardLayer::new(default_config()).with_detect_fn(panicking_detect);
        let service = layer.layer(tower::service_fn(
            |request: Request<Full<Bytes>>| async move {
                Ok::<_, Infallible>(Response::new(request.into_body()))
            },
        ));
        let request = Request::builder()
            .uri("/hello")
            .body(Full::new(Bytes::from_static(b"ping")))
            .expect("request");

        let response = service.oneshot(request).await.expect("response");
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
        assert_eq!(
            outcome,
            ScanOutcome::Threat(vec!["dir_traversal".to_owned()]),
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
        assert_eq!(outcome, ScanOutcome::Threat(vec!["sqli".to_owned()]));
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
        let response = service.oneshot(request).await.expect("response");
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn blocked_response_body_reports_the_documented_message() {
        let layer = GuardLayer::new(default_config());
        let service = layer.layer(tower::service_fn(|_request: Request<Full<Bytes>>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        }));
        let request = Request::builder()
            .uri("/files/../../etc/passwd")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = service.oneshot(request).await.expect("response");
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
    async fn exempt_ip_never_counts_detection_violations() {
        // Checklist: the exempt flag makes violation counting observable -
        // an exempt attacker can never be auto-banned.
        let gate = IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let config = IpBanConfig::new(
            true,
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
        for _ in 0..3 {
            let (status, body, _) = full_status(&layer, attack()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                body, BLOCKED_MESSAGE,
                "exempt violations are not counted, so no ban can fire"
            );
        }
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
}
