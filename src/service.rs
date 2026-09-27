//! The middleware service: body buffering, view scanning, dispatching.

use crate::GuardClientIp;
use crate::GuardLayer;
use crate::body::{BoxError, GuardBody};
use crate::response;
use bytes::{Bytes, BytesMut};
use guard_core_engine::detection_exclusions::{
    RequestSurfaces, RouteDetectionExclusions, resolve as resolve_exclusions,
};
use guard_core_engine::ip_gate::IpGateDecision;
use guard_core_engine::ip_gate::IpGateVerdict;
use guard_core_rs::responses::{build_block_payload, fire_block_hook, resolve_error_body};
use guard_core_rs::tower::{RequestObservation, RouteRateLimits};
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

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let inner = self.inner.clone();
        let layer = self.layer.clone();
        Box::pin(async move {
            let (mut parts, mut body) = request.into_parts();

            // The IP gate runs before anything else: a denied IP must not
            // cost a body buffer, and detection still scans whatever passes.
            if let Some(denial) = enforce_ip_gate(&mut parts, &layer) {
                return Ok(denial.map(GuardBody::Generated));
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
            let verdict = match scan_request(&parts, buffered.as_ref(), &layer) {
                ScanOutcome::Clean => None,
                ScanOutcome::Failed => return Ok(response::failure().map(GuardBody::Generated)),
                ScanOutcome::Threat(verdict) => Some(verdict),
            };

            // One engine-stage pass decides for every request: bans first
            // (403 `IP address banned`), then the rate-limit tiers
            // (429 + `Retry-After`), then the detection feed (the auto-ban
            // engine may answer `403 IP has been banned` on this very
            // request) - the reference pipeline order: `ip_security` (ban
            // check), `rate_limit`, `suspicious_activity`.
            let stage = layer
                .stage()
                .expect("the stage is built by GuardLayer::layer");
            let finding = verdict
                .as_ref()
                .map(|verdict| guard_core_rs::tower::ThreatFinding {
                    is_threat: true,
                    categories: verdict.categories.clone(),
                    trigger_info: verdict.reason.clone(),
                });
            let observation = request_observation(&parts);
            let decision = stage.decide_for_path_observed(
                client_ip(&parts),
                Some(parts.uri.path()),
                parts.extensions.get::<RouteRateLimits>(),
                parts.extensions.get::<IpGateDecision>().copied(),
                finding.as_ref(),
                Some(&observation),
            );
            if let Some(blocked) = decision {
                return Ok(response::stage(&blocked).map(GuardBody::Generated));
            }
            if let (Some(verdict), false) = (&verdict, stage.config().passive_mode) {
                // Below-threshold detection (or an unattributed request):
                // the plain family block shape. Under passive mode the
                // detection was observed and counted by the stage and the
                // request forwards (the reference's passive path renders
                // no block).
                return Ok(detection_block(&parts, &layer, verdict).map(GuardBody::Generated));
            }
            forward(parts, buffered, inner).await
        })
    }
}

/// Forward the buffered request to the wrapped service.
async fn forward<S, B, B2>(
    parts: Parts,
    buffered: Option<Bytes>,
    mut inner: S,
) -> Result<Response<GuardBody<B2>>, S::Error>
where
    S: Service<Request<B>, Response = Response<B2>>,
    B: Body<Data = Bytes> + From<Bytes>,
{
    let rebuilt = B::from(buffered.unwrap_or_default());
    let response = inner.call(Request::from_parts(parts, rebuilt)).await?;
    Ok(response.map(GuardBody::Passthrough))
}

/// The request's attributed client IP, when the stack provided one.
fn client_ip(parts: &Parts) -> Option<std::net::IpAddr> {
    parts.extensions.get::<GuardClientIp>().map(|ip| ip.0)
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

/// The plain detection block for a flagged request whose violations did
/// not cross a ban threshold (or that carried no client IP to attribute):
/// the family's `400 Bad Request` (`Suspicious activity detected`), with
/// the `custom_error_responses` body override and the reference `on_block`
/// payload when the corresponding seams are installed.
fn detection_block(
    parts: &Parts,
    layer: &GuardLayer,
    verdict: &guard_core_engine::detection_exclusions::RequestScanVerdict,
) -> Response<Full<Bytes>> {
    let status = 400;
    let body = resolve_error_body(
        layer.custom_error_responses(),
        status,
        response::BLOCKED_MESSAGE,
    );
    if let Some(observability) = layer.observability() {
        let ip = client_ip(parts)
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let observation = request_observation(parts);
        let payload = build_block_payload(
            "suspicious_activity",
            &format!("Suspicious activity detected: {ip}"),
            &verdict.reason,
            false,
            &ip,
            observation.url.as_deref().unwrap_or("/"),
            observation.method.as_deref().unwrap_or(""),
            Some(status),
            &observability.sensitive,
        );
        fire_block_hook(layer.on_block(), &payload);
    }
    response::blocked_with_body(status, &body)
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
        RATE_LIMITED_MESSAGE, RateLimitConfig, RateLimiter, ThreatBanEntry, default_config,
    };
    use guard_core_engine::detect::DetectConfig;
    use guard_core_engine::ip_ban::Clock;
    use guard_core_engine::ip_gate::IpGateDecision;
    use http::StatusCode;
    use http_body_util::Full;
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
        let layer = GuardLayer::new(default_config()).with_scan_fn(panicking_scan);
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
}
