//! Reference-parity behavior of the public API: the scoped `exclude_paths`
//! pipeline, client resolution, the full `from_security_config` mapping and
//! the response pass (modifier without a processor, return rules over the
//! response body, the all-checks-bypass route).

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tower::{Layer, ServiceExt};
use tower_guard_rs::{
    BehaviorRule, GeoIpHandler, GuardClientIp, GuardLayer, MetricsCollector, RouteConfig,
    SecurityConfig, default_config,
};

fn ok_service(
    body: &'static str,
) -> impl tower::Service<
    Request<Full<Bytes>>,
    Response = Response<Full<Bytes>>,
    Error = Infallible,
    Future = impl Send,
> + Clone {
    tower::service_fn(move |_request: Request<Full<Bytes>>| async move {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
    })
}

struct Reply {
    status: StatusCode,
    body: String,
    headers: http::HeaderMap,
}

async fn send_to(
    layer: &GuardLayer,
    inner_body: &'static str,
    request: Request<Full<Bytes>>,
) -> Reply {
    let response = layer
        .layer(ok_service(inner_body))
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    Reply {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        headers,
    }
}

async fn send(layer: &GuardLayer, request: Request<Full<Bytes>>) -> Reply {
    send_to(layer, "ok", request).await
}

fn from_peer(uri: &str, peer: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(uri)
        .extension(GuardClientIp(peer.parse::<IpAddr>().expect("ip")))
        .body(Full::new(Bytes::new()))
        .expect("request")
}

fn peerless(uri: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .expect("request")
}

fn layer_for(config: &SecurityConfig) -> GuardLayer {
    GuardLayer::from_security_config(config).expect("valid config")
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

// --- exclude_paths: the scoped pipeline -----------------------------------

#[tokio::test]
async fn an_excluded_prefix_covers_nested_paths_and_skips_detection() {
    let layer = layer_for(&SecurityConfig {
        exclude_paths: vec![String::from("/static")],
        ..SecurityConfig::default()
    });
    let reply = send(
        &layer,
        from_peer(
            "/static/app.js?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "203.0.113.9",
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let sibling = send(
        &layer,
        from_peer(
            "/staticx?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "203.0.113.9",
        ),
    )
    .await;
    assert_eq!(
        sibling.status,
        StatusCode::BAD_REQUEST,
        "/staticx is not under /static"
    );
}

#[tokio::test]
async fn an_excluded_path_still_hits_the_global_ip_blacklist() {
    let layer = layer_for(&SecurityConfig {
        blacklist: vec![String::from("203.0.113.9")],
        exclude_paths: vec![String::from("/docs")],
        ..SecurityConfig::default()
    });
    let reply = send(&layer, from_peer("/docs", "203.0.113.9")).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let other = send(&layer, from_peer("/docs", "203.0.113.10")).await;
    assert_eq!(other.status, StatusCode::OK);
}

#[tokio::test]
async fn an_excluded_path_still_consumes_the_rate_limit() {
    let layer = layer_for(&SecurityConfig {
        rate_limit: 1,
        exclude_paths: vec![String::from("/docs")],
        ..SecurityConfig::default()
    });
    assert_eq!(
        send(&layer, from_peer("/docs", "203.0.113.9")).await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(&layer, from_peer("/docs", "203.0.113.9")).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn an_excluded_path_still_answers_a_live_ban() {
    let layer = layer_for(&SecurityConfig {
        rate_limit: 1,
        enable_rate_limit_auto_ban: true,
        auto_ban_threshold: 1,
        exclude_paths: vec![String::from("/docs")],
        ..SecurityConfig::default()
    });
    let mut last = StatusCode::OK;
    for _ in 0..6 {
        last = send(&layer, from_peer("/docs", "203.0.113.9")).await.status;
    }
    assert_eq!(
        last,
        StatusCode::FORBIDDEN,
        "the auto-ban lands on the excluded path"
    );
}

#[tokio::test]
async fn an_excluded_path_skips_emergency_mode_and_https_enforcement() {
    let layer = layer_for(&SecurityConfig {
        emergency_mode: true,
        enforce_https: true,
        exclude_paths: vec![String::from("/health")],
        ..SecurityConfig::default()
    });
    let reply = send(&layer, from_peer("/health", "203.0.113.9")).await;
    assert_eq!(reply.status, StatusCode::OK);
    let other = send(&layer, from_peer("/data", "203.0.113.9")).await;
    assert_eq!(other.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn an_excluded_response_carries_the_security_headers() {
    let layer = layer_for(&SecurityConfig {
        exclude_paths: vec![String::from("/docs")],
        ..SecurityConfig::default()
    });
    let reply = send(&layer, from_peer("/docs", "203.0.113.9")).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply
            .headers
            .get("x-content-type-options")
            .map(|value| value.to_str().expect("ascii")),
        Some("nosniff")
    );
}

#[tokio::test]
async fn an_excluded_request_emits_request_metrics() {
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let collector = MetricsCollector::new(true).with_handler(Arc::new(
        move |metric: &tower_guard_rs::SecurityMetric| {
            sink.lock().expect("sink").push(metric.metric_type.clone());
        },
    ));
    let layer = layer_for(&SecurityConfig {
        exclude_paths: vec![String::from("/docs")],
        ..SecurityConfig::default()
    })
    .with_metrics(collector);
    let reply = send(&layer, from_peer("/docs", "203.0.113.9")).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        seen.lock()
            .expect("sink")
            .iter()
            .any(|kind| kind == "request_count"),
        "the excluded request is measured"
    );
}

// --- client resolution -----------------------------------------------------

#[tokio::test]
async fn a_missing_peer_is_rejected_under_fail_secure() {
    let layer = layer_for(&SecurityConfig::default());
    let reply = send(&layer, peerless("/data")).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.body, "Client address could not be determined");
}

#[tokio::test]
async fn a_missing_peer_continues_unattributed_without_fail_secure() {
    let layer = layer_for(&SecurityConfig {
        fail_secure: false,
        ..SecurityConfig::default()
    });
    assert_eq!(send(&layer, peerless("/data")).await.status, StatusCode::OK);
}

#[tokio::test]
async fn an_excluded_path_with_no_peer_continues() {
    let layer = layer_for(&SecurityConfig {
        exclude_paths: vec![String::from("/health")],
        ..SecurityConfig::default()
    });
    assert_eq!(
        send(&layer, peerless("/health")).await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(&layer, peerless("/data")).await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn the_rejected_request_fires_the_block_hook() {
    let payloads: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&payloads);
    let layer = layer_for(&SecurityConfig {
        on_block: Some(Arc::new(move |payload: &tower_guard_rs::BlockPayload| {
            sink.lock()
                .expect("sink")
                .push((payload.check_name.clone(), payload.reason.clone()));
        })),
        ..SecurityConfig::default()
    });
    assert_eq!(
        send(&layer, peerless("/data")).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        payloads.lock().expect("sink").as_slice(),
        [(
            String::from("client_address_unresolved"),
            String::from("Client address could not be determined")
        )]
    );
}

#[tokio::test]
async fn a_trusted_proxy_chain_decides_the_client() {
    let layer = layer_for(&SecurityConfig {
        trusted_proxies: vec![String::from("10.0.0.0/8")],
        blacklist: vec![String::from("203.0.113.9")],
        ..SecurityConfig::default()
    });
    let mut request = from_peer("/data", "10.0.0.1");
    request
        .headers_mut()
        .insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
    assert_eq!(send(&layer, request).await.status, StatusCode::FORBIDDEN);

    // An untrusted peer's header is ignored: the peer is the client.
    let mut spoofed = from_peer("/data", "198.51.100.1");
    spoofed
        .headers_mut()
        .insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
    assert_eq!(send(&layer, spoofed).await.status, StatusCode::OK);
}

#[tokio::test]
async fn an_ipv4_mapped_peer_is_canonicalized() {
    let layer = layer_for(&SecurityConfig {
        blacklist: vec![String::from("203.0.113.9")],
        ..SecurityConfig::default()
    });
    let reply = send(&layer, from_peer("/data", "::ffff:203.0.113.9")).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn trusted_proxies_gate_the_forwarded_proto_trust() {
    let layer = layer_for(&SecurityConfig {
        enforce_https: true,
        trust_x_forwarded_proto: true,
        trusted_proxies: vec![String::from("10.0.0.0/8")],
        ..SecurityConfig::default()
    });
    let forwarded = |peer: &str| {
        let mut request = from_peer("/data", peer);
        request
            .headers_mut()
            .insert("host", "example.test".parse().expect("header"));
        request
            .headers_mut()
            .insert("x-forwarded-proto", "https".parse().expect("header"));
        request
    };
    assert_eq!(
        send(&layer, forwarded("10.0.0.1")).await.status,
        StatusCode::OK,
        "a trusted proxy's proto is honored"
    );
    assert_eq!(
        send(&layer, forwarded("198.51.100.1")).await.status,
        StatusCode::MOVED_PERMANENTLY,
        "an untrusted peer's proto is ignored"
    );
}

// --- every config-driven stage is reachable from from_security_config ------

struct Russia;

impl GeoIpHandler for Russia {
    fn get_country(&self, _ip: IpAddr) -> Option<String> {
        Some(String::from("RU"))
    }
}

#[tokio::test]
async fn blocked_countries_and_the_geo_handler_are_wired() {
    let layer = layer_for(&SecurityConfig {
        blocked_countries: set(&["RU"]),
        geo_ip_handler: Some(Arc::new(Russia)),
        ..SecurityConfig::default()
    });
    assert_eq!(
        send(&layer, from_peer("/data", "203.0.113.9")).await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn endpoint_rate_limits_are_wired() {
    let layer = layer_for(&SecurityConfig {
        endpoint_rate_limits: [(String::from("/login"), (1_u32, 60_u64))]
            .into_iter()
            .collect(),
        ..SecurityConfig::default()
    });
    assert_eq!(
        send(&layer, from_peer("/login", "203.0.113.9"))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(&layer, from_peer("/login", "203.0.113.9"))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        send(&layer, from_peer("/other", "203.0.113.9"))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn rate_limit_auto_ban_is_wired() {
    let layer = layer_for(&SecurityConfig {
        rate_limit: 1,
        enable_rate_limit_auto_ban: true,
        auto_ban_threshold: 2,
        ..SecurityConfig::default()
    });
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(send(&layer, from_peer("/data", "203.0.113.9")).await.status);
    }
    assert_eq!(
        statuses.last(),
        Some(&StatusCode::FORBIDDEN),
        "the crossings ban the client: {statuses:?}"
    );
}

#[tokio::test]
async fn custom_request_check_is_wired() {
    let layer = layer_for(&SecurityConfig {
        custom_request_check: Some(Arc::new(|context| {
            (context.path == "/teapot").then_some(tower_guard_rs::CustomResponse {
                status: Some(418),
                body: None,
            })
        })),
        ..SecurityConfig::default()
    });
    assert_eq!(
        send(&layer, from_peer("/teapot", "203.0.113.9"))
            .await
            .status,
        StatusCode::IM_A_TEAPOT
    );
    assert_eq!(
        send(&layer, from_peer("/data", "203.0.113.9")).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_global_auth_verifier_backs_a_route_without_its_own() {
    let layer = layer_for(&SecurityConfig {
        auth_verifier: Some(Arc::new(|credential: &str| credential == "good")),
        ..SecurityConfig::default()
    });
    let guarded = |token: &str| {
        let mut request = from_peer("/admin", "203.0.113.9");
        request.extensions_mut().insert(Arc::new(RouteConfig {
            auth_required: Some(String::from("bearer")),
            ..RouteConfig::default()
        }));
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {token}").parse().expect("header"),
        );
        request
    };
    assert_eq!(send(&layer, guarded("good")).await.status, StatusCode::OK);
    assert_eq!(
        send(&layer, guarded("bad")).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn cors_expose_headers_are_wired() {
    let layer = layer_for(&SecurityConfig {
        enable_cors: true,
        cors_allow_origins: vec![String::from("https://app.example")],
        cors_expose_headers: vec![String::from("x-total")],
        ..SecurityConfig::default()
    });
    let mut request = from_peer("/data", "203.0.113.9");
    request
        .headers_mut()
        .insert("origin", "https://app.example".parse().expect("header"));
    let reply = send(&layer, request).await;
    assert_eq!(
        reply
            .headers
            .get("access-control-expose-headers")
            .map(|value| value.to_str().expect("ascii")),
        Some("x-total")
    );
}

#[test]
fn agent_stats_follow_the_wiring() {
    let layer = layer_for(&SecurityConfig::default());
    assert!(!layer.agent_stats().enabled);
}

// --- the response pass -------------------------------------------------------

#[tokio::test]
async fn the_modifier_runs_without_a_response_processor() {
    let layer = GuardLayer::new(default_config()).with_custom_response_modifier(Arc::new(
        |bits: &mut tower_guard_rs::ResponseBits| {
            bits.headers
                .insert(String::from("x-modified"), String::from("yes"));
        },
    ));
    let reply = send(&layer, from_peer("/data", "203.0.113.9")).await;
    assert_eq!(
        reply
            .headers
            .get("x-modified")
            .map(|value| value.to_str().expect("ascii")),
        Some("yes")
    );
}

#[tokio::test]
async fn a_config_modifier_runs_exactly_once() {
    let calls = Arc::new(Mutex::new(0_u32));
    let counter = Arc::clone(&calls);
    let layer = layer_for(&SecurityConfig {
        custom_response_modifier: Some(Arc::new(
            move |_bits: &mut tower_guard_rs::ResponseBits| {
                *counter.lock().expect("counter") += 1;
            },
        )),
        ..SecurityConfig::default()
    });
    send(&layer, from_peer("/data", "203.0.113.9")).await;
    assert_eq!(*calls.lock().expect("counter"), 1);
}

#[tokio::test]
async fn a_return_rule_matches_the_response_body() {
    let layer = layer_for(&SecurityConfig {
        global_behavior_rules: vec![BehaviorRule {
            rule_type: String::from("return_pattern"),
            threshold: 1,
            window: 60,
            pattern: String::from("SECRET-LEAK"),
            action: String::from("ban"),
            ban_duration: Some(60),
            correlate_with_detection: false,
        }],
        behavior_scan_response_body: true,
        ..SecurityConfig::default()
    });
    // The rule trips when the match count passes the threshold (1): the
    // second leaking response bans the client.
    for _ in 0..2 {
        let leak = send_to(
            &layer,
            "the SECRET-LEAK token",
            from_peer("/data", "203.0.113.9"),
        )
        .await;
        assert_eq!(leak.status, StatusCode::OK);
        assert_eq!(
            leak.body, "the SECRET-LEAK token",
            "the body is re-emitted intact"
        );
    }
    let second = send(&layer, from_peer("/data", "203.0.113.9")).await;
    assert_eq!(
        second.status,
        StatusCode::FORBIDDEN,
        "the rule banned the client"
    );
}

#[tokio::test]
async fn an_all_bypass_route_forwards_with_only_the_modifier() {
    let layer = layer_for(&SecurityConfig {
        blacklist: vec![String::from("203.0.113.9")],
        emergency_mode: true,
        custom_response_modifier: Some(Arc::new(|bits: &mut tower_guard_rs::ResponseBits| {
            bits.headers
                .insert(String::from("x-modified"), String::from("yes"));
        })),
        ..SecurityConfig::default()
    });
    let mut request = from_peer("/open?q=%3Cscript%3Ealert(1)%3C/script%3E", "203.0.113.9");
    request.extensions_mut().insert(Arc::new(RouteConfig {
        bypassed_checks: set(&["all"]),
        ..RouteConfig::default()
    }));
    let reply = send(&layer, request).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        reply.headers.contains_key("x-modified"),
        "the modifier runs"
    );
    assert!(
        !reply.headers.contains_key("x-content-type-options"),
        "no security headers on an all-bypass route"
    );
}
