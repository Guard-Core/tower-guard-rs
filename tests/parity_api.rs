//! The additive public API of the parity wave: the client policy builder,
//! the exclusion marker, the injected telemetry agent, the dynamic-rule
//! handle, the cloud refresh, the config error mapping and the response
//! pass edge cases (all-bypass routes, a failing response body).

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tower::{Layer, Service, ServiceExt};
use tower_guard_rs::{
    BanStore, BehaviorRule, ClientPolicy, GeoIpHandler, GuardClientIp, GuardConfigError,
    GuardExclusionScoped, GuardLayer, RouteConfig, SecurityConfig, SecurityEvent,
    SlidingWindowStore, TelemetryError, TelemetryHandler, Wiring, WiringError, WiringOptions,
    default_config,
};

fn from_peer(uri: &str, peer: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(uri)
        .extension(GuardClientIp(peer.parse::<IpAddr>().expect("ip")))
        .body(Full::new(Bytes::new()))
        .expect("request")
}

async fn status_of(layer: &GuardLayer, request: Request<Full<Bytes>>) -> StatusCode {
    layer
        .layer(tower::service_fn(|_request: Request<Full<Bytes>>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("ok"))))
        }))
        .oneshot(request)
        .await
        .expect("response")
        .status()
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// A telemetry sink that records every event type and counts polls.
#[derive(Default)]
struct Sink {
    events: Mutex<Vec<String>>,
    polls: AtomicUsize,
}

impl TelemetryHandler for Sink {
    fn handler_name(&self) -> &'static str {
        "sink"
    }

    fn start(&self) -> Result<(), TelemetryError> {
        Ok(())
    }

    fn stop(&self) -> Result<(), TelemetryError> {
        Ok(())
    }

    fn send_event(&self, event: &SecurityEvent) -> Result<(), TelemetryError> {
        self.events
            .lock()
            .expect("events")
            .push(event.event_type.clone());
        Ok(())
    }

    fn send_metric(&self, _metric: &tower_guard_rs::SecurityMetric) -> Result<(), TelemetryError> {
        Ok(())
    }

    fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    fn health_check(&self) -> bool {
        true
    }
}

fn with_sink(config: &SecurityConfig) -> (GuardLayer, Arc<Sink>) {
    let sink = Arc::new(Sink::default());
    let layer = GuardLayer::from_security_config_with(
        config,
        &WiringOptions {
            agent: Some(Arc::clone(&sink) as Arc<dyn TelemetryHandler>),
            logfire_client: None,
        },
    )
    .expect("valid config");
    (layer, sink)
}

// --- the builder surface ---------------------------------------------------

#[tokio::test]
async fn the_client_policy_builder_resolves_a_forwarded_chain() {
    let layer = GuardLayer::new(default_config())
        .with_client_policy(ClientPolicy {
            trusted_proxies: vec![String::from("10.0.0.0/8")],
            trusted_proxy_depth: 1,
            fail_secure: true,
        })
        .with_ip_gate(
            tower_guard_rs::IpGateConfig::new([] as [&str; 0], ["203.0.113.9"], [] as [&str; 0])
                .expect("lists"),
        );
    let mut request = from_peer("/data", "10.0.0.1");
    request
        .headers_mut()
        .insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
    assert_eq!(status_of(&layer, request).await, StatusCode::FORBIDDEN);
    // fail_secure rejects a peerless request on the builder layer too.
    let peerless = Request::builder()
        .uri("/data")
        .body(Full::new(Bytes::new()))
        .expect("request");
    assert_eq!(status_of(&layer, peerless).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_downstream_sees_the_exclusion_marker_only_for_excluded_paths() {
    let layer = GuardLayer::new(default_config()).with_exclude_paths(vec![String::from("/static")]);
    let service = layer.layer(tower::service_fn(
        |request: Request<Full<Bytes>>| async move {
            let marked = request.extensions().get::<GuardExclusionScoped>().is_some();
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(if marked {
                "scoped"
            } else {
                "full"
            }))))
        },
    ));
    for (path, expected) in [("/static/app.js", "scoped"), ("/data", "full")] {
        let response = service
            .clone()
            .oneshot(from_peer(path, "203.0.113.9"))
            .await
            .expect("response");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(body, expected.as_bytes());
    }
    assert_eq!(layer.exclude_paths(), ["/static"]);
}

// --- config error mapping --------------------------------------------------

#[test]
fn every_wiring_error_maps_onto_the_config_error() {
    let cases: Vec<(SecurityConfig, &str)> = vec![
        (
            SecurityConfig {
                whitelist: Some(vec![String::from("not-an-ip")]),
                ..SecurityConfig::default()
            },
            "ip list",
        ),
        (
            SecurityConfig {
                rate_limit: 0,
                ..SecurityConfig::default()
            },
            "rate limit",
        ),
        (
            SecurityConfig {
                blocked_user_agents: vec![String::from("(a+)+$")],
                ..SecurityConfig::default()
            },
            "blocked user agent",
        ),
        (
            SecurityConfig {
                block_cloud_providers: Some(set(&["NOPE"])),
                ..SecurityConfig::default()
            },
            "block_cloud_providers",
        ),
        (
            SecurityConfig {
                blocked_countries: set(&["RU"]),
                ..SecurityConfig::default()
            },
            "geo",
        ),
    ];
    for (config, label) in cases {
        let error = GuardLayer::from_security_config(&config).expect_err(label);
        assert!(error.to_string().contains(label), "{label}: {error}");
        let wired: GuardConfigError = Wiring::from_security_config(&config)
            .map(|_| ())
            .expect_err(label)
            .into();
        assert_eq!(
            std::mem::discriminant(&wired),
            std::mem::discriminant(&error)
        );
        assert_eq!(std::error::Error::source(&error).is_some(), label != "geo");
    }
    let ban: GuardConfigError = WiringError::Ban(tower_guard_rs::IpBanConfigError::NonPositive {
        field: "auto_ban_threshold",
    })
    .into();
    assert!(ban.to_string().contains("ip ban"));
    assert!(matches!(ban, GuardConfigError::Ban(_)));
    let redis: GuardConfigError = WiringError::Redis(String::from("down")).into();
    assert_eq!(redis.to_string(), "redis: down");
    assert!(std::error::Error::source(&redis).is_none());
    assert!(matches!(redis, GuardConfigError::Redis(_)));
}

// --- the injected agent ----------------------------------------------------

#[test]
fn agent_stats_report_the_injected_sink() {
    let (layer, _sink) = with_sink(&SecurityConfig::default());
    let stats = layer.agent_stats();
    assert!(stats.enabled);
    assert!(!stats.degraded);
    let service = layer.layer(tower::service_fn(|_request: Request<Full<Bytes>>| async {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
    }));
    assert!(service.agent_stats().enabled);
    assert!(!GuardLayer::with_defaults().agent_stats().enabled);
}

#[test]
fn the_dynamic_rule_loop_starts_only_when_the_host_asks() {
    let config = SecurityConfig {
        enable_dynamic_rules: true,
        dynamic_rule_interval: 1,
        ..SecurityConfig::default()
    };
    let (layer, sink) = with_sink(&config);
    assert_eq!(
        sink.polls.load(Ordering::SeqCst),
        0,
        "nothing runs at build"
    );
    let handle = layer.spawn_dynamic_rules().expect("a driver");
    let polled = (0..300).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(10));
        sink.polls.load(Ordering::SeqCst) > 0
    });
    assert!(polled, "the loop polled the agent");
    drop(handle);
    assert!(GuardLayer::with_defaults().spawn_dynamic_rules().is_none());
}

#[tokio::test]
async fn an_all_bypass_route_emits_the_bypass_event_and_the_modifier_status() {
    let config = SecurityConfig {
        agent_enable_events: true,
        custom_response_modifier: Some(Arc::new(|bits: &mut tower_guard_rs::ResponseBits| {
            bits.status = 418;
        })),
        ..SecurityConfig::default()
    };
    let (layer, sink) = with_sink(&config);
    let mut request = from_peer("/open?token=abc", "203.0.113.9");
    request.extensions_mut().insert(Arc::new(RouteConfig {
        bypassed_checks: set(&["all"]),
        ..RouteConfig::default()
    }));
    assert_eq!(status_of(&layer, request).await, StatusCode::IM_A_TEAPOT);
    assert!(
        sink.events
            .lock()
            .expect("events")
            .iter()
            .any(|kind| kind == "security_bypass")
    );
}

#[tokio::test]
async fn passive_mode_keeps_an_all_bypass_route_in_the_pipeline() {
    let layer = GuardLayer::from_security_config(&SecurityConfig {
        passive_mode: true,
        ..SecurityConfig::default()
    })
    .expect("valid config");
    let mut request = from_peer("/open", "203.0.113.9");
    request.extensions_mut().insert(Arc::new(RouteConfig {
        bypassed_checks: set(&["all"]),
        ..RouteConfig::default()
    }));
    let response = layer
        .layer(tower::service_fn(|_request: Request<Full<Bytes>>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
        }))
        .oneshot(request)
        .await
        .expect("response");
    assert!(
        response.headers().contains_key("x-content-type-options"),
        "the response pass still ran"
    );
}

// --- geo, cloud and the distributed stores ----------------------------------

struct Russia;

impl GeoIpHandler for Russia {
    fn get_country(&self, _ip: IpAddr) -> Option<String> {
        Some(String::from("RU"))
    }
}

#[tokio::test]
async fn an_excluded_path_still_answers_the_global_country_and_cloud_rules() {
    let config = SecurityConfig {
        blocked_countries: set(&["RU"]),
        geo_ip_handler: Some(Arc::new(Russia)),
        exclude_paths: vec![String::from("/docs")],
        ..SecurityConfig::default()
    };
    let layer = GuardLayer::from_security_config(&config).expect("valid config");
    assert_eq!(
        status_of(&layer, from_peer("/docs", "203.0.113.9")).await,
        StatusCode::FORBIDDEN
    );

    let config = SecurityConfig {
        block_cloud_providers: Some(set(&["AWS"])),
        exclude_paths: vec![String::from("/docs")],
        ..SecurityConfig::default()
    };
    let mut wiring = Wiring::from_security_config(&config).expect("wired");
    // No network: an empty provider set keeps the refresh offline.
    let refresh = wiring.cloud_refresh.as_mut().expect("cloud refresh");
    refresh.scheduler =
        Arc::new(tower_guard_rs::CloudRefreshScheduler::new().with_providers(Vec::new()));
    refresh
        .table
        .set_provider_ranges("AWS", vec![(String::from("203.0.113.0/24"), None)])
        .expect("ranges");
    let layer = GuardLayer::from_wiring(wiring);
    assert!(
        layer.refresh_cloud_ip_ranges(),
        "the maintenance call schedules"
    );
    assert_eq!(
        status_of(&layer, from_peer("/docs", "203.0.113.9")).await,
        StatusCode::FORBIDDEN,
        "the excluded path hits the global cloud rule"
    );
    assert_eq!(
        status_of(&layer, from_peer("/data", "203.0.113.9")).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status_of(&layer, from_peer("/data", "198.51.100.9")).await,
        StatusCode::OK,
        "the per-request refresh check runs at the cloud position"
    );
}

struct MemoryStore;

impl SlidingWindowStore for MemoryStore {
    fn record_hit(
        &self,
        _key: &str,
        _now: f64,
        _window: u64,
    ) -> Result<u64, tower_guard_rs::StoreError> {
        Ok(1)
    }
}

impl BanStore for MemoryStore {
    fn set_ban(
        &self,
        _key: &str,
        _expiry: f64,
        _ttl: u64,
    ) -> Result<(), tower_guard_rs::StoreError> {
        Ok(())
    }

    fn get_ban(&self, _key: &str) -> Result<Option<f64>, tower_guard_rs::StoreError> {
        Ok(None)
    }

    fn delete_ban(&self, _key: &str) -> Result<(), tower_guard_rs::StoreError> {
        Ok(())
    }
}

#[tokio::test]
async fn a_wired_distributed_store_is_installed_on_the_layer() {
    let mut wiring = Wiring::from_security_config(&SecurityConfig::default()).expect("wired");
    let store = Arc::new(MemoryStore);
    wiring.distributed = Some(tower_guard_rs::Distributed {
        window_store: Arc::clone(&store) as Arc<dyn SlidingWindowStore>,
        ban_store: store as Arc<dyn BanStore>,
        prefix: String::from("guard:"),
        fail_open: false,
    });
    let layer = GuardLayer::from_wiring(wiring);
    // The store always reports one hit, so the default limit is never crossed.
    for _ in 0..12 {
        assert_eq!(
            status_of(&layer, from_peer("/data", "203.0.113.9")).await,
            StatusCode::OK
        );
    }
}

// --- the response body ------------------------------------------------------

struct BrokenBody;

impl http_body::Body for BrokenBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(Some(Err(std::io::Error::other("reset"))))
    }
}

#[tokio::test]
async fn a_failing_response_body_answers_the_fail_secure_500() {
    let layer = GuardLayer::from_security_config(&SecurityConfig {
        global_behavior_rules: vec![BehaviorRule {
            rule_type: String::from("return_pattern"),
            threshold: 1,
            window: 60,
            pattern: String::from("leak"),
            action: String::from("log"),
            ban_duration: None,
            correlate_with_detection: false,
        }],
        behavior_scan_response_body: true,
        ..SecurityConfig::default()
    })
    .expect("valid config");
    let mut service = layer.layer(tower::service_fn(|_request: Request<Full<Bytes>>| async {
        Ok::<_, Infallible>(Response::new(BrokenBody))
    }));
    let response = service
        .ready()
        .await
        .expect("ready")
        .call(from_peer("/data", "203.0.113.9"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_whitelisted_ip_skips_the_country_rules() {
    let layer = GuardLayer::from_security_config(&SecurityConfig {
        whitelist: Some(vec![String::from("203.0.113.9")]),
        blocked_countries: set(&["RU"]),
        geo_ip_handler: Some(Arc::new(Russia)),
        ..SecurityConfig::default()
    })
    .expect("valid config");
    assert_eq!(
        status_of(&layer, from_peer("/data", "203.0.113.9")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn an_invalid_route_tier_on_an_excluded_path_fails_secure() {
    let layer = GuardLayer::from_security_config(&SecurityConfig {
        exclude_paths: vec![String::from("/docs")],
        ..SecurityConfig::default()
    })
    .expect("valid config");
    let mut request = from_peer("/docs", "203.0.113.9");
    request.extensions_mut().insert(Arc::new(RouteConfig {
        rate_limit: Some(0),
        ..RouteConfig::default()
    }));
    assert_eq!(
        status_of(&layer, request).await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn a_route_tier_applies_on_an_excluded_path() {
    let layer = GuardLayer::from_security_config(&SecurityConfig {
        exclude_paths: vec![String::from("/docs")],
        ..SecurityConfig::default()
    })
    .expect("valid config");
    let tiered = || {
        let mut request = from_peer("/docs", "203.0.113.9");
        request.extensions_mut().insert(Arc::new(RouteConfig {
            rate_limit: Some(1),
            ..RouteConfig::default()
        }));
        request
    };
    assert_eq!(status_of(&layer, tiered()).await, StatusCode::OK);
    assert_eq!(
        status_of(&layer, tiered()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}
