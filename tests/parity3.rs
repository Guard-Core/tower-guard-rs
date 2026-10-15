//! Reference parity, third pass, through the public API: the usage-rule
//! order and the rule-driven config changes.

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use tower::{Layer, ServiceExt};
use tower_guard_rs::{
    BehaviorRule, GuardClientIp, GuardLayer, IpBanManager, ResponseProcessor, RouteConfig,
    SecurityConfig, Wiring, default_config,
};

async fn send(layer: &GuardLayer, request: Request<Full<Bytes>>) -> StatusCode {
    let response = layer
        .layer(tower::service_fn(|_request: Request<Full<Bytes>>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("ok"))))
        }))
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let _ = response.into_body().collect().await;
    status
}

fn at(uri: &str, ip: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(uri)
        .extension(GuardClientIp(ip.parse::<IpAddr>().expect("ip")))
        .body(Full::new(Bytes::new()))
        .expect("request")
}

#[tokio::test]
async fn usage_rules_run_after_the_pipeline_not_before_it() {
    let route = RouteConfig {
        behavior_rules: vec![BehaviorRule {
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
    let resolver: tower_guard_rs::RouteConfigResolver = Arc::new(move |method, path| {
        (method == "GET" && path == "/api").then(|| Arc::new(route.clone()))
    });
    let processor = ResponseProcessor::new(
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
        .with_route_configs(resolver);
    for _ in 0..3 {
        // The pipeline blocks the attack: it never counts as a usage hit.
        assert_eq!(
            send(&layer, at("/api?cmd=$(whoami)", "192.0.2.81")).await,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        send(&layer, at("/api", "192.0.2.81")).await,
        StatusCode::OK,
        "the first request that passed the pipeline is the first observation"
    );
}

fn live_layer(
    change: impl FnOnce(&mut SecurityConfig),
) -> (GuardLayer, Arc<RwLock<SecurityConfig>>) {
    let mut config = SecurityConfig {
        enable_redis: false,
        ..SecurityConfig::default()
    };
    change(&mut config);
    let wiring = Wiring::from_security_config(&config).expect("wired");
    let live = Arc::clone(&wiring.live_config);
    (GuardLayer::from_wiring(wiring), live)
}

#[tokio::test]
async fn a_rate_limit_rule_changes_the_limit_the_layer_enforces() {
    let (layer, live) = live_layer(|config| {
        config.enable_rate_limiting = true;
        config.rate_limit = 1;
        config.rate_limit_window = 60;
    });
    assert_eq!(send(&layer, at("/a", "192.0.2.91")).await, StatusCode::OK);
    assert_eq!(
        send(&layer, at("/a", "192.0.2.91")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    live.write().expect("live config").rate_limit = 100;
    assert_eq!(send(&layer, at("/a", "192.0.2.91")).await, StatusCode::OK);
}

#[tokio::test]
async fn a_blocked_user_agent_rule_and_the_detection_toggle_take_effect() {
    let (layer, live) = live_layer(|_| {});
    let with_agent = |agent: &str| {
        Request::builder()
            .uri("/a")
            .header("user-agent", agent)
            .extension(GuardClientIp("192.0.2.92".parse::<IpAddr>().expect("ip")))
            .body(Full::new(Bytes::new()))
            .expect("request")
    };
    assert_eq!(send(&layer, with_agent("badbot/1.0")).await, StatusCode::OK);
    live.write().expect("live config").blocked_user_agents = vec!["badbot".to_owned()];
    assert_eq!(
        send(&layer, with_agent("badbot/1.0")).await,
        StatusCode::FORBIDDEN
    );

    live.write().expect("live config").blocked_countries = BTreeSet::new();
    assert_eq!(
        send(&layer, at("/a?cmd=$(whoami)", "192.0.2.92")).await,
        StatusCode::BAD_REQUEST
    );
    live.write()
        .expect("live config")
        .enable_penetration_detection = false;
    assert_eq!(
        send(&layer, at("/a?cmd=$(whoami)", "192.0.2.92")).await,
        StatusCode::OK
    );
}
