//! End-to-end behavior of the public API: `GuardLayer` wrapping real
//! services, exercised with `tower::ServiceExt::oneshot`.

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Response, StatusCode, header::HeaderName};
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::util::BoxCloneService;
use tower::{Layer, Service, ServiceExt};
use tower_guard_rs::{
    BLOCKED_MESSAGE, FAILURE_MESSAGE, GuardLayer, OVERSIZE_MESSAGE, default_config,
};

type Echo = BoxCloneService<Request<Full<Bytes>>, Response<Full<Bytes>>, Infallible>;

/// An inner service that echoes `method path header-value body`, so tests can
/// assert that the guard forwards the request untouched.
fn echo() -> Echo {
    BoxCloneService::new(tower::service_fn(
        |request: Request<Full<Bytes>>| async move {
            let (parts, body) = request.into_parts();
            let body = body.collect().await.expect("body").to_bytes();
            let custom = parts
                .headers
                .get("x-custom")
                .map(|value| value.to_str().expect("ascii").to_owned())
                .unwrap_or_default();
            let echo = format!(
                "{} {} {custom} {}",
                parts.method,
                parts.uri.path(),
                String::from_utf8_lossy(&body)
            );
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(echo))))
        },
    ))
}

async fn body_text<B>(response: Response<B>) -> String
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + std::fmt::Debug,
{
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn get(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Full::new(Bytes::new()))
        .expect("request")
}

fn post(path: &str, body: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .expect("request")
}

#[tokio::test]
async fn benign_request_passes_through_untouched() {
    let mut service = GuardLayer::new(default_config()).layer(echo());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/items?limit=5")
        .header("x-custom", "hello")
        .body(Full::new(Bytes::from_static(b"{\"name\":\"renn\"}")))
        .expect("request");

    let response = service.ready().await.expect("ready").call(request).await;
    let response = response.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_text(response).await,
        "POST /api/items hello {\"name\":\"renn\"}"
    );
}

#[tokio::test]
async fn xss_payload_in_body_is_blocked() {
    let service = GuardLayer::new(default_config()).layer(echo());
    let response = service
        .oneshot(post("/api/comment", "<script>alert(1)</script>"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).expect("content type"),
        "text/plain; charset=utf-8"
    );
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn traversal_payload_in_path_is_blocked() {
    let service = GuardLayer::new(default_config()).layer(echo());
    let response = service
        .oneshot(get("/files/../../etc/passwd"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn command_injection_in_query_is_blocked() {
    let service = GuardLayer::new(default_config()).layer(echo());
    let response = service
        .oneshot(get("/search?cmd=$(whoami)"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn xss_payload_in_scanned_header_is_blocked() {
    let service = GuardLayer::new(default_config()).layer(echo());
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("x-comment", "<script>alert(1)</script>")
        .body(Full::new(Bytes::new()))
        .expect("request");

    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn excluded_headers_are_never_scanned() {
    // `User-Agent` is on the exclusion list, so even a value that looks like a
    // payload is not fed to the engine. This pins the documented policy.
    let service = GuardLayer::new(default_config()).layer(echo());
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("user-agent", "<script>alert(1)</script>")
        .body(Full::new(Bytes::new()))
        .expect("request");

    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn body_over_the_cap_is_rejected_with_413() {
    let layer = GuardLayer::new(default_config()).with_body_cap(16);
    let service = layer.layer(echo());
    let response = service
        .oneshot(post(
            "/api/items",
            "this body is much longer than sixteen bytes",
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_text(response).await, OVERSIZE_MESSAGE);
}

#[tokio::test]
async fn body_under_the_cap_is_forwarded_intact() {
    let layer = GuardLayer::new(default_config()).with_body_cap(16);
    let service = layer.layer(echo());
    let response = service
        .oneshot(post("/api/items", "short but valid"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_text(response).await,
        "POST /api/items  short but valid"
    );
}

#[tokio::test]
async fn body_read_error_fails_secure_with_500() {
    // A body that yields one frame, then either errors (the failing script)
    // or ends cleanly (the forwarded rebuild the guard hands the inner
    // service - the same type must satisfy the `From<Bytes>` bound).
    struct FailingBody {
        /// `Some(())` = the failing script; `None` = the clean rebuild.
        fail: Option<()>,
        yielded: bool,
    }

    impl http_body::Body for FailingBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.yielded {
                return match self.fail {
                    Some(()) => Poll::Ready(Some(Err(io::Error::other("body blew up")))),
                    None => Poll::Ready(None),
                };
            }
            self.yielded = true;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"hi")))))
        }
    }

    // The forwarded rebuild: one clean data frame, then a clean end.
    impl From<Bytes> for FailingBody {
        fn from(_bytes: Bytes) -> Self {
            Self {
                fail: None,
                yielded: false,
            }
        }
    }

    let service = GuardLayer::new(default_config()).layer(BoxCloneService::new(tower::service_fn(
        |_request: Request<FailingBody>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"forwarded"))))
        },
    )));

    // The failing script: the read error fails secure with the 500 shape.
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/items")
        .body(FailingBody {
            fail: Some(()),
            yielded: false,
        })
        .expect("request");
    let response = service.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body_text(response).await, FAILURE_MESSAGE);

    // The clean rebuild through the same service instantiation: the buffered
    // body scans, forwards, and the inner handler answers.
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/items")
        .body(FailingBody {
            fail: None,
            yielded: false,
        })
        .expect("request");
    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, "forwarded");
}

#[tokio::test]
async fn inner_service_errors_are_propagated_not_swallowed() {
    let service = GuardLayer::new(default_config()).layer(BoxCloneService::new(tower::service_fn(
        |_request: Request<Full<Bytes>>| async {
            Err::<Response<Full<Bytes>>, _>(io::Error::other("upstream down"))
        },
    )));
    let error = service
        .oneshot(get("/health"))
        .await
        .expect_err("inner error must propagate");
    assert_eq!(error.to_string(), "upstream down");
}

#[tokio::test]
async fn concurrent_requests_are_screened_independently() {
    let service = GuardLayer::new(default_config()).layer(echo());

    let handles: Vec<_> = (0..24)
        .map(|index| {
            let service = service.clone();
            tokio::spawn(async move {
                let request = if index % 2 == 0 {
                    get("/health")
                } else {
                    post("/api/comment", "<script>alert(1)</script>")
                };
                service.oneshot(request).await.expect("response").status()
            })
        })
        .collect();

    for (index, handle) in handles.into_iter().enumerate() {
        let status = handle.await.expect("task");
        if index % 2 == 0 {
            assert_eq!(status, StatusCode::OK, "benign request {index}");
        } else {
            assert_eq!(status, StatusCode::BAD_REQUEST, "threat request {index}");
        }
    }
}

#[tokio::test]
async fn poll_ready_forwards_to_the_inner_service() {
    let mut service = GuardLayer::new(default_config()).layer(echo());
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match Service::poll_ready(&mut service, &mut cx) {
        std::task::Poll::Ready(result) => result.expect("ready"),
        std::task::Poll::Pending => panic!("echo service is always ready"),
    }
}

#[tokio::test]
async fn custom_header_name_is_case_insensitive_on_the_exclusion_list() {
    // `HeaderMap` normalizes names to lowercase; scanning decisions must not
    // depend on the casing the client sent.
    let service = GuardLayer::new(default_config()).layer(echo());
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("X-Custom", "benign value")
        .header(HeaderName::from_static("user-agent"), "guard-tests/0.1")
        .body(Full::new(Bytes::new()))
        .expect("request");

    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

// --- the newly wired stage surface (the reference pipeline checks) ---

use guard_core_engine::behavior::BehaviorRule;
use guard_core_engine::cors::CorsConfig;
use guard_core_engine::custom_checks::{CustomResponse, ValidatorAnswer};
use guard_core_engine::geo::GeoIpHandler;
use guard_core_engine::headers_auth::{HeaderAuthRules, REQUIRED_SENTINEL, RequiredHeader};
use guard_core_engine::ip_ban::{IpBanConfig, IpBanManager};
use guard_core_rs::cloud_provider::{CloudIpTable, parse_cloud_selectors};
use guard_core_rs::custom_checks::CustomChecksStage;
use guard_core_rs::emergency_mode::EmergencyModeStage;
use guard_core_rs::geo::{GeoStage, GeoStageConfig, parse_country_lists};
use guard_core_rs::headers_auth::{HeadersAuthStage, RouteGuard};
use guard_core_rs::https_enforcement::{HttpsEnforcementStage, HttpsEnforcementStageConfig};
use guard_core_rs::process_response::ResponseProcessor;
use guard_core_rs::route_gates::{GateConfig, ReferrerStage, TimeWindowStage};
use guard_core_rs::tower::RouteRateLimits;
use guard_core_rs::user_agent::{UserAgentStage, UserAgentStageConfig};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tower_guard_rs::GuardClientIp;
use tower_guard_rs::SecurityHeadersConfig;

fn attributed_get(path: &str, ip: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .extension(GuardClientIp(IpAddr::from_str(ip).expect("test ip")))
        .body(Full::new(Bytes::new()))
        .expect("request")
}

#[tokio::test]
async fn emergency_mode_blocks_outside_the_whitelist_and_fails_secure_without_an_ip() {
    let stage = EmergencyModeStage::builder(
        guard_core_rs::emergency_mode::EmergencyModeStageConfig::default(),
    )
    .emergency_mode(true)
    .emergency_whitelist(["203.0.113.9"])
    .build()
    .expect("valid whitelist");
    let service = GuardLayer::new(default_config())
        .with_emergency_mode(stage)
        .layer(echo());

    // The whitelisted IP passes.
    let response = service
        .clone()
        .oneshot(attributed_get("/api", "203.0.113.9"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    // Everyone else answers the reference 503 shape.
    let response = service
        .clone()
        .oneshot(attributed_get("/api", "192.0.2.7"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_text(response).await, "Service temporarily unavailable");

    // Fail secure: an unattributable request is outside the whitelist.
    let response = service.oneshot(get("/api")).await.expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn https_enforcement_redirects_plain_http_and_passes_https() {
    let stage = HttpsEnforcementStage::builder(HttpsEnforcementStageConfig::default())
        .enforce_https(true)
        .build()
        .expect("valid");
    let service = GuardLayer::new(default_config())
        .with_https_enforcement(stage)
        .layer(echo());

    let request = Request::builder()
        .uri("/private?token=1")
        .header("host", "guard.example")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response
            .headers()
            .get(http::header::LOCATION)
            .expect("location"),
        "https://guard.example/private?token=1"
    );

    // The inner service never saw the redirected request; an https request
    // passes through.
    let request = Request::builder()
        .uri("https://guard.example/private")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn required_headers_and_authentication_answer_the_reference_shapes() {
    let stage = HeadersAuthStage::new(
        None,
        Arc::new(|path: &str| {
            (path == "/private").then(|| {
                Arc::new(RouteGuard {
                    rules: HeaderAuthRules {
                        required_headers: vec![RequiredHeader {
                            name: String::from("x-api-key"),
                            expected: String::from(REQUIRED_SENTINEL),
                        }],
                        auth_required: Some(String::from("bearer")),
                        ..HeaderAuthRules::default()
                    },
                    verifier: Some(Arc::new(|credential: &str| credential == "let-me-in")),
                    api_key_verifier: None,
                })
            })
        }),
    );
    let service = GuardLayer::new(default_config())
        .with_headers_auth(stage)
        .layer(echo());

    // Missing required header: the dynamic 400 shape.
    let response = service
        .clone()
        .oneshot(get("/private"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Wrong bearer credential: the fixed 401 authentication shape.
    let request = Request::builder()
        .uri("/private")
        .header("x-api-key", "present")
        .header("authorization", "Bearer nope")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_text(response).await, "Authentication required");

    // The right credential passes through to the inner service.
    let request = Request::builder()
        .uri("/private")
        .header("x-api-key", "present")
        .header("authorization", "Bearer let-me-in")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn referrer_gate_blocks_a_missing_or_foreign_referrer() {
    let stage = ReferrerStage::builder(GateConfig::default())
        .resolver(Arc::new(|path: &str| {
            (path == "/gated").then(|| vec![String::from("https://good.example")])
        }))
        .build();
    let service = GuardLayer::new(default_config())
        .with_referrer_gate(stage)
        .layer(echo());

    // Missing referrer header: the reference 403 shape.
    let response = service
        .clone()
        .oneshot(get("/gated"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "Referrer required");

    // An allowed referrer passes.
    let request = Request::builder()
        .uri("/gated")
        .header("referer", "https://good.example/page")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    // A foreign referrer is invalid.
    let request = Request::builder()
        .uri("/gated")
        .header("referer", "https://evil.example/page")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "Invalid referrer");
}

#[tokio::test]
async fn custom_validators_block_with_the_validator_response() {
    let stage = CustomChecksStage::builder()
        .validators_resolver(Arc::new(|path: &str| {
            (path == "/private").then(|| {
                vec![(
                    String::from("post_only"),
                    Arc::new(
                        |ctx: &guard_core_engine::custom_checks::CustomRequestContext<'_>| {
                            (ctx.method != "POST").then_some(ValidatorAnswer::Response(
                                CustomResponse { status: Some(403) },
                            ))
                        },
                    ) as guard_core_engine::custom_checks::CustomValidatorFn,
                )]
            })
        }))
        .build();
    let service = GuardLayer::new(default_config())
        .with_custom_checks(stage)
        .layer(echo());

    let response = service
        .clone()
        .oneshot(get("/private"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = service
        .clone()
        .oneshot(post("/private", "{}"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn time_window_gate_blocks_outside_the_window() {
    // The window is computed from the live clock so the test is
    // deterministic: the gate closes for everything except a two-minute
    // band that starts two minutes from now.
    let now = chrono::Utc::now();
    let start = (now + chrono::Duration::minutes(2))
        .format("%H:%M")
        .to_string();
    let end = (now + chrono::Duration::minutes(3))
        .format("%H:%M")
        .to_string();
    let stage = TimeWindowStage::builder(GateConfig::default())
        .resolver(Arc::new(move |path: &str| {
            (path == "/nightly").then(|| guard_core_engine::time_window::TimeWindow {
                start: Some(start.clone()),
                end: Some(end.clone()),
                timezone: Some(String::from("UTC")),
            })
        }))
        .build();
    let service = GuardLayer::new(default_config())
        .with_time_window_gate(stage)
        .layer(echo());

    let response = service
        .clone()
        .oneshot(get("/nightly"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "Access not allowed at this time");

    // A path without a window passes.
    let response = service.oneshot(get("/open")).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cloud_provider_blocking_answers_the_reference_403() {
    let table = CloudIpTable::default();
    table
        .set_provider_ranges("AWS", vec![(String::from("192.0.2.0/24"), None)])
        .expect("valid ranges");
    let stage = guard_core_rs::cloud_provider::CloudProviderStage::builder(
        guard_core_rs::cloud_provider::CloudProviderStageConfig {
            block_cloud_providers: parse_cloud_selectors(["AWS"]).expect("valid selectors"),
            table,
            passive_mode: false,
        },
    )
    .build();
    let service = GuardLayer::new(default_config())
        .with_cloud_provider(stage)
        .layer(echo());

    let response = service
        .clone()
        .oneshot(attributed_get("/api", "192.0.2.9"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "Cloud provider IP not allowed");

    // An address outside the provider ranges passes.
    let response = service
        .oneshot(attributed_get("/api", "198.51.100.9"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

/// A hand-written resolver: every address resolves to `US`.
struct UnitedStates;

impl GeoIpHandler for UnitedStates {
    fn get_country(&self, _ip: std::net::IpAddr) -> Option<String> {
        Some(String::from("US"))
    }
}

#[tokio::test]
async fn geo_country_blocking_answers_the_reference_403() {
    let stage = GeoStage::new(GeoStageConfig {
        gate: parse_country_lists(Vec::<String>::new(), ["US"]),
        handler: Some(Arc::new(UnitedStates)),
        passive_mode: false,
    });
    let service = GuardLayer::new(default_config())
        .with_geo_blocking(stage)
        .layer(echo());

    let response = service
        .clone()
        .oneshot(attributed_get("/api", "192.0.2.9"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "Forbidden");
}

#[tokio::test]
async fn user_agent_blocking_answers_the_reference_403() {
    let stage = UserAgentStage::new(UserAgentStageConfig {
        blocked_user_agents: guard_core_rs::user_agent::UserAgentFilter::new(["bad-bot"])
            .expect("valid patterns"),
        ..UserAgentStageConfig::default()
    })
    .expect("valid config");
    let service = GuardLayer::new(default_config())
        .with_user_agent(stage)
        .layer(echo());

    let request = Request::builder()
        .uri("/api")
        .header("user-agent", "bad-bot/1.0")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "User-Agent not allowed");

    let request = Request::builder()
        .uri("/api")
        .header("user-agent", "friendly-crawler/2.0")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn custom_request_blocks_with_the_function_response() {
    let stage = CustomChecksStage::builder()
        .custom_request(
            "maintenance_gate",
            Arc::new(|ctx| (ctx.path == "/admin").then_some(CustomResponse { status: Some(503) })),
        )
        .build();
    let service = GuardLayer::new(default_config())
        .with_custom_checks(stage)
        .layer(echo());

    let response = service
        .clone()
        .oneshot(get("/admin"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let response = service.oneshot(get("/public")).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn response_processor_renders_security_headers_and_cors_on_every_response() {
    let processor = ResponseProcessor::new(
        Some(SecurityHeadersConfig::reference_default()),
        Some(CorsConfig {
            enabled: true,
            allow_origins: vec![String::from("https://app.example.com")],
            ..CorsConfig::default()
        }),
        Vec::new(),
        Arc::new(Mutex::new(
            guard_core_engine::behavior::BehaviorTracker::new(),
        )),
        IpBanManager::new(),
        true,
        262_144,
        false,
    );
    let service = GuardLayer::new(default_config())
        .with_response_processor(processor)
        .layer(echo());

    // Forwarded responses carry the security-header set and the CORS
    // verdict for the allowed origin.
    let request = Request::builder()
        .uri("/api")
        .header("origin", "https://app.example.com")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .expect("nosniff"),
        "nosniff"
    );
    assert_eq!(
        response
            .headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("cors"),
        "https://app.example.com"
    );

    // Block answers carry the set too (headers on blocked + passthrough).
    let response = service
        .clone()
        .oneshot(post("/api/comment", "<script>alert(1)</script>"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("x-content-type-options"),
        Some(&"nosniff".parse().expect("static value"))
    );
    assert_eq!(
        response.headers().get("x-frame-options"),
        Some(&"SAMEORIGIN".parse().expect("static value"))
    );
}

#[tokio::test]
async fn a_return_pattern_rule_bans_at_the_threshold_through_the_fused_pipeline() {
    // The processor's return rules share the layer's ban store: a crossed
    // `status:404` ban rule answers the next request with the bans arm's
    // 403 ("IP address banned"), exactly the reference's
    // behavioral-violation path.
    let bans = IpBanManager::new();
    let processor = ResponseProcessor::new(
        None,
        None,
        vec![BehaviorRule {
            rule_type: String::from("return_pattern"),
            threshold: 2,
            window: 3600,
            pattern: String::from("status:404"),
            action: String::from("ban"),
            ban_duration: Some(900),
            correlate_with_detection: false,
        }],
        Arc::new(Mutex::new(
            guard_core_engine::behavior::BehaviorTracker::new(),
        )),
        bans.clone(),
        true,
        262_144,
        false,
    );
    // An inner service answering 404 for /missing: the return-rule
    // surface the test drives.
    let not_found = || {
        BoxCloneService::new(tower::service_fn(
            |request: Request<Full<Bytes>>| async move {
                let status = if request.uri().path() == "/missing" {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::OK
                };
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(status)
                        .body(Full::new(Bytes::new()))
                        .expect("static"),
                )
            },
        )) as Echo
    };
    let service = GuardLayer::new(default_config())
        .with_ip_banning(
            bans.clone(),
            IpBanConfig::new(
                true,
                10,
                3600,
                [] as [(String, tower_guard_rs::ThreatBanEntry); 0],
            )
            .expect("valid"),
        )
        .with_response_processor(processor)
        .layer(not_found());

    // Two 404s track; the third trips the rule and bans the IP.
    for _ in 0..2 {
        let response = service
            .clone()
            .oneshot(attributed_get("/missing", "192.0.2.41"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let response = service
        .clone()
        .oneshot(attributed_get("/missing", "192.0.2.41"))
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the rule fires after the response"
    );
    assert!(
        bans.is_banned(IpAddr::from_str("192.0.2.41").expect("ip")),
        "the ban landed in the shared store"
    );

    // The next request answers from the bans arm.
    let response = service
        .oneshot(attributed_get("/missing", "192.0.2.41"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "IP address banned");
}

#[tokio::test]
async fn provided_layers_lists_the_installed_stages_in_reference_order() {
    use tower_guard_rs::{GuardStageLayer, provided_layers};

    let emergency = EmergencyModeStage::builder(
        guard_core_rs::emergency_mode::EmergencyModeStageConfig::default(),
    )
    .build()
    .expect("valid");
    let https = HttpsEnforcementStage::builder(HttpsEnforcementStageConfig::default())
        .enforce_https(true)
        .build()
        .expect("valid");
    let custom = CustomChecksStage::builder().build();
    let layer = GuardLayer::new(default_config())
        .with_emergency_mode(emergency)
        .with_https_enforcement(https)
        .with_custom_checks(custom)
        .with_rate_limiting(
            tower_guard_rs::RateLimiter::new(tower_guard_rs::RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 5,
                ..tower_guard_rs::RateLimitConfig::default()
            })
            .expect("valid limiter"),
        );

    let layers = provided_layers(&layer);
    let names: Vec<&'static str> = layers
        .iter()
        .map(|stage| match stage {
            GuardStageLayer::Emergency(_) => "emergency",
            GuardStageLayer::Https(_) => "https",
            GuardStageLayer::HeadersAuth(_) => "headers_auth",
            GuardStageLayer::Referrer(_) => "referrer",
            GuardStageLayer::CustomValidators(_) => "validators",
            GuardStageLayer::TimeWindow(_) => "time_window",
            GuardStageLayer::Bans(_) => "bans",
            GuardStageLayer::Geo(_) => "geo",
            GuardStageLayer::Cloud(_) => "cloud",
            GuardStageLayer::UserAgent(_) => "user_agent",
            GuardStageLayer::RateLimit(_) => "rate_limit",
            GuardStageLayer::CustomRequest(_) => "custom_request",
        })
        .collect();
    assert_eq!(
        names,
        vec![
            "emergency",
            "https",
            "validators",
            "bans",
            "rate_limit",
            "custom_request",
        ],
        "the reference pipeline order, uninstalled stages dropped"
    );

    // The composed stack answers like the fused layer: the enforcement
    // stage redirects the plain-HTTP request (301 + Location) before the
    // inner service sees it.
    let inner = layers.into_iter().rev().fold(
        echo(),
        |service,
         stage|
         -> BoxCloneService<Request<Full<Bytes>>, Response<Full<Bytes>>, Infallible> {
            BoxCloneService::new(Layer::layer(&stage, service))
        },
    );
    let request = Request::builder()
        .uri("/private")
        .header("host", "guard.example")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = inner.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response
            .headers()
            .get(http::header::LOCATION)
            .expect("location"),
        "https://guard.example/private"
    );
}

/// A route-tier extension rides through the fused pipeline untouched.
#[tokio::test]
async fn route_tiers_still_apply_over_the_new_stages() {
    // The route tiers ride the rate limiter (the adapter's composition
    // idiom): install both.
    let limiter = tower_guard_rs::RateLimiter::new(tower_guard_rs::RateLimitConfig {
        enable_rate_limiting: true,
        ..tower_guard_rs::RateLimitConfig::default()
    })
    .expect("valid limiter");
    let service = GuardLayer::new(default_config())
        .with_rate_limiting(limiter)
        .with_route_tiers(Arc::new(|path: &str| {
            (path == "/login").then(|| RouteRateLimits::new(Some(1), None, None).expect("tiers"))
        }))
        .layer(echo());

    let response = service
        .clone()
        .oneshot(attributed_get("/login", "192.0.2.55"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let response = service
        .oneshot(attributed_get("/login", "192.0.2.55"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ===================================================================
// The standalone stage layers: each `GuardStageLayer` variant wraps a
// service through the `provided_layers` shape and answers the reference
// block, or forwards untouched.
// ===================================================================

use tower_guard_rs::{GuardStageLayer, provided_layers};

type StageSvc = BoxCloneService<Request<Full<Bytes>>, Response<Full<Bytes>>, Infallible>;

fn wrapped(stage: &GuardStageLayer) -> StageSvc {
    BoxCloneService::new(Layer::layer(stage, echo()))
}

fn emergency_layer() -> GuardStageLayer {
    GuardStageLayer::Emergency(
        EmergencyModeStage::builder(
            guard_core_rs::emergency_mode::EmergencyModeStageConfig::default(),
        )
        .emergency_mode(true)
        .emergency_whitelist(["203.0.113.9"])
        .build()
        .expect("valid whitelist"),
    )
}

fn https_layer() -> GuardStageLayer {
    GuardStageLayer::Https(
        HttpsEnforcementStage::builder(HttpsEnforcementStageConfig::default())
            .enforce_https(true)
            .build()
            .expect("valid"),
    )
}

fn headers_auth_layer() -> GuardStageLayer {
    GuardStageLayer::HeadersAuth(HeadersAuthStage::new(
        None,
        Arc::new(|path: &str| {
            (path == "/private").then(|| {
                Arc::new(RouteGuard {
                    rules: HeaderAuthRules {
                        required_headers: vec![RequiredHeader {
                            name: String::from("x-api-key"),
                            expected: String::from(REQUIRED_SENTINEL),
                        }],
                        ..HeaderAuthRules::default()
                    },
                    verifier: None,
                    api_key_verifier: None,
                })
            })
        }),
    ))
}

fn referrer_layer() -> GuardStageLayer {
    GuardStageLayer::Referrer(
        ReferrerStage::builder(GateConfig::default())
            .resolver(Arc::new(|path: &str| {
                (path == "/gated").then(|| vec![String::from("https://good.example")])
            }))
            .build(),
    )
}

fn validators_layer() -> GuardStageLayer {
    GuardStageLayer::CustomValidators(
        CustomChecksStage::builder()
            .validators_resolver(Arc::new(|path: &str| {
                (path == "/private").then(|| {
                    vec![(
                        String::from("post_only"),
                        Arc::new(
                            |ctx: &guard_core_engine::custom_checks::CustomRequestContext<'_>| {
                                (ctx.method != "POST").then_some(ValidatorAnswer::Response(
                                    CustomResponse { status: Some(403) },
                                ))
                            },
                        )
                            as guard_core_engine::custom_checks::CustomValidatorFn,
                    )]
                })
            }))
            .build(),
    )
}

fn time_window_layer() -> GuardStageLayer {
    let now = chrono::Utc::now();
    let start = (now + chrono::Duration::minutes(2))
        .format("%H:%M")
        .to_string();
    let end = (now + chrono::Duration::minutes(3))
        .format("%H:%M")
        .to_string();
    GuardStageLayer::TimeWindow(
        TimeWindowStage::builder(GateConfig::default())
            .resolver(Arc::new(move |path: &str| {
                (path == "/nightly").then(|| guard_core_engine::time_window::TimeWindow {
                    start: Some(start.clone()),
                    end: Some(end.clone()),
                    timezone: Some(String::from("UTC")),
                })
            }))
            .build(),
    )
}

fn bans_layer(manager: &IpBanManager) -> GuardStageLayer {
    let stage = tower_guard_rs::RateLimitStage::builder(tower_guard_rs::RateLimitStageConfig {
        ip_ban: IpBanConfig::new(
            true,
            10,
            3600,
            [] as [(String, tower_guard_rs::ThreatBanEntry); 0],
        )
        .expect("valid"),
        ..tower_guard_rs::RateLimitStageConfig::default()
    })
    .ban_manager(manager.clone(), tower_guard_rs::ViolationCounters::new())
    .build()
    .expect("valid stage");
    GuardStageLayer::Bans(stage)
}

fn geo_layer() -> GuardStageLayer {
    GuardStageLayer::Geo(GeoStage::new(GeoStageConfig {
        gate: parse_country_lists(Vec::<String>::new(), ["US"]),
        handler: Some(Arc::new(UnitedStates)),
        passive_mode: false,
    }))
}

fn cloud_layer() -> GuardStageLayer {
    let table = CloudIpTable::default();
    table
        .set_provider_ranges("AWS", vec![(String::from("192.0.2.0/24"), None)])
        .expect("valid ranges");
    GuardStageLayer::Cloud(
        guard_core_rs::cloud_provider::CloudProviderStage::builder(
            guard_core_rs::cloud_provider::CloudProviderStageConfig {
                block_cloud_providers: parse_cloud_selectors(["AWS"]).expect("valid selectors"),
                table,
                passive_mode: false,
            },
        )
        .build(),
    )
}

fn user_agent_layer() -> GuardStageLayer {
    GuardStageLayer::UserAgent(
        UserAgentStage::new(UserAgentStageConfig {
            blocked_user_agents: guard_core_rs::user_agent::UserAgentFilter::new(["bad-bot"])
                .expect("valid patterns"),
            ..UserAgentStageConfig::default()
        })
        .expect("valid config"),
    )
}

fn rate_limit_layer() -> GuardStageLayer {
    GuardStageLayer::RateLimit(
        tower_guard_rs::RateLimitStage::builder(tower_guard_rs::RateLimitStageConfig {
            rate_limit: tower_guard_rs::RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 1,
                rate_limit_window: 60,
                ..tower_guard_rs::RateLimitConfig::default()
            },
            ..tower_guard_rs::RateLimitStageConfig::default()
        })
        .limiter(
            tower_guard_rs::RateLimiter::new(tower_guard_rs::RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 1,
                rate_limit_window: 60,
                ..tower_guard_rs::RateLimitConfig::default()
            })
            .expect("valid limiter"),
        )
        .build()
        .expect("valid stage"),
    )
}

fn custom_request_layer() -> GuardStageLayer {
    GuardStageLayer::CustomRequest(
        CustomChecksStage::builder()
            .custom_request(
                "maintenance_gate",
                Arc::new(|ctx| {
                    (ctx.path == "/admin").then_some(CustomResponse { status: Some(503) })
                }),
            )
            .build(),
    )
}

#[tokio::test]
async fn standalone_emergency_layer_blocks_outside_the_whitelist_and_forwards_inside() {
    let service = wrapped(&emergency_layer());

    let response = service
        .clone()
        .oneshot(attributed_get("/api", "192.0.2.7"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_text(response).await, "Service temporarily unavailable");

    let response = service
        .oneshot(attributed_get("/api", "203.0.113.9"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn standalone_https_layer_redirects_and_strips_ports_and_brackets() {
    let service = wrapped(&https_layer());

    // A host header with a port: the redirect target keeps the bare host.
    let request = Request::builder()
        .uri("/private?token=1")
        .header("host", "guard.example:8443")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response
            .headers()
            .get(http::header::LOCATION)
            .expect("location"),
        "https://guard.example:8443/private?token=1",
        "the redirect target carries the host as sent; the port strip feeds
        the trusted-proxy comparison only"
    );

    // An absolute-form URI takes the host from the authority.
    let request = Request::builder()
        .uri("http://[2001:db8::1]/private")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response
            .headers()
            .get(http::header::LOCATION)
            .expect("location"),
        "https://[2001:db8::1]/private"
    );

    // An https request forwards untouched.
    let request = Request::builder()
        .uri("https://guard.example/private")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn standalone_headers_auth_layer_blocks_without_the_header_and_forwards_with_it() {
    let service = wrapped(&headers_auth_layer());

    let response = service
        .clone()
        .oneshot(get("/private"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let request = Request::builder()
        .uri("/private")
        .header("x-api-key", "present")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn standalone_referrer_layer_blocks_and_forwards() {
    let service = wrapped(&referrer_layer());

    let response = service
        .clone()
        .oneshot(get("/gated"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "Referrer required");

    let request = Request::builder()
        .uri("/gated")
        .header("referer", "https://good.example/page")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn standalone_validators_layer_blocks_with_the_validator_status_and_forwards() {
    let service = wrapped(&validators_layer());

    let response = service
        .clone()
        .oneshot(get("/private"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = service
        .oneshot(post("/private", "{}"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn standalone_time_window_layer_blocks_outside_the_window_and_forwards_inside() {
    let service = wrapped(&time_window_layer());

    let response = service
        .clone()
        .oneshot(get("/nightly"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "Access not allowed at this time");

    let response = service.oneshot(get("/open")).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn standalone_bans_layer_blocks_a_banned_ip_and_forwards_the_rest() {
    let manager = IpBanManager::new();
    manager
        .ban_ip(IpAddr::from_str("192.0.2.55").expect("ip"), 60, "operator")
        .expect("ban");
    let service = wrapped(&bans_layer(&manager));

    let response = service
        .clone()
        .oneshot(attributed_get("/api", "192.0.2.55"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "IP address banned");

    let response = service
        .oneshot(attributed_get("/api", "192.0.2.56"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn standalone_geo_layer_blocks_and_forwards() {
    let service = wrapped(&geo_layer());

    let response = service
        .clone()
        .oneshot(attributed_get("/api", "192.0.2.9"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "Forbidden");

    let response = service.oneshot(get("/api")).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK, "unattributed forwards");
}

#[tokio::test]
async fn standalone_cloud_layer_blocks_and_forwards() {
    let service = wrapped(&cloud_layer());

    let response = service
        .clone()
        .oneshot(attributed_get("/api", "192.0.2.9"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "Cloud provider IP not allowed");

    let response = service
        .oneshot(attributed_get("/api", "198.51.100.9"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn standalone_user_agent_layer_blocks_and_forwards() {
    let service = wrapped(&user_agent_layer());

    let request = Request::builder()
        .uri("/api")
        .header("user-agent", "bad-bot/1.0")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(response).await, "User-Agent not allowed");

    let request = Request::builder()
        .uri("/api")
        .header("user-agent", "friendly-crawler/2.0")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn standalone_rate_limit_layer_throttles_with_retry_after() {
    let service = wrapped(&rate_limit_layer());

    let response = service
        .clone()
        .oneshot(attributed_get("/api", "192.0.2.55"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let response = service
        .oneshot(attributed_get("/api", "192.0.2.55"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get(http::header::RETRY_AFTER)
            .expect("retry-after"),
        "60"
    );
    assert_eq!(body_text(response).await, "Too many requests");
}

#[tokio::test]
async fn standalone_rate_limit_layer_renders_the_custom_error_override() {
    let stage = tower_guard_rs::RateLimitStage::builder(tower_guard_rs::RateLimitStageConfig {
        rate_limit: tower_guard_rs::RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 60,
            ..tower_guard_rs::RateLimitConfig::default()
        },
        custom_error_responses: tower_guard_rs::CustomErrorResponses::from([(
            429,
            String::from("Slow down"),
        )]),
        ..tower_guard_rs::RateLimitStageConfig::default()
    })
    .limiter(
        tower_guard_rs::RateLimiter::new(tower_guard_rs::RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 60,
            ..tower_guard_rs::RateLimitConfig::default()
        })
        .expect("valid limiter"),
    )
    .build()
    .expect("valid stage");
    let service = wrapped(&GuardStageLayer::RateLimit(stage));

    let response = service
        .clone()
        .oneshot(attributed_get("/api", "192.0.2.55"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let response = service
        .oneshot(attributed_get("/api", "192.0.2.55"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_text(response).await, "Slow down");
}

#[tokio::test]
async fn standalone_custom_request_layer_blocks_with_status_and_forwards() {
    let service = wrapped(&custom_request_layer());

    let response = service
        .clone()
        .oneshot(get("/admin"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let response = service.oneshot(get("/public")).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn provided_layers_full_surface_lists_every_stage_in_reference_order() {
    let layer = GuardLayer::new(default_config())
        .with_emergency_mode(match emergency_layer() {
            GuardStageLayer::Emergency(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_https_enforcement(match https_layer() {
            GuardStageLayer::Https(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_headers_auth(match headers_auth_layer() {
            GuardStageLayer::HeadersAuth(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_referrer_gate(match referrer_layer() {
            GuardStageLayer::Referrer(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_custom_checks(match validators_layer() {
            GuardStageLayer::CustomValidators(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_time_window_gate(match time_window_layer() {
            GuardStageLayer::TimeWindow(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_geo_blocking(match geo_layer() {
            GuardStageLayer::Geo(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_cloud_provider(match cloud_layer() {
            GuardStageLayer::Cloud(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_user_agent(match user_agent_layer() {
            GuardStageLayer::UserAgent(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_rate_limiting(
            tower_guard_rs::RateLimiter::new(tower_guard_rs::RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 5,
                ..tower_guard_rs::RateLimitConfig::default()
            })
            .expect("valid limiter"),
        );

    let layers = provided_layers(&layer);
    let names: Vec<&'static str> = layers
        .iter()
        .map(|stage| match stage {
            GuardStageLayer::Emergency(_) => "emergency",
            GuardStageLayer::Https(_) => "https",
            GuardStageLayer::HeadersAuth(_) => "headers_auth",
            GuardStageLayer::Referrer(_) => "referrer",
            GuardStageLayer::CustomValidators(_) => "validators",
            GuardStageLayer::TimeWindow(_) => "time_window",
            GuardStageLayer::Bans(_) => "bans",
            GuardStageLayer::Geo(_) => "geo",
            GuardStageLayer::Cloud(_) => "cloud",
            GuardStageLayer::UserAgent(_) => "user_agent",
            GuardStageLayer::RateLimit(_) => "rate_limit",
            GuardStageLayer::CustomRequest(_) => "custom_request",
        })
        .collect();
    assert_eq!(
        names,
        vec![
            "emergency",
            "https",
            "headers_auth",
            "referrer",
            "validators",
            "time_window",
            "bans",
            "geo",
            "cloud",
            "user_agent",
            "rate_limit",
            "custom_request",
        ],
        "the reference pipeline order with every stage installed"
    );
}

#[tokio::test]
async fn provided_layers_without_stateful_stages_still_lists_the_middle_stages() {
    let layer = GuardLayer::new(default_config())
        .with_geo_blocking(match geo_layer() {
            GuardStageLayer::Geo(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_cloud_provider(match cloud_layer() {
            GuardStageLayer::Cloud(stage) => stage,
            _ => unreachable!("fixture shape"),
        })
        .with_user_agent(match user_agent_layer() {
            GuardStageLayer::UserAgent(stage) => stage,
            _ => unreachable!("fixture shape"),
        });

    let names: Vec<&'static str> = provided_layers(&layer)
        .iter()
        .map(|stage| match stage {
            GuardStageLayer::Geo(_) => "geo",
            GuardStageLayer::Cloud(_) => "cloud",
            GuardStageLayer::UserAgent(_) => "user_agent",
            _ => unreachable!("unexpected stage"),
        })
        .collect();
    assert_eq!(names, vec!["geo", "cloud", "user_agent"]);
}

// -------------------------------------------------------------------
// Fused-pass arms the stage wiring added: the request-logging compose
// and the trusted-proxy host forms.
// -------------------------------------------------------------------

#[tokio::test]
async fn request_logging_stage_composes_and_never_blocks() {
    let stage =
        tower_guard_rs::RequestLoggingStage::new(tower_guard_rs::RequestLoggingStageConfig {
            log_request_level: Some(guard_core_rs::logging::LogLevel::Info),
            ..tower_guard_rs::RequestLoggingStageConfig::default()
        });
    assert!(stage.exists(), "the reference construction gate");
    let service = GuardLayer::new(default_config())
        .with_request_logging(stage)
        .layer(echo());

    // The stage composes a line (the host's to emit) and never blocks.
    let response = service
        .clone()
        .oneshot(attributed_get("/api", "192.0.2.9"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    // An attack still blocks through the same pipeline.
    let response = service
        .oneshot(post("/api/comment", "<script>alert(1)</script>"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn https_enforcement_host_forms_feed_the_trusted_proxy_comparison() {
    let stage = HttpsEnforcementStage::builder(HttpsEnforcementStageConfig::default())
        .enforce_https(true)
        .build()
        .expect("valid");
    let service = GuardLayer::new(default_config())
        .with_https_enforcement(stage)
        .layer(echo());

    // A host header with a port: the redirect target keeps the host as
    // sent; the port strip feeds the trusted-proxy comparison only.
    let request = Request::builder()
        .uri("/private")
        .header("host", "guard.example:8443")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response
            .headers()
            .get(http::header::LOCATION)
            .expect("location"),
        "https://guard.example:8443/private"
    );

    // A bracketed IPv6 authority survives verbatim in the target.
    let request = Request::builder()
        .uri("http://[2001:db8::1]:8443/private")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        response
            .headers()
            .get(http::header::LOCATION)
            .expect("location"),
        "https://[2001:db8::1]:8443/private"
    );
}
