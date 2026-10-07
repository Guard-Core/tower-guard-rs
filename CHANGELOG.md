# Changelog

All notable changes to this project.

v1.4.0 (2026-10-07)
-------------------

The reference-surface release: the status route lands as a tower service, training with the 4.3.1 parity-completion engine (v1.4.0)
-----------------------------------------------------------------------------------------------------------------------------------

### Note

- Trains with the engine: the `guard-core-engine` and `guard-core-rs` floors move to 4.3.1 (the parity-completion release)

### Added

- The reference status route (fastapi-guard `add_status_route` + `HandlerInitializer.get_initialization_status`): `GuardStatus` wired into the crate root, a tower `Service` serving the cloud-provider readiness table and the geo-ip component at `/_guard/status` from the handles the app already holds (#36). The WebSocket upgrade guard has no surface here: hyper-level upgrades live outside the tower `Service` contract

### Changed

- CI chores: the first-interaction greeting action takes its inputs underscore_named (#34) and is pinned to the v3.1.0 sha the engine repo pins (#33)

## [Unreleased]

### Added

- The reference route-config carrier consumption (`GuardLayer::with_route_configs`, the GAP-R2 tower leg): the engine's `RouteConfigResolver` (`(method, path) -> Option<Arc<RouteConfig>>`) resolves the route's `RouteConfig` per request - an `Arc<RouteConfig>` request extension wins over the resolver (the reference `request.state.route_config` idiom) - and the pipeline consumes it with the reference semantics: `bypassed_checks` (and the `"all"` wildcard) skip the named reference checks at their pipeline positions (the fused stages map as documented: `required_headers`/`authentication` skip the headers-auth stage, `ip_security` skips the gate, ban, and geo arms, `suspicious_activity` skips the scan and its violation feed), `require_https` rides the HTTPS stage's carrier lane (`decide_route`, the same trust knobs and passive handling as the global arm; with no stage installed the route arm still composes the reference `301`), `max_request_size` replaces the body cap for the route, `blocked_user_agents` runs additively before the global filter through the trusted-compile lane (a non-compilable route pattern fails secure `500`), the rate-limit group becomes the route's tier (an invalid tier fails secure), and the detection-exclusion group resolves through the engine's detection view; `RouteConfig`/`RouteConfigResolver` re-exported


### Added

- The unified-config consumption (`GuardLayer::from_security_config`, the GAP-R1 adapter wiring): the 129-field `SecurityConfig` (guard-core-engine 4.3.2's fieldized surface) builds the wired pipeline in one call - the detection budgets onto `DetectConfig`, the IP lists onto the gate, the rate-limit knobs onto the limiter, the ban group onto `IpBanManager` + `IpBanConfig`, `enforce_https`/`trust_x_forwarded_proto` onto the HTTPS stage, `emergency_mode` + its whitelist onto the emergency stage, `custom_error_responses`/`on_block` onto the response surface, the detection-exclusion group (with the reference's empty-set-disables-all-categories semantics) onto the scan, the observability group (level, mutes, the three sensitive sets) onto the log/redaction knobs, `blocked_user_agents` onto the user-agent stage (ReDoS-validated, failing closed), and the security-headers/CORS/behavior group onto the response processor; invalid values fail closed through the new typed `GuardConfigError`; the reference `exclude_paths` carve-out lands as a first-class builder consumed first in the pipeline (an excluded path bypasses every check, gate included)

### Changed

- The IP-gate denial path now renders the reference ip_filter behavior end to end: passive mode logs the crossing and forwards (no block, no gate decision downstream), the `on_block` hook fires once with the reference payload keys (`ip_security`), and the custom-error body override wins over the family default - previously the gate denial rendered the family body unconditionally and skipped both

## [Unreleased]
### Changed

- The CI coverage gate computes line coverage from the lcov export's per-line DA records instead of llvm-cov's summary table: llvm-cov 22's summary aggregation falsely reports missed lines that no line-level view (show text/html, lcov, cobertura, the JSON segment list) can see on the same profdata, and the divergence persists on the newest available toolchain (cargo-llvm-cov 0.9.1 + rustc 1.99.0). The gate keeps the same fail-closed 100%-lines semantics with nothing hidden or excluded; the summary table stays in the job as an informational printout. Evidence linked in the workflow (#35)

## [1.3.0] - 2026-10-01

### Note

- Trains with the engine: the `guard-core-engine` and `guard-core-rs` floors move to 4.3.0 (the safety-chain release: the full pattern-safety chain, the six pipeline stages' middleware events, the section-08 Redis key schema, the cloud fetchers, and the performance monitor). The adapter ships no logic changes of its own

### Changed

- Process and CI chores: the community and security process scaffold (#21), the 100% line coverage gate enforced with cargo-llvm-cov (#22), the CDLA-Permissive-2.0 license allowed from the engine sibling's graph (#28), and the routine GitHub Actions and crates-group dependency bumps with the lockfile refreshes that keep the sibling graph resolvable (#23-#27, #29-#31)

## [1.2.0] - 2026-09-27

### Note

- Trains with the engine: `guard-core-engine` and `guard-core-rs` floors move to 4.2.0 (the 4.1.0 engine dists were yanked; this release restores registry resolution)

### Added

- The wave surfaces are publicly configurable on `GuardLayer`, each wired to the engine facade's rate-limit stage (`guard_core_rs::tower::RateLimitStage`, which the layer now builds and delegates every stateful decision and emission to):
  - `with_route_tiers(resolver)` (`path -> Option<RouteRateLimits>`, the tower counterpart of `request.state.route_config`; a `RouteRateLimits` request extension wins over the resolver) and `with_geo_handler(Arc<dyn GeoIpHandler>)`: the reference's endpoint/route/geo rate-limit tiers; the first tier that crosses answers the same `429 + Retry-After` shape and feeds the auto-ban engine
  - `with_detection_exclusions(DetectionExclusionConfig)` plus the `RouteDetectionExclusions` request extension: the reference per-route detection-exclusion surface (`excluded_detection_headers/params/body_fields`, `enabled_detection_categories`, `detection_scan_body`), resolved per request through the engine's `detection_exclusions::resolve` + `scan_request` (excluded params and body fields skip, excluded headers scan with their false-positive categories suppressed, an all-filtered threat ends the scan clean)
  - `with_event_bus(Arc<SecurityEventBus>)`: the `penetration_attempt`/`rate_limited`/`ip_banned` events with the reference fields, metadata, and redaction
  - `with_observability(ObservabilityConfig)`: `log_suspicious_level`, `muted_check_logs`, and the `log_sensitive_headers/params/body_fields` redaction sets for the suspicious log lines, event fields, and `on_block` payloads
  - `with_on_block(OnBlockHook)` and `with_custom_error_responses(CustomErrorResponses)`: the hook fires exactly once per blocked request (and per passive-flagged detection with no status); the status-to-body map overrides every block body, the `400` detection block included
  - `with_distributed_store(window_store, redis_prefix, redis_fail_open)` + `with_distributed_ban_store(store)`: the reference distributed mode (fail-closed backend errors answer `503 "Redis rate limiting unavailable"`, `fail_open = true` degrades to the in-memory window)
  - `with_passive_mode(bool)`: the reference passive mode - windows and counters record, log lines and events fire, no block ever renders
- New re-exports: `DetectionExclusionConfig`, `RouteDetectionExclusions`, `GeoIpHandler`, `BanStore`, `SlidingWindowStore`, `ViolationCounters`, `RouteRateLimits`, `RateLimitEntry`, `RateLimitTier`, `TierDecision`, `SecurityEventBus`, `ObservabilityConfig`, `RequestObservation`, `StageResponse`, `BlockPayload`, `OnBlockHook`, `CustomErrorResponses`

### Changed

- `guard-core-rs` (the engine facade) joins `guard-core-engine` as a pinned 4.1.0 dependency with the sibling-checkout path fallback; the stage delegation is an implementation detail behind the existing `with_rate_limiting`/`with_ip_banning` signatures, which keep their shared-handle semantics (out-of-band bans and custom clocks honored) through the stage builder's `limiter`/`ban_manager` injection seams
- Scan semantics move onto the engine's reference surface: the query string is scanned as `parse_qsl`-decoded per-parameter pairs (previously one raw encoded blob), and the headers the exclusion resolution marks are scanned with their known false-positive categories suppressed (`ssrf` for address-chain values) instead of an adapter-level blanket skip. Exempt IPs now feed the violation counters (the reference suspicious-activity stage skips a whitelisted IP only; detection still scans and blocks them), so a crossed threshold bans even an exempt attacker


## [1.1.0] - 2026-09-26

### Added

- Stateful stage (rate limiting, dynamic bans, auto-ban) over the engine's new `rate_limit` and `ip_ban` modules, in-memory first (Redis-distributed mode is an engine follow-up):
  - `GuardLayer::with_rate_limiting(RateLimiter)`: the sliding-window limiter runs after the IP gate and the ban check, before body buffering - a crossing answers `429 Too Many Requests` with `Retry-After: <window seconds>`, the references' rate-limit shape. With the limiter's `enable_rate_limit_auto_ban` on, every crossing counts one `rate_limit` violation toward the auto-ban engine (`threat_ban_config["rate_limit"]` first, then the flat threshold), the reference pipeline's `_record_rate_limit_autoban`
  - `GuardLayer::with_ip_banning(IpBanManager, IpBanConfig)`: a live ban answers `403 Forbidden` (`IP address banned`) before the limiter, so banned traffic never consumes rate budget; every detected threat counts its categories per client IP (the reference pipeline's suspicious-activity stage) and a crossed `threat_ban_config` entry or the flat `auto_ban_threshold` bans on the spot, answering `403 Forbidden` (`IP has been banned`); `config.enable_ip_banning = false` counts violations but never bans; the plain detection block mirrors the reference suspicious-activity stage's status: `400 Bad Request` (`Suspicious activity detected`) for a flagged request, `403 Forbidden` (`IP has been banned`) only when the auto-ban fires on it
  - both stages honor the `exempt_ips` contract: whitelisted and exempt IPs are never rate limited, never banned (ban stage), and never have violations counted - which makes `exempt_ips` observable under load; unattributed requests (no `GuardClientIp` extension) cannot be held responsible and skip the stage, detection still screens them
  - `RateLimiter`, `IpBanManager`, and `ViolationCounters` are cheaply clonable and clone-share their stores, so out-of-band handles (admin unban endpoints, stats) work alongside the installed layer
- Optional global IP gate (`GuardLayer::with_ip_gate` over the new engine `IpGateConfig`): `whitelist`, `blacklist`, and `exempt_ips` lists parsed once at startup (invalid entry is a config error, fail closed), evaluated before body buffering - a blacklisted IP, or an IP a non-empty whitelist matches neither directly nor through `exempt_ips`, is denied with `403 Forbidden`. `exempt_ips` is the skip-list for known-friendly automation: it sets the same skip state a whitelist match sets (`IpGateDecision`, inserted into the request extensions) but never adds a deny path and never opens the whitelist gate; the blacklist, bans-style checks, and detection still apply to exempt IPs. The client IP comes from the new `GuardClientIp` request extension, so unattributed requests (no extension) are not gated and still screened by detection

### Changed

- `guard-core-engine` dependency pinned to the published 4.1.0 release (path dep kept for local builds and CI against a sibling `guard-core-rs` checkout), carrying the stateful sliding-window rate limiter and dynamic IP ban engine, the tower stage with a reusable `decide()`, and the new detection stages (request size/content, user-agent, headers/auth, cloud provider blocking, geo blocking)
- The buffered request body is no longer scanned as one lossy blob: it is routed by content type through the engine's body-value extraction (guard-core 4.0.4 parity, upstream commit 5f399234), and every extracted value is scanned through the normal detect path with its reference context - urlencoded field values under `request_body:form_field`, multipart part entries (label scan, `filename="..."` entry with RFC 2231 handling, raw part headers, payload) under `request_body:multipart_field`, embedded JSON leaves under the `:embedded_json` suffix, JSON mongo operator keys (`$where`, `$ne`, ...) as direct `nosql` hits, and the whole-body blob only as the fallback for plain or unparseable bodies
- Binary-dense multipart file-part payloads are reduced to printable runs of at least `detection_binary_min_run_length` (default 16) before pattern scanning, so compressed upload bytes stop producing attack-shaped matches while text embedded in uploads still scans in full; text uploads, text parts without a filename, and whole-body fallback scans keep their full scan
- 403/413/500 short-circuit responses now carry the bare message (`Suspicious activity detected`, `Payload too large`, `Security check failed`) as `text/plain; charset=utf-8`, matching the Python family's block-response convention, instead of the JSON `{"detail":"..."}` shape

## [1.0.0] - 2026-09-24

### Added

- First stable release of `tower-guard-rs` 1.0.0: application-layer security middleware for tower-based services, powered by `guard-core-engine` 4.0.4 (17/17 checks parity with guard-core 4.0.4, binary-noise gates)
- `GuardLayer` middleware: one engine call per request view (path, query string, headers, buffered body), 403/413/500 fail-secure responses with the ecosystem JSON `detail` shape, configurable body cap (default: engine full-scan cap), `catch_unwind` panic recovery
- Example apps: `examples/simple_app` and `examples/advanced_app` with Dockerfiles and docker-compose smoke stacks
- Dockerized live smoke workflow (`.github/workflows/live-smoke.yml`): compose run of `simple_app` with curl assertions of real engine behavior (XSS block, traversal block, 413 body cap, passthrough)
- Upstream drift guard (`.github/workflows/upstream-drift.yml`): daily test suite run against `guard-core-rs@master`
- Security audit workflow (`cargo deny`), release gate (fmt/clippy/test at tag on stable and MSRV 1.92, tag/version consistency), automated crates.io publish on GitHub release via `CARGO_REGISTRY_TOKEN`
- `Makefile` (`install`, `test`, `lint`, `fix`, `bump-version`, `clean`) and `.github/scripts/bump_version.py` (stdlib-only version bump across the crate, example pins, `Cargo.lock`, and a CHANGELOG scaffold)

### Changed

- `guard-core-engine` dependency pinned to the published 4.0.4 release (path dep kept for local builds and CI against a sibling `guard-core-rs` checkout)
