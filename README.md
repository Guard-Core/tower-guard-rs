# tower-guard-rs

Application-layer security middleware for [tower](https://github.com/tower-rs/tower)-based services, powered by the [guard-core-rs](https://github.com/rennf93/guard-core-rs) detection engine. Part of the [guard ecosystem](https://github.com/rennf93).

Docs: <https://rennf93.github.io/tower-guard-rs/>

Works with any framework built on `tower::Service`, including [axum](https://github.com/tokio-rs/axum) (see [axum-guard-rs](https://github.com/rennf93/axum-guard-rs)), [hyper](https://github.com/hyperium/hyper), and [warp](https://github.com/seanmonstar/warp).

**Status:** Released. Version 1.2.0, published to crates.io. `GuardLayer` and `GuardService` are working `tower` middleware over `http::Request<B>`, screened by the engine.

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/rennf93/fastapi-guard), [flaskapi-guard](https://github.com/rennf93/flaskapi-guard), [djapi-guard](https://github.com/rennf93/djapi-guard), [tornadoapi-guard](https://github.com/rennf93/tornadoapi-guard)
- **TypeScript**: guard-core-ts with adapters for Express, Fastify, Hono, NestJS
- **Rust**: [guard-core-rs](https://github.com/rennf93/guard-core-rs) with adapters for tower (this repo), [axum](https://github.com/rennf93/axum-guard-rs), [actix-web](https://github.com/rennf93/actix-guard-rs), and [rocket](https://github.com/rennf93/rocket-guard-rs)

Per the ecosystem boundary rules, this crate holds framework glue only: every detection decision comes from the engine.

## Usage

```rust
use tower::Layer;

let layer = tower_guard_rs::GuardLayer::new(tower_guard_rs::default_config());

// Any `Service<Request<B>>` works; `axum::Router` is the usual one.
let service = layer.layer(my_service);
```

For axum, [axum-guard-rs](https://github.com/rennf93/axum-guard-rs) wraps this layer with `with_guard(config)`. The full crate documentation is in [`src/lib.rs`](src/lib.rs) (build it with `cargo doc --open`).

## What it inspects

One engine call per request view, mirroring the mapping used by the sibling TypeScript adapters:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers (`Host`, `User-Agent`, `Accept`, `Accept-Encoding`, `Connection`, `Origin`, `Referer`) |
| Body | `request_body` | Buffered first, capped |

The HTTP method is not fed to the engine: the engine's `detect(content, context, config)` takes content plus a context, and the reference adapters do not scan the method either.

## Engine surfaces (public config)

Every stateful decision and emission runs through the engine facade's rate-limit stage, configured through `GuardLayer` builders:

| Surface | Builder / idiom |
|---|---|
| Rate-limit tiers | `.with_route_tiers(resolver)` (`path -> Option<RouteRateLimits>`; a `RouteRateLimits` request extension wins), `.with_geo_handler(handler)` (geo tiers) |
| Detection exclusions | `.with_detection_exclusions(config)` (global `excluded_detection_headers/params/body_fields`, `enabled_detection_categories`, `detection_scan_body`); per route via a `RouteDetectionExclusions` request extension (a non-`None` route value replaces the global set; headers always merge) |
| Events + log settings | `.with_event_bus(bus)` (`SecurityEventBus` hook registration), `.with_observability(config)` (`log_suspicious_level`, `muted_check_logs`, the `log_sensitive_headers/params/body_fields` redaction sets) |
| `on_block` + custom errors | `.with_on_block(hook)`, `.with_custom_error_responses(map)` (status-to-body overrides on every block answer, including the `400` detection block) |
| Distributed mode | `.with_distributed_store(window_store, prefix, fail_open)` + `.with_distributed_ban_store(ban_store)` (fail-closed backend errors answer `503 Redis rate limiting unavailable`) |
| Passive mode | `.with_passive_mode(true)` (windows and counters still record, log lines and events still fire, no `400`/`403`/`429` renders, auto-ban feeds suppressed) |

Scan notes: the query string is scanned as `parse_qsl`-decoded per-parameter pairs (what makes `excluded_detection_params` functional), and excluded headers scan with their known false-positive categories suppressed (`ssrf` for address-chain values) instead of a blanket skip.

## Responses

| Situation | Status | Body |
|---|---|---|
| The IP gate denies the client IP | `403 Forbidden` | `Forbidden` |
| A live ban on the client IP | `403 Forbidden` | `IP address banned` |
| Rate limit crossed | `429 Too Many Requests` (+ `Retry-After: <window>`) | `Too many requests` |
| The distributed backend fails with `redis_fail_open = false` | `503 Service Unavailable` | `Redis rate limiting unavailable` |
| Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
| Engine flags a view and a crossed auto-ban threshold bans on the spot | `403 Forbidden` | `IP has been banned` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

The bodies follow the ecosystem's plain-text error convention (the bare message, `text/plain; charset=utf-8`, same as the Python family), but the adapter is deliberately **fail-secure**: unlike the TypeScript adapters, whose check pipeline logs and skips on error, any failure to complete the security check answers `500`, never an uninspected passthrough.

Engine panics are caught with `catch_unwind`, so a detected threat or a failed check still produces a response instead of unwinding out of the connection task. `panic = "abort"` in the release profile disables that recovery.

## Body cap

Request bodies are buffered so the engine can inspect them, and the buffer is bounded. The cap defaults to the engine's full-scan cap (`DetectConfig::max_full_scan_bytes`, 262 144 bytes in the ecosystem default) and is configurable:

```rust
let layer = tower_guard_rs::GuardLayer::new(tower_guard_rs::default_config())
    .with_body_cap(1_048_576);
```

A body larger than the cap is rejected with `413` rather than forwarded unscanned: the engine would only ever see a truncated prefix, which would be a bypass vector.

## Status route

`status::GuardStatusService::new(GuardStatus::new().with_cloud_table(table))` is the `add_status_route` mirror (fastapi-guard `guard/status.py` + `HandlerInitializer.get_initialization_status`): a plain tower service answering every request with the initialization snapshot, so the host framework routes it wherever the family default `/_guard/status` (`status::DEFAULT_STATUS_PATH`) belongs. The payload carries the cloud-provider readiness table (`{"ready":...}` per provider from the live `CloudIpTable`) and the geo-ip component (`null` without a handler, `{"configured":true}` with one). The Rust engine tracks cloud readiness only, so the `entries`/`last_refreshed` keys the Python family serves have no counterpart here; the payload is rendered per request from in-memory state with no dependency added. axum applications get the mounted route through `axum-guard-rs`'s `status::status_router`.

## WebSocket upgrades

WebSocket upgrades are not guarded by this adapter. A tower service sees the upgrade request like any other, but the upgrade itself completes at the hyper connection level (hyper's `on_upgrade` runtime), outside the `tower::Service` contract this crate is written against - there is no framework surface here to reject a handshake with the reference's close shapes. The guard exists where the framework exposes the upgrade: axum applications use [`axum-guard-rs`](https://github.com/rennf93/axum-guard-rs)'s `websocket::WebSocketGuard` (1008 policy / 1013 try-again-later close semantics, 403 pre-accept), and actix Web applications use `actix-guard-rs`'s `websocket::WebSocketGuard`. Plain requests (upgrade or not) still pass through this crate's checks as always.

## Engine dependency

The Cargo.toml pins `guard-core-engine` and `guard-core-rs` at 4.2.0 and carries paths pointing at the sibling `guard-core-rs` checkout (`../guard-core-rs/crates/guard-core-engine`, `../guard-core-rs/crates/guard-core-rs`) so local builds and CI compile the engine from source. Registry note, stated plainly: the 4.1.0 dists were yanked (the version-accuracy fix for the family tag mistake), so the 1.1.0 of this crate could not resolve its engine from the registry alone; the synchronized 4.2.0 train restores resolution (`tower-guard-rs` 1.2.0 over `guard-core-engine`/`guard-core-rs` 4.2.0). CI checks out `rennf93/guard-core-rs` (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)), mirroring the sibling adapter pattern in `laravel-guard`/`symfony-guard`.

The adapter now depends on both halves of the sibling checkout: the `guard-core-engine` crate (detection, rate limiting, bans, exclusions, geo, distributed traits) and the `guard-core-rs` facade (the event bus, the log/redaction port, the `on_block`/custom-error contract, and the rate-limit stage the layer delegates to), both pinned at 4.2.0 with path fallbacks into `../guard-core-rs`.

## Stage surface (the reference 17-check pipeline, wired)

Every reference check the engine ships is installable on `GuardLayer`, and `GuardService` runs the installed set in the reference pipeline order (`provided_layers` hands the same stages back as standalone tower layers in that order): emergency mode, HTTPS enforcement, request logging, request size/content caps, required headers + authentication, referrer, custom validators, time windows, geo country blocking, cloud-provider blocking, user-agent filtering, bans, rate limiting, the custom-request check, and the response-side pass (behavioral return rules + security headers + CORS). The builder table lives in the crate docs.

## Not wired on purpose

- **WebSocket guard**: a tower service sees a WebSocket upgrade as an ordinary request, so the handshake is screened like any request; frames after the upgrade are not intercepted. There is no per-frame guard surface.
- **Status route**: no `add_status_route` equivalent ships (a gap tracked family-wide); expose engine state through your own route if you need it.

## Development

- MSRV: 1.92 (matches guard-core-rs); edition 2024
- Requires a sibling `guard-core-rs` checkout at `../guard-core-rs`

```bash
cargo check --all-targets
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

CI (`.github/workflows/ci.yml`) runs the same checks on stable plus an MSRV 1.92 job, checking out `guard-core-rs` first so the path dependency resolves.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
