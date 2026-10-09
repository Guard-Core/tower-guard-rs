<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Application-layer security middleware for [tower](https://github.com/tower-rs/tower)-based services, powered by the [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection engine. Part of the [guard ecosystem](https://github.com/Guard-Core).</strong>
</p>

<p align="center">
    <a href="https://crates.io/crates/tower-guard-rs">
        <img src="https://img.shields.io/crates/v/tower-guard-rs?color=0080ff" alt="Crates.io version">
    </a>
    <a href="https://guard-core.github.io/tower-guard-rs/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/tower-guard-rs/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/tower-guard-rs/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/tower-guard-rs/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/tower-guard-rs/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/tower-guard-rs/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/tower-guard-rs/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/tower-guard-rs/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/tower-guard-rs/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/tower-guard-rs/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/tower-guard-rs/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/tower-guard-rs?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Tower-1B1B1B.svg?style=flat" alt="Tower">
    <a href="https://crates.io/crates/tower-guard-rs">
        <img src="https://img.shields.io/crates/d/tower-guard-rs" alt="Downloads">
    </a>
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/tower-guard-rs/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---


## Ecosystem

Guard Core is the Python engine. Framework adapters are thin wrappers that translate native request/response types into Guard Core's protocols. The telemetry agents ship security events and metrics to the monitoring backend. Parallel engine implementations exist for Go, PHP, TypeScript (on npm), and Rust (on crates.io) - all ports of the same reference semantics, conformance-tested against the shared adversarial corpus.

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/Guard-Core/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/Guard-Core/fastapi-guard) | FastAPI / Starlette adapter | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/Guard-Core/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### Go

Go modules published via GitHub releases. **Production-ready.**

| Package | Role | Release |
|---|---|---|
| [guard-core-go](https://github.com/Guard-Core/guard-core-go) | Go engine | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-core-go?label=tag)](https://github.com/Guard-Core/guard-core-go/releases) |
| [nethttp-guard](https://github.com/Guard-Core/nethttp-guard) | net/http adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/nethttp-guard?label=tag)](https://github.com/Guard-Core/nethttp-guard/releases) |
| [gin-guard](https://github.com/Guard-Core/gin-guard) | Gin adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/gin-guard?label=tag)](https://github.com/Guard-Core/gin-guard/releases) |
| [echo-guard](https://github.com/Guard-Core/echo-guard) | Echo (v4) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/echo-guard?label=tag)](https://github.com/Guard-Core/echo-guard/releases) |
| [fiber-guard](https://github.com/Guard-Core/fiber-guard) | Fiber (v3) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/fiber-guard?label=tag)](https://github.com/Guard-Core/fiber-guard/releases) |
| [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) | Telemetry agent | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-agent-go?label=tag)](https://github.com/Guard-Core/guard-agent-go/releases) |

### PHP

Published on [Packagist](https://packagist.org/) under the `rennf93` vendor. **Production-ready.**

| Package | Role | Packagist |
|---|---|---|
| [guard-core-php](https://github.com/Guard-Core/guard-core-php) | PHP engine | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-core-php)](https://packagist.org/packages/rennf93/guard-core-php) |
| [laravel-guard](https://github.com/Guard-Core/laravel-guard) | Laravel adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/laravel-guard)](https://packagist.org/packages/rennf93/laravel-guard) |
| [symfony-guard](https://github.com/Guard-Core/symfony-guard) | Symfony adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/symfony-guard)](https://packagist.org/packages/rennf93/symfony-guard) |
| [psr15-guard](https://github.com/Guard-Core/psr15-guard) | PSR-15 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/psr15-guard)](https://packagist.org/packages/rennf93/psr15-guard) |
| [slim-guard](https://github.com/Guard-Core/slim-guard) | Slim 4 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/slim-guard)](https://packagist.org/packages/rennf93/slim-guard) |
| [guard-agent-php](https://github.com/Guard-Core/guard-agent-php) | Telemetry agent | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-agent-php)](https://packagist.org/packages/rennf93/guard-agent-php) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope; source in the [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| | [@guardcore/core](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/@guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/hono) | Hono (edge) adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |
| [guardagent](https://github.com/Guard-Core/guard-agent-ts) | Telemetry agent | [![npm](https://img.shields.io/npm/v/guardagent)](https://www.npmjs.com/package/guardagent) |

### Rust

Published on crates.io. **Production-ready.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core-engine](https://github.com/Guard-Core/guard-core-rs) | Core engine crate | [![crates.io](https://img.shields.io/crates/v/guard-core-engine)](https://crates.io/crates/guard-core-engine) |
| [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) | Facade crate (consumer entry point) | [![crates.io](https://img.shields.io/crates/v/guard-core-rs)](https://crates.io/crates/guard-core-rs) |
| [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs) | Actix Web adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |
| [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [guard-agent-rs](https://github.com/Guard-Core/guard-agent-rs) | Telemetry agent | [![crates.io](https://img.shields.io/crates/v/guard-agent-rs)](https://crates.io/crates/guard-agent-rs) |

### AI Coding Agents

| Package | Role | PyPI |
|---|---|---|
| [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp) | MCP server: config validation, docs search, detection sandbox | [![PyPI](https://img.shields.io/pypi/v/guard-core-mcp)](https://pypi.org/project/guard-core-mcp/) |

___

## Documentation

📚 **[Documentation](https://guard-core.github.io/tower-guard-rs/latest/)** - full technical documentation for this package.

🛡️ **[Guard Core](https://guard-core.github.io/guard-core/latest/)** - the engine's reference documentation.

🤖 **[Monitoring Agent Integration](https://github.com/Guard-Core/guard-agent)** - monitor your Guard instance with a monitoring agent.
___

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/Guard-Core/fastapi-guard), [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard), [djapi-guard](https://github.com/Guard-Core/djapi-guard), [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard)
- **TypeScript**: guard-core-ts with adapters for Express, Fastify, Hono, NestJS
- **Rust**: [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) with adapters for tower (this repo), [axum](https://github.com/Guard-Core/axum-guard-rs), [actix-web](https://github.com/Guard-Core/actix-guard-rs), and [rocket](https://github.com/Guard-Core/rocket-guard-rs)

Per the ecosystem boundary rules, this crate holds framework glue only: every detection decision comes from the engine.

## Usage

```rust
use tower::Layer;

let layer = tower_guard_rs::GuardLayer::new(tower_guard_rs::default_config());

// Any `Service<Request<B>>` works; `axum::Router` is the usual one.
let service = layer.layer(my_service);
```

For axum, [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) wraps this layer with `with_guard(config)`. The full crate documentation is in [`src/lib.rs`](src/lib.rs) (build it with `cargo doc --open`).

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

`status::GuardStatusService::new(GuardStatus::new().with_cloud_table(table))` is the `add_status_route` mirror (fastapi-guard `guard/status.py` + `HandlerInitializer.get_initialization_status`): a plain tower service answering every request with the initialization snapshot, so the host framework routes it wherever the family default `/_guard/status` (`status::DEFAULT_STATUS_PATH`) belongs. The payload carries the cloud-provider status table (`{"ready":..., "last_refreshed":<unix-seconds|null>, "entries":N}` per provider from the live `CloudIpTable`) and the geo-ip component (`null` without a handler, `{"configured":true}` with the lookup trait only, the `{ready, last_refreshed, entries}` health snapshot with the `IpInfoManager` lifecycle manager). The maintenance trio lives on `GuardLayer`/`GuardService`: `reset()` drops the rate-limit windows, `refresh_cloud_ip_ranges()` schedules one single-flight refresh through `with_cloud_refresh_scheduler` (the refreshed ranges land in the shared table), and `agent_stats()` answers the reference property's no-agent shape. axum applications get the mounted route through `axum-guard-rs`'s `status::status_router`.

## WebSocket upgrades

WebSocket upgrades are not guarded by this adapter. A tower service sees the upgrade request like any other, but the upgrade itself completes at the hyper connection level (hyper's `on_upgrade` runtime), outside the `tower::Service` contract this crate is written against - there is no framework surface here to reject a handshake with the reference's close shapes. The guard exists where the framework exposes the upgrade: axum applications use [`axum-guard-rs`](https://github.com/Guard-Core/axum-guard-rs)'s `websocket::WebSocketGuard` (1008 policy / 1013 try-again-later close semantics, 403 pre-accept), and actix Web applications use `actix-guard-rs`'s `websocket::WebSocketGuard`. Plain requests (upgrade or not) still pass through this crate's checks as always.

## Engine dependency

The Cargo.toml pins `guard-core-engine` and `guard-core-rs` at 4.2.0 and carries paths pointing at the sibling `guard-core-rs` checkout (`../guard-core-rs/crates/guard-core-engine`, `../guard-core-rs/crates/guard-core-rs`) so local builds and CI compile the engine from source. Registry note, stated plainly: the 4.1.0 dists were yanked (the version-accuracy fix for the family tag mistake), so the 1.1.0 of this crate could not resolve its engine from the registry alone; the synchronized 4.2.0 train restores resolution (`tower-guard-rs` 1.2.0 over `guard-core-engine`/`guard-core-rs` 4.2.0). CI checks out `Guard-Core/guard-core-rs` (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)), mirroring the sibling adapter pattern in `laravel-guard`/`symfony-guard`.

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
