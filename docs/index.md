# tower-guard-rs

`tower-guard-rs` is application-layer security middleware for
[tower](https://github.com/tower-rs/tower)-based services, powered by the
[guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection engine.
It is part of the [Guard ecosystem](https://github.com/Guard-Core). It works
with any framework built on `tower::Service`, including
[axum](https://github.com/tokio-rs/axum) ([axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs)
composes this crate), [hyper](https://github.com/hyperium/hyper), and
[warp](https://github.com/seanmonstar/warp).

The crate holds framework glue only: every detection decision comes from the
engine. `GuardLayer` is a working `tower::Layer` and `GuardService` a working
`tower::Service` over `http::Request<B>`. The adapter is fail-secure: any
failure to complete the security check answers `500`, never an uninspected
passthrough.

## Ecosystem position

```text
guard-core (Python)           <- Reference implementation, spec owner
├── guard-core-rs             <- Rust engine: detection, preprocessing, semantics
│   ├── tower-guard-rs        <- Adapter: tower middleware (this repo)
│   ├── axum-guard-rs         <- Adapter: axum layer over tower-guard-rs
│   ├── actix-guard-rs        <- Adapter: actix-web middleware
│   └── rocket-guard-rs       <- Adapter: rocket fairing and guards
├── guard-core-go             <- Go port
└── guard-core-ts             <- TypeScript port
```

The adapter translates native request content into engine inputs (path, query
string, header values, buffered body), runs one engine call per request view,
and translates a threat verdict into a native block response.

## Installation

```bash
cargo add tower-guard-rs
```

The published crate is `1.0.0` and depends on the published
`guard-core-engine` `4.0.4`. Requires Rust 1.92 or later (edition 2024) and
tower 0.5. See [Installation](installation.md) for details.

## Quick start

```rust
use tower::Layer;

let layer = tower_guard_rs::GuardLayer::new(tower_guard_rs::default_config());

// Any `Service<Request<B>>` works; `axum::Router` is the usual one.
let service = layer.layer(my_service);
```

For axum, [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) wraps
this layer with `with_guard(config)`.

## What it inspects

One engine call per request view, mirroring the mapping used by the sibling
adapters:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers |
| Body | `request_body` | Buffered first, capped |

The HTTP method is not fed to the engine: the engine's
`detect(content, context, config)` takes content plus a context, and the
reference adapters do not scan the method either.

## Responses

| Situation | Status | Body |
|---|---|---|
| Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

## Where to go next

- [Installation](installation.md) for requirements and dependency setup
- [API](api.md) for the full public surface and behavior tables
- [Examples](examples.md) for runnable applications
