---
name: tower-guard-rs
description: Use when working in the tower-guard-rs Rust crate (github.com/Guard-Core/tower-guard-rs): editing the tower Layer/Service security middleware, adding or changing engine view mapping (url_path/query_param/header/request_body), changing the request body buffering cap or the 403/413/500 fail-secure response translation, wiring the guard-core-rs engine dependency (path vs versioned, CI checkout), or answering questions about what the adapter inspects and blocks. Covers CI-verified cargo commands, the EXCLUDED_HEADERS policy, and the cfg(test) detector seam for panic-recovery tests.
---

# tower-guard-rs

Framework-agnostic `tower` adapter for the Guard ecosystem. `GuardLayer` + `GuardService` screen `http::Request` traffic through the `guard-core-engine` detection engine and short-circuit with a `403`/`413`/`500` when needed. No security logic lives here.

## Quick Reference

```bash
# A sibling guard-core-rs checkout at ../guard-core-rs is required.
cargo check --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings   # pedantic is warn, so this enforces it
cargo test                                  # 12 unit + 13 integration + 3 doctests
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

## Public API

- `GuardLayer::new(DetectConfig)`, `GuardLayer::with_defaults()`, `GuardLayer::with_body_cap(usize)`. Implements `tower::Layer<S>` -> `GuardService<S>`.
- `GuardService<S>` implements `tower::Service<Request<B>>` with `Response = Response<GuardBody<B2>>` and `Error = S::Error`. Requires `S: Service<Request<B>, Response = Response<B2>> + Clone + Send + 'static`, `B: Body<Data = Bytes> + Unpin + Send + 'static + From<Bytes>`, `B2: Body<Data = Bytes> + Unpin + Send + 'static`.
- `default_config() -> DetectConfig` pins the ecosystem defaults because the engine's `DetectConfig` has no `Default`: `max_content_length` 10 000, `max_full_scan_bytes` 262 144, `preserve_attack_patterns` true, `semantic_threshold` 0.7, `threat_score_threshold` 1.0.
- `BLOCKED_MESSAGE` / `OVERSIZE_MESSAGE` / `FAILURE_MESSAGE` are the public detail strings; `GuardBody<B>` is `Passthrough(B) | Generated(Full<Bytes>)`.

## Engine Mapping

`guard_core_engine::detect::detect(content, request_context, config) -> DetectVerdict` is called once per view:

| Request part | Context |
|---|---|
| `uri.path()` (not `/`) | `url_path` |
| `uri.query()` (non-empty) | `query_param` |
| header value (name not excluded) | `header` |
| buffered body (non-empty) | `request_body` |

`DetectVerdict` carries `is_threat`/`threat_score`/`threats` and no response shape; the response translation is adapter-side in `src/response.rs`.

## Behavior Contracts

- Block: `400` + `Suspicious activity detected`.
- Oversize body: `413` + `Payload too large`. Cap defaults to `max_full_scan_bytes`; oversize is rejected, never passed unscanned.
- Body read error or engine panic: `500` + `Security check failed`. Fail-secure, unlike the TypeScript adapters which fail open.
- `EXCLUDED_HEADERS` (never scanned): `host`, `user-agent`, `accept`, `accept-encoding`, `connection`, `origin`, `referer`, plus every `sec-*` header. Mirrors `guard-core-ts`.
- Method is not scanned (the engine has no method parameter). Non-UTF-8 header values are skipped.
- The inner service is cloned into the request future, so `S: Clone` is required (axum's `Route` and every framework service satisfy this).
- The request future is boxed per request (`Pin<Box<dyn Future + Send>>`), one allocation; the body is re-emitted as `B::from(Bytes)` after buffering.

## Footguns

- `panic = "abort"` disables the `catch_unwind` recovery; the process dies before the `500` can be returned. Documented, not mitigated.
- The panic test relies on `#[cfg(test)] GuardLayer::with_detect_fn`. It does not exist in production builds; do not make it public.
- `axum::body::Body` implements `From<Bytes>` but not `From<Full<Bytes>>`. That is why the rebuild bound is `From<Bytes>`; do not "simplify" it back.
- The engine dependency is a path dependency (`../guard-core-rs/crates/guard-core-engine`) with a `TODO(engine)` to move to the versioned crate. CI checks out `Guard-Core/guard-core-rs@master` into place. The facade crate `guard-core-rs` is NOT used because it does not re-export `detect`.
- Payloads in tests must come from the spec 4.0.2 corpus (`guard-core-rs/conformance/guard-core-spec-4.0.2/cases/`) so they are guaranteed threats.

## Related

- `axum-guard-rs`: axum wrapper (`with_guard`) over this crate.
- `guard-core-rs`: the engine. Engine behavior changes belong there, not here.
