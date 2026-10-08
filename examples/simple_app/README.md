# simple_app

Minimal guarded service for tower: a tiny hand-rolled router wrapped in
[`tower_guard_rs::GuardLayer`](https://github.com/Guard-Core/tower-guard-rs) and
served over hyper. Every detection decision comes from the guard-core-rs
engine; the example itself holds no security logic.

## Routes

| Route | Guard | Behavior |
|---|---|---|
| `GET /health` | excluded | `200 ok`, answered before the guard |
| `GET /` | guarded | `200`, greeting text |
| `GET /search?q=...` | guarded | `200 search ok`, or `400` when the query trips the engine |
| `POST /echo` | guarded | echoes the request body; `400` for a threat, `413` over the body cap |
| anything else | guarded | `404 not found` |

`/health` demonstrates excluded-path behavior: the adapter scans every request
it sees, so exclusion is expressed as routing (the branch runs before the
guard), the same effect the Python distro's excluded-paths configuration has.

## Running

```sh
docker compose -f examples/simple_app/docker-compose.yml up --build -d --wait
```

The compose stack builds the example from the repository root and pulls the
engine source from the sibling checkout at `../guard-core-rs` (a compose
`additional_contexts` entry named `engine`). Locally, run from a directory
layout with both repositories checked out side by side. There is no Redis
service: guard-core-rs currently ships the CPU-bound detection pipeline only,
with no Redis, rate limit, or ban surface to wire up.

Run natively instead (requires the sibling `../guard-core-rs` checkout):

```sh
cargo build -p tower-guard-simple-app
APP_ADDR=127.0.0.1:8080 target/debug/tower-guard-simple-app
```

## Smoke assertions

The `live-smoke` GitHub Actions workflow runs exactly these against the
compose stack (on port 8080; set `SMOKE_PORT` to remap the host port):

| Assertion | Expected |
|---|---|
| `GET /` | `200` |
| `GET /health` | `200` (excluded path) |
| `GET /search?q=hello` | `200` |
| `GET /search?q=<script>alert(1)</script>` | `400`, body `Suspicious activity detected` |
| `GET /files/../../etc/passwd` (`--path-as-is`) | `400`, body `Suspicious activity detected` |
| `POST /echo` with a 300 KB body | `413`, body `Payload too large` (default cap: 262144 bytes) |
| `POST /echo` with body `hello world` | `200`, body echoed |

Quick manual check:

```sh
curl -is -G http://localhost:8080/search --data-urlencode 'q=<script>alert(1)</script>'
curl -is --path-as-is http://localhost:8080/files/../../etc/passwd
```

Tear down with:

```sh
docker compose -f examples/simple_app/docker-compose.yml down -v --remove-orphans
```
