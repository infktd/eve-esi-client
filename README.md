# eve-esi-client

[![crates.io](https://img.shields.io/crates/v/eve-esi-client.svg)](https://crates.io/crates/eve-esi-client)
[![docs.rs](https://img.shields.io/docsrs/eve-esi-client)](https://docs.rs/eve-esi-client)
[![CI](https://github.com/infktd/eve-esi-client/actions/workflows/ci.yml/badge.svg)](https://github.com/infktd/eve-esi-client/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A **complete, always-in-sync** Rust client for [EVE Online](https://www.eveonline.com/)'s
[ESI API](https://developers.eveonline.com/api-explorer) — every endpoint,
generated at compile time from CCP's own published OpenAPI spec, with a thin
hand-written layer that follows ESI's operating rules for you.

```
cargo add eve-esi-client
```

## Every endpoint. Zero hand-written bindings.

Most ESI crates hand-implement endpoints and cover a subset. This crate
compiles CCP's published spec ([pinned in-repo](spec/esi-latest.json))
through [progenitor](https://github.com/oxidecomputer/progenitor), so
coverage is **all 203 routes / 218 operations** — exactly what CCP ships,
including the current compatibility-date API surface (the modern ESI
versioning; this crate pins and sends `X-Compatibility-Date` for you).

A scheduled workflow watches CCP's spec around the clock. When CCP changes
it, the workflow builds and tests against the new spec and opens a PR
annotated with an additive/breaking classification of every change — so the
crate tracks ESI at the pace CCP publishes, not at the pace endpoints get
hand-written.

## ESI's rules, enforced automatically

ESI error-limits (and ultimately bans) clients that ignore its headers.
Every request through this client gets, with no configuration:

- **Error-limit backoff** — `X-ESI-Error-Limit-Remain`/`-Reset` tracked on
  every response; requests are held until the window resets once the
  remaining budget runs low, before you're anywhere near a 420.
- **Cache correctness** — a route is never re-requested before its
  `Expires` elapses (answered from a bounded in-memory cache), and stale
  routes revalidate with `If-None-Match`, transparently resurrecting the
  body on `304 Not Modified`. Bring your own storage? `.http_cache(false)`.
- **Compatibility-date pinning** — the required `X-Compatibility-Date`
  header is injected on every request, pinned to the exact date the crate's
  types were generated against. Your types and the wire format can't drift
  apart.
- **Identified traffic** — a `User-Agent` is mandatory at build time, per
  CCP's third-party guidelines.

## Quick start

```rust,no_run
# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let client = eve_esi_client::Client::builder()
    .user_agent("my-app/1.0 (contact@example.com)")
    .build()?;

let status = client.get_status().send().await?;
println!("players online: {}", status.players);

let orders = client
    .get_markets_region_id_orders()
    .region_id(10000002) // The Forge
    .send()
    .await?;
println!("orders in The Forge: {}", orders.len());
# Ok(())
# }
```

## EVE SSO (OAuth2 + PKCE) built in

Register an application at
[developers.eveonline.com](https://developers.eveonline.com/) (PKCE — no
secret needed), then:

```rust,no_run
# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
use eve_esi_client::auth::{Authenticator, SsoClient};

let sso = SsoClient::new("your-client-id", "http://localhost:8787/callback")?;
let pending = sso.authorize(["esi-location.read_location.v1"]);
// Send the user to `pending.url`; EVE redirects back with ?code=...&state=...
# let (code, returned_state) = ("", String::new());
assert_eq!(&returned_state, pending.csrf_state.secret());
let tokens = sso.exchange(code, pending.pkce_verifier).await?;
println!("logged in as {:?}", tokens.character_name());

let client = eve_esi_client::Client::builder()
    .user_agent("my-app/1.0 (contact@example.com)")
    .authenticator(Authenticator::new(sso, tokens))
    .build()?;
// every request now carries a Bearer token, refreshed before expiry
# Ok(())
# }
```

The SSO endpoint URLs come out of the spec's own security scheme at build
time, and tokens refresh automatically ahead of expiry on any request. See
[`examples/sso_login.rs`](examples/sso_login.rs) for the complete
round-trip including the localhost callback listener.

## How it compares

| | `eve-esi-client` | typical hand-written ESI crates |
|---|---|---|
| Endpoint coverage | All 203 routes, generated from CCP's spec | Partial, added endpoint-by-endpoint |
| Tracks ESI changes | Scheduled spec watch → annotated PR | Manual maintenance |
| Compatibility-date API | Yes, pinned + sent automatically | Mostly legacy versioned routes |
| Error-limit backoff | Automatic | Usually caller's responsibility |
| `Expires`/`ETag`/304 handling | Automatic, in-memory | Usually caller's responsibility |
| SSO (PKCE) + auto-refresh | Built in | Varies |

(If you only need a handful of endpoints and prefer a curated wrapper,
[rfesi](https://github.com/celeo/rfesi) is a fine hand-maintained
alternative.)

## Design notes

- **Generated code is never committed.** `build.rs` regenerates the client
  from the pinned spec on every build; releases provably match the exact
  spec version they ship with.
- **Faithful bindings, thin wrapper.** The generated API mirrors ESI's
  shape; the hand-written layer is auth + rate-limit + cache, not a
  re-modeling. No trading logic, no persistence, no opinions.
- **Golden-file tested.** A pinned historical spec snapshot must generate a
  method for every one of its operations on every CI run, catching codegen
  regressions independently of CCP.

## License

MIT or Apache-2.0, at your option.
