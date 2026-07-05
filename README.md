# eve-esi

A complete, always-in-sync Rust client for [EVE Online](https://www.eveonline.com/)'s
[ESI API](https://developers.eveonline.com/api-explorer) — generated at
compile time from CCP's own published OpenAPI spec, with a thin hand-written
layer that implements ESI's operating rules for you.

## Why this crate

- **Complete, by construction.** Every route in CCP's spec (203 paths, 218
  operations) gets a generated method — coverage is whatever CCP publishes,
  not a hand-maintained subset. A scheduled workflow watches CCP's spec and
  opens a reviewable PR when it changes, so the crate tracks ESI with
  near-zero maintenance.
- **ESI's rules, automatically.** ESI bans clients that ignore its error
  budget and cache headers. This client:
  - tracks `X-ESI-Error-Limit-Remain`/`-Reset` on every response and holds
    requests until the window resets once the budget runs low;
  - never re-requests a route before its `Expires` elapses (served from a
    bounded in-memory cache) and revalidates stale routes with
    `If-None-Match`, transparently resurrecting bodies on `304`;
  - sends the required `X-Compatibility-Date` on every request, pinned to
    the exact date the crate's types were generated against;
  - requires a `User-Agent` identifying your app, per CCP's guidelines.
- **EVE SSO built in.** OAuth2 authorization-code + PKCE flow, with
  automatic token refresh on every authenticated request.

## Quick start

```rust,no_run
# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let client = eve_esi::Client::builder()
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

## Authentication

Register an application at
[developers.eveonline.com](https://developers.eveonline.com/) (PKCE, no
secret needed), then:

```rust,no_run
# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
use eve_esi::auth::{Authenticator, SsoClient};

let sso = SsoClient::new("your-client-id", "http://localhost:8787/callback")?;
let pending = sso.authorize(["esi-location.read_location.v1"]);
// Send the user to `pending.url`; EVE redirects back with ?code=...&state=...
# let (code, returned_state) = ("", String::new());
assert_eq!(&returned_state, pending.csrf_state.secret());
let tokens = sso.exchange(code, pending.pkce_verifier).await?;

let client = eve_esi::Client::builder()
    .user_agent("my-app/1.0 (contact@example.com)")
    .authenticator(Authenticator::new(sso, tokens))
    .build()?;
# Ok(())
# }
```

See [`examples/sso_login.rs`](examples/sso_login.rs) for the full
round-trip including the localhost callback listener.

## How it stays in sync

`spec/esi-latest.json` is CCP's published OpenAPI document, committed
verbatim (pretty-printed for reviewable diffs). `build.rs` feeds it through
[progenitor](https://github.com/oxidecomputer/progenitor) at compile time —
generated code is never committed. A scheduled GitHub Action re-fetches the
spec, and when it changes, builds and tests against it and opens a PR
annotated with an additive/breaking classification of every change.
Releases are manual, never automatic.

## Non-goals

Transport and bindings only: no trading logic, no opinionated re-modeling
of ESI's shape, no persistence (the HTTP cache is in-memory only — disable
it with `.http_cache(false)` and bring your own storage if you need more).

## License

MIT or Apache-2.0, at your option.
