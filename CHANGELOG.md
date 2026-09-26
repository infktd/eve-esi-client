# Changelog

Changes to the crate itself. Routine spec refreshes are released
automatically and listed on the
[GitHub releases page](https://github.com/infktd/eve-esi-client/releases).

## 0.6.0

### Breaking: the TLS backend is a Cargo feature

reqwest's default features are no longer enabled, so aws-lc-sys (a C/cmake
build) is no longer unavoidable. Pick a backend:

- `rustls-aws-lc` (default): rustls with aws-lc-rs, the same as before.
- `rustls-no-provider`: rustls with no crypto provider, so no aws-lc-sys.
  Your application must install a process-wide rustls `CryptoProvider`
  (for example ring) before building any client, or reqwest panics. See
  [the README](README.md#installing-a-rustls-cryptoprovider).
- `native-tls`: the platform's TLS library.

reqwest's `charset`, `http2` and `system-proxy` features stay on.

Migrating: nothing changes with default features. If you depend on this
crate with `default-features = false`, it now fails to compile until you
enable one of the three features; previously you silently got rustls with
aws-lc-rs.

### Configurable HTTP clients and SSO endpoints

- `SsoClient::builder(client_id, redirect_uri)` with `.authorize_url(..)`,
  `.token_url(..)` and `.http_client(reqwest::Client)`. `SsoClient::new` is
  shorthand for the defaults, which are still `SSO_AUTHORIZE_URL` and
  `SSO_TOKEN_URL`.
- `ClientBuilder::http_client(reqwest::Client)` sends ESI requests through
  your client. `User-Agent` and `X-Compatibility-Date` are still added to
  every request.
- The HTTP clients built when you don't supply one now have a 30-second
  request timeout and a 10-second connect timeout (`DEFAULT_TIMEOUT`,
  `DEFAULT_CONNECT_TIMEOUT`); before, they had none. The SSO client's also
  identifies itself as `eve-esi-client/<version>` and no longer follows
  redirects, so a redirecting token endpoint now fails with
  `AuthError::Unreachable` instead of forwarding the code or refresh token.

### Pluggable response cache

- New `EsiCache` async trait (`get`, `put`, `remove`), keyed by
  `CacheKey { url, principal }`. `principal` is the bearer token's `sub`
  claim, so a cache shared between clients never serves one character's
  authenticated responses to another; a request whose bearer token has no
  readable `sub` is not cached. Implement it with `#[eve_esi_client::async_trait]`.
- `CachedResponse` has public fields (status, headers, body, ETag, and an
  absolute `expires_at: SystemTime`), so a persistent cache can store and
  rebuild entries and survives restarts. Its docs show how.
- `ClientBuilder::cache(Arc<dyn EsiCache>)` installs one. `MemoryCache`, the
  previous in-memory cache, is the default. `http_cache(false)` still turns
  caching off, including a cache passed to `cache(..)`.
- Unchanged: only GETs are cached, freshness is measured from ESI's `Date`
  and capped at 24 hours.

### Fixed: cached responses replayed stale budget headers

A cache hit or a revalidated 304 used to return the stored response's
original headers, including `X-ESI-Error-Limit-*` and `X-Ratelimit-*` from
when it was first fetched, and looked exactly like a fresh response. Now:

- responses answered from the cache carry `x-esi-client-cache: hit` and no
  budget headers;
- responses resurrected from a 304 carry `x-esi-client-cache: revalidated`,
  with the stored headers updated from the 304's own (whose budget headers
  are current);
- stored entries never keep budget headers.

Responses fetched from ESI are unchanged and carry no marker.

### Readable budgets

- `EsiInner::error_budget()` / `Client::error_budget()` return
  `Option<ErrorBudget { remain, resets_in }>`.
- `EsiInner::rate_budgets()` / `Client::rate_budgets()` return a
  `Vec<RateBudget { group, max_tokens, window, remaining_estimate, blocked_for }>`.

Both are `#[non_exhaustive]`. Read budgets from these instead of from
response headers.

### Other additions

- `EsiInner::without_cache()`: the same limiters, authenticator and default
  headers without a cache, for requests that must never be cached but should
  share backoff with the main client.
- `auth::PkceCodeVerifier` and `auth::CsrfToken` are re-exported, and so is
  the whole `oauth2` crate (`eve_esi_client::oauth2`), so a stored verifier
  can be rebuilt without depending on the same oauth2 version yourself.
- A poisoned lock in the cache or the error limiter no longer panics; their
  state is always written whole, so it stays usable.

## 0.5.0

### Breaking: SSO token failures are distinguishable by kind

`SsoClient::exchange`, `SsoClient::refresh` and
`Authenticator::access_token` used to report every token-endpoint failure as
`AuthError::Token(message)`, so "EVE rejected this refresh token" looked the
same as a network error or a Cloudflare 5xx page. `AuthError` now has:

- `Rejected { error, description }`: EVE SSO answered with an OAuth error
  response. `error` is the code exactly as returned (`invalid_grant`,
  `invalid_client`, `invalid_request`, `access_denied`, ...), and
  `description` is its `error_description`.
- `Unreachable(String)`: no usable answer came back. Either the HTTP request
  failed (the message now includes the underlying cause, e.g.
  `tcp connect error: Connection refused`) or the body wasn't an OAuth
  response, such as an HTML error page.
- `Token(String)`, `Config(String)` and `NoRefreshToken` are unchanged.
  `Token` now covers only the remaining cases, such as an empty response body.

`AuthError::is_permanent()` returns `true` when the user has to log in again:
a `Rejected` with `invalid_grant`, `invalid_token`, `invalid_client`,
`unauthorized_client` or `access_denied`, or `NoRefreshToken`. For anything
else, keep the tokens and retry later:

```rust
match sso.refresh(&refresh_token).await {
    Ok(tokens) => save(tokens),
    Err(e) if e.is_permanent() => ask_user_to_log_in_again(),
    Err(e) => retry_later(e),
}
```

Migrating: an exhaustive `match` on `AuthError` needs arms for `Rejected` and
`Unreachable`. Code that only matched `Token` still compiles, but most
failures no longer arrive as `Token`.

Requests made through `Client` still report an authentication failure as
`Error::Custom` holding the message, so the kind is only available to direct
callers of `SsoClient` and `Authenticator`.

## 0.4.0

### Breaking: untagged `oneOf` enums now discriminate correctly

Untagged `oneOf` enums now discriminate correctly; previously every value
parsed as the first variant.

ESI models tagged unions as a `oneOf` of single-key objects —
`{"faction": {..}}`, `{"alliance": {..}}`, `{"unclaimed": true}` — without
marking the key `required`. The generated enums were `#[serde(untagged)]` with
an optional field per variant, so the first variant matched every value with
its field set to `None`. For example, every system in
`GET /sovereignty/systems` parsed as a faction claim with no faction, and all
alliance sovereignty was lost.

The spec normalization now marks each branch's key as required, so these
become externally tagged enums that serde discriminates on the key:

```rust
// 0.3.x: every claim parsed as `Faction { faction: None }`
pub enum SovereigntySystemsSolarsystemClaim {
    Faction { faction: Option<SovereigntySystemsFaction> },
    Alliance { alliance: Option<SovereigntySystemsAlliance> },
    Unclaimed { unclaimed: Option<bool> },
}

// 0.4.0
pub enum SovereigntySystemsSolarsystemClaim {
    Faction(SovereigntySystemsFaction),
    Alliance(SovereigntySystemsAlliance),
    Unclaimed(bool),
}
```

Migrating: match `Claim::Alliance(alliance)` instead of
`Claim::Alliance { alliance: Some(alliance) }`. Each variant also gets a
`From` impl for its payload type when that type is unique within the enum. An
object whose key names no known variant (for example, one CCP adds later) is
now a deserialization error instead of a silent, empty first variant.

All 39 union enums in the spec change this way:

- `SovereigntySystemsSolarsystemClaim`
- `CharactersCosmeticsSkinrComponentsItemRuns`
- `CharactersParagonHubSkinrItemPrice`, `CharactersParagonHubSkinrItemTarget`
- `ParagonHubSkinrInternalItemPrice`
- `CosmeticsSkinrLayoutslotConfiguration`
- `CorporationsStructuresSovereigntyHubsDetailTransportConfiguration`,
  `CorporationsStructuresSovereigntyHubsDetailTransportState`
  (`Transit(Option<bool>)`, because `transit` is nullable)
- `FreelanceJobsDetailConfigurationParametersValue`
- `CorporationsProjectsDetailConfiguration` (17 variants)
- The `CorporationsProjectsDetailConfiguration*` list-item unions for each
  project kind: `*LocationsItem` (×12), `*IdentitiesItem` (×6),
  `*ShipsItem` (×6), `*ItemsItem` (×2), `*DockingLocationsItem` (×2),
  `*MaterialsItem` (×1)

No structs or client methods changed.
