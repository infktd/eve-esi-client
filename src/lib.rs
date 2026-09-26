//! A complete, spec-generated Rust client for EVE Online's
//! [ESI API](https://developers.eveonline.com/api-explorer).
//!
//! Every endpoint is generated at compile time from CCP's published OpenAPI
//! spec (`spec/esi-latest.json`), so coverage is always exactly what CCP
//! ships rather than a hand-maintained subset. On top of the generated
//! client sits a thin layer that implements ESI's operating rules
//! automatically:
//!
//! - **Rate-limit groups** — each route's token budget is known from the
//!   spec and tracked from `X-Ratelimit-*` headers. A request that could
//!   overdraw its group waits until enough spent tokens are released, so the
//!   client's own traffic never earns a 429; a 429 anyway holds the group
//!   until `Retry-After`. A drained bucket can mean waiting up to the group's
//!   full window (typically 15 minutes).
//! - **Error-limit backoff** — `X-ESI-Error-Limit-Remain`/`-Reset` are
//!   tracked from every response, and requests are held once the remaining
//!   error budget drops to a threshold, until the window resets.
//! - **Cache respect** — GET responses carrying `Expires`/`ETag` are kept
//!   in a cache (bounded and in memory by default; bring your own with
//!   [`ClientBuilder::cache`]). A route is never re-requested before its
//!   `Expires` elapses (it's answered from the cache), and stale routes are
//!   revalidated with `If-None-Match`, transparently resurrecting the body
//!   on `304 Not Modified`. See the [`cache`] module.
//! - **SSO** — EVE's OAuth2/PKCE flow ([`auth`]), with automatic token
//!   refresh on every request via [`ClientBuilder::authenticator`].
//! - The ESI-required `X-Compatibility-Date` header is injected on every
//!   request, pinned to the exact date this crate's types were generated
//!   against ([`COMPATIBILITY_DATE`]).
//!
//! # Quick start
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let client = eve_esi_client::Client::builder()
//!     .user_agent("my-app/1.0 (contact@example.com)")
//!     .build()?;
//! let status = client.get_status().send().await?;
//! println!("players online: {}", status.players);
//! # Ok(())
//! # }
//! ```
//!
//! ESI requires a `User-Agent` identifying your application; the builder
//! makes it mandatory.
//!
//! # TLS backends
//!
//! Pick one with Cargo features:
//!
//! - `rustls-aws-lc` (default): rustls with the aws-lc-rs crypto provider.
//! - `rustls-no-provider`: rustls with no crypto provider compiled in, so
//!   no aws-lc-sys (and its C/cmake build). The application **must** install
//!   a process-wide rustls `CryptoProvider` before building any client
//!   ([`Client`], [`auth::SsoClient`], or its own `reqwest::Client`), or
//!   reqwest panics:
//!
//!   ```ignore
//!   rustls::crypto::ring::default_provider()
//!       .install_default()
//!       .expect("no other CryptoProvider installed yet");
//!   ```
//! - `native-tls`: the platform's TLS library.

#[cfg(not(any(
    feature = "rustls-aws-lc",
    feature = "rustls-no-provider",
    feature = "native-tls"
)))]
compile_error!(
    "eve-esi-client needs a TLS backend: enable one of its features `rustls-aws-lc` \
     (the default), `rustls-no-provider` or `native-tls`. With `rustls-no-provider` your \
     application must install a rustls CryptoProvider before building a client; see \
     https://github.com/infktd/eve-esi-client#installing-a-rustls-cryptoprovider"
);

pub mod auth;
pub mod cache;
mod hooks;
mod limiter;
mod rate_limit;

mod generated {
    #![allow(clippy::all)]
    // CCP's endpoint descriptions become doc comments verbatim; some contain
    // bare URLs and bracketed text that trip rustdoc's lints.
    #![allow(rustdoc::broken_intra_doc_links, rustdoc::bare_urls)]
    include!(concat!(env!("OUT_DIR"), "/codegen.rs"));
}

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};

pub use async_trait::async_trait;
pub use cache::{CacheKey, CachedResponse, EsiCache, MemoryCache};
pub use generated::*;
pub use oauth2;

/// Total time allowed for a request made by a default HTTP client (the one
/// [`ClientBuilder::build`] or [`auth::SsoClientBuilder::build`] creates
/// when you don't supply your own).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Time allowed to establish a connection by a default HTTP client.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared per-client state consulted by the request hooks: rate-limit
/// bookkeeping, optional authenticator, optional HTTP cache.
///
/// Constructed by [`ClientBuilder`]. Clones share the same limiters, cache
/// and authenticator; `EsiInner::default()` has fresh limiters and no cache.
#[derive(Clone, Default)]
pub struct EsiInner {
    pub(crate) limiter: Arc<limiter::ErrorLimiter>,
    pub(crate) rate_limiter: Arc<rate_limit::RateLimiter>,
    pub(crate) cache: Option<Arc<dyn EsiCache>>,
    pub(crate) auth: Option<Arc<auth::Authenticator>>,
    /// Set on every request that doesn't already carry them.
    pub(crate) default_headers: HeaderMap,
}

impl EsiInner {
    /// The same state without a response cache: shares this one's error and
    /// rate limiters (so backoff is shared), authenticator and default
    /// headers. Use it for requests that must never be cached, e.g.
    /// `Client::new_with_client(base_url, http, inner.without_cache())`.
    pub fn without_cache(&self) -> EsiInner {
        EsiInner {
            cache: None,
            ..self.clone()
        }
    }

    /// The error budget ESI last reported, or `None` if none has been
    /// reported yet or its window has since reset.
    ///
    /// Read budgets here rather than from response headers: responses
    /// served from the cache carry no budget headers.
    pub fn error_budget(&self) -> Option<ErrorBudget> {
        self.limiter.budget()
    }

    /// The budget of every rate-limit group this client has used or learned
    /// about, ordered by group name.
    pub fn rate_budgets(&self) -> Vec<RateBudget> {
        self.rate_limiter.budgets()
    }
}

impl fmt::Debug for EsiInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EsiInner")
            .field("limiter", &self.limiter)
            .field("rate_limiter", &self.rate_limiter)
            .field("cache", &self.cache.as_ref().map(|_| "EsiCache"))
            .field("auth", &self.auth)
            .field("default_headers", &self.default_headers)
            .finish()
    }
}

/// ESI's error budget: how many more error responses (4xx/5xx) are allowed
/// before ESI starts answering 420, and when that count resets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ErrorBudget {
    /// Errors left in the current window (`X-ESI-Error-Limit-Remain`).
    pub remain: u32,
    /// Time until the window resets (from `X-ESI-Error-Limit-Reset`).
    pub resets_in: Duration,
}

/// One rate-limit group's token budget, as this client currently sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateBudget {
    /// The group name, e.g. `status` or `char-location`.
    pub group: String,
    /// Tokens the group allows per window.
    pub max_tokens: u32,
    /// The floating window spent tokens are released after.
    pub window: Duration,
    /// Tokens available to a new request now: ESI's last reported
    /// remaining count adjusted for released spends, minus what requests in
    /// flight have reserved. Other processes sharing the bucket can make
    /// the real figure lower.
    pub remaining_estimate: u32,
    /// Set after a 429: how much longer the group is held.
    pub blocked_for: Option<Duration>,
}

impl Client {
    /// Start building a [`Client`] wired for ESI: base URL, compatibility
    /// date, and (mandatory) user agent.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Shorthand for `client.inner().error_budget()`; see
    /// [`EsiInner::error_budget`].
    pub fn error_budget(&self) -> Option<ErrorBudget> {
        self.inner.error_budget()
    }

    /// Shorthand for `client.inner().rate_budgets()`; see
    /// [`EsiInner::rate_budgets`].
    pub fn rate_budgets(&self) -> Vec<RateBudget> {
        self.inner.rate_budgets()
    }
}

/// Builds a [`Client`] preconfigured for ESI.
#[derive(Default)]
pub struct ClientBuilder {
    user_agent: Option<String>,
    base_url: Option<String>,
    authenticator: Option<Arc<auth::Authenticator>>,
    http_cache: Option<bool>,
    cache: Option<Arc<dyn EsiCache>>,
    http_client: Option<reqwest::Client>,
    error_limit_threshold: Option<u32>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Identify your application to CCP, e.g.
    /// `"my-app/1.0 (contact@example.com)"`. Required — ESI asks that all
    /// third-party traffic carry an identifying `User-Agent`. It is sent
    /// even through a client passed to [`ClientBuilder::http_client`].
    pub fn user_agent(mut self, value: impl Into<String>) -> Self {
        self.user_agent = Some(value.into());
        self
    }

    /// Override the base URL (defaults to [`BASE_URL`]).
    pub fn base_url(mut self, value: impl Into<String>) -> Self {
        self.base_url = Some(value.into());
        self
    }

    /// Authenticate every request with EVE SSO, refreshing tokens
    /// automatically. See the [`auth`] module for the full flow.
    pub fn authenticator(mut self, value: auth::Authenticator) -> Self {
        self.authenticator = Some(Arc::new(value));
        self
    }

    /// Enable or disable response caching (default: enabled, with a
    /// [`MemoryCache`]). `false` disables caching entirely, including a
    /// cache set with [`ClientBuilder::cache`].
    pub fn http_cache(mut self, enabled: bool) -> Self {
        self.http_cache = Some(enabled);
        self
    }

    /// Cache responses in `cache` instead of a private [`MemoryCache`], for
    /// example to share one between clients or persist it across restarts.
    pub fn cache(mut self, cache: Arc<dyn EsiCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Send requests through `client` instead of one the builder creates.
    ///
    /// The `User-Agent` and `X-Compatibility-Date` headers are still added
    /// to every request; timeouts, proxies, TLS and any other policy are
    /// the supplied client's.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Hold requests once the remaining ESI error budget drops to this
    /// count, until the error window resets (default: 10).
    pub fn error_limit_threshold(mut self, remaining: u32) -> Self {
        self.error_limit_threshold = Some(remaining);
        self
    }

    /// Builds the client. Without [`ClientBuilder::http_client`], it gets
    /// its own `reqwest::Client` with a [`DEFAULT_TIMEOUT`] and a
    /// [`DEFAULT_CONNECT_TIMEOUT`].
    pub fn build(self) -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
        let user_agent = self
            .user_agent
            .ok_or("a User-Agent identifying your application is required by ESI")?;
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::try_from(user_agent)?);
        headers.insert(
            "X-Compatibility-Date",
            HeaderValue::from_static(COMPATIBILITY_DATE),
        );
        let http = match self.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .default_headers(headers.clone())
                .timeout(DEFAULT_TIMEOUT)
                .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
                .build()?,
        };
        let cache = match (self.http_cache.unwrap_or(true), self.cache) {
            (false, _) => None,
            (true, Some(cache)) => Some(cache),
            (true, None) => Some(Arc::new(MemoryCache::new()) as Arc<dyn EsiCache>),
        };
        let inner = EsiInner {
            limiter: Arc::new(limiter::ErrorLimiter::new(
                self.error_limit_threshold.unwrap_or(10),
            )),
            rate_limiter: Arc::default(),
            cache,
            auth: self.authenticator,
            default_headers: headers,
        };
        Ok(Client::new_with_client(
            self.base_url.as_deref().unwrap_or(BASE_URL),
            http,
            inner,
        ))
    }
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("user_agent", &self.user_agent)
            .field("base_url", &self.base_url)
            .field("authenticator", &self.authenticator)
            .field("http_cache", &self.http_cache)
            .field("cache", &self.cache.as_ref().map(|_| "EsiCache"))
            .field("http_client", &self.http_client)
            .field("error_limit_threshold", &self.error_limit_threshold)
            .finish()
    }
}
