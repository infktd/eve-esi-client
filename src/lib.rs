//! A complete, spec-generated Rust client for EVE Online's
//! [ESI API](https://developers.eveonline.com/api-explorer).
//!
//! Every endpoint is generated at compile time from CCP's published OpenAPI
//! spec (`spec/esi-latest.json`), so coverage is always exactly what CCP
//! ships rather than a hand-maintained subset. On top of the generated
//! client sits a thin layer that implements ESI's operating rules
//! automatically:
//!
//! - **Error-limit backoff** — `X-ESI-Error-Limit-Remain`/`-Reset` are
//!   tracked from every response, and requests are held once the remaining
//!   error budget drops to a threshold, until the window resets.
//! - **Cache respect** — GET responses carrying `Expires`/`ETag` are kept
//!   in a bounded in-memory cache. A route is never re-requested before its
//!   `Expires` elapses (it's answered from memory), and stale routes are
//!   revalidated with `If-None-Match`, transparently resurrecting the body
//!   on `304 Not Modified`. Disable with [`ClientBuilder::http_cache`] if
//!   you layer your own storage.
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
//! let client = eve_esi::Client::builder()
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

pub mod auth;
mod cache;
mod hooks;
mod limiter;

mod generated {
    #![allow(clippy::all)]
    // CCP's endpoint descriptions become doc comments verbatim; some contain
    // bare URLs and bracketed text that trip rustdoc's lints.
    #![allow(rustdoc::broken_intra_doc_links, rustdoc::bare_urls)]
    include!(concat!(env!("OUT_DIR"), "/codegen.rs"));
}

use std::sync::Arc;

pub use generated::*;

/// Shared per-client state consulted by the request hooks: rate-limit
/// bookkeeping, optional authenticator, optional HTTP cache.
///
/// Constructed by [`ClientBuilder`]; you normally never touch this type.
#[derive(Debug, Clone, Default)]
pub struct EsiInner {
    pub(crate) limiter: Arc<limiter::ErrorLimiter>,
    pub(crate) cache: Option<Arc<cache::HttpCache>>,
    pub(crate) auth: Option<Arc<auth::Authenticator>>,
}

impl Client {
    /// Start building a [`Client`] wired for ESI: base URL, compatibility
    /// date, and (mandatory) user agent.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }
}

/// Builds a [`Client`] preconfigured for ESI.
#[derive(Debug, Default)]
pub struct ClientBuilder {
    user_agent: Option<String>,
    base_url: Option<String>,
    authenticator: Option<Arc<auth::Authenticator>>,
    http_cache: Option<bool>,
    error_limit_threshold: Option<u32>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Identify your application to CCP, e.g.
    /// `"my-app/1.0 (contact@example.com)"`. Required — ESI asks that all
    /// third-party traffic carry an identifying `User-Agent`.
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

    /// Enable or disable the in-memory `Expires`/`ETag` cache
    /// (default: enabled). Disable it if you layer your own HTTP caching.
    pub fn http_cache(mut self, enabled: bool) -> Self {
        self.http_cache = Some(enabled);
        self
    }

    /// Hold requests once the remaining ESI error budget drops to this
    /// count, until the error window resets (default: 10).
    pub fn error_limit_threshold(mut self, remaining: u32) -> Self {
        self.error_limit_threshold = Some(remaining);
        self
    }

    pub fn build(self) -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
        let user_agent = self
            .user_agent
            .ok_or("a User-Agent identifying your application is required by ESI")?;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "X-Compatibility-Date",
            reqwest::header::HeaderValue::from_static(COMPATIBILITY_DATE),
        );
        let http = reqwest::Client::builder()
            .user_agent(user_agent)
            .default_headers(headers)
            .build()?;
        let inner = EsiInner {
            limiter: Arc::new(limiter::ErrorLimiter::new(
                self.error_limit_threshold.unwrap_or(10),
            )),
            cache: self
                .http_cache
                .unwrap_or(true)
                .then(|| Arc::new(cache::HttpCache::new())),
            auth: self.authenticator,
        };
        Ok(Client::new_with_client(
            self.base_url.as_deref().unwrap_or(BASE_URL),
            http,
            inner,
        ))
    }
}
