//! A complete, spec-generated Rust client for EVE Online's
//! [ESI API](https://developers.eveonline.com/api-explorer).
//!
//! Every endpoint is generated at compile time from CCP's published OpenAPI
//! spec (`spec/esi-latest.json`), so coverage is always exactly what CCP
//! ships rather than a hand-maintained subset.
//!
//! # Quick start
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
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
//! makes it mandatory. The `X-Compatibility-Date` header — required by ESI
//! on every request — is injected automatically with the exact date this
//! crate's types were generated against ([`COMPATIBILITY_DATE`]).

mod generated {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/codegen.rs"));
}

pub use generated::*;

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
        Ok(Client::new_with_client(
            self.base_url.as_deref().unwrap_or(BASE_URL),
            http,
        ))
    }
}
