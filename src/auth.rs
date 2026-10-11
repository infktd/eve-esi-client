//! EVE SSO (OAuth2 authorization-code + PKCE) support.
//!
//! The endpoint URLs come from the spec's own OAuth2 security scheme
//! ([`crate::SSO_AUTHORIZE_URL`], [`crate::SSO_TOKEN_URL`]), so they stay in
//! lockstep with what CCP publishes.
//!
//! Flow:
//!
//! 1. [`SsoClient::authorize`] — get a browser URL plus the PKCE verifier
//!    and CSRF state to hold on to.
//! 2. The user logs in; EVE redirects to your `redirect_uri` with
//!    `code` and `state` query parameters.
//! 3. [`SsoClient::exchange`] the code (with the verifier) for a
//!    [`TokenSet`].
//! 4. Hand the token set to [`Authenticator::new`] and pass that to
//!    [`crate::ClientBuilder::authenticator`] — every request then carries
//!    a Bearer token, refreshed automatically before expiry.
//!
//! # Servers acting for many characters
//!
//! - **Web (confidential) applications** registered with a client secret
//!   pass it to [`SsoClientBuilder::client_secret`]; code exchanges and
//!   refreshes then authenticate with HTTP Basic, so refresh tokens issued
//!   to a secret-based application keep working.
//!   [`SsoClient::authorize_without_pkce`] and
//!   [`SsoClient::exchange_without_pkce`] serve flows that can't keep a PKCE
//!   verifier between the login redirect and the callback.
//! - **One client, many principals**: anything implementing
//!   [`TokenProvider`] (an [`Authenticator`], a [`StaticToken`], or your own
//!   database-backed provider) can be attached to a clone of a client with
//!   [`crate::Client::with_token_provider`] or
//!   [`crate::Client::with_access_token`]. The clones share error and
//!   rate limiters and the response cache, which stays keyed by character.
//! - **Rotated refresh tokens**: EVE may return a new refresh token on every
//!   refresh. Register a [`RefreshListener`] with
//!   [`Authenticator::with_listener`] to store them, and to learn when a
//!   token has been revoked ([`AuthError::is_revoked`]).
//! - **Claims**: [`TokenClaims`] reads the character, owner hash, scopes and
//!   expiry from an access token.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use std::sync::Arc;

use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, RedirectUrl, RefreshToken, RequestTokenError, Scope, TokenResponse as _,
    TokenUrl,
};

mod claims;
mod provider;
#[cfg(feature = "verify")]
mod verify;

pub(crate) use claims::jwt_claim;
pub use claims::TokenClaims;
pub use provider::{RefreshListener, StaticToken, TokenProvider};
#[cfg(feature = "verify")]
pub use verify::{JwtVerifier, VerifyError, SSO_JWKS_URL};

/// Re-exported from [`oauth2`] because [`PendingAuthorization`] and
/// [`SsoClient::exchange`] use them: rebuild a stored verifier with
/// `PkceCodeVerifier::new(secret)` without depending on `oauth2` yourself.
pub use oauth2::{CsrfToken, PkceCodeVerifier};

type ConfiguredClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// Errors from SSO configuration, token exchange, or refresh.
///
/// Token-request failures are split by what they mean for the tokens you
/// hold: [`AuthError::Rejected`] is EVE SSO's answer (check
/// [`AuthError::is_permanent`] — an `invalid_grant` means the user must log
/// in again), while [`AuthError::Unreachable`] means no usable answer came
/// back at all, so the token may well still be good and the request is
/// worth retrying later.
#[derive(Debug)]
pub enum AuthError {
    /// Invalid configuration (bad redirect URI, etc.).
    Config(String),
    /// EVE SSO answered with an OAuth error response.
    Rejected {
        /// The OAuth error code exactly as returned, e.g. `invalid_grant`,
        /// `invalid_client`, `invalid_request`, `unauthorized_client`,
        /// `access_denied`, `unsupported_grant_type`.
        error: String,
        /// The response's `error_description`, if it had one.
        description: Option<String>,
    },
    /// The token request never got a usable answer: the HTTP request itself
    /// failed, or the body wasn't an OAuth response (e.g. a Cloudflare error
    /// page in front of a 5xx).
    Unreachable(String),
    /// Any other token-request failure, e.g. an empty response body or an
    /// unexpected `Content-Type` on a success response.
    Token(String),
    /// No refresh token is available to renew an expired access token.
    NoRefreshToken,
}

impl AuthError {
    /// Whether retrying can't help and the user has to log in again: EVE
    /// rejected the grant, token, or client (`invalid_grant`,
    /// `invalid_token`, `invalid_client`, `unauthorized_client`,
    /// `access_denied`), or there is no refresh token to try. `false` for
    /// transient failures, where the held tokens should be kept.
    pub fn is_permanent(&self) -> bool {
        match self {
            AuthError::Rejected { error, .. } => matches!(
                error.as_str(),
                "invalid_grant"
                    | "invalid_token"
                    | "invalid_client"
                    | "unauthorized_client"
                    | "access_denied"
            ),
            AuthError::NoRefreshToken => true,
            AuthError::Config(_) | AuthError::Unreachable(_) | AuthError::Token(_) => false,
        }
    }

    /// Whether EVE rejected the token or grant itself (`invalid_grant`,
    /// `invalid_token`): the refresh token is revoked or expired, so discard
    /// it and have the user log in again.
    ///
    /// Narrower than [`AuthError::is_permanent`], which is also `true` for
    /// failures of the client as a whole (`invalid_client`,
    /// `unauthorized_client`, e.g. a wrong client secret). A server holding
    /// tokens for many users should delete a stored token only when this
    /// returns `true`; a client-level rejection would otherwise wipe every
    /// user's token at once.
    pub fn is_revoked(&self) -> bool {
        matches!(
            self,
            AuthError::Rejected { error, .. }
                if matches!(error.as_str(), "invalid_grant" | "invalid_token")
        )
    }

    fn from_token_request<RE: std::error::Error + 'static>(
        err: oauth2::basic::BasicRequestTokenError<RE>,
    ) -> Self {
        match err {
            RequestTokenError::ServerResponse(response) => AuthError::Rejected {
                error: response.error().as_ref().to_string(),
                description: response.error_description().cloned(),
            },
            RequestTokenError::Request(e) => AuthError::Unreachable(error_with_sources(&e)),
            // The body is deliberately left out: a parse failure can also
            // come from a success response, whose body would carry tokens.
            RequestTokenError::Parse(e, _body) => {
                AuthError::Unreachable(format!("unparseable token endpoint response: {e}"))
            }
            RequestTokenError::Other(e) => AuthError::Token(e),
        }
    }
}

/// An error's message followed by its `source()` chain, skipping causes
/// whose text an outer message already includes.
fn error_with_sources(err: &dyn std::error::Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Config(e) => write!(f, "SSO configuration error: {e}"),
            AuthError::Rejected { error, description } => {
                write!(f, "EVE SSO rejected the request: {error}")?;
                match description {
                    Some(description) => write!(f, " ({description})"),
                    None => Ok(()),
                }
            }
            AuthError::Unreachable(e) => write!(f, "EVE SSO could not be reached: {e}"),
            AuthError::Token(e) => write!(f, "SSO token request failed: {e}"),
            AuthError::NoRefreshToken => {
                write!(f, "access token expired and no refresh token is available")
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// An EVE SSO application client.
///
/// Register your application at <https://developers.eveonline.com/> to get
/// a client ID. A "native application" uses PKCE and needs no secret; a web
/// application with a client secret sets it with
/// [`SsoClientBuilder::client_secret`].
pub struct SsoClient {
    oauth: ConfiguredClient,
    http: BridgeClient,
    confidential: bool,
}

/// Builds an [`SsoClient`]; start with [`SsoClient::builder`].
pub struct SsoClientBuilder {
    client_id: String,
    redirect_uri: String,
    authorize_url: Option<String>,
    token_url: Option<String>,
    http_client: Option<reqwest::Client>,
    client_secret: Option<String>,
}

impl fmt::Debug for SsoClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SsoClientBuilder")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("authorize_url", &self.authorize_url)
            .field("token_url", &self.token_url)
            .field("http_client", &self.http_client)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl SsoClientBuilder {
    /// Authenticate token requests with this client secret (HTTP Basic), as
    /// a confidential "web application" registered with a secret does.
    ///
    /// Code exchanges and refreshes then send the secret, which EVE SSO
    /// requires for refresh tokens it issued to a secret-based application.
    /// PKCE stays on for [`SsoClient::authorize`] and
    /// [`SsoClient::exchange`]; with a secret,
    /// [`SsoClient::authorize_without_pkce`] and
    /// [`SsoClient::exchange_without_pkce`] also become available.
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// Where [`SsoClient::authorize`] sends the user (defaults to
    /// [`crate::SSO_AUTHORIZE_URL`]).
    pub fn authorize_url(mut self, url: impl Into<String>) -> Self {
        self.authorize_url = Some(url.into());
        self
    }

    /// Where codes and refresh tokens are exchanged (defaults to
    /// [`crate::SSO_TOKEN_URL`]).
    pub fn token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = Some(url.into());
        self
    }

    /// Send token requests through `client` instead of a default one.
    ///
    /// Disable redirects on it (`reqwest::redirect::Policy::none()`), as the
    /// default client does: a token endpoint that redirects could otherwise
    /// forward the authorization code or refresh token elsewhere.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Fails with [`AuthError::Config`] on an invalid URL, or if the default
    /// HTTP client can't be built.
    ///
    /// The default client identifies itself as `eve-esi-client/<version>`,
    /// allows [`crate::DEFAULT_TIMEOUT`] per request and
    /// [`crate::DEFAULT_CONNECT_TIMEOUT`] to connect, and never follows
    /// redirects.
    pub fn build(self) -> Result<SsoClient, AuthError> {
        let config = |e: oauth2::url::ParseError| AuthError::Config(e.to_string());
        let oauth = BasicClient::new(ClientId::new(self.client_id))
            .set_auth_uri(
                AuthUrl::new(
                    self.authorize_url
                        .unwrap_or_else(|| crate::SSO_AUTHORIZE_URL.to_string()),
                )
                .map_err(config)?,
            )
            .set_token_uri(
                TokenUrl::new(
                    self.token_url
                        .unwrap_or_else(|| crate::SSO_TOKEN_URL.to_string()),
                )
                .map_err(config)?,
            )
            .set_redirect_uri(RedirectUrl::new(self.redirect_uri).map_err(config)?);
        let confidential = self.client_secret.is_some();
        let oauth = match self.client_secret {
            Some(secret) => oauth.set_client_secret(ClientSecret::new(secret)),
            None => oauth,
        };
        let http = match self.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .user_agent(DEFAULT_USER_AGENT)
                .timeout(crate::DEFAULT_TIMEOUT)
                .connect_timeout(crate::DEFAULT_CONNECT_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| AuthError::Config(error_with_sources(&e)))?,
        };
        Ok(SsoClient {
            oauth,
            http: BridgeClient(http),
            confidential,
        })
    }
}

/// Sent by the default SSO HTTP client.
const DEFAULT_USER_AGENT: &str = concat!(
    "eve-esi-client/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/infktd/eve-esi-client)"
);

/// A pending authorization: send the user to `url`, keep `pkce_verifier`
/// and `csrf_state` for the callback.
pub struct PendingAuthorization {
    pub url: String,
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_state: CsrfToken,
}

impl SsoClient {
    /// `redirect_uri` must exactly match one registered for the
    /// application, e.g. `http://localhost:8787/callback`.
    ///
    /// Shorthand for `SsoClient::builder(client_id, redirect_uri).build()`:
    /// CCP's published endpoints and a default HTTP client.
    pub fn new(client_id: impl Into<String>, redirect_uri: &str) -> Result<Self, AuthError> {
        Self::builder(client_id, redirect_uri).build()
    }

    /// Configure the SSO endpoints or the HTTP client token requests go
    /// through.
    pub fn builder(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> SsoClientBuilder {
        SsoClientBuilder {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            authorize_url: None,
            token_url: None,
            http_client: None,
            client_secret: None,
        }
    }

    /// Whether this client authenticates with a client secret (see
    /// [`SsoClientBuilder::client_secret`]).
    pub fn is_confidential(&self) -> bool {
        self.confidential
    }

    /// Build the browser authorization URL for the given ESI scopes
    /// (e.g. `["esi-location.read_location.v1"]`).
    pub fn authorize<S: Into<String>>(
        &self,
        scopes: impl IntoIterator<Item = S>,
    ) -> PendingAuthorization {
        self.authorize_with_state(scopes, CsrfToken::new_random())
    }

    /// Like [`SsoClient::authorize`], with a `state` of your choosing instead
    /// of a random one, e.g. one that also encodes what the login is for.
    /// It must still be unguessable to protect the callback against CSRF.
    pub fn authorize_with_state<S: Into<String>>(
        &self,
        scopes: impl IntoIterator<Item = S>,
        state: CsrfToken,
    ) -> PendingAuthorization {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, csrf_state) = self
            .oauth
            .authorize_url(|| state)
            .add_scopes(scopes.into_iter().map(|s| Scope::new(s.into())))
            .set_pkce_challenge(challenge)
            .url();
        PendingAuthorization {
            url: url.to_string(),
            pkce_verifier: verifier,
            csrf_state,
        }
    }

    /// The browser authorization URL without a PKCE challenge, for a
    /// confidential client that can't keep a verifier until the callback
    /// (e.g. a stateless server whose callback page posts the code back).
    /// Exchange the code with [`SsoClient::exchange_without_pkce`]; the
    /// client secret authenticates that exchange instead.
    ///
    /// Fails with [`AuthError::Config`] unless a client secret is set.
    pub fn authorize_without_pkce<S: Into<String>>(
        &self,
        scopes: impl IntoIterator<Item = S>,
        state: CsrfToken,
    ) -> Result<String, AuthError> {
        self.require_secret("authorize_without_pkce")?;
        let (url, _) = self
            .oauth
            .authorize_url(|| state)
            .add_scopes(scopes.into_iter().map(|s| Scope::new(s.into())))
            .url();
        Ok(url.to_string())
    }

    fn require_secret(&self, method: &str) -> Result<(), AuthError> {
        if self.confidential {
            Ok(())
        } else {
            Err(AuthError::Config(format!(
                "SsoClient::{method} needs a client secret (SsoClientBuilder::client_secret)"
            )))
        }
    }

    /// Exchange the authorization code from the callback for tokens.
    pub async fn exchange(
        &self,
        code: impl Into<String>,
        pkce_verifier: PkceCodeVerifier,
    ) -> Result<TokenSet, AuthError> {
        let response = self
            .oauth
            .exchange_code(AuthorizationCode::new(code.into()))
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.http)
            .await
            .map_err(AuthError::from_token_request)?;
        Ok(TokenSet::from_response(&response))
    }

    /// Exchange an authorization code obtained without PKCE (see
    /// [`SsoClient::authorize_without_pkce`]), authenticating with the
    /// client secret.
    ///
    /// Fails with [`AuthError::Config`] unless a client secret is set.
    pub async fn exchange_without_pkce(
        &self,
        code: impl Into<String>,
    ) -> Result<TokenSet, AuthError> {
        self.require_secret("exchange_without_pkce")?;
        let response = self
            .oauth
            .exchange_code(AuthorizationCode::new(code.into()))
            .request_async(&self.http)
            .await
            .map_err(AuthError::from_token_request)?;
        Ok(TokenSet::from_response(&response))
    }

    /// Obtain a fresh token set from a refresh token.
    ///
    /// EVE may rotate the refresh token: store the returned
    /// [`TokenSet::refresh_token`] in place of the one you passed. If the
    /// response carries no refresh token, the one passed in is kept.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenSet, AuthError> {
        self.refresh_with_scopes(refresh_token, std::iter::empty::<String>())
            .await
    }

    /// Like [`SsoClient::refresh`], requesting `scopes` for the new access
    /// token (OAuth's `scope` parameter on a refresh). EVE SSO grants at
    /// most the scopes the refresh token carries; an empty list asks for
    /// all of them.
    pub async fn refresh_with_scopes<S: Into<String>>(
        &self,
        refresh_token: &str,
        scopes: impl IntoIterator<Item = S>,
    ) -> Result<TokenSet, AuthError> {
        let refresh = RefreshToken::new(refresh_token.to_string());
        let response = self
            .oauth
            .exchange_refresh_token(&refresh)
            .add_scopes(scopes.into_iter().map(|s| Scope::new(s.into())))
            .request_async(&self.http)
            .await
            .map_err(AuthError::from_token_request)?;
        let mut tokens = TokenSet::from_response(&response);
        tokens
            .refresh_token
            .get_or_insert_with(|| refresh_token.to_string());
        Ok(tokens)
    }
}

impl fmt::Debug for SsoClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SsoClient")
            .field("confidential", &self.confidential)
            .finish_non_exhaustive()
    }
}

/// Access + refresh tokens with their expiry.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<SystemTime>,
}

impl TokenSet {
    fn from_response(response: &oauth2::basic::BasicTokenResponse) -> Self {
        let access_token = response.access_token().secret().clone();
        let expires_at = match response.expires_in() {
            Some(d) => Some(SystemTime::now() + d),
            // Fall back to the JWT's own `exp`.
            None => TokenClaims::from_jwt_unverified(&access_token).and_then(|c| c.expires_at),
        };
        Self {
            access_token,
            refresh_token: response.refresh_token().map(|t| t.secret().clone()),
            expires_at,
        }
    }

    /// Whether the access token expires within `margin` from now. `false`
    /// when the expiry is unknown.
    pub fn expires_within(&self, margin: Duration) -> bool {
        match self.expires_at {
            Some(at) => SystemTime::now() + margin >= at,
            None => false,
        }
    }

    /// The access token's claims, read without signature verification (see
    /// [`TokenClaims::from_jwt_unverified`]). `None` if the access token
    /// isn't a JWT.
    pub fn claims(&self) -> Option<TokenClaims> {
        TokenClaims::from_jwt_unverified(&self.access_token)
    }

    /// The authenticated character's ID, from the access token's `sub`
    /// claim (`CHARACTER:EVE:<id>`). The claim is read without signature
    /// verification — fine for identifying your own session; do not use it
    /// to authenticate third-party tokens.
    pub fn character_id(&self) -> Option<u64> {
        self.claims()?.character_id
    }

    /// The authenticated character's name, from the token's `name` claim.
    /// Unverified; see [`TokenSet::character_id`].
    pub fn character_name(&self) -> Option<String> {
        self.claims()?.name
    }

    /// The scopes granted to the access token (its `scp` claim). Empty if
    /// none were granted or the token isn't a JWT. Unverified; see
    /// [`TokenSet::character_id`].
    pub fn scopes(&self) -> Vec<String> {
        self.claims().map(|c| c.scopes).unwrap_or_default()
    }

    /// The character owner hash (the `owner` claim), which changes when the
    /// character is transferred to another account. Unverified; see
    /// [`TokenSet::character_id`].
    pub fn owner_hash(&self) -> Option<String> {
        self.claims()?.owner
    }
}

/// Owns a [`TokenSet`] and refreshes it before expiry. Pass to
/// [`crate::ClientBuilder::authenticator`] to authenticate every request, or
/// use it as a [`TokenProvider`] with [`crate::Client::with_token_provider`].
pub struct Authenticator {
    sso: Arc<SsoClient>,
    tokens: tokio::sync::Mutex<TokenSet>,
    scopes: Vec<String>,
    listener: Option<Arc<dyn RefreshListener>>,
}

/// How long before expiry the held access token is refreshed.
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

impl Authenticator {
    pub fn new(sso: SsoClient, tokens: TokenSet) -> Self {
        Self::with_shared_client(Arc::new(sso), tokens)
    }

    /// Like [`Authenticator::new`], sharing one [`SsoClient`] (and its HTTP
    /// connection pool) between the authenticators of many characters.
    pub fn with_shared_client(sso: Arc<SsoClient>, tokens: TokenSet) -> Self {
        Self {
            sso,
            tokens: tokio::sync::Mutex::new(tokens),
            scopes: Vec::new(),
            listener: None,
        }
    }

    /// Notify `listener` after every refresh attempt, e.g. to store the
    /// rotated refresh token or drop a revoked one. See [`RefreshListener`].
    pub fn with_listener(mut self, listener: Arc<dyn RefreshListener>) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Request these scopes on every refresh (see
    /// [`SsoClient::refresh_with_scopes`]). By default none are named, so
    /// the new access token carries every scope the refresh token has.
    pub fn with_refresh_scopes<S: Into<String>>(
        mut self,
        scopes: impl IntoIterator<Item = S>,
    ) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// A currently-valid access token, refreshing first if the held one
    /// expires within the next minute.
    ///
    /// Concurrent callers wait for a single refresh. A [`RefreshListener`]
    /// runs before the lock is released, so stored tokens are always written
    /// in the order EVE issued them.
    pub async fn access_token(&self) -> Result<String, AuthError> {
        let mut tokens = self.tokens.lock().await;
        if tokens.expires_within(REFRESH_MARGIN) {
            let Some(refresh) = tokens.refresh_token.clone() else {
                let err = AuthError::NoRefreshToken;
                if let Some(listener) = &self.listener {
                    listener.refresh_failed(&tokens, &err).await;
                }
                return Err(err);
            };
            match self
                .sso
                .refresh_with_scopes(&refresh, self.scopes.iter().cloned())
                .await
            {
                Ok(fresh) => {
                    *tokens = fresh;
                    if let Some(listener) = &self.listener {
                        listener.refreshed(&tokens).await;
                    }
                }
                Err(err) => {
                    if let Some(listener) = &self.listener {
                        listener.refresh_failed(&tokens, &err).await;
                    }
                    return Err(err);
                }
            }
        }
        Ok(tokens.access_token.clone())
    }

    /// Snapshot of the current tokens (e.g. to persist the refresh token).
    pub async fn tokens(&self) -> TokenSet {
        self.tokens.lock().await.clone()
    }
}

#[async_trait::async_trait]
impl TokenProvider for Authenticator {
    async fn access_token(&self) -> Result<String, AuthError> {
        Authenticator::access_token(self).await
    }
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authenticator").finish_non_exhaustive()
    }
}

/// Bridges the `oauth2` crate onto this crate's reqwest, avoiding a second
/// HTTP/TLS stack in the dependency tree.
struct BridgeClient(reqwest::Client);

#[derive(Debug)]
enum BridgeError {
    Reqwest(reqwest::Error),
    Http(http::Error),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeError::Reqwest(e) => e.fmt(f),
            BridgeError::Http(e) => e.fmt(f),
        }
    }
}

// A transparent wrapper: same message as the inner error, same causes.
impl std::error::Error for BridgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BridgeError::Reqwest(e) => e.source(),
            BridgeError::Http(e) => e.source(),
        }
    }
}

impl<'c> oauth2::AsyncHttpClient<'c> for BridgeClient {
    type Error = BridgeError;
    type Future =
        Pin<Box<dyn Future<Output = Result<oauth2::HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: oauth2::HttpRequest) -> Self::Future {
        Box::pin(async move {
            let request = reqwest::Request::try_from(request).map_err(BridgeError::Reqwest)?;
            let response = self
                .0
                .execute(request)
                .await
                .map_err(BridgeError::Reqwest)?;
            let mut builder = http::Response::builder().status(response.status().as_u16());
            for (name, value) in response.headers() {
                builder = builder.header(name.as_str(), value.as_bytes());
            }
            let body = response.bytes().await.map_err(BridgeError::Reqwest)?;
            builder.body(body.to_vec()).map_err(BridgeError::Http)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use oauth2::basic::{BasicErrorResponse, BasicErrorResponseType, BasicRequestTokenError};

    /// What Cloudflare serves in front of a failing origin.
    const CLOUDFLARE_502: &str = "<!DOCTYPE html>\n<html><head><title>login.eveonline.com | \
        502: Bad gateway</title></head><body>Bad gateway</body></html>";

    fn server_response(
        error: BasicErrorResponseType,
        description: Option<&str>,
    ) -> BasicRequestTokenError<BridgeError> {
        RequestTokenError::ServerResponse(BasicErrorResponse::new(
            error,
            description.map(String::from),
            None,
        ))
    }

    /// Under `rustls-no-provider` nothing can build a reqwest client until a
    /// CryptoProvider is installed; these tests use ring.
    fn install_crypto_provider() {
        #[cfg(feature = "rustls-no-provider")]
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    const TOKEN_RESPONSE: &str = r#"{"access_token":"access","token_type":"Bearer","expires_in":1199,"refresh_token":"next-refresh"}"#;

    /// A localhost URL nothing is listening on.
    fn closed_port_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{addr}/v2/oauth/token")
    }

    #[test]
    fn server_error_response_is_rejected_with_its_exact_code() {
        let err = AuthError::from_token_request(server_response(
            BasicErrorResponseType::InvalidGrant,
            Some("Invalid refresh token. Token missing/expired."),
        ));
        match &err {
            AuthError::Rejected { error, description } => {
                assert_eq!(error, "invalid_grant");
                assert_eq!(
                    description.as_deref(),
                    Some("Invalid refresh token. Token missing/expired.")
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert!(err.is_permanent());
        assert_eq!(
            err.to_string(),
            "EVE SSO rejected the request: invalid_grant \
             (Invalid refresh token. Token missing/expired.)"
        );
    }

    #[test]
    fn only_rejections_that_need_a_new_login_are_permanent() {
        let cases = [
            (BasicErrorResponseType::InvalidGrant, true),
            (BasicErrorResponseType::InvalidClient, true),
            (BasicErrorResponseType::UnauthorizedClient, true),
            (
                BasicErrorResponseType::Extension("invalid_token".into()),
                true,
            ),
            (
                BasicErrorResponseType::Extension("access_denied".into()),
                true,
            ),
            (BasicErrorResponseType::InvalidRequest, false),
            (BasicErrorResponseType::InvalidScope, false),
            (BasicErrorResponseType::UnsupportedGrantType, false),
            (
                BasicErrorResponseType::Extension("temporarily_unavailable".into()),
                false,
            ),
        ];
        for (code, permanent) in cases {
            let expected_code = code.as_ref().to_string();
            let err = AuthError::from_token_request(server_response(code, None));
            assert!(
                matches!(&err, AuthError::Rejected { error, description: None } if *error == expected_code),
                "{expected_code}: got {err:?}"
            );
            assert_eq!(err.is_permanent(), permanent, "{expected_code}");
            assert_eq!(
                err.to_string(),
                format!("EVE SSO rejected the request: {expected_code}")
            );
        }
    }

    #[test]
    fn unparseable_response_is_unreachable_and_transient() {
        let parse_error = serde_path_to_error::deserialize::<_, BasicErrorResponse>(
            &mut serde_json::Deserializer::from_str(CLOUDFLARE_502),
        )
        .unwrap_err();
        let err = AuthError::from_token_request(RequestTokenError::<BridgeError, _>::Parse(
            parse_error,
            CLOUDFLARE_502.as_bytes().to_vec(),
        ));
        let AuthError::Unreachable(detail) = &err else {
            panic!("expected Unreachable, got {err:?}");
        };
        assert!(detail.contains("expected value"), "{detail}");
        assert!(!err.is_permanent());
        assert!(err
            .to_string()
            .starts_with("EVE SSO could not be reached: "));
        assert!(
            !err.to_string().contains("<html>"),
            "response body leaked into {err}"
        );
    }

    #[tokio::test]
    async fn transport_failure_is_unreachable_and_transient() {
        install_crypto_provider();
        let reqwest_error = reqwest::Client::new()
            .post(closed_port_url())
            .send()
            .await
            .unwrap_err();
        let top_level = reqwest_error.to_string();
        let err = AuthError::from_token_request(BasicRequestTokenError::Request(
            BridgeError::Reqwest(reqwest_error),
        ));
        let AuthError::Unreachable(detail) = &err else {
            panic!("expected Unreachable, got {err:?}");
        };
        // The cause chain, not just reqwest's "error sending request for url".
        assert!(detail.starts_with(&top_level), "{detail}");
        assert!(detail.to_lowercase().contains("refused"), "{detail}");
        assert!(!err.is_permanent());
        assert!(err
            .to_string()
            .starts_with("EVE SSO could not be reached: "));
    }

    #[test]
    fn other_failures_stay_token_and_transient() {
        let err = AuthError::from_token_request(BasicRequestTokenError::<BridgeError>::Other(
            "server returned empty error response".into(),
        ));
        assert!(
            matches!(&err, AuthError::Token(e) if e == "server returned empty error response"),
            "{err:?}"
        );
        assert!(!err.is_permanent());
        assert!(AuthError::NoRefreshToken.is_permanent());
        assert!(!AuthError::Config("bad redirect URI".into()).is_permanent());
    }

    /// `refresh` and `exchange` both go through the mapping, end to end.
    #[tokio::test]
    async fn refresh_and_exchange_classify_real_token_endpoint_failures() {
        install_crypto_provider();
        let rejecting = MockServer::start_async().await;
        rejecting
            .mock_async(|when, then| {
                when.method(POST).path("/v2/oauth/token");
                then.status(400)
                    .header("content-type", "application/json")
                    .body(
                        r#"{"error":"invalid_grant","error_description":"Invalid refresh token."}"#,
                    );
            })
            .await;
        let cloudflare = MockServer::start_async().await;
        cloudflare
            .mock_async(|when, then| {
                when.method(POST).path("/v2/oauth/token");
                then.status(502)
                    .header("content-type", "text/html; charset=UTF-8")
                    .body(CLOUDFLARE_502);
            })
            .await;

        for (token_url, permanent) in [
            (rejecting.url("/v2/oauth/token"), true),
            (cloudflare.url("/v2/oauth/token"), false),
            (closed_port_url(), false),
        ] {
            let sso = SsoClient::builder("test-client", "http://localhost:8787/callback")
                .token_url(&token_url)
                .build()
                .unwrap();
            let refreshed = sso.refresh("stale-refresh-token").await.unwrap_err();
            let exchanged = sso
                .exchange("auth-code", PkceCodeVerifier::new("v".repeat(43)))
                .await
                .unwrap_err();
            for err in [refreshed, exchanged] {
                if permanent {
                    assert!(
                        matches!(&err, AuthError::Rejected { error, .. } if error == "invalid_grant"),
                        "{token_url}: {err:?}"
                    );
                } else {
                    assert!(
                        matches!(err, AuthError::Unreachable(_)),
                        "{token_url}: {err:?}"
                    );
                }
                assert_eq!(err.is_permanent(), permanent, "{token_url}: {err:?}");
            }
        }
    }

    #[test]
    fn builder_overrides_the_authorize_url() {
        install_crypto_provider();
        let sso = SsoClient::builder("test-client", "http://localhost:8787/callback")
            .authorize_url("https://sso.example.test/v2/oauth/authorize")
            .build()
            .unwrap();
        let pending = sso.authorize(["esi-location.read_location.v1"]);
        assert!(
            pending
                .url
                .starts_with("https://sso.example.test/v2/oauth/authorize?"),
            "{}",
            pending.url
        );
        assert!(
            pending.url.contains("client_id=test-client"),
            "{}",
            pending.url
        );

        let default = SsoClient::new("test-client", "http://localhost:8787/callback").unwrap();
        let pending = default.authorize(["esi-location.read_location.v1"]);
        assert!(
            pending.url.starts_with(crate::SSO_AUTHORIZE_URL),
            "{}",
            pending.url
        );
    }

    #[test]
    fn invalid_urls_are_config_errors() {
        install_crypto_provider();
        for builder in [
            SsoClient::builder("c", "http://localhost:8787/callback").authorize_url("not a url"),
            SsoClient::builder("c", "http://localhost:8787/callback").token_url("not a url"),
            SsoClient::builder("c", "not a url"),
        ] {
            let err = builder.build().unwrap_err();
            assert!(matches!(err, AuthError::Config(_)), "{err:?}");
        }
    }

    /// Token requests go through the caller's client, e.g. one that enforces
    /// an egress allow-list.
    #[tokio::test]
    async fn token_requests_use_the_supplied_http_client() {
        install_crypto_provider();
        let server = MockServer::start_async().await;
        let token = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/v2/oauth/token")
                    .header("x-egress", "allow-listed");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(TOKEN_RESPONSE);
            })
            .await;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-egress", "allow-listed".parse().unwrap());
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap();
        let sso = SsoClient::builder("test-client", "http://localhost:8787/callback")
            .token_url(server.url("/v2/oauth/token"))
            .http_client(http)
            .build()
            .unwrap();

        let tokens = sso.refresh("refresh").await.unwrap();
        let exchanged = sso
            .exchange("auth-code", PkceCodeVerifier::new("v".repeat(43)))
            .await
            .unwrap();
        assert_eq!(token.calls_async().await, 2);
        assert_eq!(tokens.access_token, "access");
        assert_eq!(exchanged.refresh_token.as_deref(), Some("next-refresh"));
    }

    /// The default client names the crate and doesn't forward a token
    /// request to wherever the endpoint redirects.
    #[tokio::test]
    async fn default_client_identifies_itself_and_refuses_redirects() {
        install_crypto_provider();
        let elsewhere = MockServer::start_async().await;
        let stolen = elsewhere
            .mock_async(|when, then| {
                when.any_request();
                then.status(200)
                    .header("content-type", "application/json")
                    .body(TOKEN_RESPONSE);
            })
            .await;
        let server = MockServer::start_async().await;
        let token = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/v2/oauth/token")
                    .header_prefix("user-agent", "eve-esi-client/");
                then.status(307)
                    .header("location", elsewhere.url("/v2/oauth/token"));
            })
            .await;
        let sso = SsoClient::builder("test-client", "http://localhost:8787/callback")
            .token_url(server.url("/v2/oauth/token"))
            .build()
            .unwrap();

        let err = sso.refresh("refresh").await.unwrap_err();
        assert_eq!(token.calls_async().await, 1);
        assert_eq!(stolen.calls_async().await, 0, "redirect was followed");
        assert!(!err.is_permanent(), "{err:?}");
    }

    #[test]
    fn oauth2_types_are_reexported() {
        let verifier: PkceCodeVerifier = crate::oauth2::PkceCodeVerifier::new("v".repeat(43));
        assert_eq!(verifier.secret(), &"v".repeat(43));
        let state: crate::auth::CsrfToken = CsrfToken::new("state".into());
        assert_eq!(state.secret(), "state");
    }
}
