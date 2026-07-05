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

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse as _,
    TokenUrl,
};

type ConfiguredClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// Errors from SSO configuration, token exchange, or refresh.
#[derive(Debug)]
pub enum AuthError {
    /// Invalid configuration (bad redirect URI, etc.).
    Config(String),
    /// The token endpoint rejected or failed the request.
    Token(String),
    /// No refresh token is available to renew an expired access token.
    NoRefreshToken,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Config(e) => write!(f, "SSO configuration error: {e}"),
            AuthError::Token(e) => write!(f, "SSO token request failed: {e}"),
            AuthError::NoRefreshToken => {
                write!(f, "access token expired and no refresh token is available")
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// An EVE SSO application client (PKCE, no client secret).
///
/// Register your application at <https://developers.eveonline.com/> to get
/// a client ID; use "native application" / PKCE, which needs no secret.
pub struct SsoClient {
    oauth: ConfiguredClient,
    http: BridgeClient,
}

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
    pub fn new(client_id: impl Into<String>, redirect_uri: &str) -> Result<Self, AuthError> {
        let oauth = BasicClient::new(ClientId::new(client_id.into()))
            .set_auth_uri(
                AuthUrl::new(crate::SSO_AUTHORIZE_URL.to_string())
                    .map_err(|e| AuthError::Config(e.to_string()))?,
            )
            .set_token_uri(
                TokenUrl::new(crate::SSO_TOKEN_URL.to_string())
                    .map_err(|e| AuthError::Config(e.to_string()))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(redirect_uri.to_string())
                    .map_err(|e| AuthError::Config(e.to_string()))?,
            );
        Ok(Self {
            oauth,
            http: BridgeClient(reqwest::Client::new()),
        })
    }

    /// Build the browser authorization URL for the given ESI scopes
    /// (e.g. `["esi-location.read_location.v1"]`).
    pub fn authorize<S: Into<String>>(
        &self,
        scopes: impl IntoIterator<Item = S>,
    ) -> PendingAuthorization {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, csrf_state) = self
            .oauth
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes.into_iter().map(|s| Scope::new(s.into())))
            .set_pkce_challenge(challenge)
            .url();
        PendingAuthorization {
            url: url.to_string(),
            pkce_verifier: verifier,
            csrf_state,
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
            .map_err(|e| AuthError::Token(e.to_string()))?;
        Ok(TokenSet::from_response(&response))
    }

    /// Obtain a fresh token set from a refresh token.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenSet, AuthError> {
        let response = self
            .oauth
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(&self.http)
            .await
            .map_err(|e| AuthError::Token(e.to_string()))?;
        Ok(TokenSet::from_response(&response))
    }
}

impl fmt::Debug for SsoClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SsoClient").finish_non_exhaustive()
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
        Self {
            access_token: response.access_token().secret().clone(),
            refresh_token: response.refresh_token().map(|t| t.secret().clone()),
            expires_at: response.expires_in().map(|d| SystemTime::now() + d),
        }
    }

    fn expires_within(&self, margin: Duration) -> bool {
        match self.expires_at {
            Some(at) => SystemTime::now() + margin >= at,
            None => false,
        }
    }

    /// The authenticated character's ID, from the access token's `sub`
    /// claim (`CHARACTER:EVE:<id>`). The claim is read without signature
    /// verification — fine for identifying your own session; do not use it
    /// to authenticate third-party tokens.
    pub fn character_id(&self) -> Option<u64> {
        self.claim("sub")?
            .as_str()?
            .rsplit(':')
            .next()?
            .parse()
            .ok()
    }

    /// The authenticated character's name, from the token's `name` claim.
    /// Unverified; see [`TokenSet::character_id`].
    pub fn character_name(&self) -> Option<String> {
        Some(self.claim("name")?.as_str()?.to_string())
    }

    fn claim(&self, name: &str) -> Option<serde_json::Value> {
        let payload = self.access_token.split('.').nth(1)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?;
        let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        Some(claims.get(name)?.clone())
    }
}

/// Owns a [`TokenSet`] and refreshes it before expiry. Pass to
/// [`crate::ClientBuilder::authenticator`] to authenticate every request.
pub struct Authenticator {
    sso: SsoClient,
    tokens: tokio::sync::Mutex<TokenSet>,
}

impl Authenticator {
    pub fn new(sso: SsoClient, tokens: TokenSet) -> Self {
        Self {
            sso,
            tokens: tokio::sync::Mutex::new(tokens),
        }
    }

    /// A currently-valid access token, refreshing first if the held one
    /// expires within the next minute.
    pub async fn access_token(&self) -> Result<String, AuthError> {
        let mut tokens = self.tokens.lock().await;
        if tokens.expires_within(Duration::from_secs(60)) {
            let refresh = tokens
                .refresh_token
                .clone()
                .ok_or(AuthError::NoRefreshToken)?;
            *tokens = self.sso.refresh(&refresh).await?;
        }
        Ok(tokens.access_token.clone())
    }

    /// Snapshot of the current tokens (e.g. to persist the refresh token).
    pub async fn tokens(&self) -> TokenSet {
        self.tokens.lock().await.clone()
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

impl std::error::Error for BridgeError {}

impl<'c> oauth2::AsyncHttpClient<'c> for BridgeClient {
    type Error = BridgeError;
    type Future =
        Pin<Box<dyn Future<Output = Result<oauth2::HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: oauth2::HttpRequest) -> Self::Future {
        Box::pin(async move {
            let request = reqwest::Request::try_from(request).map_err(BridgeError::Reqwest)?;
            let response = self.0.execute(request).await.map_err(BridgeError::Reqwest)?;
            let mut builder = http::Response::builder().status(response.status().as_u16());
            for (name, value) in response.headers() {
                builder = builder.header(name.as_str(), value.as_bytes());
            }
            let body = response.bytes().await.map_err(BridgeError::Reqwest)?;
            builder.body(body.to_vec()).map_err(BridgeError::Http)
        })
    }
}
