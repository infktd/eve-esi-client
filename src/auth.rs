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
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, RequestTokenError, Scope,
    TokenResponse as _, TokenUrl,
};

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
        Self::with_token_url(client_id.into(), redirect_uri, crate::SSO_TOKEN_URL)
    }

    fn with_token_url(
        client_id: String,
        redirect_uri: &str,
        token_url: &str,
    ) -> Result<Self, AuthError> {
        let oauth = BasicClient::new(ClientId::new(client_id))
            .set_auth_uri(
                AuthUrl::new(crate::SSO_AUTHORIZE_URL.to_string())
                    .map_err(|e| AuthError::Config(e.to_string()))?,
            )
            .set_token_uri(
                TokenUrl::new(token_url.to_string())
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
            .map_err(AuthError::from_token_request)?;
        Ok(TokenSet::from_response(&response))
    }

    /// Obtain a fresh token set from a refresh token.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenSet, AuthError> {
        let response = self
            .oauth
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(&self.http)
            .await
            .map_err(AuthError::from_token_request)?;
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
            let sso = SsoClient::with_token_url(
                "test-client".into(),
                "http://localhost:8787/callback",
                &token_url,
            )
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
}
