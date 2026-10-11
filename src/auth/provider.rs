//! Pluggable sources of access tokens, and refresh notifications.

use std::fmt;

use super::{AuthError, TokenSet};

/// A source of access tokens for one principal (usually one character).
///
/// The client asks for a token before every request it authenticates. An
/// implementation decides where tokens live and when to refresh them:
/// [`super::Authenticator`] holds a [`TokenSet`] in memory, [`StaticToken`]
/// is a token obtained elsewhere, and a server can implement it over its
/// database.
///
/// Attach one to a client with [`crate::ClientBuilder::token_provider`], or
/// to a clone of an existing client with
/// [`crate::Client::with_token_provider`]; the clones share their error and
/// rate limiters and response cache.
///
/// A failure is reported by the request as [`crate::Error::Custom`] holding
/// the error's message. To act on the [`AuthError`] itself, fetch the token
/// first and send it with [`crate::Client::with_access_token`].
///
/// Implement it with [`macro@crate::async_trait`]:
///
/// ```
/// use eve_esi_client::auth::{AuthError, TokenProvider};
///
/// struct FromEnv;
///
/// #[eve_esi_client::async_trait]
/// impl TokenProvider for FromEnv {
///     async fn access_token(&self) -> Result<String, AuthError> {
///         std::env::var("EVE_ACCESS_TOKEN").map_err(|_| AuthError::NoRefreshToken)
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait TokenProvider: Send + Sync {
    /// An access token that is valid now.
    async fn access_token(&self) -> Result<String, AuthError>;
}

/// An access token obtained elsewhere, used as-is and never refreshed.
#[derive(Clone)]
pub struct StaticToken(String);

impl StaticToken {
    pub fn new(access_token: impl Into<String>) -> Self {
        Self(access_token.into())
    }
}

impl fmt::Debug for StaticToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StaticToken").field(&"<redacted>").finish()
    }
}

#[async_trait::async_trait]
impl TokenProvider for StaticToken {
    async fn access_token(&self) -> Result<String, AuthError> {
        Ok(self.0.clone())
    }
}

/// Told about every refresh an [`super::Authenticator`] attempts; register
/// one with [`super::Authenticator::with_listener`].
///
/// EVE may issue a new refresh token on every refresh, and the old one can
/// stop working, so a server should store [`TokenSet::refresh_token`] from
/// [`RefreshListener::refreshed`] before using the new access token. Both
/// methods run while the authenticator holds its lock, so no other refresh
/// for the same principal happens until they return; keep them short.
///
/// ```
/// use eve_esi_client::auth::{AuthError, RefreshListener, TokenSet};
///
/// struct Store;
///
/// #[eve_esi_client::async_trait]
/// impl RefreshListener for Store {
///     async fn refreshed(&self, tokens: &TokenSet) {
///         // UPDATE refresh_token SET token = .. WHERE character_id = ..
///     }
///     async fn refresh_failed(&self, tokens: &TokenSet, error: &AuthError) {
///         if error.is_revoked() {
///             // DELETE the stored token: the user has to log in again.
///         }
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait RefreshListener: Send + Sync {
    /// A refresh succeeded; `tokens` are the new tokens now in use.
    async fn refreshed(&self, tokens: &TokenSet);

    /// A refresh failed. `tokens` are the (expired) tokens still held.
    /// [`AuthError::is_revoked`] tells a revoked token, which should be
    /// discarded, from a transient failure worth retrying later. Does
    /// nothing by default.
    async fn refresh_failed(&self, tokens: &TokenSet, error: &AuthError) {
        let _ = (tokens, error);
    }
}
