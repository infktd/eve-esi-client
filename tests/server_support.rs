//! Features for servers acting for many characters: confidential SSO
//! clients, per-principal clients sharing one budget and cache, refresh
//! notifications, and readable error responses.
//!
//! Requests use `GET /alliances` (a bare array of IDs) so CCP schema
//! changes can't invalidate the fixtures.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use chrono::{Duration as ChronoDuration, Utc};
use eve_esi_client::auth::{
    AuthError, Authenticator, CsrfToken, PkceCodeVerifier, RefreshListener, SsoClient,
    TokenProvider, TokenSet,
};
use eve_esi_client::{Error, ErrorExt as _};
use httpmock::prelude::*;

mod common;

const ALLIANCES_BODY: &str = "[99000001, 99000002, 99000003]";
const CLIENT_ID: &str = "test-client";
const CLIENT_SECRET: &str = "s3cr3t";
const REDIRECT: &str = "https://waitlist.example/auth/cb";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// An unsigned JWT for `character_id` with `scp`.
fn access_token_for(character_id: u64, scopes: &[&str]) -> String {
    format!(
        "{}.{}.signature",
        b64(br#"{"alg":"none"}"#),
        b64(serde_json::json!({
            "sub": format!("CHARACTER:EVE:{character_id}"),
            "name": format!("Pilot {character_id}"),
            "owner": "owner-hash",
            "scp": scopes,
        })
        .to_string()
        .as_bytes())
    )
}

fn token_response(access_token: &str, refresh_token: Option<&str>) -> String {
    let mut body = serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 1199,
    });
    if let Some(refresh) = refresh_token {
        body["refresh_token"] = refresh.into();
    }
    body.to_string()
}

fn basic_auth() -> String {
    let credentials = format!("{CLIENT_ID}:{CLIENT_SECRET}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(credentials)
    )
}

fn confidential_sso(server: &MockServer) -> SsoClient {
    common::install_crypto_provider();
    SsoClient::builder(CLIENT_ID, REDIRECT)
        .token_url(server.url("/v2/oauth/token"))
        .client_secret(CLIENT_SECRET)
        .build()
        .unwrap()
}

fn http_date(offset_secs: i64) -> String {
    (Utc::now() + ChronoDuration::seconds(offset_secs))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

#[tokio::test]
async fn confidential_client_authenticates_refresh_and_exchange_with_its_secret() {
    let server = MockServer::start_async().await;
    let refresh = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v2/oauth/token")
                .header("authorization", basic_auth())
                .form_urlencoded_tuple("grant_type", "refresh_token")
                .form_urlencoded_tuple("refresh_token", "legacy-refresh")
                .form_urlencoded_tuple_missing("client_secret");
            then.status(200)
                .header("content-type", "application/json")
                .body(token_response(
                    &access_token_for(1, &["publicData"]),
                    Some("rotated"),
                ));
        })
        .await;
    let exchange = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v2/oauth/token")
                .header("authorization", basic_auth())
                .form_urlencoded_tuple("grant_type", "authorization_code")
                .form_urlencoded_tuple("code", "the-code")
                .form_urlencoded_tuple_missing("code_verifier");
            then.status(200)
                .header("content-type", "application/json")
                .body(token_response(
                    &access_token_for(2, &["publicData"]),
                    Some("fresh"),
                ));
        })
        .await;
    let sso = confidential_sso(&server);
    assert!(sso.is_confidential());

    let refreshed = sso.refresh("legacy-refresh").await.unwrap();
    assert_eq!(refreshed.refresh_token.as_deref(), Some("rotated"));
    assert_eq!(refreshed.character_id(), Some(1));
    let exchanged = sso.exchange_without_pkce("the-code").await.unwrap();
    assert_eq!(exchanged.refresh_token.as_deref(), Some("fresh"));
    assert_eq!(refresh.calls_async().await, 1);
    assert_eq!(exchange.calls_async().await, 1);

    // PKCE still works alongside the secret.
    exchange.delete_async().await;
    let pkce = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v2/oauth/token")
                .header("authorization", basic_auth())
                .form_urlencoded_tuple_exists("code_verifier");
            then.status(200)
                .header("content-type", "application/json")
                .body(token_response(&access_token_for(2, &[]), Some("fresh")));
        })
        .await;
    sso.exchange("the-code", PkceCodeVerifier::new("v".repeat(43)))
        .await
        .unwrap();
    assert_eq!(pkce.calls_async().await, 1);
}

#[test]
fn authorize_variants_carry_the_callers_state() {
    common::install_crypto_provider();
    let public = SsoClient::new(CLIENT_ID, REDIRECT).unwrap();
    assert!(!public.is_confidential());
    let pending = public.authorize_with_state(["publicData"], CsrfToken::new("alt.nonce".into()));
    assert!(pending.url.contains("state=alt.nonce"), "{}", pending.url);
    assert!(pending.url.contains("code_challenge="), "{}", pending.url);
    assert_eq!(pending.csrf_state.secret(), "alt.nonce");

    // Without a secret, PKCE can't be skipped.
    let err = public
        .authorize_without_pkce(["publicData"], CsrfToken::new("normal".into()))
        .unwrap_err();
    assert!(matches!(err, AuthError::Config(_)), "{err:?}");

    let confidential = SsoClient::builder(CLIENT_ID, REDIRECT)
        .client_secret(CLIENT_SECRET)
        .build()
        .unwrap();
    let url = confidential
        .authorize_without_pkce(
            ["publicData", "esi-skills.read_skills.v1"],
            CsrfToken::new("normal".into()),
        )
        .unwrap();
    assert!(url.starts_with(eve_esi_client::SSO_AUTHORIZE_URL), "{url}");
    assert!(url.contains("state=normal"), "{url}");
    assert!(
        url.contains("scope=publicData+esi-skills.read_skills.v1"),
        "{url}"
    );
    assert!(!url.contains("code_challenge"), "{url}");
    assert!(!url.contains(CLIENT_SECRET), "{url}");
    assert!(!format!("{confidential:?}").contains(CLIENT_SECRET));
}

#[tokio::test]
async fn exchange_without_pkce_needs_a_secret() {
    common::install_crypto_provider();
    let public = SsoClient::new(CLIENT_ID, REDIRECT).unwrap();
    let err = public.exchange_without_pkce("code").await.unwrap_err();
    assert!(matches!(err, AuthError::Config(_)), "{err:?}");
    assert!(!err.is_permanent());
}

#[tokio::test]
async fn refresh_keeps_the_old_refresh_token_unless_rotated_and_sends_scopes() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v2/oauth/token")
                .form_urlencoded_tuple("scope", "publicData esi-fleets.read_fleet.v1");
            then.status(200)
                .header("content-type", "application/json")
                .body(token_response(&access_token_for(1, &["publicData"]), None));
        })
        .await;
    let sso = confidential_sso(&server);
    let tokens = sso
        .refresh_with_scopes("keep-me", ["publicData", "esi-fleets.read_fleet.v1"])
        .await
        .unwrap();
    assert_eq!(mock.calls_async().await, 1);
    assert_eq!(tokens.refresh_token.as_deref(), Some("keep-me"));
    assert_eq!(tokens.scopes(), ["publicData"]);
    assert_eq!(tokens.owner_hash().as_deref(), Some("owner-hash"));
    assert!(!tokens.expires_within(Duration::from_secs(60)));
}

#[derive(Default)]
struct Recorder {
    refreshed: Mutex<Vec<TokenSet>>,
    failed: Mutex<Vec<(Option<String>, bool, bool)>>,
}

#[eve_esi_client::async_trait]
impl RefreshListener for Recorder {
    async fn refreshed(&self, tokens: &TokenSet) {
        self.refreshed.lock().unwrap().push(tokens.clone());
    }
    async fn refresh_failed(&self, tokens: &TokenSet, error: &AuthError) {
        self.failed.lock().unwrap().push((
            tokens.refresh_token.clone(),
            error.is_revoked(),
            error.is_permanent(),
        ));
    }
}

fn expired(refresh_token: Option<&str>) -> TokenSet {
    TokenSet {
        access_token: access_token_for(1, &[]),
        refresh_token: refresh_token.map(String::from),
        expires_at: Some(SystemTime::now() - Duration::from_secs(5)),
    }
}

#[tokio::test]
async fn listener_sees_rotated_tokens_once_however_many_requests_wait() {
    let server = MockServer::start_async().await;
    let token = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/v2/oauth/token")
                .form_urlencoded_tuple("refresh_token", "first");
            then.status(200)
                .header("content-type", "application/json")
                .delay(Duration::from_millis(50))
                .body(token_response(&access_token_for(1, &[]), Some("second")));
        })
        .await;
    let recorder = Arc::new(Recorder::default());
    let auth = Arc::new(
        Authenticator::new(confidential_sso(&server), expired(Some("first")))
            .with_listener(recorder.clone()),
    );
    let tokens = futures_join(auth.clone()).await;
    assert!(tokens.iter().all(|t| t == &access_token_for(1, &[])));
    assert_eq!(token.calls_async().await, 1);
    let refreshed = recorder.refreshed.lock().unwrap().clone();
    assert_eq!(refreshed.len(), 1);
    assert_eq!(refreshed[0].refresh_token.as_deref(), Some("second"));
    assert_eq!(auth.tokens().await.refresh_token.as_deref(), Some("second"));
}

async fn futures_join(auth: Arc<Authenticator>) -> Vec<String> {
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let auth = auth.clone();
            tokio::spawn(async move { TokenProvider::access_token(&*auth).await.unwrap() })
        })
        .collect();
    let mut out = Vec::new();
    for handle in handles {
        out.push(handle.await.unwrap());
    }
    out
}

#[tokio::test]
async fn listener_tells_revoked_tokens_from_transient_and_client_failures() {
    let server = MockServer::start_async().await;
    for (refresh, status, body) in [
        (
            "revoked",
            400,
            r#"{"error":"invalid_grant","error_description":"Invalid refresh token. Token missing/expired."}"#,
        ),
        ("bad-client", 401, r#"{"error":"invalid_client"}"#),
        ("flaky", 502, "<html>502 Bad Gateway</html>"),
    ] {
        server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/v2/oauth/token")
                    .form_urlencoded_tuple("refresh_token", refresh);
                then.status(status)
                    .header(
                        "content-type",
                        if status == 502 {
                            "text/html"
                        } else {
                            "application/json"
                        },
                    )
                    .body(body);
            })
            .await;
    }
    let recorder = Arc::new(Recorder::default());
    for refresh in [Some("revoked"), Some("bad-client"), Some("flaky"), None] {
        let auth = Authenticator::new(confidential_sso(&server), expired(refresh))
            .with_listener(recorder.clone());
        auth.access_token().await.unwrap_err();
    }
    assert_eq!(
        *recorder.failed.lock().unwrap(),
        [
            (Some("revoked".into()), true, true),
            (Some("bad-client".into()), false, true),
            (Some("flaky".into()), false, false),
            (None, false, true),
        ]
    );
    assert!(recorder.refreshed.lock().unwrap().is_empty());
}

/// Per-principal clients cloned from one base client share its error
/// budget and cache, and the cache never crosses characters.
#[tokio::test]
async fn principals_share_limits_and_a_character_keyed_cache() {
    let server = MockServer::start_async().await;
    let alice_token = access_token_for(1, &["publicData"]);
    let bob_token = access_token_for(2, &["publicData"]);
    let alice_mock = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/alliances")
                .header("authorization", format!("Bearer {alice_token}"));
            then.status(200)
                .header("content-type", "application/json")
                .header("Date", http_date(0))
                .header("Expires", http_date(60))
                .header("X-ESI-Error-Limit-Remain", "77")
                .header("X-ESI-Error-Limit-Reset", "30")
                .body(ALLIANCES_BODY);
        })
        .await;
    let bob_mock = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/alliances")
                .header("authorization", format!("Bearer {bob_token}"));
            then.status(200)
                .header("content-type", "application/json")
                .header("Date", http_date(0))
                .header("Expires", http_date(60))
                .body("[99000009]");
        })
        .await;
    let anonymous_mock = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/alliances")
                .header_missing("authorization");
            then.status(200)
                .header("content-type", "application/json")
                .body("[]");
        })
        .await;
    common::install_crypto_provider();
    let base = eve_esi_client::Client::builder()
        .user_agent("eve-esi tests")
        .base_url(server.base_url())
        .build()
        .unwrap();

    let alice = base.with_access_token(alice_token.clone());
    let bob = base.with_token_provider(Arc::new(eve_esi_client::auth::StaticToken::new(
        bob_token.clone(),
    )));
    assert_eq!(alice.get_alliances().send().await.unwrap().len(), 3);
    // Alice's request taught every clone the error budget.
    assert_eq!(base.error_budget().unwrap().remain, 77);
    assert_eq!(bob.error_budget().unwrap().remain, 77);

    // Bob is not served Alice's cached response.
    assert_eq!(bob.get_alliances().send().await.unwrap().len(), 1);
    // A second clone for Alice is served from the shared cache.
    let alice_again = base.with_access_token(alice_token);
    let hit = alice_again.get_alliances().send().await.unwrap();
    assert_eq!(hit.headers()["x-esi-client-cache"], "hit");
    assert_eq!(alice_mock.calls_async().await, 1);
    assert_eq!(bob_mock.calls_async().await, 1);

    // And without_auth sends no token at all.
    assert!(alice
        .without_auth()
        .get_alliances()
        .send()
        .await
        .unwrap()
        .is_empty());
    assert_eq!(anonymous_mock.calls_async().await, 1);
}

#[tokio::test]
async fn token_provider_failures_fail_the_request_without_reaching_esi() {
    struct Revoked;
    #[eve_esi_client::async_trait]
    impl TokenProvider for Revoked {
        async fn access_token(&self) -> Result<String, AuthError> {
            Err(AuthError::NoRefreshToken)
        }
    }
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200).body(ALLIANCES_BODY);
        })
        .await;
    common::install_crypto_provider();
    let client = eve_esi_client::Client::builder()
        .user_agent("eve-esi tests")
        .base_url(server.base_url())
        .token_provider(Arc::new(Revoked))
        .build()
        .unwrap();
    let err = client.get_alliances().send().await.unwrap_err();
    assert!(
        matches!(&err, Error::Custom(m) if m.contains("no refresh token")),
        "{err:?}"
    );
    assert_eq!(err.esi_message(), None);
    assert_eq!(mock.calls_async().await, 0);
}

#[tokio::test]
async fn error_responses_keep_their_status_and_message_whatever_the_body() {
    let server = MockServer::start_async().await;
    common::install_crypto_provider();
    let client = eve_esi_client::Client::builder()
        .user_agent("eve-esi tests")
        .base_url(server.base_url())
        .build()
        .unwrap();
    let cases = [
        (
            404,
            "application/json",
            r#"{"error":"Character is not in a fleet"}"#,
            "Character is not in a fleet",
        ),
        (
            502,
            "text/html",
            "<html><title>502: Bad gateway</title></html>",
            "<html><title>502: Bad gateway</title></html>",
        ),
        (403, "text/plain", "", "Forbidden"),
    ];
    for (status, content_type, body, message) in cases {
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path("/alliances");
                then.status(status)
                    .header("content-type", content_type)
                    .header("X-ESI-Error-Limit-Remain", "90")
                    .header("X-ESI-Error-Limit-Reset", "30")
                    .body(body);
            })
            .await;
        let err = client.get_alliances().send().await.unwrap_err();
        assert!(matches!(err, Error::ErrorResponse(_)), "{status}: {err:?}");
        assert_eq!(err.status().map(|s| s.as_u16()), Some(status));
        assert_eq!(err.esi_message(), Some(message), "{status}");
        assert_eq!(err.is_retryable(), status == 502);
        mock.delete_async().await;
    }
    assert_eq!(client.error_budget().unwrap().remain, 90);
}
