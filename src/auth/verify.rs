//! Verifying EVE SSO access tokens against CCP's published signing keys
//! (the `verify` feature).

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;

use super::claims::{jwt_payload, RawClaims};
use super::TokenClaims;

/// EVE SSO's JSON Web Key Set: the public keys access tokens are signed with.
pub const SSO_JWKS_URL: &str = "https://login.eveonline.com/oauth/jwks";

/// Issuers EVE SSO writes into `iss` (it has used both forms).
const ISSUERS: [&str; 2] = ["login.eveonline.com", "https://login.eveonline.com"];

/// Every EVE SSO access token lists this audience besides the client ID.
const EVE_AUDIENCE: &str = "EVE Online";

/// Allowed clock skew when checking `exp`.
const LEEWAY: Duration = Duration::from_secs(60);

/// An unknown `kid` refetches the key set at most this often.
const REFETCH_INTERVAL: Duration = Duration::from_secs(300);

/// Why an access token failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// Not a well-formed JWT, or its claims aren't an EVE token's.
    Malformed(String),
    /// Signed with an algorithm other than RS256.
    UnsupportedAlgorithm(String),
    /// No key in the key set has the token's `kid`.
    UnknownKey(String),
    /// The signature doesn't match.
    BadSignature,
    /// `iss` isn't EVE SSO.
    WrongIssuer(Option<String>),
    /// `aud` doesn't name this application's client ID and `EVE Online`.
    WrongAudience(Vec<String>),
    /// The token has expired.
    Expired,
    /// The key set couldn't be fetched or parsed.
    Jwks(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Malformed(e) => write!(f, "malformed access token: {e}"),
            VerifyError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported token signing algorithm {alg}")
            }
            VerifyError::UnknownKey(kid) => write!(f, "no EVE SSO signing key with kid {kid}"),
            VerifyError::BadSignature => write!(f, "access token signature is invalid"),
            VerifyError::WrongIssuer(iss) => {
                write!(f, "access token issuer {iss:?} is not EVE SSO")
            }
            VerifyError::WrongAudience(aud) => {
                write!(f, "access token audience {aud:?} is not this application")
            }
            VerifyError::Expired => write!(f, "access token has expired"),
            VerifyError::Jwks(e) => write!(f, "could not load EVE SSO signing keys: {e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verifies EVE SSO access tokens: RS256 signature against CCP's key set,
/// issuer, audience (your client ID and `EVE Online`) and expiry.
///
/// Use it for tokens you didn't receive from EVE SSO yourself, e.g. one a
/// browser or another service hands you. The key set is fetched on first
/// use and again when a token names an unknown key, so CCP's key rotation
/// is picked up.
///
/// ```no_run
/// # async fn run(token: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// use eve_esi_client::auth::JwtVerifier;
///
/// let verifier = JwtVerifier::new("your-client-id")?;
/// let claims = verifier.verify(token).await?;
/// println!("token for {:?}", claims.character_id);
/// # Ok(())
/// # }
/// ```
pub struct JwtVerifier {
    client_id: String,
    jwks_url: String,
    /// `None` for keys given up front, which are never refetched.
    http: Option<reqwest::Client>,
    keys: tokio::sync::Mutex<KeyCache>,
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, RsaPublicKey>,
    fetched_at: Option<Instant>,
}

impl JwtVerifier {
    /// Verifies tokens issued to `client_id`, fetching keys from
    /// [`SSO_JWKS_URL`] with a default HTTP client.
    pub fn new(client_id: impl Into<String>) -> Result<Self, VerifyError> {
        let http = reqwest::Client::builder()
            .timeout(crate::DEFAULT_TIMEOUT)
            .connect_timeout(crate::DEFAULT_CONNECT_TIMEOUT)
            .build()
            .map_err(|e| VerifyError::Jwks(e.to_string()))?;
        Ok(Self::with_http_client(client_id, SSO_JWKS_URL, http))
    }

    /// Fetches keys from `jwks_url` through `http`.
    pub fn with_http_client(
        client_id: impl Into<String>,
        jwks_url: impl Into<String>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            jwks_url: jwks_url.into(),
            http: Some(http),
            keys: tokio::sync::Mutex::new(KeyCache::default()),
        }
    }

    /// Uses the keys in `jwks` (a JWK Set document) and never fetches any.
    pub fn from_jwks(client_id: impl Into<String>, jwks: &str) -> Result<Self, VerifyError> {
        Ok(Self {
            client_id: client_id.into(),
            jwks_url: String::new(),
            http: None,
            keys: tokio::sync::Mutex::new(KeyCache {
                keys: parse_jwks(jwks.as_bytes())?,
                fetched_at: Some(Instant::now()),
            }),
        })
    }

    /// Verify `token` and return its claims.
    pub async fn verify(&self, token: &str) -> Result<TokenClaims, VerifyError> {
        let (signed, signature) = token
            .rsplit_once('.')
            .ok_or_else(|| VerifyError::Malformed("not a JWT".into()))?;
        let header: Header = decode_segment(signed.split('.').next().unwrap_or_default())?;
        if header.alg != "RS256" {
            return Err(VerifyError::UnsupportedAlgorithm(header.alg));
        }
        let kid = header
            .kid
            .ok_or_else(|| VerifyError::Malformed("no kid in header".into()))?;
        let key = self.key(&kid).await?;
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|e| VerifyError::Malformed(e.to_string()))?;
        let signature =
            Signature::try_from(signature.as_slice()).map_err(|_| VerifyError::BadSignature)?;
        VerifyingKey::<Sha256>::new(key)
            .verify(signed.as_bytes(), &signature)
            .map_err(|_| VerifyError::BadSignature)?;

        let payload =
            jwt_payload(token).ok_or_else(|| VerifyError::Malformed("bad payload".into()))?;
        let raw: RawClaims =
            serde_json::from_slice(&payload).map_err(|e| VerifyError::Malformed(e.to_string()))?;
        let claims = TokenClaims::from_raw(raw);
        if !claims
            .issuer
            .as_deref()
            .is_some_and(|iss| ISSUERS.contains(&iss))
        {
            return Err(VerifyError::WrongIssuer(claims.issuer));
        }
        let audience = |a: &str| claims.audience.iter().any(|x| x == a);
        if !audience(&self.client_id) || !audience(EVE_AUDIENCE) {
            return Err(VerifyError::WrongAudience(claims.audience));
        }
        match claims.expires_at {
            Some(at) if at + LEEWAY > SystemTime::now() => Ok(claims),
            Some(_) => Err(VerifyError::Expired),
            None => Err(VerifyError::Malformed("no exp claim".into())),
        }
    }

    async fn key(&self, kid: &str) -> Result<RsaPublicKey, VerifyError> {
        let mut cache = self.keys.lock().await;
        if let Some(key) = cache.keys.get(kid) {
            return Ok(key.clone());
        }
        let recently = cache
            .fetched_at
            .is_some_and(|at| at.elapsed() < REFETCH_INTERVAL);
        let Some(http) = self.http.as_ref().filter(|_| !recently) else {
            return Err(VerifyError::UnknownKey(kid.to_string()));
        };
        let body = async {
            http.get(&self.jwks_url)
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await
        }
        .await
        .map_err(|e| VerifyError::Jwks(e.to_string()))?;
        cache.keys = parse_jwks(&body)?;
        cache.fetched_at = Some(Instant::now());
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| VerifyError::UnknownKey(kid.to_string()))
    }
}

impl fmt::Debug for JwtVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtVerifier")
            .field("client_id", &self.client_id)
            .field("jwks_url", &self.jwks_url)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

fn decode_segment<T: serde::de::DeserializeOwned>(segment: &str) -> Result<T, VerifyError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| VerifyError::Malformed(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| VerifyError::Malformed(e.to_string()))
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

/// The RSA keys of a JWK Set, by `kid`. Other key types (EVE also publishes
/// an ES256 key) are skipped.
fn parse_jwks(body: &[u8]) -> Result<HashMap<String, RsaPublicKey>, VerifyError> {
    let set: JwkSet = serde_json::from_slice(body).map_err(|e| VerifyError::Jwks(e.to_string()))?;
    let b64 = |s: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.trim_end_matches('='))
            .map_err(|e| VerifyError::Jwks(e.to_string()))
    };
    let mut keys = HashMap::new();
    for jwk in set.keys {
        let (Some(kid), Some(n), Some(e)) = (jwk.kid, jwk.n, jwk.e) else {
            continue;
        };
        if jwk.kty != "RSA" {
            continue;
        }
        let key = RsaPublicKey::new(
            BigUint::from_bytes_be(&b64(&n)?),
            BigUint::from_bytes_be(&b64(&e)?),
        )
        .map_err(|e| VerifyError::Jwks(e.to_string()))?;
        keys.insert(kid, key);
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use std::sync::OnceLock;

    use rand_chacha::rand_core::SeedableRng as _;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    use rsa::traits::PublicKeyParts as _;
    use rsa::RsaPrivateKey;

    const KID: &str = "JWT-Signature-Key";

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A throwaway key, generated (deterministically) once per test run.
    fn private_key() -> RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0x5eed);
            RsaPrivateKey::new(&mut rng, 1024).unwrap()
        })
        .clone()
    }

    fn jwks() -> String {
        let public = private_key().to_public_key();
        serde_json::json!({
            "keys": [
                {"alg": "RS256", "e": b64(&public.e().to_bytes_be()), "kid": KID,
                 "kty": "RSA", "n": b64(&public.n().to_bytes_be()), "use": "sig"},
                {"alg": "ES256", "crv": "P-256", "kid": "8878a23f", "kty": "EC",
                 "use": "sig", "x": "AA", "y": "AA"}
            ],
            "SkipUnresolvedJsonWebKeys": true
        })
        .to_string()
    }

    fn sign(header: serde_json::Value, claims: serde_json::Value) -> String {
        let signed = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let signature = SigningKey::<Sha256>::new(private_key()).sign(signed.as_bytes());
        format!("{signed}.{}", b64(&signature.to_bytes()))
    }

    fn header() -> serde_json::Value {
        serde_json::json!({"alg": "RS256", "kid": KID, "typ": "JWT"})
    }

    fn claims(exp_offset: i64) -> serde_json::Value {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        serde_json::json!({
            "scp": ["esi-fleets.read_fleet.v1"],
            "sub": "CHARACTER:EVE:2112625428",
            "aud": ["client-id", "EVE Online"],
            "name": "Rapid Bounce",
            "owner": "owner-hash",
            "exp": now + exp_offset,
            "iat": now - 60,
            "iss": "https://login.eveonline.com",
        })
    }

    #[tokio::test]
    async fn accepts_a_valid_token_and_returns_its_claims() {
        let verifier = JwtVerifier::from_jwks("client-id", &jwks()).unwrap();
        let claims = verifier
            .verify(&sign(header(), claims(1200)))
            .await
            .unwrap();
        assert_eq!(claims.character_id, Some(2112625428));
        assert_eq!(claims.scopes, ["esi-fleets.read_fleet.v1"]);
    }

    #[tokio::test]
    async fn rejects_tampering_and_wrong_claims() {
        let verifier = JwtVerifier::from_jwks("client-id", &jwks()).unwrap();
        let valid = sign(header(), claims(1200));

        // Swap in a payload for another character, keeping the signature.
        let mut forged = claims(1200);
        forged["sub"] = "CHARACTER:EVE:1".into();
        let parts: Vec<&str> = valid.split('.').collect();
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            b64(forged.to_string().as_bytes()),
            parts[2]
        );
        assert_eq!(
            verifier.verify(&tampered).await,
            Err(VerifyError::BadSignature)
        );

        assert_eq!(
            verifier.verify(&sign(header(), claims(-3600))).await,
            Err(VerifyError::Expired)
        );
        let mut other_app = claims(1200);
        other_app["aud"] = serde_json::json!(["someone-else", "EVE Online"]);
        assert!(matches!(
            verifier.verify(&sign(header(), other_app)).await,
            Err(VerifyError::WrongAudience(_))
        ));
        let mut other_issuer = claims(1200);
        other_issuer["iss"] = "https://evil.example".into();
        assert!(matches!(
            verifier.verify(&sign(header(), other_issuer)).await,
            Err(VerifyError::WrongIssuer(_))
        ));
        let hs256 = serde_json::json!({"alg": "HS256", "kid": KID});
        assert_eq!(
            verifier.verify(&sign(hs256, claims(1200))).await,
            Err(VerifyError::UnsupportedAlgorithm("HS256".into()))
        );
        let unknown = serde_json::json!({"alg": "RS256", "kid": "rotated-away"});
        assert_eq!(
            verifier.verify(&sign(unknown, claims(1200))).await,
            Err(VerifyError::UnknownKey("rotated-away".into()))
        );
        assert!(matches!(
            verifier.verify("not-a-jwt").await,
            Err(VerifyError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn fetches_the_key_set_once() {
        let server = MockServer::start_async().await;
        let jwks_mock = server
            .mock_async(|when, then| {
                when.method(GET).path("/oauth/jwks");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(jwks());
            })
            .await;
        #[cfg(feature = "rustls-no-provider")]
        let _ = rustls::crypto::ring::default_provider().install_default();
        let verifier = JwtVerifier::with_http_client(
            "client-id",
            server.url("/oauth/jwks"),
            reqwest::Client::new(),
        );
        for _ in 0..3 {
            verifier
                .verify(&sign(header(), claims(1200)))
                .await
                .unwrap();
        }
        // An unknown kid right after a fetch doesn't hammer the endpoint.
        let unknown = serde_json::json!({"alg": "RS256", "kid": "new-key"});
        assert!(verifier.verify(&sign(unknown, claims(1200))).await.is_err());
        assert_eq!(jwks_mock.calls_async().await, 1);
    }
}
