//! Reading EVE SSO access-token (JWT) claims.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Deserialize;

/// The claims of an EVE SSO access token (a JWT).
///
/// ```
/// # use eve_esi_client::auth::TokenClaims;
/// # fn run(access_token: &str) {
/// if let Some(claims) = TokenClaims::from_jwt_unverified(access_token) {
///     println!("{:?} ({:?})", claims.name, claims.character_id);
///     assert!(claims.has_scope("esi-skills.read_skills.v1"));
/// }
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TokenClaims {
    /// The `sub` claim, e.g. `CHARACTER:EVE:2112625428`.
    pub subject: String,
    /// The character ID from `sub`, when it names a character.
    pub character_id: Option<u64>,
    /// The character's name (`name`).
    pub name: Option<String>,
    /// The character owner hash (`owner`). It changes when the character
    /// moves to another EVE account, so a server can notice a sold
    /// character and stop trusting tokens stored for its previous owner.
    pub owner: Option<String>,
    /// The granted scopes (`scp`, which EVE sends as a string for a single
    /// scope and an array otherwise). Empty when no scopes were granted.
    pub scopes: Vec<String>,
    /// When the token expires (`exp`).
    pub expires_at: Option<SystemTime>,
    /// When the token was issued (`iat`).
    pub issued_at: Option<SystemTime>,
    /// The issuer (`iss`), e.g. `https://login.eveonline.com`.
    pub issuer: Option<String>,
    /// The audiences (`aud`): the client ID and `"EVE Online"`.
    pub audience: Vec<String>,
    /// The client ID the token was issued to (`azp`).
    pub authorized_party: Option<String>,
}

impl TokenClaims {
    /// Decode a JWT's claims **without verifying its signature**.
    ///
    /// Fine for tokens you received from EVE SSO yourself over TLS (the
    /// response of a code exchange or refresh). Never use it to authenticate
    /// a token someone else hands you; verify those with `JwtVerifier`
    /// (the `verify` feature) instead. Returns `None` if `token` isn't a JWT
    /// or has no `sub`.
    pub fn from_jwt_unverified(token: &str) -> Option<Self> {
        let payload = jwt_payload(token)?;
        serde_json::from_slice::<RawClaims>(&payload)
            .ok()
            .map(Self::from_raw)
    }

    pub(crate) fn from_raw(raw: RawClaims) -> Self {
        let character_id = raw
            .sub
            .strip_prefix("CHARACTER:EVE:")
            .and_then(|id| id.parse().ok());
        Self {
            character_id,
            subject: raw.sub,
            name: raw.name,
            owner: raw.owner,
            scopes: raw.scp.into_vec(),
            expires_at: raw.exp.map(unix_time),
            issued_at: raw.iat.map(unix_time),
            issuer: raw.iss,
            audience: raw.aud.into_vec(),
            authorized_party: raw.azp,
        }
    }

    /// Whether `scope` was granted.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Whether the token has expired (`false` if it has no `exp`).
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|at| at <= SystemTime::now())
    }
}

fn unix_time(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// The JWT claims as EVE SSO sends them.
#[derive(Deserialize)]
pub(crate) struct RawClaims {
    sub: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    scp: OneOrMany,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: OneOrMany,
    #[serde(default)]
    azp: Option<String>,
}

/// A claim that is a string for one value and an array for several.
#[derive(Deserialize, Default)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
    #[default]
    None,
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
            OneOrMany::None => Vec::new(),
        }
    }
}

/// The decoded payload segment of a JWT.
pub(crate) fn jwt_payload(token: &str) -> Option<Vec<u8>> {
    let payload = token.split('.').nth(1)?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()
}

/// A claim from a JWT's payload, read without verifying its signature.
pub(crate) fn jwt_claim(token: &str, name: &str) -> Option<serde_json::Value> {
    let mut claims: serde_json::Value = serde_json::from_slice(&jwt_payload(token)?).ok()?;
    Some(claims.get_mut(name)?.take())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(claims: serde_json::Value) -> String {
        let encode = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        format!(
            "{}.{}.sig",
            encode(br#"{"alg":"RS256","kid":"JWT-Signature-Key","typ":"JWT"}"#),
            encode(claims.to_string().as_bytes())
        )
    }

    #[test]
    fn reads_every_claim_of_an_eve_token() {
        let token = jwt(serde_json::json!({
            "scp": ["esi-skills.read_skills.v1", "esi-fleets.read_fleet.v1"],
            "jti": "998e12c7-3241-43c5-8355-2c48822e0a1b",
            "kid": "JWT-Signature-Key",
            "sub": "CHARACTER:EVE:2112625428",
            "azp": "my3rdpartyclientid",
            "tenant": "tranquility",
            "tier": "live",
            "region": "world",
            "aud": ["my3rdpartyclientid", "EVE Online"],
            "name": "Rapid Bounce",
            "owner": "8PmzCeTKb4VFUDrHLc/AeZXDSWM=",
            "exp": 1_648_563_218_u64,
            "iat": 1_648_562_018_u64,
            "iss": "https://login.eveonline.com"
        }));
        let claims = TokenClaims::from_jwt_unverified(&token).unwrap();
        assert_eq!(claims.subject, "CHARACTER:EVE:2112625428");
        assert_eq!(claims.character_id, Some(2112625428));
        assert_eq!(claims.name.as_deref(), Some("Rapid Bounce"));
        assert_eq!(
            claims.owner.as_deref(),
            Some("8PmzCeTKb4VFUDrHLc/AeZXDSWM=")
        );
        assert_eq!(
            claims.scopes,
            ["esi-skills.read_skills.v1", "esi-fleets.read_fleet.v1"]
        );
        assert!(claims.has_scope("esi-fleets.read_fleet.v1"));
        assert!(!claims.has_scope("esi-fleets.write_fleet.v1"));
        assert_eq!(claims.expires_at, Some(unix_time(1_648_563_218)));
        assert_eq!(claims.issued_at, Some(unix_time(1_648_562_018)));
        assert!(claims.is_expired());
        assert_eq!(
            claims.issuer.as_deref(),
            Some("https://login.eveonline.com")
        );
        assert_eq!(claims.audience, ["my3rdpartyclientid", "EVE Online"]);
        assert_eq!(
            claims.authorized_party.as_deref(),
            Some("my3rdpartyclientid")
        );
    }

    #[test]
    fn a_single_scope_is_a_string_and_none_is_absent() {
        let one = jwt(serde_json::json!({"sub": "CHARACTER:EVE:1", "scp": "publicData"}));
        assert_eq!(
            TokenClaims::from_jwt_unverified(&one).unwrap().scopes,
            ["publicData"]
        );
        let none = jwt(serde_json::json!({"sub": "CHARACTER:EVE:1", "aud": "EVE Online"}));
        let claims = TokenClaims::from_jwt_unverified(&none).unwrap();
        assert!(claims.scopes.is_empty());
        assert_eq!(claims.audience, ["EVE Online"]);
        assert!(!claims.is_expired());
    }

    #[test]
    fn non_jwts_and_non_character_subjects() {
        assert_eq!(TokenClaims::from_jwt_unverified("opaque-token"), None);
        assert_eq!(TokenClaims::from_jwt_unverified("a.!!!.c"), None);
        let no_sub = jwt(serde_json::json!({"name": "x"}));
        assert_eq!(TokenClaims::from_jwt_unverified(&no_sub), None);
        let corp = jwt(serde_json::json!({"sub": "CORPORATION:EVE:98000001"}));
        let claims = TokenClaims::from_jwt_unverified(&corp).unwrap();
        assert_eq!(claims.character_id, None);
        assert_eq!(claims.subject, "CORPORATION:EVE:98000001");
    }
}
